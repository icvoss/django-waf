"""
Anomaly detector service for django-waf.

Analyses recent RequestLog records for behavioural patterns and auto-creates
expiring BlockRules when suspicious patterns are detected.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import timedelta
from decimal import ROUND_HALF_UP, Decimal

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("django_waf.anomaly_detector")

# A referer that is a bare origin with no path (e.g. "https://host") cannot be
# produced by genuine browser navigation: even Referrer-Policy: origin always
# serialises at least a trailing slash after the host ("https://host/"). A
# botnet that spoofs a static bare-origin referer to defeat the missing-referer
# check must therefore be treated the same as a missing referer (issue #24).
BARE_ORIGIN_REFERER_RE = r"^https?://[^/]+$"

# Single source of truth for the five detector function names, so
# DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS (BR-ANOM-008) and the boot-time
# check that validates it (checks.check_observe_only_detector_names,
# django_waf.W008) cannot desync if a detector is ever renamed. Each
# detector passes its own __name__-matching entry as detector_name to
# _get_or_create_auto_rule.
DETECTOR_NAMES = frozenset(
    {
        "detect_ua_rotation",
        "detect_subnet_burst",
        "detect_challenge_farms",
        "detect_unsolved_challenges",
        "detect_cloud_spray",
    }
)


def detect_ua_rotation(
    window_minutes: int = 5,
    threshold: int | None = None,
    dry_run: bool = False,
) -> list:
    """Detect IPs using an unusually large number of distinct User-Agent strings.

    Per BR-ANOM-001: flags IPs with more than threshold distinct UAs from the
    same IP within window_minutes. Creates expiring BlockRules with source='auto',
    action='challenge'. Does not duplicate existing active rules (BR-ANOM-004).

    Args:
        window_minutes: Time window to analyse (default 5).
        threshold: Distinct UA count threshold. Defaults to
                   DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS.
        dry_run: When True (#38), collects what would be created without
                 writing any BlockRule or emitting the anomaly_detected signal.

    Returns:
        List of BlockRule instances that were created (or, in dry-run, would
        have been created).
    """
    from django.db.models import Count

    from django_waf import conf
    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import RequestLog

    effective_threshold = threshold if threshold is not None else conf.DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS
    cutoff = timezone.now() - timedelta(minutes=window_minutes)

    # Group by ip_address, count distinct user_agent values
    qs = (
        RequestLog.objects.filter(timestamp__gte=cutoff)
        .values("ip_address")
        .annotate(distinct_ua_count=Count("user_agent", distinct=True))
        .filter(distinct_ua_count__gt=effective_threshold)
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS)

    for row in qs:
        ip = row["ip_address"]
        details = {"distinct_ua_count": row["distinct_ua_count"], "window_minutes": window_minutes}
        confidence = _scaled_confidence(
            observed=row["distinct_ua_count"],
            threshold=effective_threshold,
            span=effective_threshold * 2,
        )
        rule, created = _get_or_create_auto_rule(
            name=f"Auto: UA rotation from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.CHALLENGE,
            expiry=expiry,
            dry_run=dry_run,
            detector_name="detect_ua_rotation",
            confidence=confidence,
            evidence=details,
        )
        if created:
            created_rules.append(rule)
            if not dry_run:
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.UA_ROTATION,
                    details=details,
                )
                logger.info("django-waf: auto-created UA rotation rule for %s", ip)

    return created_rules


def detect_subnet_burst(window_minutes: int = 15, dry_run: bool = False) -> list:
    """Detect /24 (IPv4) or /48 (IPv6) subnets with anomalously high request volume.

    Per BR-ANOM-002 (as amended, issue #80): flags a subnet when BOTH of the
    following hold in the last window_minutes:

    1. Its request count meets the absolute floor,
       DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT. This floor is a
       fixed number read from settings, entirely independent of
       ``subnet_counts``, so no traffic pattern the detector is scoring can
       move it.
    2. Its request count also exceeds 3x the MEDIAN per-subnet count.

    Before #80, the multiplier was applied to the arithmetic MEAN. The mean
    is pulled towards every value added to the population it is computed
    over, including the attacker's own subnets: a botnet spread across many
    adjacent /24s at a similar low volume raises the mean it is judged
    against, so the more prefixes it occupies, the higher its own bar
    climbs and the safer every one of its own subnets becomes. This was
    observed in production (issue #80): a cohort sustained ~1.2 requests/hour
    per prefix across several adjacent /24s and /25s for a month and never
    triggered this detector, because each additional prefix it added
    inflated the mean it needed to clear.

    The median does not have this property to nearly the same degree: it is
    the middle-ranked value, so adding more attacker subnets at a similar
    (low) volume only ever inserts more values into the low end of the
    distribution. The median stays put until attacker-controlled subnets
    make up more than half of all subnets seen in the window, a materially
    harder bar than "adds one more low-volume entry", which is all it takes
    to move the mean. The median alone is not a complete fix (a large enough
    fraction of the window's traffic being attacker-controlled can still
    shift it), which is why the absolute floor is required as well: floor 1
    can never be diluted by population size, so it is the property's actual
    guarantee, and the median-based ratio remains as the existing
    proportionate signal for genuinely high-traffic deployments where a
    fixed floor alone would be too coarse.

    Args:
        window_minutes: Time window to analyse (default 15).
        dry_run: When True (#38), collects what would be created without
                 writing any BlockRule or emitting the anomaly_detected signal.

    Returns:
        List of BlockRule instances that were created (or, in dry-run, would
        have been created).
    """
    import statistics

    from django_waf import conf
    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import RequestLog

    cutoff = timezone.now() - timedelta(minutes=window_minutes)
    logs = RequestLog.objects.filter(timestamp__gte=cutoff).values_list("ip_address", flat=True)

    # Count requests per subnet (/24 for IPv4, /48 for IPv6)
    subnet_counts: dict[str, int] = {}
    for ip in logs:
        try:
            subnet = _get_subnet_prefix(ip)
        except ValueError:
            continue
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

    if not subnet_counts:
        return []

    median_count = statistics.median(subnet_counts.values())
    burst_threshold = median_count * 3
    min_count = conf.DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS)

    for subnet, count in subnet_counts.items():
        # Either condition is sufficient, and that is the whole point of
        # #80. Requiring BOTH would leave the defect in place: an attacker
        # who spreads across enough subnets at equal volume raises the
        # median until the ratio gate can never fire, and an AND would then
        # mean the floor never gets a say. The floor is the guarantee
        # precisely because it is population-independent, so it must be able
        # to fire on its own. The ratio remains as the proportionate signal
        # for high-traffic deployments, where a fixed floor alone is too
        # coarse to catch a subnet that is anomalous relative to its peers
        # while sitting below an absolute count.
        if count < min_count and count <= burst_threshold:
            continue

        details = {"count": count, "median": median_count, "threshold": burst_threshold, "min_count": min_count}
        confidence = _scaled_confidence(
            observed=count,
            threshold=burst_threshold,
            span=burst_threshold * 2,
        )
        rule, created = _get_or_create_auto_rule(
            name=f"Auto: subnet burst from {subnet}",
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern=subnet,
            action=RuleAction.CHALLENGE,
            expiry=expiry,
            dry_run=dry_run,
            detector_name="detect_subnet_burst",
            confidence=confidence,
            evidence=details,
        )
        if created:
            created_rules.append(rule)
            if not dry_run:
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.SUBNET_FLOOD,
                    details=details,
                )
                logger.info("django-waf: auto-created subnet burst rule for %s (count=%d)", subnet, count)

    return created_rules


def detect_challenge_farms(window_hours: int = 24, dry_run: bool = False) -> list:
    """Detect IPs with high challenge failure rates and low pass rates.

    Per BR-ANOM-003: IPs with challenge_failures > 10 and challenge_passes < 2
    within window_hours are blocked.

    Args:
        window_hours: Time window to analyse (default 24).
        dry_run: When True (#38), collects what would be created without
                 writing any BlockRule or emitting the anomaly_detected signal.

    Returns:
        List of BlockRule instances that were created (or, in dry-run, would
        have been created).
    """
    from django_waf import conf
    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import IPReputation

    cutoff = timezone.now() - timedelta(hours=window_hours)
    suspects = IPReputation.objects.filter(
        last_seen_at__gte=cutoff,
        challenge_failures__gt=10,
        challenge_passes__lt=2,
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS)

    for rep in suspects:
        ip = rep.ip_address
        details = {
            "challenge_failures": rep.challenge_failures,
            "challenge_passes": rep.challenge_passes,
        }
        confidence = _scaled_confidence(observed=rep.challenge_failures, threshold=10, span=20)

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: challenge farm from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
            expiry=expiry,
            dry_run=dry_run,
            detector_name="detect_challenge_farms",
            confidence=confidence,
            evidence=details,
        )
        if created:
            created_rules.append(rule)
            if not dry_run:
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.CHALLENGE_FARM,
                    details=details,
                )
                logger.info("django-waf: auto-created challenge farm rule for %s", ip)

    return created_rules


def detect_unsolved_challenges(
    window_minutes: int = 60,
    min_challenged: int | None = None,
    referer_ratio: float | None = None,
    subnet_window_minutes: int | None = None,
    dry_run: bool = False,
) -> list:
    """Detect IPs, and subnets, that receive challenges but never solve them.

    Per issue #84, traced against a live deployment: the signal is
    ABANDONMENT (a challenge issued and never attempted), not failure, and
    it concentrates by subnet far more sharply than by IP. An attacker
    rotating ~120 addresses per /24 leaves almost no individual IP reaching
    ``min_challenged`` within the window, while the /24 in aggregate is
    unmistakable (thousands of abandoned challenges, 100+ distinct IPs).
    This detector therefore runs two parallel aggregations:

    Per-IP path (unchanged in shape from before #84):
    1. IP has >= min_challenged challenged verdicts in the window.
    2. IP has no ChallengeToken solved within the configured recency
       window (DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS). Before
       #84 this was unbounded, granting permanent immunity from a single
       solve at any point in history.
    3. Majority (>= referer_ratio) of the IP's requests have empty referer
       on paths other than "/"

    Creates an IP-exact BLOCK rule directly (unchanged: an IP that clears
    all three per-IP signals is already high-confidence).

    Subnet path (new in #84, given its own window in #93):
    1. The /24 (IPv4) or /48 (IPv6) subnet's total challenged-verdict count
       across its OWN window (subnet_window_minutes, independent of the
       per-IP path's window_minutes) meets
       DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED, AND the number of
       DISTINCT contributing IPs meets DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS.
       Both are required so one noisy host cannot escalate its neighbours:
       a single IP alone can never cross the distinct-IP floor no matter
       its own challenge count.
    2. The subnet is exempted if any of its contributing IPs solved a
       challenge within the recency window (same bound as the per-IP path,
       for the same reason: an occasional solve from a rotating pool must
       not grant the whole /24 permanent immunity).

    The two paths were sharing window_minutes until #93: the subnet
    thresholds above were calibrated in #84 against a seven-day aggregate,
    but the per-IP path's 60-minute default left the subnet path unable to
    accumulate enough volume in an hour to ever clear them against a
    deliberately slow-drip attacker (measured live: 42 subnets seen in 60
    minutes, 0 qualifying; 241 subnets seen in 360 minutes, 10 qualifying,
    with the existing thresholds unchanged). The per-IP path's window stays
    at its existing default (it is already producing correct BLOCK rules in
    production and widening it is out of scope); the subnet path now reads
    its own window from subnet_window_minutes /
    DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES (default 360). See conf.py for
    the full measurement.

    The empty-referer requirement is deliberately NOT applied to the subnet
    path: it is evaluated per-IP against a specific IP's non-root request
    mix, and a subnet aggregate has no single "the subnet's referer" to
    test. Composing distinct-IP weighting with challenge-before-block
    staging (see ``_get_or_create_auto_rule``'s two-stage promotion below)
    is what keeps the subnet path false-positive-safe without it, per
    issue #84's stated discipline.

    A subnet clearing its threshold is never blocked directly: the first
    crossing creates (or refreshes) a CHALLENGE rule. Only a REPEAT
    crossing, detected by an already-active auto CHALLENGE rule for the
    same subnet that THIS detector itself created (own-provenance-only,
    #97; another detector's CHALLENGE rule of the same shape, e.g. from
    detect_subnet_burst or detect_cloud_spray, does not count), promotes
    it to BLOCK. This matters more here than for the per-IP path because
    abandonment has a legitimate cause: a real user who closes the tab or
    whose JavaScript is blocked abandons a challenge exactly as a bot
    does, so a single crossing is not enough evidence to block outright.
    Issue #82 measured that a coarse signal here would have caught at
    least 35.6% real users on the same deployment.

    Args:
        window_minutes: Time window to analyse for the per-IP path (default
                        60). Unchanged by #93: this path is already
                        producing correct BLOCK rules in production at this
                        window and widening it is out of scope.
        min_challenged: Minimum challenged verdicts for the per-IP path.
                        Defaults to DJANGO_WAF_UNSOLVED_MIN_CHALLENGED.
        referer_ratio: Fraction of non-root requests with empty referer
                       required to trigger the per-IP path. Defaults to
                       DJANGO_WAF_UNSOLVED_REFERER_RATIO.
        subnet_window_minutes: Time window to analyse for the subnet path,
                       independent of window_minutes. Defaults to
                       DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES (360). See
                       conf.py and this docstring's "Subnet path" section
                       for why the subnet path needs a wider window than
                       the per-IP path (#93).
        dry_run: When True (#38), collects what would be created without
                 writing any BlockRule or emitting the anomaly_detected signal.

    Returns:
        List of BlockRule instances that were created (or, in dry-run, would
        have been created). May include both IP and CIDR rules.
    """
    from django.db.models import Count

    from django_waf import conf
    from django_waf.enums import ChallengeStatus, RequestLogSource, Verdict
    from django_waf.models import ChallengeToken, RequestLog

    effective_min_challenged = min_challenged if min_challenged is not None else conf.DJANGO_WAF_UNSOLVED_MIN_CHALLENGED
    effective_referer_ratio = referer_ratio if referer_ratio is not None else conf.DJANGO_WAF_UNSOLVED_REFERER_RATIO
    effective_subnet_window_minutes = (
        subnet_window_minutes if subnet_window_minutes is not None else conf.DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES
    )

    cutoff = timezone.now() - timedelta(minutes=window_minutes)
    solve_exemption_cutoff = timezone.now() - timedelta(hours=conf.DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS)

    # All challenged verdicts in the per-IP window, per IP, with their
    # counts. Scoped to source=middleware (#32): a nginx_log row's verdict
    # is inferred from the access-log status code, not observed by
    # rule_engine.evaluate_request. The nginx access log records the same
    # request middleware already logged, so counting both would double the
    # apparent challenged_count for every IP and distort this detector's
    # threshold checks.
    challenged_by_ip = list(
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            verdict=Verdict.CHALLENGED,
            source=RequestLogSource.MIDDLEWARE,
        )
        .values("ip_address")
        .annotate(challenged_count=Count("id"))
    )

    # The subnet path's own aggregation, over its own (wider) window (#93).
    # A separate query rather than filtering challenged_by_ip: the per-IP
    # window is a strict subset of the subnet window by default (60 vs 360
    # minutes), so reusing challenged_by_ip would silently cap the subnet
    # aggregate at whatever the per-IP path happened to see.
    subnet_cutoff = timezone.now() - timedelta(minutes=effective_subnet_window_minutes)
    challenged_by_ip_for_subnet = list(
        RequestLog.objects.filter(
            timestamp__gte=subnet_cutoff,
            verdict=Verdict.CHALLENGED,
            source=RequestLogSource.MIDDLEWARE,
        )
        .values("ip_address")
        .annotate(challenged_count=Count("id"))
    )

    all_challenged_ips = {row["ip_address"] for row in challenged_by_ip} | {
        row["ip_address"] for row in challenged_by_ip_for_subnet
    }

    # IPs with a SOLVED ChallengeToken within the recency window (#84).
    # Before #84 this had no time bound at all, so a single solve at any
    # point in an IP's history granted permanent immunity; traced live,
    # that removed half the candidates in a 60-minute window. Computed once
    # against the union of both paths' candidate IPs so the same recency
    # bound applies identically regardless of which window surfaced the IP.
    # order_by() clears ChallengeToken.Meta.ordering (-issued_at) before
    # distinct(): without it, Django appends issued_at to the SELECT, so
    # DISTINCT applies to (ip_address, issued_at) and this returns one row
    # per solved token rather than one row per IP (#59).
    solved_ips = set(
        ChallengeToken.objects.filter(
            ip_address__in=all_challenged_ips,
            status=ChallengeStatus.SOLVED,
            solved_at__gte=solve_exemption_cutoff,
        )
        .order_by()
        .values_list("ip_address", flat=True)
        .distinct()
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS)

    created_rules.extend(
        _detect_unsolved_challenges_per_ip(
            challenged_by_ip=challenged_by_ip,
            solved_ips=solved_ips,
            cutoff=cutoff,
            window_minutes=window_minutes,
            min_challenged=effective_min_challenged,
            referer_ratio=effective_referer_ratio,
            expiry=expiry,
            dry_run=dry_run,
        )
    )
    created_rules.extend(
        _detect_unsolved_challenges_by_subnet(
            challenged_by_ip=challenged_by_ip_for_subnet,
            solved_ips=solved_ips,
            window_minutes=effective_subnet_window_minutes,
            expiry=expiry,
            dry_run=dry_run,
        )
    )

    return created_rules


def _detect_unsolved_challenges_per_ip(
    *,
    challenged_by_ip: list,
    solved_ips: set,
    cutoff,
    window_minutes: int,
    min_challenged: int,
    referer_ratio: float,
    expiry,
    dry_run: bool,
) -> list:
    """The per-IP half of detect_unsolved_challenges. See that function's
    docstring for the three-signal contract this implements unchanged.
    """
    from django.db.models import Count, Q

    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import RequestLog

    candidates = [row for row in challenged_by_ip if row["challenged_count"] >= min_challenged]
    if not candidates:
        return []

    candidate_ips = [row["ip_address"] for row in candidates]

    # Prefetch referer stats for all candidate IPs in two queries
    non_root_counts = dict(
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            ip_address__in=candidate_ips,
        )
        .exclude(path="/")
        .values("ip_address")
        .annotate(total=Count("id"))
        .values_list("ip_address", "total")
    )
    empty_referer_counts = dict(
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            ip_address__in=candidate_ips,
        )
        .exclude(path="/")
        .filter(Q(referer="") | Q(referer__isnull=True))
        .values("ip_address")
        .annotate(total=Count("id"))
        .values_list("ip_address", "total")
    )

    created_rules = []

    for row in candidates:
        ip = row["ip_address"]

        if ip in solved_ips:
            continue

        non_root_count = non_root_counts.get(ip, 0)
        if non_root_count == 0:
            continue

        empty_count = empty_referer_counts.get(ip, 0)
        empty_referer_ratio = empty_count / non_root_count
        if empty_referer_ratio < referer_ratio:
            continue

        details = {
            "challenged_count": row["challenged_count"],
            "empty_referer_ratio": round(empty_referer_ratio, 2),
            "non_root_requests": non_root_count,
            "window_minutes": window_minutes,
        }
        confidence = _scaled_confidence(
            observed=empty_referer_ratio,
            threshold=referer_ratio,
            span=1 - referer_ratio,
        )

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: unsolved challenges from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
            expiry=expiry,
            dry_run=dry_run,
            detector_name="detect_unsolved_challenges",
            confidence=confidence,
            evidence=details,
        )
        if created:
            created_rules.append(rule)
            if not dry_run:
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.UNSOLVED_CHALLENGE,
                    details=details,
                )
                logger.info(
                    "django-waf: auto-created unsolved challenge rule for %s (challenged=%d, referer_empty=%.0f%%)",
                    ip,
                    row["challenged_count"],
                    empty_referer_ratio * 100,
                )

    return created_rules


def _detect_unsolved_challenges_by_subnet(
    *,
    challenged_by_ip: list,
    solved_ips: set,
    window_minutes: int,
    expiry,
    dry_run: bool,
) -> list:
    """The subnet half of detect_unsolved_challenges (#84). See that
    function's docstring for the two-signal, two-stage contract this
    implements. ``challenged_by_ip`` and ``window_minutes`` here are already
    scoped to the subnet path's own window (#93), independent of the per-IP
    path's window.
    """
    from django_waf import conf
    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import BlockRule, RuleSource

    min_subnet_challenged = conf.DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED
    min_subnet_ips = conf.DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS

    # Aggregate every challenged IP (not only per-IP candidates: a subnet's
    # abandonment can be real even when no single contributing IP reaches
    # min_challenged, which is exactly the gap #84 measured) into subnets,
    # tracking both the total challenged count and the set of distinct
    # contributing IPs.
    subnet_totals: dict[str, int] = {}
    subnet_ips: dict[str, set] = {}
    for row in challenged_by_ip:
        ip = row["ip_address"]
        try:
            subnet = _get_subnet_prefix(ip)
        except ValueError:
            continue
        subnet_totals[subnet] = subnet_totals.get(subnet, 0) + row["challenged_count"]
        subnet_ips.setdefault(subnet, set()).add(ip)

    created_rules = []

    for subnet, total in subnet_totals.items():
        distinct_ips = subnet_ips[subnet]
        if total < min_subnet_challenged or len(distinct_ips) < min_subnet_ips:
            continue

        # Exempt a subnet if any of its contributing IPs solved a challenge
        # within the recency window (same bound and rationale as the per-IP
        # path): an occasional solve from a rotating pool must not grant
        # the whole /24 permanent immunity.
        if distinct_ips & solved_ips:
            continue

        details = {
            "subnet_challenged_count": total,
            "distinct_ips": len(distinct_ips),
            "window_minutes": window_minutes,
        }
        confidence = _scaled_confidence(
            observed=total,
            threshold=min_subnet_challenged,
            span=min_subnet_challenged * 2,
        )

        # Two-stage promotion (#84, issue #82's false-positive discipline):
        # a subnet never goes straight to BLOCK on one crossing. Detect a
        # repeat crossing as "this subnet already has an active auto
        # CHALLENGE rule from THIS detector" and promote to BLOCK only
        # then; a first crossing creates (or refreshes) the CHALLENGE rule.
        # This existence check is a read, so it runs identically under
        # dry_run: BR-ANOM-006 requires a dry run to report what a real run
        # WOULD do, and only the write below is conditioned on dry_run.
        #
        # own-provenance-only (#97): membership in detectors is checked in
        # Python, not via a database filter on the raw comma-joined string,
        # so "detect_unsolved_challenges" cannot false-match as a substring
        # of some other, longer detector name. A CHALLENGE rule created by
        # detect_subnet_burst or detect_cloud_spray, which target the same
        # rule_type/pattern/source/action shape via the same
        # _get_subnet_prefix, does not count as this detector's own prior
        # crossing merely because it exists; this detector's own name must
        # actually be present in the set. Before the detectors field
        # existed, rule_type/pattern/source/action alone could not
        # distinguish "this detector already challenged this subnet" from
        # "some other detector already did", and because both of those
        # detectors run by default, this detector's own first crossing
        # almost never reached CHALLENGE: a default deployment measured 9
        # of 10 subnet rules promoted straight to BLOCK. The owner ruled
        # against cross-detector acceleration: another detector's rule does
        # not promote this one.
        #
        # detectors is additive (see _merge_detector_names), so even
        # though detect_cloud_spray runs after this detector on every
        # run_all_detectors pass and also targets this same subnet shape,
        # its write only adds "detect_cloud_spray" to the set rather than
        # replacing "detect_unsolved_challenges" already in it. Without
        # that additive guarantee, this membership check would still fail:
        # the next pass would find this detector's own name missing from a
        # row a sibling detector had since overwritten, and the two-stage
        # promotion would never reach BLOCK for exactly the subnets
        # multiple detectors independently flag.
        existing_subnet_rule = BlockRule.objects.filter(
            rule_type=RuleType.CIDR,
            pattern=subnet,
            source=RuleSource.AUTO,
            action=RuleAction.CHALLENGE,
            is_active=True,
        ).first()
        already_challenged = existing_subnet_rule is not None and "detect_unsolved_challenges" in (
            existing_subnet_rule.detectors.split(",")
        )
        stage_action = RuleAction.BLOCK if already_challenged else RuleAction.CHALLENGE

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: unsolved challenges from {subnet} ({len(distinct_ips)} IPs)",
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern=subnet,
            action=stage_action,
            expiry=expiry,
            dry_run=dry_run,
            detector_name="detect_unsolved_challenges",
            confidence=confidence,
            evidence=details,
        )
        if created:
            created_rules.append(rule)
            if not dry_run:
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.UNSOLVED_CHALLENGE,
                    details=details,
                )
                logger.info(
                    "django-waf: auto-created unsolved challenge %s rule for %s (challenged=%d, ips=%d)",
                    stage_action,
                    subnet,
                    total,
                    len(distinct_ips),
                )

    return created_rules


def detect_cloud_spray(window_minutes: int = 30, dry_run: bool = False) -> list:
    """Detect coordinated low-and-slow scraping from many distinct IPs.

    Identifies UAs shared by many distinct IPs (>= DJANGO_WAF_CLOUD_SPRAY_MIN_IPS)
    where each IP makes only 1-3 requests with no referer. This pattern is
    characteristic of cloud-hosted bot farms that evade per-IP rate limits.

    A referer that is a bare origin with no path (``BARE_ORIGIN_REFERER_RE``,
    e.g. "https://example.com") is treated the same as a missing referer:
    genuine browser navigation always serialises at least a trailing slash
    after the host, so a spoofed static bare-origin referer is otherwise
    invisible to this detector (issue #24).

    Flags subnets rather than individual IPs — cloud providers allocate
    contiguous blocks, so a single CIDR catches the cluster efficiently.
    Aggregation uses ``_get_subnet_prefix`` (the /24 network for IPv4, the
    /48 network for IPv6), shared with ``detect_subnet_burst``.

    Args:
        window_minutes: Time window to analyse (default 30).
        dry_run: When True (#38), collects what would be created without
                 writing any BlockRule or emitting the anomaly_detected signal.

    Returns:
        List of BlockRule instances that were created (or, in dry-run, would
        have been created).
    """
    from django.db.models import Count, Q

    from django_waf import conf
    from django_waf.enums import AnomalyType, RuleAction, RuleType
    from django_waf.models import RequestLog

    cutoff = timezone.now() - timedelta(minutes=window_minutes)
    min_ips = conf.DJANGO_WAF_CLOUD_SPRAY_MIN_IPS
    max_per_ip = conf.DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP

    # Step 1: Find UAs used by many distinct IPs with no referer (or a
    # spoofed bare-origin referer, which is indistinguishable from missing).
    spray_uas = (
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
        )
        .filter(Q(referer="") | Q(referer__isnull=True) | Q(referer__regex=BARE_ORIGIN_REFERER_RE))
        .exclude(user_agent="")
        .values("user_agent")
        .annotate(distinct_ips=Count("ip_address", distinct=True))
        .filter(distinct_ips__gte=min_ips)
        .order_by("-distinct_ips")[:5]
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS)

    for ua_row in spray_uas:
        ua = ua_row["user_agent"]

        # Step 2: Get IPs using this UA with low request counts and no referer
        # (or a spoofed bare-origin referer — same treatment as Step 1).
        ip_counts = (
            RequestLog.objects.filter(
                timestamp__gte=cutoff,
                user_agent=ua,
            )
            .filter(Q(referer="") | Q(referer__isnull=True) | Q(referer__regex=BARE_ORIGIN_REFERER_RE))
            .values("ip_address")
            .annotate(req_count=Count("id"))
            .filter(req_count__lte=max_per_ip)
        )

        suspicious_ips = [row["ip_address"] for row in ip_counts]
        if len(suspicious_ips) < min_ips:
            continue

        # Step 3: Aggregate into subnets (/24 IPv4, /48 IPv6) and create rules
        subnet_counts: dict[str, int] = {}
        for ip in suspicious_ips:
            try:
                subnet = _get_subnet_prefix(ip)
            except ValueError:
                continue
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        for subnet, count in subnet_counts.items():
            if count < 2:
                continue

            details = {
                "subnet": subnet,
                "ip_count": count,
                "total_spray_ips": len(suspicious_ips),
                "user_agent": ua[:200],
                "window_minutes": window_minutes,
            }
            confidence = _scaled_confidence(observed=count, threshold=min_ips, span=min_ips * 2)

            rule, created = _get_or_create_auto_rule(
                name=f"Auto: cloud spray from {subnet} ({count} IPs, UA: {ua[:40]})",
                rule_type=RuleType.CIDR,
                match_type="cidr",
                pattern=subnet,
                action=RuleAction.CHALLENGE,
                expiry=expiry,
                dry_run=dry_run,
                detector_name="detect_cloud_spray",
                confidence=confidence,
                evidence=details,
            )
            if created:
                created_rules.append(rule)
                if not dry_run:
                    _emit_anomaly_signal(
                        rule=rule,
                        anomaly_type=AnomalyType.CLOUD_SPRAY,
                        details=details,
                    )
                    logger.info(
                        "django-waf: auto-created cloud spray rule for %s (%d IPs)",
                        subnet,
                        count,
                    )

    return created_rules


def run_all_detectors(window_minutes: int | None = None, dry_run: bool = False) -> dict:
    """Run all anomaly detectors and return a summary of findings.

    Args:
        window_minutes: Override the analysis window, in minutes, for every
            detector. ``None`` (the default) leaves each detector on its own
            configured default window. ``detect_challenge_farms`` takes its
            window in hours, so the value is converted (rounded up to the
            nearest hour, minimum 1) before being forwarded to it. Forwarded
            to ``detect_unsolved_challenges`` as its per-IP ``window_minutes``
            only (#93): that detector's subnet path keeps its own,
            independently configured window
            (``DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES``) regardless of
            this override, since the two paths were deliberately decoupled.
        dry_run: When True (#38), every detector collects what would be
            created and reports it in the return value without writing any
            BlockRule, activating anything, or emitting the
            anomaly_detected signal. ``run_all_detectors(dry_run=True)``
            makes zero DB writes.

    Returns:
        Dict with keys: ua_rotation_rules, subnet_burst_rules,
        challenge_farm_rules, unsolved_challenge_rules, cloud_spray_rules,
        total_rules_created. In dry-run these counts describe what WOULD be
        created, not what was created.
    """
    if window_minutes is None:
        ua_rules = detect_ua_rotation(dry_run=dry_run)
        subnet_rules = detect_subnet_burst(dry_run=dry_run)
        farm_rules = detect_challenge_farms(dry_run=dry_run)
        unsolved_rules = detect_unsolved_challenges(dry_run=dry_run)
        spray_rules = detect_cloud_spray(dry_run=dry_run)
    else:
        window_hours = max(1, -(-window_minutes // 60))  # ceiling division
        ua_rules = detect_ua_rotation(window_minutes=window_minutes, dry_run=dry_run)
        subnet_rules = detect_subnet_burst(window_minutes=window_minutes, dry_run=dry_run)
        farm_rules = detect_challenge_farms(window_hours=window_hours, dry_run=dry_run)
        unsolved_rules = detect_unsolved_challenges(window_minutes=window_minutes, dry_run=dry_run)
        spray_rules = detect_cloud_spray(window_minutes=window_minutes, dry_run=dry_run)

    total = len(ua_rules) + len(subnet_rules) + len(farm_rules) + len(unsolved_rules) + len(spray_rules)
    logger.info(
        "django-waf anomaly detection%s: ua_rotation=%d subnet_burst=%d "
        "challenge_farm=%d unsolved_challenge=%d cloud_spray=%d total=%d",
        " (dry-run)" if dry_run else "",
        len(ua_rules),
        len(subnet_rules),
        len(farm_rules),
        len(unsolved_rules),
        len(spray_rules),
        total,
    )

    return {
        "ua_rotation_rules": len(ua_rules),
        "subnet_burst_rules": len(subnet_rules),
        "challenge_farm_rules": len(farm_rules),
        "unsolved_challenge_rules": len(unsolved_rules),
        "cloud_spray_rules": len(spray_rules),
        "total_rules_created": total,
    }


def auto_rule_review_outcomes(window_hours: int = 168) -> dict:
    """Return the confirmed/rejected/expired-unreviewed outcome counts (BR-ANOM-010).

    A live GROUP BY over BlockRule, not a separate aggregate table (per the
    ratified spec decision, CHK-OPEN-005): review_status is queried directly,
    so there is nothing to keep in sync. Every ReviewStatus bucket is present
    and zero-filled even when no rows fall into it.

    ``not_applicable`` rules were never queued for review (BR-ANOM-007): they
    are counted in their own bucket, never folded into ``pending``, so the
    metric does not misrepresent a rule nobody was ever asked to review as
    one still awaiting a decision.

    The window matches a rule that is either still ``source=auto`` or carries
    any review status other than ``not_applicable``. Confirming a rule
    promotes it to ``source=admin``, so filtering on source alone would empty
    the ``confirmed`` bucket permanently (django-waf #56).

    Args:
        window_hours: How far back, in hours, to look at BlockRule.created_at.
            Default 168 (7 days).

    Returns:
        Dict with keys "pending", "confirmed", "rejected",
        "expired_unreviewed", "not_applicable", and "total".
    """
    from django.db.models import Count, Q

    from django_waf.enums import ReviewStatus, RuleSource
    from django_waf.models import BlockRule

    window_start = timezone.now() - timedelta(hours=window_hours)
    # Match on provenance OR review state, not on source alone. A confirmed
    # rule is promoted to source=ADMIN by DashboardAnomalyConfirmView (which
    # is what stops it reappearing in the review queue and stops the detector
    # re-matching it on its source=AUTO lookup key), so a source=AUTO-only
    # filter would drop every rule out of this metric at the exact moment it
    # was confirmed, leaving the confirmed bucket permanently empty and the
    # metric reporting only the outcomes nobody approved.
    #
    # Widening on review_status rather than source is precise rather than
    # loose: review_status only ever leaves NOT_APPLICABLE for a rule an
    # anomaly detector created, so no hand-authored or feed-sourced rule can
    # enter the count through this arm.
    reviewed = ~Q(review_status=ReviewStatus.NOT_APPLICABLE)
    rows = (
        BlockRule.objects.filter(Q(source=RuleSource.AUTO) | reviewed, created_at__gte=window_start)
        .values("review_status")
        .annotate(count=Count("id"))
    )

    counts = dict.fromkeys(ReviewStatus.values, 0)
    for row in rows:
        counts[row["review_status"]] = row["count"]

    return {
        "pending": counts[ReviewStatus.PENDING],
        "confirmed": counts[ReviewStatus.CONFIRMED],
        "rejected": counts[ReviewStatus.REJECTED],
        "expired_unreviewed": counts[ReviewStatus.EXPIRED_UNREVIEWED],
        "not_applicable": counts[ReviewStatus.NOT_APPLICABLE],
        "total": sum(counts.values()),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_subnet_prefix(ip: str) -> str:
    """Return the subnet prefix used for aggregating an IP address.

    IPv4 addresses are truncated to their /24 network. IPv6 addresses are
    truncated to their /48 network — a /24-equivalent aggregation for IPv6
    would silently span an enormous address range (a /24 IPv6 network still
    contains 2**104 addresses), corrupting burst detection, cloud-spray
    aggregation, and telemetry aggregation alike. Shared by
    ``detect_subnet_burst`` and ``detect_cloud_spray`` (this module) and
    ``threat_feed.build_telemetry_payload``.

    Args:
        ip: An IPv4 or IPv6 address string.

    Returns:
        The subnet in CIDR notation, e.g. "192.0.2.0/24" or "2001:db8::/48".

    Raises:
        ValueError: If ``ip`` is not a valid IP address.
    """
    parsed = ipaddress.ip_address(ip)
    prefix_length = 24 if parsed.version == 4 else 48
    return str(ipaddress.ip_network(f"{ip}/{prefix_length}", strict=False))


def _scaled_confidence(observed: float, threshold: float, span: float) -> Decimal:
    """Compute an auto-generated rule's confidence from how far it clears a threshold.

    Implements the shared shape of every per-detector confidence formula in
    03-services.md section 7: ``min(0.99, 0.5 + (observed - threshold) / span)``,
    floored at 0.5 (a detection that only just clears its threshold is a
    coin-flip signal, not a confident one). The 0.99 figure is an asymptotic
    ceiling, never an achievable value: after quantisation to two decimal
    places the result is capped so it never reaches 0.99, which would
    otherwise be reachable for a wide-enough margin and make an
    auto-generated rule's confidence indistinguishable from the 1.00
    hand-authored/feed default (BR-ANOM-009).

    Args:
        observed: The value the detector measured (e.g. distinct UA count).
        threshold: The threshold the detector compares against.
        span: The denominator that scales the margin. Guarded against zero
            or negative values (falls back to 1.0) so a misconfigured
            threshold cannot raise ZeroDivisionError or invert the scale.

    Returns:
        A Decimal quantised to 2 decimal places (matching the model field's
        ``DecimalField(max_digits=3, decimal_places=2)``), in the range
        [0.50, 0.99) - the formula approaches but never reaches 0.99
        (03-services.md section 7), so an unbounded margin cannot produce a
        value indistinguishable from the 0.99 ceiling itself.
    """
    safe_span = span if span > 0 else 1.0
    raw = 0.5 + (observed - threshold) / safe_span
    # Cap strictly below 0.99 after quantisation: min(raw, 0.99) alone can
    # round-trip to exactly 0.99 for a wide-enough margin (e.g. 0.985 rounds
    # up under ROUND_HALF_UP), which would violate the "never reaches 0.99"
    # guarantee that keeps an auto-generated rule's confidence always
    # distinguishable from the 1.00 hand-authored/feed default (BR-ANOM-009).
    # 0.984 is the largest two-decimal-safe value that quantises to 0.98.
    clamped = min(0.984, max(0.5, raw))
    return Decimal(str(clamped)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _get_or_create_auto_rule(
    *,
    name: str,
    rule_type: str,
    match_type: str,
    pattern: str,
    action: str,
    expiry,
    dry_run: bool = False,
    detector_name: str = "",
    confidence: Decimal | None = None,
    evidence: dict | None = None,
) -> tuple:
    """Create or refresh an auto-generated BlockRule, avoiding duplicates.

    Uses update_or_create keyed on (rule_type, pattern, source=AUTO, action)
    so concurrent detector runs cannot create duplicates. If the rule already
    exists, its expiry and is_active flag are refreshed, subject to the
    re-detection guard below.

    If duplicate rows already exist (created before this function existed, or
    via a race condition), catches MultipleObjectsReturned, deduplicates by
    keeping the newest row and deleting the rest, then retries.

    When ``dry_run`` is True (#38), performs a read-only existence check
    instead of update_or_create: no BlockRule is written, activated, or
    refreshed. Returns an unsaved ``BlockRule`` instance built from the same
    fields a real run would use, with ``created`` mirroring what a real run
    would report (``False`` if a matching auto rule is already active,
    ``True`` otherwise), so command/task output describing "would create N
    rules" matches what a subsequent non-dry-run invocation would actually do.
    Dry-run's no-writes contract is unconditional (BR-ANOM-006) and takes
    precedence over quarantine/observe-only, which only have an observable
    effect on a non-dry-run invocation.

    Quarantine decision (BR-ANOM-007, BR-ANOM-008): a newly-created rule is
    quarantined, is_active=False and review_status=PENDING, when either
    DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES is True or ``detector_name`` is
    listed in DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS. Otherwise it is
    created enforcing, is_active=True and review_status=NOT_APPLICABLE,
    exactly as before this rule existed.

    Evidence (BR-ANOM-009): when ``confidence`` is given, it is stored on
    the rule. When ``evidence`` is given, it is rendered as a human-readable
    ``notes`` value (one "key: value" line per entry), the same dict already
    built for the anomaly_detected signal. Neither key is touched when the
    corresponding argument is omitted, so a caller not yet passing them sees
    unchanged behaviour.

    Provenance (#97): ``detector_name`` (when non-empty) is added to
    ``BlockRule.detectors``, a comma-separated, sorted SET of every detector
    that has ever written to this row, not only used for the observe-only
    membership test above. This lets a detector that does its own promotion
    between actions, currently only ``detect_unsolved_challenges``'s subnet
    path, recognise a prior rule it created itself even after a *different*
    detector has since written to the same row. ``detectors`` sits in
    ``defaults`` (via the merge performed in ``_update_or_create_auto_rule``,
    not here), never in ``lookup``, so it does not affect the dedup key: two
    detectors that independently target the same (rule_type, pattern,
    source=AUTO, action) still update_or_create the same single row.

    The set must be additive, not last-writer-wins, because three detectors
    (``detect_subnet_burst``, ``detect_unsolved_challenges``'s subnet path,
    ``detect_cloud_spray``) can all independently target the identical
    (CIDR, subnet, AUTO, CHALLENGE) key when they share a subnet via
    ``_get_subnet_prefix``, and ``run_all_detectors`` runs all three, in
    that order, on every pass. A plain overwrite would mean
    ``detect_cloud_spray``, which always runs last, clobbers
    ``detect_unsolved_challenges``'s own stamp at the end of every pass; on
    the next pass that detector would no longer recognise its own prior
    rule, and its two-stage promotion would get stuck at stage one forever
    for exactly the subnets multiple detectors independently flag, which are
    the most suspicious ones. This does not reintroduce #97 (it fails safe
    toward CHALLENGE, never a wrong BLOCK), but it silently defeats the
    promotion mechanism, so the set must accumulate rather than replace.

    Re-detection guard (BR-ANOM-007, mirrors threat_feed.sync_feed's
    survive-later-syncs guarantee for feed-sourced allow rules): before
    writing, the existing row's review_status (if any) is read. When it is
    already CONFIRMED or REJECTED, is_active and review_status are left out
    of ``defaults`` entirely, so a later detector run refreshes only
    expires_at (and the evidence fields) and can never silently undo an
    operator's decision.

    Returns:
        (rule, created) tuple. ``rule`` is unsaved (``rule._state.adding is
        True``, never written to the database) when ``dry_run`` is True.
        Its ``pk`` is not unset: ``BlockRule.id`` is a UUIDField with
        ``default=uuid.uuid4``, so Django generates the UUID at
        instantiation regardless of whether the instance is ever saved.
    """
    from django_waf import conf
    from django_waf.enums import ReviewStatus, RuleSource
    from django_waf.models import BlockRule

    quarantine = conf.DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES
    observe_only = conf.DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS
    is_active_on_create = not (quarantine or detector_name in observe_only)
    review_status_on_create = ReviewStatus.NOT_APPLICABLE if is_active_on_create else ReviewStatus.PENDING

    lookup = {
        "rule_type": rule_type,
        "pattern": pattern,
        "source": RuleSource.AUTO,
        "action": action,
    }
    defaults = {
        "name": name,
        "match_type": match_type,
        "is_active": is_active_on_create,
        "review_status": review_status_on_create,
        "expires_at": expiry,
    }
    if confidence is not None:
        defaults["confidence"] = confidence
    if evidence is not None:
        defaults["notes"] = "\n".join(f"{key}: {value}" for key, value in evidence.items())

    if dry_run:
        existing = BlockRule.objects.filter(**lookup).first()
        if existing is not None:
            return existing, False
        defaults["detectors"] = _merge_detector_names("", detector_name)
        return BlockRule(**lookup, **defaults), True

    try:
        with transaction.atomic():
            rule, created = _update_or_create_auto_rule(lookup, defaults, detector_name)
        return rule, created
    except BlockRule.MultipleObjectsReturned:
        logger.warning(
            "django-waf: duplicate BlockRule rows for %s/%s, deduplicating",
            rule_type,
            pattern,
        )
        _deduplicate_block_rules(**lookup)
        with transaction.atomic():
            rule, created = _update_or_create_auto_rule(lookup, defaults, detector_name)
        return rule, created


def _merge_detector_names(existing_value: str, detector_name: str) -> str:
    """Add ``detector_name`` to the existing comma-separated detector set.

    Returns a sorted, comma-joined, deduplicated string. Additive by design
    (#97): the set only ever grows, so a later detector's write cannot
    remove a name a prior detector's write already added. An empty
    ``detector_name`` is a no-op (some callers, e.g. tests exercising
    _get_or_create_auto_rule directly, do not pass one), and never
    contributes an empty entry to the set.
    """
    names = {name for name in existing_value.split(",") if name}
    if detector_name:
        names.add(detector_name)
    return ",".join(sorted(names))


def _update_or_create_auto_rule(lookup: dict, defaults: dict, detector_name: str = "") -> tuple:
    """Read-before-write wrapper around BlockRule.objects.update_or_create.

    A plain single-shot update_or_create would let a later detector run
    silently undo an operator's review decision: BR-ANOM-007 requires that
    once an auto-generated rule's review_status is CONFIRMED or REJECTED, a
    re-detection of the same (rule_type, pattern, source=AUTO, action) must
    refresh only expires_at (and the evidence fields), leaving is_active and
    review_status exactly as the operator last set them. This mirrors
    threat_feed.sync_feed's equivalent guarantee for feed-sourced allow
    rules (services/threat_feed.py).

    ``detectors`` (#97) is merged here, not passed pre-computed in
    ``defaults``, because computing it correctly requires the existing
    row's current value, which is only fetched here under
    ``select_for_update()``. Merging happens unconditionally, including
    when the review-status guard below strips ``is_active``/
    ``review_status``: provenance is not a review decision, so a
    CONFIRMED/REJECTED rule's detector set still accumulates on
    re-detection exactly as an unreviewed rule's does.

    Must run inside the same transaction.atomic() block as its caller so the
    read and the write are consistent.
    """
    from django_waf.enums import ReviewStatus
    from django_waf.models import BlockRule

    existing = BlockRule.objects.filter(**lookup).select_for_update().first()
    write_defaults = dict(defaults)
    if existing is not None and existing.review_status in (ReviewStatus.CONFIRMED, ReviewStatus.REJECTED):
        write_defaults.pop("is_active", None)
        write_defaults.pop("review_status", None)

    write_defaults["detectors"] = _merge_detector_names(
        existing.detectors if existing is not None else "",
        detector_name,
    )

    return BlockRule.objects.update_or_create(**lookup, defaults=write_defaults)


def _deduplicate_block_rules(**lookup) -> int:
    """Keep the newest BlockRule matching ``lookup`` and delete the rest.

    Returns:
        Number of duplicate rows deleted.
    """
    from django_waf.models import BlockRule

    qs = BlockRule.objects.filter(**lookup).order_by("-created_at")
    if qs.count() <= 1:
        return 0
    keep_pk = qs.first().pk
    deleted, _ = qs.exclude(pk=keep_pk).delete()
    logger.info("django-waf: deleted %d duplicate BlockRule rows for %s", deleted, lookup)
    return deleted


def _emit_anomaly_signal(rule, anomaly_type: str, details: dict) -> None:
    """Emit the anomaly_detected signal safely."""
    try:
        from django_waf.signals import anomaly_detected

        anomaly_detected.send(
            sender=type(rule),
            rule=rule,
            anomaly_type=anomaly_type,
            details=details,
        )
    except Exception:
        logger.exception("django-waf: failed to emit anomaly_detected signal for rule %s", rule.pk)
