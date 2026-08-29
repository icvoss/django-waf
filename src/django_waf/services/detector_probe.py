"""
Detector liveness probe for django-waf.

Runs every anomaly detector against synthetic fixture traffic, shaped to
provably cross each detector's own configured threshold, and reports which
detectors did (and did not) produce a rule. This is not a dry-run against
real recent traffic: ``run_all_detectors`` returning ``total_rules_created:
0`` is the normal, healthy, overwhelmingly common result on a quiet site,
which is indistinguishable from a dead detector returning 0 against
anything. Three real defects this cycle (a ``getdel`` call reporting
success 40,936 times while doing nothing, 2.0.0's subnet feature producing
0 rules for 13 hours, and #97's staging skip) all passed tests, review and
release, and a probe built on real traffic would have stayed green
throughout each of them, reproducing the exact failure it exists to catch.
Building fixture rows that are guaranteed to cross a threshold makes zero
an unambiguous defect signal instead.

No environment guard of any kind gates this module. #97's staging skip was
exactly that class of defect: a probe that quietly does nothing in some
environments is the next one.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("django_waf.detector_probe")

# TEST-NET ranges (RFC 5737 documentation ranges), one distinct block per
# detector, so a leftover real BlockRule for the same pattern shape cannot
# make _get_or_create_auto_rule report created=False (a false red) or,
# under an inverted assertion, a false green. Real production traffic is
# never sourced from these ranges, so a collision here can only be this
# probe's own prior run (uncommitted, per the forced rollback below),
# never live traffic.
#
# Sub-ranges within the three /24s are chosen so each detector's synthetic
# IPs are disjoint from every other detector's, even though detect_subnet_burst
# aggregates ALL RequestLog rows within its window regardless of which
# detector's fixture wrote them: its floor check (count >= configured
# minimum) is population-independent by construction (see its own
# docstring), so the presence of other detectors' fixture rows in the same
# probe run cannot dilute or falsely trip it, provided its own subnet stays
# disjoint from any other detector's IPs that might otherwise land in the
# same /24 and change ITS count.
#
# These same octets also appear as literal fixtures scattered across this
# package's own test suite (test_commands.py, test_review_workflow.py,
# and others use addresses inside the same three /24s, including
# 203.0.113.10). This is not a collision risk: every test in this suite
# runs inside pytest-django's own per-test transaction, rolled back at
# teardown, and this module's transaction.atomic()/set_rollback(True) gives
# a real (non-test) invocation the same guarantee, so no test, and no probe
# run, can ever leave a persisted row behind for a later run to trip over.
_UA_ROTATION_IP = "192.0.2.10"
_UNSOLVED_CHALLENGE_IP = "192.0.2.50"
_SUBNET_BURST_SUBNET_BASE = "198.51.100."  # .10-.15 used below
_CHALLENGE_FARM_IP = "203.0.113.10"
_CLOUD_SPRAY_SUBNET_BASE = "203.0.113."  # .20-.40 used below (21 IPs)

_PROBE_UA = "django-waf-detector-probe/1.0"


def run_detector_probe(dry_run: bool = True) -> dict:
    """Run every anomaly detector against synthetic fixture traffic.

    Builds fixture ``RequestLog`` (and, for ``detect_challenge_farms``,
    ``IPReputation``) rows shaped to cross each detector's own configured
    threshold, derived from the documented business rules (``02-business-
    rules.md`` BR-ANOM-001 through BR-ANOM-003, BR-ANOM-002a) and the
    current ``conf.DJANGO_WAF_*`` settings, not by reading the detector's
    own query: deriving fixtures from the query would only prove the query
    still does what the query does, not that it does what the business
    rule requires.

    Everything runs inside a single ``transaction.atomic()`` block that is
    unconditionally rolled back before returning: no synthetic ``RequestLog``,
    ``IPReputation``, or ``BlockRule`` row is ever left committed, regardless
    of ``dry_run``. This is the single biggest risk in this module's design:
    a leaked synthetic row would corrupt dashboard counters, ``update_ip_
    reputation``'s next run, the real detectors' next run, and would ship a
    fake subnet to the collective threat feed via
    ``threat_feed.build_telemetry_payload``.

    Args:
        dry_run: Forwarded to every detector's own ``dry_run`` keyword
            (BR-ANOM-006). ``True`` (the default) makes every detector
            perform its read-only existence check only: no ``BlockRule`` is
            written or activated, and ``anomaly_detected`` is never
            emitted. ``True`` is the safe default because dry-run's
            no-writes contract is unconditional and detector-independent,
            so a probe run can never itself create an enforcing rule,
            however briefly, even before the surrounding rollback.

            ``False`` ("exercise writes") is an explicit, deliberate
            opt-in: it makes every detector run for real, which still
            cannot commit anything (the rollback is unconditional) but
            DOES fire ``anomaly_detected``. That signal is not
            transactional and is not covered by the rollback: any receiver
            a consumer has wired to it (paging, an external webhook, a
            metrics counter) fires for real, for a synthetic event, the
            moment a real detector call happens to create a rule. The
            package cannot know what a consuming project wired to that
            signal, so this is opt-in rather than the default. It exists
            because dry-run mode cannot reach defects in the write path
            itself (quarantine logic, the review_status guard, or the
            dedup-retry path), which only a real ``update_or_create`` call
            exercises.

    Returns:
        Dict with keys:
            - one key per name in ``anomaly_detector.DETECTOR_NAMES``,
              each mapping to a per-detector dict with ``alive`` (bool)
              and ``rules_reported`` (int, the count
              ``run_all_detectors`` attributed to that detector for this
              run).
            - ``all_alive`` (bool): True only when every detector reported
              at least one rule against its own fixture.
            - ``silent_detectors`` (list[str]): names of any detector that
              reported zero, empty when ``all_alive`` is True.
            - ``dry_run`` (bool): echoes the argument, so a caller does not
              need to thread it through separately to interpret the result.
    """
    from django_waf.services.anomaly_detector import (
        DETECTOR_NAME_TO_RESULT_KEY,
        DETECTOR_NAMES,
        run_all_detectors,
    )

    with transaction.atomic():
        try:
            _build_fixture_traffic()
            # window_minutes=None (the default) is deliberate: run_all_detectors
            # forwards an explicit override to every detector uniformly except
            # detect_unsolved_challenges's subnet path, which always keeps its
            # own DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES regardless (#93).
            # Passing None here means every detector, including that subnet
            # path, evaluates on its own real configured window, which is
            # exactly the window the fixture timestamps below are built
            # against. A probe passing a small override would silently
            # exercise a different window than it thinks for that one path.
            result = run_all_detectors(dry_run=dry_run)
        finally:
            # Unconditional: even if fixture construction or detection raises,
            # nothing synthetic may survive this function. No branch below
            # this point may skip the rollback.
            transaction.set_rollback(True)

    report: dict = {}
    silent_detectors: list[str] = []
    for detector_name in sorted(DETECTOR_NAMES):
        result_key = DETECTOR_NAME_TO_RESULT_KEY[detector_name]
        rules_reported = result.get(result_key, 0)
        alive = rules_reported > 0
        report[detector_name] = {"alive": alive, "rules_reported": rules_reported}
        if not alive:
            silent_detectors.append(detector_name)

    all_alive = not silent_detectors
    if all_alive:
        # No extra={} structured fields: WafStructuredFormatter's
        # _OPTIONAL_FIELDS (logging.py) is shaped for a single request event
        # (ip, verdict, rule_id, path, method, ...), and no existing call site
        # in this package populates it via extra= today. This line summarises
        # a multi-detector run rather than one event, so a "detector" /
        # "count" field would not fit that schema's shape (a per-request
        # dimension) even if it were in use, and would land alone as the only
        # populated field on this line while every existing field stayed
        # absent. The message text carries the full detail (detector names,
        # per-detector rules_reported) instead; see the module docstring's
        # freshness note for the consumer-side alerting contract this line
        # backs.
        logger.info(
            "django-waf: detector probe, all %d detectors alive",
            len(DETECTOR_NAMES),
        )
    else:
        logger.warning(
            "django-waf: detector probe, silent detectors: %s",
            ", ".join(silent_detectors),
        )

    report["all_alive"] = all_alive
    report["silent_detectors"] = silent_detectors
    report["dry_run"] = dry_run
    return report


def _build_fixture_traffic() -> None:
    """Insert synthetic RequestLog/IPReputation rows shaped to cross every
    detector's configured threshold. Must run inside the caller's
    transaction.atomic() block, which is unconditionally rolled back.
    """
    from django_waf import conf

    now = timezone.now()

    _build_ua_rotation_fixture(now=now, conf=conf)
    _build_subnet_burst_fixture(now=now, conf=conf)
    _build_challenge_farm_fixture(now=now, conf=conf)
    _build_unsolved_challenge_fixture(now=now, conf=conf)
    _build_cloud_spray_fixture(now=now, conf=conf)


def _build_ua_rotation_fixture(*, now, conf, distinct_ua_count: int | None = None) -> None:
    """BR-ANOM-001: more than DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS
    (default 20) distinct UAs from the same IP within a 5-minute window
    (detect_ua_rotation's default window_minutes=5).

    ``distinct_ua_count`` defaults to ``conf.DJANGO_WAF_ANOMALY_THRESHOLD_
    DISTINCT_UAS + 1``, which survives an operator retuning the threshold on
    the normal (non-test) path. Falsifiability tests that need to raise the
    threshold past a FIXED fixture size, so the real query can genuinely
    fail to match, must pass an explicit literal here: reading ``conf``
    for BOTH the fixture size and the threshold the query compares against
    means raising the threshold alone can never break anything, since the
    fixture silently grows to stay one above whatever the threshold now is.
    """
    from django_waf.enums import Verdict
    from django_waf.models import RequestLog

    if distinct_ua_count is None:
        distinct_ua_count = conf.DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS + 1

    RequestLog.objects.bulk_create(
        [
            RequestLog(
                timestamp=now,
                ip_address=_UA_ROTATION_IP,
                user_agent=f"{_PROBE_UA} (ua-rotation-fixture-{i})",
                path="/",
                method="GET",
                verdict=Verdict.ALLOWED,
            )
            for i in range(distinct_ua_count)
        ]
    )


def _build_subnet_burst_fixture(*, now, conf, total_requests: int | None = None) -> None:
    """BR-ANOM-002 (amended #80): a subnet's request count meeting the
    absolute floor, DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT
    (default 30), is sufficient on its own (an OR, not an AND, with the
    3x-median ratio check), specifically so this floor can never be diluted
    by how many other subnets are present in the window. One request over
    the floor, from a handful of IPs in one /24, inside detect_subnet_
    burst's default 15-minute window.

    ``total_requests`` defaults to ``conf.DJANGO_WAF_ANOMALY_THRESHOLD_
    SUBNET_BURST_MIN_COUNT + 1``, for the same reason as
    ``_build_ua_rotation_fixture``: a falsifiability test that wants to
    raise the threshold past a fixed fixture size must pass an explicit
    literal, or the fixture grows in lockstep with the threshold and the
    detector keeps matching regardless of how high it is raised.
    """
    from django_waf.enums import Verdict
    from django_waf.models import RequestLog

    if total_requests is None:
        total_requests = conf.DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT + 1
    fixture_ips = [f"{_SUBNET_BURST_SUBNET_BASE}{10 + (i % 6)}" for i in range(total_requests)]

    RequestLog.objects.bulk_create(
        [
            RequestLog(
                timestamp=now,
                ip_address=ip,
                user_agent=_PROBE_UA,
                path="/",
                method="GET",
                verdict=Verdict.ALLOWED,
            )
            for ip in fixture_ips
        ]
    )


def _build_challenge_farm_fixture(*, now, conf, challenge_failures: int = 11, challenge_passes: int = 0) -> None:
    """BR-ANOM-003: a single IP with more than 10 challenge failures and
    fewer than 2 passes within a 24-hour window (detect_challenge_farms'
    default window_hours=24). Sourced from IPReputation, not RequestLog.

    ``conf`` is accepted but unused: BR-ANOM-003's 10/2 thresholds are fixed
    in the detector itself (``challenge_failures__gt=10,
    challenge_passes__lt=2``), not settings-driven, unlike every other
    fixture builder in this module. There is therefore no conf setting a
    falsifiability test could raise to defeat this fixture the way the
    other four detectors' tests do; the coupling trap those four had does
    not exist here because nothing self-adjusts against a hardcoded
    literal. Instead, ``challenge_failures``/``challenge_passes`` default to
    values that clear the detector's own hardcoded thresholds (11 > 10,
    0 < 2) and a falsifiability test passes values that do not (e.g.
    ``challenge_failures=10``, which fails ``__gt=10``), proving the real
    query genuinely finds nothing.
    """
    from django_waf.models import IPReputation

    IPReputation.objects.create(
        ip_address=_CHALLENGE_FARM_IP,
        total_requests=20,
        blocked_requests=0,
        challenged_requests=20,
        challenge_passes=challenge_passes,
        challenge_failures=challenge_failures,
        distinct_ua_count=1,
        last_seen_at=now,
    )


def _build_unsolved_challenge_fixture(*, now, conf, challenged_count: int | None = None) -> None:
    """BR-ANOM-006 / the per-IP path of detect_unsolved_challenges: an IP
    with at least DJANGO_WAF_UNSOLVED_MIN_CHALLENGED (default 3) challenged
    verdicts in the window, no solved ChallengeToken in the recency window,
    and at least DJANGO_WAF_UNSOLVED_REFERER_RATIO (default 0.8) of its
    non-root requests carrying an empty referer. source=middleware
    explicitly (BR-LOG-006): the detector scopes its challenged-verdict
    count to that source and would not see nginx_log rows.

    Only the per-IP path is targeted here, not the subnet path: the subnet
    path's own thresholds (DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED=30,
    DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS=10) would require materially more
    fixture rows for one more detector alive/dead signal that the per-IP
    path already provides for the same detector function and the same
    DETECTOR_NAMES entry (detect_unsolved_challenges covers both paths, but
    run_all_detectors' result dict does not distinguish which path
    contributed a rule). This fixture's single IP never reaches the
    subnet path's DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS=10 distinct-IP floor
    regardless of DJANGO_WAF_UNSOLVED_MIN_CHALLENGED, so raising the
    per-IP setting to falsify this fixture cannot accidentally trip the
    subnet path instead.

    ``challenged_count`` defaults to ``conf.DJANGO_WAF_UNSOLVED_MIN_
    CHALLENGED + 1``, for the same reason as the other config-derived
    fixtures above: raising the threshold alone cannot falsify a fixture
    that grows to match it.
    """
    from django_waf.enums import RequestLogSource, Verdict
    from django_waf.models import RequestLog

    if challenged_count is None:
        challenged_count = conf.DJANGO_WAF_UNSOLVED_MIN_CHALLENGED + 1

    RequestLog.objects.bulk_create(
        [
            RequestLog(
                timestamp=now,
                ip_address=_UNSOLVED_CHALLENGE_IP,
                user_agent=_PROBE_UA,
                path=f"/fixture-path-{i}/",
                method="GET",
                verdict=Verdict.CHALLENGED,
                source=RequestLogSource.MIDDLEWARE,
                referer="",
            )
            for i in range(challenged_count)
        ]
    )


def _build_cloud_spray_fixture(*, now, conf, distinct_ip_count: int | None = None) -> None:
    """BR-ANOM-002a / detect_cloud_spray: a UA shared by at least
    DJANGO_WAF_CLOUD_SPRAY_MIN_IPS (default 20) distinct IPs, each with no
    more than DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP (default 3)
    requests and no referer, inside detect_cloud_spray's default 30-minute
    window. All IPs share one /24 so the subsequent per-subnet aggregation
    (count >= 2) is satisfied trivially.

    ``distinct_ip_count`` defaults to ``conf.DJANGO_WAF_CLOUD_SPRAY_MIN_IPS
    + 1``, for the same reason as the other config-derived fixtures above:
    raising the threshold alone cannot falsify a fixture that grows to
    match it. The detector gates on this same setting twice (the UA-level
    distinct-IP aggregation, and the subsequent per-IP recheck), so a
    pinned literal here defeats both in one move.
    """
    from django_waf.enums import Verdict
    from django_waf.models import RequestLog

    if distinct_ip_count is None:
        distinct_ip_count = conf.DJANGO_WAF_CLOUD_SPRAY_MIN_IPS + 1
    shared_ua = f"{_PROBE_UA} (cloud-spray-fixture)"

    RequestLog.objects.bulk_create(
        [
            RequestLog(
                timestamp=now,
                ip_address=f"{_CLOUD_SPRAY_SUBNET_BASE}{20 + i}",
                user_agent=shared_ua,
                path="/",
                method="GET",
                verdict=Verdict.ALLOWED,
                referer="",
            )
            for i in range(distinct_ip_count)
        ]
    )
