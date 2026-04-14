"""
Anomaly detector service for icv-waf.

Analyses recent RequestLog records for behavioural patterns and auto-creates
expiring BlockRules when suspicious patterns are detected.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("icv_waf.anomaly_detector")


def detect_ua_rotation(
    window_minutes: int = 5,
    threshold: int | None = None,
) -> list:
    """Detect IPs using an unusually large number of distinct User-Agent strings.

    Per BR-ANOM-001: flags IPs with more than threshold distinct UAs from the
    same IP within window_minutes. Creates expiring BlockRules with source='auto',
    action='challenge'. Does not duplicate existing active rules (BR-ANOM-004).

    Args:
        window_minutes: Time window to analyse (default 5).
        threshold: Distinct UA count threshold. Defaults to
                   ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS.

    Returns:
        List of BlockRule instances created.
    """
    from django.db.models import Count

    from icv_waf import conf
    from icv_waf.enums import AnomalyType, RuleAction, RuleType
    from icv_waf.models import RequestLog

    effective_threshold = threshold if threshold is not None else conf.ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS
    cutoff = timezone.now() - timedelta(minutes=window_minutes)

    # Group by ip_address, count distinct user_agent values
    qs = (
        RequestLog.objects.filter(timestamp__gte=cutoff)
        .values("ip_address")
        .annotate(distinct_ua_count=Count("user_agent", distinct=True))
        .filter(distinct_ua_count__gt=effective_threshold)
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.ICV_WAF_AUTO_RULE_EXPIRY_HOURS)

    for row in qs:
        ip = row["ip_address"]
        rule, created = _get_or_create_auto_rule(
            name=f"Auto: UA rotation from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.CHALLENGE,
            expiry=expiry,
        )
        if created:
            created_rules.append(rule)
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.UA_ROTATION,
                details={"distinct_ua_count": row["distinct_ua_count"], "window_minutes": window_minutes},
            )
            logger.info("icv-waf: auto-created UA rotation rule for %s", ip)

    return created_rules


def detect_subnet_burst(window_minutes: int = 15) -> list:
    """Detect /24 subnets with anomalously high request volume.

    Per BR-ANOM-002: flags subnets where request count exceeds 3× the mean
    per-subnet rate in the last window_minutes.

    Args:
        window_minutes: Time window to analyse (default 15).

    Returns:
        List of BlockRule instances created.
    """
    from icv_waf import conf
    from icv_waf.enums import AnomalyType, RuleAction, RuleType
    from icv_waf.models import RequestLog

    cutoff = timezone.now() - timedelta(minutes=window_minutes)
    logs = RequestLog.objects.filter(timestamp__gte=cutoff).values_list("ip_address", flat=True)

    # Count requests per /24 subnet
    subnet_counts: dict[str, int] = {}
    for ip in logs:
        try:
            subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            continue
        subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

    if not subnet_counts:
        return []

    mean_count = sum(subnet_counts.values()) / len(subnet_counts)
    burst_threshold = mean_count * 3

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.ICV_WAF_AUTO_RULE_EXPIRY_HOURS)

    for subnet, count in subnet_counts.items():
        if count <= burst_threshold:
            continue

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: subnet burst from {subnet}",
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern=subnet,
            action=RuleAction.CHALLENGE,
            expiry=expiry,
        )
        if created:
            created_rules.append(rule)
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.SUBNET_FLOOD,
                details={"count": count, "mean": mean_count, "threshold": burst_threshold},
            )
            logger.info("icv-waf: auto-created subnet burst rule for %s (count=%d)", subnet, count)

    return created_rules


def detect_challenge_farms(window_hours: int = 24) -> list:
    """Detect IPs with high challenge failure rates and low pass rates.

    Per BR-ANOM-003: IPs with challenge_failures > 10 and challenge_passes < 2
    within window_hours are blocked.

    Args:
        window_hours: Time window to analyse (default 24).

    Returns:
        List of BlockRule instances created.
    """
    from icv_waf import conf
    from icv_waf.enums import AnomalyType, RuleAction, RuleType
    from icv_waf.models import IPReputation

    cutoff = timezone.now() - timedelta(hours=window_hours)
    suspects = IPReputation.objects.filter(
        last_seen_at__gte=cutoff,
        challenge_failures__gt=10,
        challenge_passes__lt=2,
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.ICV_WAF_AUTO_RULE_EXPIRY_HOURS)

    for rep in suspects:
        ip = rep.ip_address

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: challenge farm from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
            expiry=expiry,
        )
        if created:
            created_rules.append(rule)
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.CHALLENGE_FARM,
                details={
                    "challenge_failures": rep.challenge_failures,
                    "challenge_passes": rep.challenge_passes,
                },
            )
            logger.info("icv-waf: auto-created challenge farm rule for %s", ip)

    return created_rules


def detect_unsolved_challenges(
    window_minutes: int = 60,
    min_challenged: int = 3,
    referer_ratio: float = 0.8,
) -> list:
    """Detect IPs that receive challenges but never solve them.

    Composite detector combining three signals:
    1. IP has >= min_challenged challenged verdicts in the window
    2. IP has zero solved ChallengeTokens (ever)
    3. Majority (>= referer_ratio) of the IP's requests have empty referer
       on paths other than "/"

    The three-way conjunction gives high-confidence bot classification with
    near-zero false-positive risk: real users always solve JS challenges,
    and real browsing always produces referer headers from search engines
    or internal navigation.

    Args:
        window_minutes: Time window to analyse (default 60).
        min_challenged: Minimum challenged verdicts to consider (default 3).
        referer_ratio: Fraction of non-root requests with empty referer
                       required to trigger (default 0.8).

    Returns:
        List of BlockRule instances created.
    """
    from django.db.models import Count, Q

    from icv_waf import conf
    from icv_waf.enums import (
        AnomalyType,
        ChallengeStatus,
        RuleAction,
        RuleType,
        Verdict,
    )
    from icv_waf.models import ChallengeToken, RequestLog

    cutoff = timezone.now() - timedelta(minutes=window_minutes)

    # Step 1: IPs with >= min_challenged challenged verdicts in window
    challenged_ips = (
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            verdict=Verdict.CHALLENGED,
        )
        .values("ip_address")
        .annotate(challenged_count=Count("id"))
        .filter(challenged_count__gte=min_challenged)
    )

    # Prefetch all IPs with solved challenges in one query (fixes N+1)
    challenged_ip_list = [row["ip_address"] for row in challenged_ips]
    solved_ips = set(
        ChallengeToken.objects.filter(
            ip_address__in=challenged_ip_list,
            status=ChallengeStatus.SOLVED,
        )
        .values_list("ip_address", flat=True)
        .distinct()
    )

    # Prefetch referer stats for all candidate IPs in two queries
    non_root_counts = dict(
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            ip_address__in=challenged_ip_list,
        )
        .exclude(path="/")
        .values("ip_address")
        .annotate(total=Count("id"))
        .values_list("ip_address", "total")
    )
    empty_referer_counts = dict(
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
            ip_address__in=challenged_ip_list,
        )
        .exclude(path="/")
        .filter(Q(referer="") | Q(referer__isnull=True))
        .values("ip_address")
        .annotate(total=Count("id"))
        .values_list("ip_address", "total")
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.ICV_WAF_AUTO_RULE_EXPIRY_HOURS)

    for row in challenged_ips:
        ip = row["ip_address"]

        if ip in solved_ips:
            continue

        non_root_count = non_root_counts.get(ip, 0)
        if non_root_count == 0:
            continue

        empty_count = empty_referer_counts.get(ip, 0)
        if empty_count / non_root_count < referer_ratio:
            continue

        rule, created = _get_or_create_auto_rule(
            name=f"Auto: unsolved challenges from {ip}",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
            expiry=expiry,
        )
        if created:
            created_rules.append(rule)
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.UNSOLVED_CHALLENGE,
                details={
                    "challenged_count": row["challenged_count"],
                    "empty_referer_ratio": round(empty_count / non_root_count, 2),
                    "non_root_requests": non_root_count,
                    "window_minutes": window_minutes,
                },
            )
            logger.info(
                "icv-waf: auto-created unsolved challenge rule for %s (challenged=%d, referer_empty=%.0f%%)",
                ip,
                row["challenged_count"],
                (empty_count / non_root_count) * 100,
            )

    return created_rules


def detect_cloud_spray(window_minutes: int = 30) -> list:
    """Detect coordinated low-and-slow scraping from many distinct IPs.

    Identifies UAs shared by many distinct IPs (>= ICV_WAF_CLOUD_SPRAY_MIN_IPS)
    where each IP makes only 1-3 requests with no referer. This pattern is
    characteristic of cloud-hosted bot farms that evade per-IP rate limits.

    Flags /24 subnets rather than individual IPs — cloud providers allocate
    contiguous blocks, so a single /24 CIDR catches the cluster efficiently.

    Args:
        window_minutes: Time window to analyse (default 30).

    Returns:
        List of BlockRule instances created.
    """
    from django.db.models import Count, Q

    from icv_waf import conf
    from icv_waf.enums import AnomalyType, RuleAction, RuleType
    from icv_waf.models import RequestLog

    cutoff = timezone.now() - timedelta(minutes=window_minutes)
    min_ips = conf.ICV_WAF_CLOUD_SPRAY_MIN_IPS
    max_per_ip = conf.ICV_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP

    # Step 1: Find UAs used by many distinct IPs with no referer
    spray_uas = (
        RequestLog.objects.filter(
            timestamp__gte=cutoff,
        )
        .filter(Q(referer="") | Q(referer__isnull=True))
        .exclude(user_agent="")
        .values("user_agent")
        .annotate(distinct_ips=Count("ip_address", distinct=True))
        .filter(distinct_ips__gte=min_ips)
        .order_by("-distinct_ips")[:5]
    )

    created_rules = []
    expiry = timezone.now() + timedelta(hours=conf.ICV_WAF_AUTO_RULE_EXPIRY_HOURS)

    for ua_row in spray_uas:
        ua = ua_row["user_agent"]

        # Step 2: Get IPs using this UA with low request counts and no referer
        ip_counts = (
            RequestLog.objects.filter(
                timestamp__gte=cutoff,
                user_agent=ua,
            )
            .filter(Q(referer="") | Q(referer__isnull=True))
            .values("ip_address")
            .annotate(req_count=Count("id"))
            .filter(req_count__lte=max_per_ip)
        )

        suspicious_ips = [row["ip_address"] for row in ip_counts]
        if len(suspicious_ips) < min_ips:
            continue

        # Step 3: Aggregate into /24 subnets and create rules
        subnet_counts: dict[str, int] = {}
        for ip in suspicious_ips:
            try:
                subnet = str(ipaddress.ip_network(f"{ip}/24", strict=False))
            except ValueError:
                continue
            subnet_counts[subnet] = subnet_counts.get(subnet, 0) + 1

        for subnet, count in subnet_counts.items():
            if count < 2:
                continue

            rule, created = _get_or_create_auto_rule(
                name=f"Auto: cloud spray from {subnet} ({count} IPs, UA: {ua[:40]})",
                rule_type=RuleType.CIDR,
                match_type="cidr",
                pattern=subnet,
                action=RuleAction.CHALLENGE,
                expiry=expiry,
            )
            if created:
                created_rules.append(rule)
                _emit_anomaly_signal(
                    rule=rule,
                    anomaly_type=AnomalyType.CLOUD_SPRAY,
                    details={
                        "subnet": subnet,
                        "ip_count": count,
                        "total_spray_ips": len(suspicious_ips),
                        "user_agent": ua[:200],
                        "window_minutes": window_minutes,
                    },
                )
                logger.info(
                    "icv-waf: auto-created cloud spray rule for %s (%d IPs)",
                    subnet,
                    count,
                )

    return created_rules


def run_all_detectors() -> dict:
    """Run all anomaly detectors and return a summary of findings.

    Returns:
        Dict with keys: ua_rotation_rules, subnet_burst_rules,
        challenge_farm_rules, total_rules_created.
    """
    ua_rules = detect_ua_rotation()
    subnet_rules = detect_subnet_burst()
    farm_rules = detect_challenge_farms()
    unsolved_rules = detect_unsolved_challenges()
    spray_rules = detect_cloud_spray()

    total = len(ua_rules) + len(subnet_rules) + len(farm_rules) + len(unsolved_rules) + len(spray_rules)
    logger.info(
        "icv-waf anomaly detection: ua_rotation=%d subnet_burst=%d "
        "challenge_farm=%d unsolved_challenge=%d cloud_spray=%d total=%d",
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


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_or_create_auto_rule(
    *,
    name: str,
    rule_type: str,
    match_type: str,
    pattern: str,
    action: str,
    expiry,
) -> tuple:
    """Create or refresh an auto-generated BlockRule, avoiding duplicates.

    Uses update_or_create keyed on (rule_type, pattern, source=AUTO, action)
    so concurrent detector runs cannot create duplicates. If the rule already
    exists, its expiry and is_active flag are refreshed.

    If duplicate rows already exist (created before this function existed, or
    via a race condition), catches MultipleObjectsReturned, deduplicates by
    keeping the newest row and deleting the rest, then retries.

    Returns:
        (rule, created) tuple.
    """
    from icv_waf.enums import RuleSource
    from icv_waf.models import BlockRule

    lookup = {
        "rule_type": rule_type,
        "pattern": pattern,
        "source": RuleSource.AUTO,
        "action": action,
    }
    defaults = {
        "name": name,
        "match_type": match_type,
        "is_active": True,
        "expires_at": expiry,
    }

    try:
        with transaction.atomic():
            rule, created = BlockRule.objects.update_or_create(**lookup, defaults=defaults)
        return rule, created
    except BlockRule.MultipleObjectsReturned:
        logger.warning(
            "icv-waf: duplicate BlockRule rows for %s/%s — deduplicating",
            rule_type,
            pattern,
        )
        _deduplicate_block_rules(**lookup)
        with transaction.atomic():
            rule, created = BlockRule.objects.update_or_create(**lookup, defaults=defaults)
        return rule, created


def _deduplicate_block_rules(**lookup) -> int:
    """Keep the newest BlockRule matching ``lookup`` and delete the rest.

    Returns:
        Number of duplicate rows deleted.
    """
    from icv_waf.models import BlockRule

    qs = BlockRule.objects.filter(**lookup).order_by("-created_at")
    if qs.count() <= 1:
        return 0
    keep_pk = qs.first().pk
    deleted, _ = qs.exclude(pk=keep_pk).delete()
    logger.info("icv-waf: deleted %d duplicate BlockRule rows for %s", deleted, lookup)
    return deleted


def _emit_anomaly_signal(rule, anomaly_type: str, details: dict) -> None:
    """Emit the anomaly_detected signal safely."""
    try:
        from icv_waf.signals import anomaly_detected

        anomaly_detected.send(
            sender=type(rule),
            rule=rule,
            anomaly_type=anomaly_type,
            details=details,
        )
    except Exception:
        logger.exception("icv-waf: failed to emit anomaly_detected signal for rule %s", rule.pk)
