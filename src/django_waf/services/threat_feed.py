"""
Threat feed service for django-waf.

Manages synchronisation from the central threat feed and opt-in anonymised
telemetry reporting. Per BR-FEED-001 through BR-TEL-004.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger("django_waf.threat_feed")

_INSTALL_ID_SETTING = "DJANGO_WAF_INSTALL_ID"


# ---------------------------------------------------------------------------
# Feed sync
# ---------------------------------------------------------------------------


def sync_feed(
    feed_url: str | None = None,
    min_confidence: float | None = None,
) -> dict:
    """Fetch the central threat feed and create/update/expire rules.

    Only processes entries with confidence >= min_confidence (BR-FEED-002).
    Each entry carries an optional ``kind`` discriminator (ADR-035, spec
    06-threat-feed-api.md section 2.8): absent or ``"block"`` imports as a
    BlockRule exactly as before; ``"allow"`` imports as an AllowRule. The two
    kinds are tracked and matched independently: a BlockRule and an
    AllowRule sharing the same (rule_type, pattern) never interfere with each
    other, because they live in separate tables.

    Rules are tagged source='feed' (BR-FEED-003). Existing rules are matched on
    (source='feed', rule_type, pattern) — idempotent (BR-FEED-006).
    Rules absent from the feed are deactivated (BR-FEED-005).
    Emits feed_synced signal on completion.

    Args:
        feed_url: Override URL. Defaults to DJANGO_WAF_FEED_URL.
        min_confidence: Override confidence threshold. Defaults to DJANGO_WAF_FEED_MIN_CONFIDENCE.

    Returns:
        Dict with keys: created, updated, expired, skipped (totals across
        both block and allow entries).
    """
    import httpx

    from django_waf import conf
    from django_waf.enums import RuleSource
    from django_waf.models import AllowRule, BlockRule

    url = feed_url or conf.DJANGO_WAF_FEED_URL
    threshold = min_confidence if min_confidence is not None else conf.DJANGO_WAF_FEED_MIN_CONFIDENCE

    # No Authorization header, by design. The feed is a public read: the
    # collective threat intel is servable to every install without a key, so
    # a bearer token is neither required nor sent even when
    # DJANGO_WAF_FEED_API_KEY is set. Telemetry (submit_telemetry) is the
    # authenticated write; see 06-threat-feed-api.md section 4 for the
    # documented asymmetry. Do not add auth here without a contract change.
    try:
        response = httpx.get(url, timeout=30)
        response.raise_for_status()
        feed_data = response.json()
    except Exception as exc:
        logger.error("django-waf: feed sync failed to fetch %s: %s", url, exc)
        return {"created": 0, "updated": 0, "expired": 0, "skipped": 0, "error": str(exc)}

    feed_entries = feed_data if isinstance(feed_data, list) else feed_data.get("rules", [])

    created = updated = expired = skipped = 0
    seen_block_keys: set[tuple[str, str]] = set()  # (rule_type, pattern)
    seen_allow_keys: set[tuple[str, str]] = set()  # (rule_type, pattern)

    for entry in feed_entries:
        confidence = float(entry.get("confidence", 0.0))
        if confidence < threshold:
            skipped += 1
            continue

        rule_type = entry.get("rule_type", "")
        pattern = entry.get("pattern", "")
        if not rule_type or not pattern:
            skipped += 1
            continue

        kind = entry.get("kind", "block")
        match_type = entry.get("match_type", "exact")

        # expires_at from feed or 30 days from now (BR-FEED-005)
        feed_expires = entry.get("expires")
        if feed_expires:
            from django.utils.dateparse import parse_datetime

            expires_at = parse_datetime(feed_expires) or (timezone.now() + timedelta(days=30))
        else:
            expires_at = timezone.now() + timedelta(days=30)

        if kind == "allow":
            seen_allow_keys.add((rule_type, pattern))
            verify_rdns = bool(entry.get("verify_rdns", False))
            rdns_pattern = entry.get("rdns_pattern", "")

            with transaction.atomic():
                existing_allow = AllowRule.objects.filter(
                    source=RuleSource.FEED,
                    rule_type=rule_type,
                    pattern=pattern,
                ).first()

                if existing_allow:
                    existing_allow.match_type = match_type
                    existing_allow.verify_rdns = verify_rdns
                    existing_allow.rdns_pattern = rdns_pattern
                    existing_allow.expires_at = expires_at
                    existing_allow.confidence = confidence
                    existing_allow.is_active = True
                    existing_allow.feed_reporters = entry.get("reporters", existing_allow.feed_reporters)
                    existing_allow.save()
                    updated += 1
                else:
                    AllowRule.objects.create(
                        name=f"Feed: {rule_type} {pattern[:50]}",
                        rule_type=rule_type,
                        match_type=match_type,
                        pattern=pattern,
                        verify_rdns=verify_rdns,
                        rdns_pattern=rdns_pattern,
                        source=RuleSource.FEED,
                        expires_at=expires_at,
                        confidence=confidence,
                        feed_reporters=entry.get("reporters", 0),
                        feed_first_seen=timezone.now().date(),
                    )
                    created += 1
            continue

        # kind == "block" (or any unrecognised value, per section 2.8)
        seen_block_keys.add((rule_type, pattern))
        action = entry.get("action", "block")

        with transaction.atomic():
            existing = BlockRule.objects.filter(
                source=RuleSource.FEED,
                rule_type=rule_type,
                pattern=pattern,
            ).first()

            if existing:
                existing.action = action
                existing.match_type = match_type
                existing.expires_at = expires_at
                existing.confidence = confidence
                existing.is_active = True
                existing.feed_reporters = entry.get("reporters", existing.feed_reporters)
                existing.save()
                updated += 1
            else:
                BlockRule.objects.create(
                    name=f"Feed: {rule_type} {pattern[:50]}",
                    rule_type=rule_type,
                    match_type=match_type,
                    pattern=pattern,
                    action=action,
                    source=RuleSource.FEED,
                    expires_at=expires_at,
                    confidence=confidence,
                    feed_reporters=entry.get("reporters", 0),
                    feed_first_seen=timezone.now().date(),
                )
                created += 1

    # Deactivate feed rules no longer present in the feed (BR-FEED-005).
    # Block and allow rules live in separate tables and are checked against
    # separate seen-key sets, so a block entry and an allow entry sharing the
    # same (rule_type, pattern) never expire each other.
    active_feed_block_rules = BlockRule.objects.filter(source=RuleSource.FEED, is_active=True)
    for block_rule in active_feed_block_rules:
        if (block_rule.rule_type, block_rule.pattern) not in seen_block_keys:
            block_rule.is_active = False
            block_rule.save(update_fields=["is_active"])
            expired += 1

    active_feed_allow_rules = AllowRule.objects.filter(source=RuleSource.FEED, is_active=True)
    for allow_rule in active_feed_allow_rules:
        if (allow_rule.rule_type, allow_rule.pattern) not in seen_allow_keys:
            allow_rule.is_active = False
            allow_rule.save(update_fields=["is_active"])
            expired += 1

    result = {"created": created, "updated": updated, "expired": expired, "skipped": skipped}

    try:
        from django_waf.signals import feed_synced

        feed_synced.send(sender=None, **result)
    except Exception:
        logger.exception("django-waf: failed to emit feed_synced signal")

    logger.info(
        "django-waf: feed sync complete — created=%d updated=%d expired=%d skipped=%d",
        created,
        updated,
        expired,
        skipped,
    )
    return result


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------


def build_telemetry_payload(period_start, period_end) -> dict:
    """Build the anonymised telemetry payload for the reporting period.

    Per BR-TEL-002: no full IPs, no paths, no user identifiers. UA strings are
    SHA-256 hashed. IPs are truncated to /24 subnets (IPv4) or /48 subnets
    (IPv6) — a full IPv6 address must never appear in the payload.

    Args:
        period_start: datetime of the reporting period start.
        period_end: datetime of the reporting period end.

    Returns:
        Dict matching the telemetry payload schema.
    """
    from django.db.models import Count

    from django_waf.enums import RuleSource
    from django_waf.models import BlockRule, RequestLog
    from django_waf.services.anomaly_detector import _get_subnet_prefix

    install_id = get_or_create_install_id()

    # --- UA hashes from BlockRules with source in ('admin', 'auto') ---
    ua_hashes = []
    ua_rules = BlockRule.objects.filter(
        source__in=[RuleSource.ADMIN, RuleSource.AUTO],
        rule_type="ua",
    ).values("pattern", "action", "hit_count")

    for rule in ua_rules:
        ua_hash = hashlib.sha256(rule["pattern"].encode()).hexdigest()
        ua_hashes.append(
            {
                "sha256": ua_hash,
                "action": rule["action"],
                "hits": rule["hit_count"],
            }
        )

    # --- IP /24 subnets from RequestLog in the period ---
    logs_in_period = RequestLog.objects.filter(
        timestamp__gte=period_start,
        timestamp__lte=period_end,
    )

    subnet_counts: dict[str, dict] = {}
    for log in logs_in_period.values("ip_address", "verdict"):
        try:
            subnet = _get_subnet_prefix(log["ip_address"])
        except ValueError:
            continue
        if subnet not in subnet_counts:
            subnet_counts[subnet] = {"cidr": subnet, "action": log["verdict"], "hits": 0}
        subnet_counts[subnet]["hits"] += 1

    subnets = list(subnet_counts.values())

    # --- Summary ---
    summary_qs = logs_in_period.values("verdict").annotate(count=Count("id"))
    summary: dict[str, int] = {
        "total_requests": logs_in_period.count(),
        "blocked": 0,
        "challenged": 0,
        "throttled": 0,
    }
    for row in summary_qs:
        verdict = row["verdict"]
        if verdict in summary:
            summary[verdict] = row["count"]

    period_str = f"{period_start.isoformat()}/{period_end.isoformat()}"

    return {
        "install_id": install_id,
        "period": period_str,
        "ua_hashes": ua_hashes,
        "subnets": subnets,
        "anomalies": [],  # populated by callers if desired
        "summary": summary,
    }


def submit_telemetry(payload: dict, report_url: str | None = None) -> bool:
    """POST the telemetry payload to the central reporting endpoint.

    Per BR-TEL-004: never raises on failure. Logs a warning on failure.

    Args:
        payload: Telemetry dict from build_telemetry_payload().
        report_url: Override URL. Defaults to DJANGO_WAF_FEED_REPORT_URL.

    Returns:
        True if submission succeeded (2xx response), False otherwise.
    """
    import httpx

    from django_waf import conf

    url = report_url or conf.DJANGO_WAF_FEED_REPORT_URL
    api_key = conf.DJANGO_WAF_FEED_API_KEY

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = httpx.post(url, json=payload, headers=headers, timeout=30)
        if response.is_success:
            logger.info("django-waf: telemetry submitted successfully to %s", url)
            return True
        logger.warning(
            "django-waf: telemetry submission failed — status %d from %s",
            response.status_code,
            url,
        )
        return False
    except Exception as exc:
        logger.warning("django-waf: telemetry submission error: %s", exc)
        return False  # BR-TEL-004: never raise


def get_or_create_install_id() -> str:
    """Return the stable install_id UUID, creating it on first call.

    Storage priority:
    1. Django cache (warm path — avoids I/O on subsequent calls)
    2. Filesystem file at ``~/.django_waf_install_id`` (stable across restarts)
    3. Generate a new UUID and persist to the file

    Per BR-TEL-003: the install_id must not be derived from any user identity,
    domain, or SECRET_KEY. It is a random UUID generated once and stored.

    Returns:
        String UUID (random, stable across calls).
    """
    import os

    from django.core.cache import cache

    cached = cache.get(_INSTALL_ID_SETTING)
    if cached:
        return str(cached)

    # Determine storage path: respect DATA_DIR/BASE_DIR settings if available
    try:
        from django.conf import settings as dj_settings

        base = getattr(dj_settings, "BASE_DIR", None) or os.path.expanduser("~")
        id_file = os.path.join(str(base), ".django_waf_install_id")
    except Exception:
        id_file = os.path.expanduser("~/.django_waf_install_id")

    # Read from file
    if os.path.isfile(id_file):
        try:
            with open(id_file) as fh:
                install_id = fh.read().strip()
            if install_id:
                cache.set(_INSTALL_ID_SETTING, install_id, timeout=60 * 60 * 24 * 30)
                return install_id
        except OSError:
            pass

    # Generate new UUID and persist
    install_id = str(uuid.uuid4())
    try:
        with open(id_file, "w") as fh:
            fh.write(install_id)
    except OSError as exc:
        logger.warning("django-waf: could not persist install_id to %s: %s", id_file, exc)

    cache.set(_INSTALL_ID_SETTING, install_id, timeout=60 * 60 * 24 * 30)
    return install_id
