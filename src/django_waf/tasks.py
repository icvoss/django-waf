"""
Celery tasks for django-waf.

All tasks use @shared_task and lazy imports for Celery compatibility.
Tasks are idempotent and fail gracefully.

Scheduled tasks (Celery Beat):
  - generate_blocklist      — every 5 minutes (BR-BL-004)
  - flush_rule_hit_counts   — every 5 minutes
  - detect_anomalies        — every 15 minutes (BR-ANOM-005)
  - parse_access_log        — every 10 minutes
  - prune_request_logs      — daily 04:00 (BR-LOG-003)
  - prune_challenge_tokens  — daily 04:15
  - expire_rules            — every 30 minutes (BR-LIFE-002)
  - update_ip_reputation    — every 6 hours
  - sync_threat_feed        — daily 04:30
  - report_threat_telemetry — daily 05:00
  - update_geoip_database   — weekly (Sunday 03:00 UTC recommended)
"""

from __future__ import annotations

import logging
import re
from datetime import timedelta

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("django_waf.tasks")


@shared_task
def generate_blocklist() -> dict:
    """Generate the nginx blocklist conf file and reload nginx.

    Returns:
        Dict with keys: rules_written, reload_succeeded.

    Scheduled: every 5 minutes (BR-BL-004).
    """
    from django_waf.services.blocklist_generator import generate_nginx_blocklist, reload_nginx

    try:
        count = generate_nginx_blocklist()
    except PermissionError as exc:
        logger.error(
            "django-waf: cannot write blocklist — %s. Set DJANGO_WAF_NGINX_BLOCKLIST_PATH to a writable location.",
            exc,
        )
        return {"rules_written": 0, "reload_succeeded": False, "error": str(exc)}

    success = reload_nginx()
    logger.info("django-waf: generate_blocklist — %d rules, reload=%s", count, success)
    return {"rules_written": count, "reload_succeeded": success}


@shared_task
def detect_anomalies() -> dict:
    """Run all anomaly detectors and auto-create BlockRules for suspicious patterns.

    Returns:
        Dict with keys: ua_rotation_rules, subnet_burst_rules,
        challenge_farm_rules, total_rules_created.

    Scheduled: every 15 minutes (BR-ANOM-005).
    """
    from django_waf.services.anomaly_detector import run_all_detectors

    return run_all_detectors()


@shared_task
def parse_access_log(log_path: str | None = None) -> dict:
    """Parse the nginx access log and populate RequestLog records.

    Uses file offset tracking to avoid re-parsing previously imported lines.
    The offset is persisted in the Django cache.

    Args:
        log_path: Override path. Defaults to DJANGO_WAF_ACCESS_LOG_PATH.

    Returns:
        Dict with keys: parsed_lines, created_records, skipped_lines.

    Scheduled: every 10 minutes.
    """
    import os

    from django.core.cache import cache

    from django_waf import conf
    from django_waf.models import RequestLog

    path = log_path or conf.DJANGO_WAF_ACCESS_LOG_PATH
    offset_key = f"django_waf:access_log_offset:{path}"

    if not path or not os.path.isfile(path):
        logger.debug("django-waf: access log not found at %s — skipping parse", path)
        return {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}

    stored_offset = cache.get(offset_key, 0)
    parsed_lines = created_records = skipped_lines = 0

    # Combined log format pattern:
    # IP - - [timestamp] "METHOD /path HTTP/x.x" status size "referer" "ua"
    _LOG_RE = re.compile(
        r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+\S+'
        r'(?:\s+"[^"]*"\s+"([^"]*)")?'
    )

    records_to_create = []

    try:
        with open(path, errors="replace") as fh:
            fh.seek(stored_offset)
            for line in fh:
                parsed_lines += 1
                match = _LOG_RE.match(line.strip())
                if not match:
                    skipped_lines += 1
                    continue

                ip_address = match.group(1)
                # timestamp_str = match.group(2)  # e.g. 23/Mar/2026:10:00:00 +0000
                method = match.group(3)[:16]
                path_str = match.group(4)[:2048]
                status_code = int(match.group(5))
                user_agent = (match.group(6) or "")[:1024]

                records_to_create.append(
                    RequestLog(
                        timestamp=timezone.now(),
                        ip_address=ip_address,
                        user_agent=user_agent,
                        path=path_str,
                        method=method,
                        verdict=_infer_verdict_from_status(status_code, path_str),
                        response_code=status_code,
                    )
                )

            new_offset = fh.tell()

        if records_to_create:
            RequestLog.objects.bulk_create(records_to_create, ignore_conflicts=True)
            created_records = len(records_to_create)

        cache.set(offset_key, new_offset, timeout=None)

    except OSError as exc:
        logger.error("django-waf: error reading access log %s: %s", path, exc)

    return {
        "parsed_lines": parsed_lines,
        "created_records": created_records,
        "skipped_lines": skipped_lines,
    }


@shared_task
def prune_request_logs(days: int | None = None) -> dict:
    """Delete RequestLog records older than the retention period.

    Uses hard deletes. Per BR-LOG-003: retains 30 days by default.

    Args:
        days: Number of days to retain. Defaults to DJANGO_WAF_LOG_RETENTION_DAYS.

    Returns:
        Dict with keys: deleted_count.

    Scheduled: daily at 04:00 (BR-LOG-003).
    """
    from django_waf import conf
    from django_waf.models import RequestLog

    retention_days = days if days is not None else conf.DJANGO_WAF_LOG_RETENTION_DAYS
    cutoff = timezone.now() - timedelta(days=retention_days)
    deleted, _ = RequestLog.objects.filter(timestamp__lt=cutoff).delete()
    logger.info("django-waf: pruned %d RequestLog records older than %d days", deleted, retention_days)
    return {"deleted_count": deleted}


@shared_task
def prune_challenge_tokens(hours: int = 24) -> dict:
    """Delete expired or failed ChallengeToken records older than N hours.

    Only PENDING and FAILED tokens are pruned — SOLVED tokens are kept for
    reputation aggregation (see update_ip_reputation) and EXPIRED tokens are
    handled separately by the challenge-verification flow, not this task.

    Args:
        hours: Age threshold in hours, measured against expires_at. Defaults to 24.

    Returns:
        Dict with keys: deleted_count.

    Scheduled: daily at 04:15.
    """
    from django_waf.enums import ChallengeStatus
    from django_waf.models import ChallengeToken

    cutoff = timezone.now() - timedelta(hours=hours)
    deleted, _ = ChallengeToken.objects.filter(
        status__in=[ChallengeStatus.PENDING, ChallengeStatus.FAILED],
        expires_at__lt=cutoff,
    ).delete()
    logger.info("django-waf: pruned %d ChallengeToken records older than %d hours", deleted, hours)
    return {"deleted_count": deleted}


@shared_task
def expire_rules() -> dict:
    """Deactivate BlockRules whose expires_at has passed.

    Sets is_active=False. Does not delete rules (BR-LIFE-001). After bulk update,
    manually increments the Redis rule version key to invalidate the cache since
    bulk update() does not trigger post_save signals.

    Returns:
        Dict with keys: expired_count.

    Scheduled: every 30 minutes (BR-LIFE-002).
    """
    from django_waf.models import BlockRule

    expired_qs = BlockRule.objects.expired()
    count = expired_qs.update(is_active=False)

    if count > 0:
        # bulk update() bypasses signals — manually invalidate the rule cache
        try:
            _invalidate_rule_cache_redis()
        except Exception:
            logger.exception("django-waf: failed to invalidate rule cache after expire_rules")

        logger.info("django-waf: expired %d BlockRules", count)

    return {"expired_count": count}


@shared_task
def update_ip_reputation() -> dict:
    """Aggregate IP behaviour from recent RequestLog records into IPReputation.

    Covers the last 24 hours. Upserts one record per IP (BR-REP-003). Computes
    threat score per BR-REP-002.

    Returns:
        Dict with keys: updated_count, created_count.

    Scheduled: every 6 hours.
    """
    from django.db.models import Count, Q

    from django_waf import conf
    from django_waf.enums import Verdict
    from django_waf.models import IPReputation, RequestLog

    cutoff = timezone.now() - timedelta(hours=24)
    updated_count = 0
    created_count = 0

    # Aggregate per IP
    ip_stats = (
        RequestLog.objects.filter(timestamp__gte=cutoff)
        .values("ip_address")
        .annotate(
            total=Count("id"),
            blocked=Count("id", filter=Q(verdict=Verdict.BLOCKED)),
            challenged=Count("id", filter=Q(verdict=Verdict.CHALLENGED)),
            distinct_ua=Count("user_agent", distinct=True),
        )
    )

    for row in ip_stats:
        ip = row["ip_address"]
        total = row["total"]
        blocked = row["blocked"]
        challenged = row["challenged"]
        distinct_ua = row["distinct_ua"]

        # Count actual challenge outcomes from ChallengeToken
        from django_waf.enums import ChallengeStatus
        from django_waf.models import ChallengeToken

        passes = ChallengeToken.objects.filter(ip_address=ip, status=ChallengeStatus.SOLVED).count()
        failures = ChallengeToken.objects.filter(
            ip_address=ip, status__in=[ChallengeStatus.EXPIRED, ChallengeStatus.FAILED]
        ).count()

        # Unsolved challenge rate: challenged verdicts with zero solves
        unsolved_rate = 0.0
        if challenged > 0 and passes == 0:
            unsolved_rate = 1.0
        elif challenged > 0:
            unsolved_rate = max(0.0, 1.0 - (passes / challenged))

        # Threat score formula (BR-REP-002, revised)
        # - block_rate: fraction of requests that were blocked
        # - unsolved_rate: challenged but never solved (strongest bot signal)
        # - challenge_fail_rate: explicit challenge failures vs passes
        # - ua_diversity: distinct UA count relative to threshold
        block_rate = blocked / total if total > 0 else 0.0
        challenge_fail_rate = failures / (passes + failures + 1)
        ua_diversity = min(distinct_ua / conf.DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS, 1.0)
        threat_score = min(
            (block_rate * 0.2) + (unsolved_rate * 0.35) + (challenge_fail_rate * 0.25) + (ua_diversity * 0.2),
            1.0,
        )

        defaults = {
            "total_requests": total,
            "blocked_requests": blocked,
            "challenged_requests": challenged,
            "challenge_passes": passes,
            "challenge_failures": failures,
            "distinct_ua_count": distinct_ua,
            "threat_score": round(threat_score, 2),
            "last_seen_at": timezone.now(),
            "window_start": cutoff,
            "window_end": timezone.now(),
        }

        _, was_created = IPReputation.objects.update_or_create(
            ip_address=ip,
            defaults=defaults,
        )
        if was_created:
            created_count += 1
        else:
            updated_count += 1

    logger.info(
        "django-waf: update_ip_reputation — updated=%d created=%d",
        updated_count,
        created_count,
    )
    return {"updated_count": updated_count, "created_count": created_count}


@shared_task
def sync_threat_feed() -> dict:
    """Fetch the central threat feed and synchronise BlockRules.

    Exits early if DJANGO_WAF_FEED_ENABLED is False (BR-FEED-001).

    Returns:
        Dict with keys: created, updated, expired, skipped (or skipped=True if disabled).

    Scheduled: daily at 04:30.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_FEED_ENABLED:
        logger.debug("django-waf: sync_threat_feed skipped — DJANGO_WAF_FEED_ENABLED=False")
        return {"skipped": True, "reason": "feed disabled"}

    from django_waf.services.threat_feed import sync_feed

    return sync_feed()


@shared_task
def report_threat_telemetry() -> dict:
    """Build and submit anonymised threat telemetry to the central feed.

    Exits early if DJANGO_WAF_FEED_REPORT is False (BR-TEL-001).

    Returns:
        Dict with keys: submitted, ua_hashes_count, subnets_count (or skipped).

    Scheduled: daily at 05:00.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_FEED_REPORT:
        logger.debug("django-waf: report_threat_telemetry skipped — DJANGO_WAF_FEED_REPORT=False")
        return {"skipped": True, "reason": "reporting disabled"}

    from django_waf.services.threat_feed import build_telemetry_payload, submit_telemetry

    period_end = timezone.now()
    period_start = period_end - timedelta(hours=24)

    payload = build_telemetry_payload(period_start, period_end)
    submitted = submit_telemetry(payload)

    return {
        "submitted": submitted,
        "ua_hashes_count": len(payload.get("ua_hashes", [])),
        "subnets_count": len(payload.get("subnets", [])),
    }


@shared_task
def update_geoip_database() -> dict:
    """Download and install the MaxMind GeoLite2-Country database.

    Wraps ``services.geoip.install_geoip_database`` with a 6-day freshness
    check so re-running the task within the recommended weekly window is
    a no-op. Requires ``DJANGO_WAF_MAXMIND_LICENSE_KEY`` to be set and the
    ``geoip2`` package to be installed (``pip install django-waf[geoip]``).

    MaxMind releases GeoLite2 updates twice a week (Tuesday and Friday).
    A weekly run on Sunday catches both updates with a day's latency.

    Returns:
        Dict with keys: path, size_bytes, skipped, edition, build_epoch.
        If the operation failed gracefully (missing key, geoip2 not
        installed, HTTP error), returns ``{"skipped": True, "error": ...}``.

    Scheduled: weekly — recommended cron: Sunday 03:00 UTC. Example for
    consuming projects' CELERY_BEAT_SCHEDULE::

        "django-waf-update-geoip": {
            "task": "django_waf.tasks.update_geoip_database",
            "schedule": crontab(day_of_week=0, hour=3, minute=0),
        }
    """
    from django_waf.services.geoip import GeoIPError, install_geoip_database

    try:
        result = install_geoip_database(if_older_than_days=6)
        logger.info(
            "django-waf: update_geoip_database — path=%s skipped=%s size=%d",
            result["path"],
            result["skipped"],
            result["size_bytes"],
        )
        return result
    except GeoIPError as exc:
        logger.warning("django-waf: update_geoip_database skipped — %s", exc)
        return {"skipped": True, "error": str(exc)}


@shared_task(bind=True, ignore_result=True)
def flush_rule_hit_counts(self) -> dict:
    """Flush block rule hit counters from Redis to the database.

    Reads waf:rule_hits:{rule_id} keys, updates BlockRule.hit_count and
    last_hit_at, then deletes the Redis keys. Designed to run every 5 minutes
    alongside the blocklist generation task.
    """
    from django_waf.models import BlockRule

    try:
        from django_redis import get_redis_connection

        from django_waf import conf

        redis_client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except Exception:
        logger.warning("django-waf: Redis unavailable for hit count flush")
        return {"flushed": 0}

    flushed = 0
    prefix = "waf:rule_hits:"

    try:
        keys = redis_client.keys(f"{prefix}*")
    except Exception:
        return {"flushed": 0}

    for key in keys:
        try:
            key_str = key.decode() if isinstance(key, bytes) else key
            rule_id = key_str[len(prefix) :]
            count = int(redis_client.getdel(key) or 0)
            if count > 0:
                from django.db.models import F

                updated = BlockRule.objects.filter(id=rule_id).update(
                    hit_count=F("hit_count") + count,
                    last_hit_at=timezone.now(),
                )
                if updated:
                    flushed += 1
        except Exception:
            continue

    logger.info("django-waf: flushed hit counts for %d rules", flushed)
    return {"flushed": flushed}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _infer_verdict_from_status(status_code: int, path: str) -> str:
    """Infer a WAF verdict from an nginx response status code."""
    if status_code == 403:
        return "blocked"
    if status_code == 429:
        return "throttled"
    if status_code == 302 and "/waf/challenge" in path:
        return "challenged"
    return "allowed"


def _invalidate_rule_cache_redis() -> None:
    """Increment waf:rules:version in Redis to invalidate the cached rule set."""
    try:
        from django_redis import get_redis_connection

        from django_waf import conf

        redis_client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
        redis_client.incr("waf:rules:version")
    except Exception:
        # Fall back to Django cache
        from django.core.cache import cache

        version = (cache.get("waf:rules:version") or 0) + 1
        cache.set("waf:rules:version", version)
