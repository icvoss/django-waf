"""
Celery tasks for django-waf.

All tasks use @shared_task and lazy imports for Celery compatibility.
Tasks are idempotent and fail gracefully.

Scheduled tasks (Celery Beat):
  - generate_blocklist, every 5 minutes (BR-BL-004)
  - flush_rule_hit_counts, every 5 minutes
  - detect_anomalies, every 15 minutes (BR-ANOM-005)
  - parse_access_log, every 10 minutes
  - prune_request_logs, daily 04:00 (BR-LOG-003)
  - prune_challenge_tokens, daily 04:15
  - prune_stale_rules       : daily 04:20 (wave 2, the rule-provenance wave)
  - expire_rules, every 30 minutes (BR-LIFE-002)
  - update_ip_reputation, every 6 hours
  - sync_threat_feed, daily 04:30
  - report_threat_telemetry, daily 05:00
  - update_geoip_database, weekly (Sunday 03:00 UTC recommended)
  - probe_detectors: hourly (BR-ANOM-012)
"""

from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timedelta

from celery import shared_task
from django.utils import timezone

logger = logging.getLogger("django_waf.tasks")

# nginx's default log_format writes [dd/Mon/yyyy:HH:MM:SS +ZZZZ].
_NGINX_LOG_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"


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
            "django-waf: cannot write blocklist, %s. Set DJANGO_WAF_NGINX_BLOCKLIST_PATH to a writable location.",
            exc,
        )
        return {"rules_written": 0, "reload_succeeded": False, "error": str(exc)}

    success = reload_nginx()
    logger.info("django-waf: generate_blocklist, %d rules, reload=%s", count, success)
    return {"rules_written": count, "reload_succeeded": success}


@shared_task
def detect_anomalies() -> dict:
    """Run all anomaly detectors and auto-create BlockRules for suspicious patterns.

    Returns:
        Dict with keys: ua_rotation_rules, subnet_burst_rules,
        challenge_farm_rules, unsolved_challenge_rules, cloud_spray_rules,
        scraper_404_rules, total_rules_created.

    Scheduled: every 15 minutes (BR-ANOM-005).
    """
    from django_waf.services.anomaly_detector import run_all_detectors

    return run_all_detectors()


@shared_task
def parse_access_log(log_path: str | None = None) -> dict:
    """Parse the nginx access log and populate RequestLog records.

    Uses file offset tracking to avoid re-parsing previously imported lines.
    The offset is persisted in the Django cache.

    Rows created here are tagged ``source="nginx_log"`` with a deterministic
    ``source_event_id`` (#32), so re-ingesting the same lines (e.g. after a
    cache eviction forces a re-read from offset 0) collides against the
    partial unique constraint and ``bulk_create(ignore_conflicts=True)``
    silently skips the duplicates instead of creating them again.

    Offset storage is cache-only (not yet a durable model row): if the cache
    entry is evicted the file is re-read from the start. That re-read is safe
    (thanks to the dedup constraint above), but not free, it costs a full
    file scan and a bulk_create attempt for every previously-seen line, only
    to have them silently discarded. A durable offset store is left for the
    next pass. Rotation/truncation is detected without depending on the
    cache's own durability: if the file's current size is smaller than the
    stored offset, the log has rotated or been truncated underneath us, so
    the stored offset is treated as invalid and reset to 0 rather than
    silently skipping the file's live tail forever.

    A line whose IP address does not pass the same validation
    ``RequestLog.ip_address`` (``GenericIPAddressField``) would apply at
    write time, or whose status code exceeds the ``response_code`` column's
    smallint range, is skipped (counted in ``skipped_lines``) rather than
    included in the batch (#72). Access logs are attacker-influenced input,
    so a malformed value in either position is an expected condition: before
    this validation, one bad IP raised ``ValueError`` from Django's own
    field validation inside ``bulk_create``, escaped the ``except OSError``
    below, and discarded the whole batch, including every well-formed row.

    Args:
        log_path: Override path. Defaults to DJANGO_WAF_ACCESS_LOG_PATH.

    Returns:
        Dict with keys: parsed_lines, created_records, skipped_lines.

    Scheduled: every 10 minutes.
    """
    import os

    from django.core.cache import cache
    from django.core.exceptions import ValidationError as DjangoValidationError
    from django.core.validators import validate_ipv46_address

    from django_waf import conf
    from django_waf.enums import RequestLogSource
    from django_waf.models import RequestLog

    path = log_path or conf.DJANGO_WAF_ACCESS_LOG_PATH

    if not path:
        # Feature not configured at all: an expected, quiet no-op, not a
        # failure, so this stays at DEBUG.
        logger.debug("django-waf: DJANGO_WAF_ACCESS_LOG_PATH not set, skipping parse")
        return {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}

    offset_key = f"django_waf:access_log_offset:{path}"

    if not os.path.isfile(path):
        # A path *was* configured but does not resolve to a file: this is
        # very likely a wrong DJANGO_WAF_ACCESS_LOG_PATH, which otherwise
        # yields the identical {"parsed_lines": 0} as an idle site, forever,
        # with no signal at all (the return dict is not itself surfaced
        # anywhere; the log line is the only observable). WARNING so it is
        # visible in production rather than silently invisible at DEBUG.
        logger.warning("django-waf: configured access log %s does not exist, skipping parse", path)
        return {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}

    stored_offset = cache.get(offset_key)
    if stored_offset is None:
        # No cached offset, either the first run, or the cache entry was
        # evicted. Either way the whole file will be re-read from 0; that is
        # only safe because of the dedup constraint on nginx_log rows, so
        # surface it rather than let a silent full re-read go unnoticed.
        logger.warning(
            "django-waf: no cached offset for access log %s, re-reading from start "
            "(safe due to source_event_id dedup, but re-scans the whole file)",
            path,
        )
        stored_offset = 0

    parsed_lines = created_records = skipped_lines = 0
    skipped_ip_lines = 0

    # Combined log format pattern:
    # IP - - [timestamp] "METHOD /path HTTP/x.x" status size "referer" "ua"
    _LOG_RE = re.compile(
        r'^(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+\S+'
        r'(?:\s+"[^"]*"\s+"([^"]*)")?'
    )

    # response_code is a PositiveSmallIntegerField. The regex only
    # guarantees the matched group is digits, not that it fits the column,
    # so a corrupted or crafted line with an oversized status code is
    # validated the same way as the IP address below rather than reaching
    # bulk_create.
    #
    # 32767 is PostgreSQL's signed-smallint ceiling, which is what
    # connection.ops.integer_field_range reports for this field on
    # PostgreSQL (verified) and the tightest bound among the backends this
    # package supports. It is deliberately a fixed literal rather than a
    # per-backend lookup: the bound is only used to reject a value no real
    # access log carries, so the tightest one is correct everywhere, and
    # introducing a backend-dependent limit inside the parse loop would
    # make ingestion silently accept different rows on different databases.
    _MAX_SMALLINT = 32767

    records_to_create = []

    try:
        file_size = os.path.getsize(path)
        if file_size < stored_offset:
            # The file is smaller than where we last stopped reading: it has
            # been rotated or truncated underneath us. Resuming from the
            # stale offset would either raise or silently skip the new
            # tail, so reset to the start of the (new) file instead.
            logger.warning(
                "django-waf: access log %s appears rotated (size %d < stored offset %d), resetting offset",
                path,
                file_size,
                stored_offset,
            )
            stored_offset = 0

        with open(path, errors="replace") as fh:
            fh.seek(stored_offset)
            for line in fh:
                parsed_lines += 1
                match = _LOG_RE.match(line.strip())
                if not match:
                    skipped_lines += 1
                    continue

                ip_address = match.group(1)
                timestamp_str = match.group(2)  # e.g. 23/Mar/2026:10:00:00 +0000
                method = match.group(3)[:16]
                path_str = match.group(4)[:2048]
                status_code = int(match.group(5))
                user_agent = (match.group(6) or "")[:1024]

                # Access logs are attacker-influenced input, so a malformed
                # value in the IP position is an expected condition, not an
                # exceptional one (#72). validate_ipv46_address is the exact
                # validator RequestLog.ip_address (GenericIPAddressField,
                # protocol="both") runs at full_clean() time, so "valid"
                # here means precisely what the field will accept at write
                # time; previously nothing validated this before
                # bulk_create, so one malformed IP raised ValueError from
                # Django's own field validation deep inside bulk_create and
                # discarded the whole batch, including every well-formed row.
                try:
                    validate_ipv46_address(ip_address)
                except DjangoValidationError:
                    skipped_lines += 1
                    skipped_ip_lines += 1
                    continue

                if status_code > _MAX_SMALLINT:
                    skipped_lines += 1
                    continue

                log_timestamp = _parse_nginx_timestamp(timestamp_str)
                event_id = _build_source_event_id(ip_address, timestamp_str, method, path_str, status_code)

                records_to_create.append(
                    RequestLog(
                        timestamp=log_timestamp,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        path=path_str,
                        method=method,
                        verdict=_infer_verdict_from_status(status_code, path_str),
                        response_code=status_code,
                        source=RequestLogSource.NGINX_LOG,
                        source_event_id=event_id,
                    )
                )

            new_offset = fh.tell()

        if records_to_create:
            RequestLog.objects.bulk_create(records_to_create, ignore_conflicts=True)
            created_records = len(records_to_create)

        cache.set(offset_key, new_offset, timeout=None)

        if skipped_ip_lines:
            # One summarising line rather than one per bad line: a burst of
            # malformed IPs (a proxy misconfiguration, a crafted header) is
            # exactly the condition this validation exists to survive, so
            # logging per-line at WARNING would itself flood production.
            logger.warning(
                "django-waf: skipped %d access log line(s) with a malformed IP address (path=%s)",
                skipped_ip_lines,
                path,
            )

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

    Only PENDING and FAILED tokens are pruned, SOLVED tokens are kept for
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
    """Deactivate BlockRules and AllowRules whose expires_at has passed.

    Sets is_active=False. Does not delete rules (BR-LIFE-001). Covers both
    rule tables (#25): an expired AllowRule left active would otherwise
    keep bypassing every WAF check indefinitely. After bulk update,
    manually increments the Redis rule version key to invalidate the cache
    since bulk update() does not trigger post_save signals.

    Per BR-ANOM-010 (#48), also sweeps auto-generated BlockRules still
    review_status=PENDING whose expires_at has passed, independently of
    is_active: BlockRuleManager.expired() only ever matches is_active=True
    rows, so a quarantined (is_active=False) rule that nobody reviews would
    otherwise sit PENDING forever and never reach expired_unreviewed. This
    sweep runs as a separate update() against a review_status-scoped
    queryset, so it catches a PENDING rule whether the BlockRule sweep above
    just deactivated it (still active when this task started) or it was
    already quarantined (is_active=False from the moment it was created):
    both cases end this task with is_active=False (from either this task's
    own BlockRule sweep or the original quarantine) and
    review_status=EXPIRED_UNREVIEWED.

    Returns:
        Dict with keys: expired_block_count, expired_allow_count,
        expired_count (total, kept for backwards compatibility),
        expired_unreviewed_count.

    Scheduled: every 30 minutes (BR-LIFE-002).
    """
    from django_waf.enums import ReviewStatus, RuleSource
    from django_waf.models import AllowRule, BlockRule

    # Ordering note: this BlockRule deactivation and the review-status sweep
    # below touch different fields (is_active vs review_status) via
    # independent update() calls, so their relative order does not affect
    # correctness. Running deactivation first keeps the log line's counts
    # readable in the order an operator thinks about them (rules turned
    # off, then rules flagged unreviewed).
    expired_block_count = BlockRule.objects.expired().update(is_active=False)
    expired_allow_count = AllowRule.objects.expired().update(is_active=False)
    total = expired_block_count + expired_allow_count

    expired_unreviewed_count = BlockRule.objects.filter(
        source=RuleSource.AUTO,
        review_status=ReviewStatus.PENDING,
        expires_at__lte=timezone.now(),
    ).update(review_status=ReviewStatus.EXPIRED_UNREVIEWED)

    if total > 0:
        # bulk update() bypasses signals: manually invalidate the rule cache.
        # A review_status-only change (expired_unreviewed_count) does not,
        # by itself, affect evaluation: is_active is what the rule cache and
        # rule_engine key off, and BlockRuleManager.active() already
        # excludes quarantined (is_active=False) rows regardless of
        # review_status. So cache invalidation is gated on `total`
        # (is_active changes) only, not on expired_unreviewed_count.
        try:
            _invalidate_rule_cache_redis()
        except Exception:
            logger.exception("django-waf: failed to invalidate rule cache after expire_rules")

        logger.info(
            "django-waf: expired %d BlockRules, %d AllowRules",
            expired_block_count,
            expired_allow_count,
        )

    if expired_unreviewed_count > 0:
        logger.info(
            "django-waf: marked %d auto-generated BlockRule(s) expired_unreviewed",
            expired_unreviewed_count,
        )

    return {
        "expired_block_count": expired_block_count,
        "expired_allow_count": expired_allow_count,
        "expired_count": total,
        "expired_unreviewed_count": expired_unreviewed_count,
    }


@shared_task
def prune_stale_rules(days: int | None = None) -> dict:
    """Hard-delete expired, inactive, auto-generated BlockRules older than the retention window.

    Mirrors prune_request_logs' shape. Per DJANGO_WAF_RULE_RETENTION_DAYS
    (default 90, the wave 2 rule-provenance plan): measured on a live 2.4.0 deployment,
    48,319 BlockRule rows were older than 90 days with nothing older than
    150 (the table's own age since expire_rules only deactivates, never
    deletes). Unbounded row growth is not the only cost: a surviving
    expired-and-inactive, source=auto row whose pattern coincides with a
    detector's probe fixture permanently reports that detector SILENT in
    django_waf_probe_detectors, because the probe's dry-run existence check
    filters on neither is_active nor expires_at. This task is what stops
    that collision from being permanent as well as what bounds the table.

    The predicate (BlockRuleManager.stale(), see models.py for the full
    reasoning) never deletes an active rule, an unexpired rule, a rule
    still PENDING review, one an operator CONFIRMED, or one an operator
    REJECTED. A rejection is a decision the operator already made once,
    and deleting its record only forces them to make it again the next
    time a detector re-observes the same pattern. It is scoped to
    source=AUTO only: a hand-authored admin rule or a feed-sourced rule is
    never touched by this task regardless of age, is_active, or
    review_status, since neither regenerates itself on the next detector
    run the way an auto rule does.

    This is the one destructive task in the package: unlike
    prune_request_logs (sampled, low-value rows) and
    prune_challenge_tokens (ephemeral proof-of-work state), a deleted
    BlockRule is a decision record. Gated on DJANGO_WAF_RULE_PRUNE_ENABLED
    (default False): while disabled, this task still runs on schedule and
    still counts and logs how many rows are stale, but deletes nothing, so
    a consumer who merges DJANGO_WAF_CELERY_BEAT_SCHEDULE unmodified gets a
    standing visibility signal rather than either silent inaction or
    silent deletion. An operator turns deletion on deliberately once
    satisfied with what the count reports. See
    management/commands/django_waf_prune_rules.py for the equivalent
    report-first default on the manual path.

    Args:
        days: Number of days to retain. Defaults to DJANGO_WAF_RULE_RETENTION_DAYS.

    Returns:
        Dict with keys: deleted_count, dry_run.

    Scheduled: daily at 04:20, immediately after prune_challenge_tokens'
    04:15 slot, keeping the retention-sweep tasks clustered in the
    package's quiet-hours window rather than scattered across the day.
    """
    from django_waf import conf
    from django_waf.models import BlockRule

    retention_days = days if days is not None else conf.DJANGO_WAF_RULE_RETENTION_DAYS
    stale_qs = BlockRule.objects.stale(days=retention_days)

    if not conf.DJANGO_WAF_RULE_PRUNE_ENABLED:
        count = stale_qs.count()
        logger.info(
            "django-waf: %d stale BlockRule record(s) older than %d days would be pruned "
            "(DJANGO_WAF_RULE_PRUNE_ENABLED is False, nothing deleted)",
            count,
            retention_days,
        )
        return {"deleted_count": 0, "dry_run": True}

    deleted, _ = stale_qs.delete()
    logger.info("django-waf: pruned %d stale BlockRule record(s) older than %d days", deleted, retention_days)
    return {"deleted_count": deleted, "dry_run": False}


@shared_task
def update_ip_reputation() -> dict:
    """Aggregate IP behaviour from recent RequestLog records into IPReputation.

    Covers the last 24 hours. Upserts one record per IP (BR-REP-003). Computes
    threat score per BR-REP-002.

    ``detect_challenge_farms`` (services/anomaly_detector.py) reads
    ``IPReputation`` directly, so a silent zero here is not just an idle
    metric: it blinds that detector for the whole window. ``ips_seen``
    distinguishes "no RequestLog rows landed at all" (logged at WARNING,
    since either ingestion has stopped or nothing has been logged in 24
    hours, both worth an operator's attention) from "rows landed but every
    IP was already up to date", which is a genuinely quiet window.

    Returns:
        Dict with keys: updated_count, created_count, ips_seen.

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
    ip_stats = list(
        RequestLog.objects.filter(timestamp__gte=cutoff)
        .values("ip_address")
        .annotate(
            total=Count("id"),
            blocked=Count("id", filter=Q(verdict=Verdict.BLOCKED)),
            challenged=Count("id", filter=Q(verdict=Verdict.CHALLENGED)),
            distinct_ua=Count("user_agent", distinct=True),
        )
    )
    ips_seen = len(ip_stats)

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

    if ips_seen == 0:
        # No RequestLog rows landed in the window at all: either logging
        # has genuinely gone quiet or ingestion (parse_access_log,
        # WafMiddleware's own logging) has stopped. Either way,
        # detect_challenge_farms is now blind for this window, so this is
        # worth a WARNING rather than the same log line as "processed
        # everyone, nothing changed".
        logger.warning(
            "django-waf: update_ip_reputation saw no RequestLog rows in the last 24h window, "
            "detect_challenge_farms has no data for this window"
        )
    else:
        logger.info(
            "django-waf: update_ip_reputation, ips_seen=%d updated=%d created=%d",
            ips_seen,
            updated_count,
            created_count,
        )
    return {"updated_count": updated_count, "created_count": created_count, "ips_seen": ips_seen}


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
        logger.debug("django-waf: sync_threat_feed skipped, DJANGO_WAF_FEED_ENABLED=False")
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
        logger.debug("django-waf: report_threat_telemetry skipped, DJANGO_WAF_FEED_REPORT=False")
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

    Scheduled: weekly, recommended cron: Sunday 03:00 UTC. Example for
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
            "django-waf: update_geoip_database, path=%s skipped=%s size=%d",
            result["path"],
            result["skipped"],
            result["size_bytes"],
        )
        return result
    except GeoIPError as exc:
        logger.warning("django-waf: update_geoip_database skipped, %s", exc)
        return {"skipped": True, "error": str(exc)}


@shared_task
def probe_detectors() -> dict:
    """Run the detector liveness probe (BR-ANOM-012) and report the result.

    Delegates to ``services.detector_probe.run_detector_probe``, which
    builds synthetic fixture traffic guaranteed to cross every anomaly
    detector's own configured threshold and reports which detectors did,
    and did not, produce a rule against it. Real recent traffic cannot be
    used for this: ``run_all_detectors`` returning zero is the normal,
    healthy, overwhelmingly common result on a quiet site, indistinguishable
    from a dead detector, which is exactly how 2.0.0's subnet-detection
    regression went unnoticed for 13 hours.

    Freshness of this task's OWN execution is the consumer's job, not this
    package's: a dead Celery Beat entry, a paused worker, or a broken
    schedule produces no log line at all, which looks identical to "the
    task has simply never needed to run" from inside this function. This
    package stays stateless (CHK-OPEN-005) and does not persist a last-run
    timestamp, so a consumer wiring alerting to this probe MUST alert on
    the ABSENCE of the structured log line below within the expected
    cadence, not only on its WARNING content: a probe that cannot itself
    detect that it stopped running is not a safety net for that failure
    mode, only for a detector that runs and returns nothing.

    Runs with ``dry_run=True`` (the default from ``run_detector_probe``):
    no ``BlockRule`` is ever created, activated, or refreshed, and the
    ``anomaly_detected`` signal is never emitted from a scheduled run. Use
    the ``django_waf_probe_detectors --exercise-writes`` management command
    for the opt-in real-write mode; this task deliberately does not expose
    it, since a signal wired to a paging system firing on a schedule from
    synthetic data would be a self-inflicted incident.

    This task never raises: unlike most tasks in this module, its entire
    purpose is unattended liveness reporting, so a task that itself crashes
    defeats the reason it exists (a crashed Celery task is a silent no-op
    to Beat in the same way a missing log line is, from an operator's
    perspective, unless task-failure alerting is separately wired). Any
    exception is logged at ERROR with the traceback and reported as a
    failure result rather than propagated.

    Returns:
        On success, the dict ``run_detector_probe`` returns (BR-ANOM-012):
        one key per detector name with ``alive``/``rules_reported``, plus
        ``all_alive``, ``silent_detectors``, and ``dry_run``. On failure,
        ``{"all_alive": False, "silent_detectors": [...], "error": ...}``,
        with every named detector reported as not alive by omission: a
        probe that could not run proves liveness for nothing.

    Scheduled: hourly.
    """
    from django_waf.services.anomaly_detector import DETECTOR_NAMES
    from django_waf.services.detector_probe import run_detector_probe

    try:
        # run_detector_probe itself logs the all-alive INFO line or the
        # silent-detectors WARNING line; this task does not re-log the same
        # outcome, mirroring detect_anomalies's thin delegation to
        # run_all_detectors (which likewise does its own logging).
        return run_detector_probe(dry_run=True)
    except Exception:
        logger.exception("django-waf: probe_detectors failed to run")
        return {
            "all_alive": False,
            "silent_detectors": sorted(DETECTOR_NAMES),
            "error": "probe_detectors raised; see traceback in the preceding log record",
        }


@shared_task(bind=True, ignore_result=True)
def flush_rule_hit_counts(self) -> dict:
    """Flush block rule hit counters from Redis to the database.

    Reads waf:rule_hits:{rule_id} keys, updates BlockRule.hit_count and
    last_hit_at, then deletes the Redis keys. Designed to run every 5 minutes
    alongside the blocklist generation task.

    ``ignore_result=True`` means Celery discards the returned dict, so the
    log line below is the only real observable this task has. All three
    failure exits, and the success exit, now report ``keys_seen`` and
    ``errors`` alongside ``flushed``, so "Redis unreachable", "keys listed
    but every read/write failed", and a genuinely idle site with nothing to
    flush produce three different log lines instead of the same
    ``{"flushed": 0}`` for all three. Fail-open is unchanged (BR-EVAL-007):
    an unflushed counter just waits for the next run.
    """
    from django_waf.models import BlockRule

    try:
        from django_redis import get_redis_connection

        from django_waf import conf

        redis_client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except Exception:
        logger.warning("django-waf: Redis unavailable for hit count flush, flushed=0 keys_seen=0 errors=0")
        return {"flushed": 0, "keys_seen": 0, "errors": 0}

    flushed = 0
    errors = 0
    prefix = "waf:rule_hits:"

    try:
        keys = redis_client.keys(f"{prefix}*")
    except Exception:
        logger.error(
            "django-waf: failed to list Redis hit count keys, flushed=0 keys_seen=0 errors=1",
            exc_info=True,
        )
        return {"flushed": 0, "keys_seen": 0, "errors": 1}

    keys_seen = len(keys)

    for key in keys:
        key_str = key.decode() if isinstance(key, bytes) else key
        rule_id = key_str[len(prefix) :]

        try:
            # GETDEL requires Redis 6.2+; the package's own floor is 6.0
            # (see django_waf.E005), so use a GET+DEL pipeline instead. Not
            # atomic against a concurrent INCR landing between the two
            # commands, but this is a coarse hit counter flushed every five
            # minutes, not a balance: a count dropped or double counted in
            # that narrow window is an acceptable trade for staying on the
            # 6.0 floor.
            pipe = redis_client.pipeline()
            pipe.get(key)
            pipe.delete(key)
            get_result, _ = pipe.execute()
            count = int(get_result or 0)
        except Exception:
            errors += 1
            logger.error("django-waf: failed to read/clear hit counter for rule %s", rule_id, exc_info=True)
            continue

        if count <= 0:
            continue

        try:
            from django.db.models import F

            updated = BlockRule.objects.filter(id=rule_id).update(
                hit_count=F("hit_count") + count,
                last_hit_at=timezone.now(),
            )
        except Exception:
            # The Redis counter is already cleared at this point, so this
            # count is lost, not retried on the next run. Fail-open per
            # BR-EVAL-007 means we do not raise and abort the whole flush
            # over one bad rule id, but a lost count must be loud: previously
            # this was a bare `except Exception: continue` that swallowed a
            # DB error identically to a Redis error, with no log at all.
            errors += 1
            logger.error(
                "django-waf: failed to persist hit count for rule %s (count=%d, Redis counter already cleared)",
                rule_id,
                count,
                exc_info=True,
            )
            continue

        if updated:
            flushed += 1

    if errors:
        logger.warning(
            "django-waf: flushed hit counts for %d rules, keys_seen=%d errors=%d",
            flushed,
            keys_seen,
            errors,
        )
    else:
        logger.info(
            "django-waf: flushed hit counts for %d rules, keys_seen=%d errors=0",
            flushed,
            keys_seen,
        )
    return {"flushed": flushed, "keys_seen": keys_seen, "errors": errors}


@shared_task
def probe_flush_path() -> dict:
    """Run the flush-path liveness probe (#100) and report the result.

    Delegates to ``services.flush_probe.run_flush_probe``, which drives a
    real counter through the real producer
    (``rule_engine._record_rule_hit``) and the real consumer
    (``flush_rule_hit_counts`` above), then asserts the counter
    demonstrably reached the database. This exists because
    ``flush_rule_hit_counts`` used to call Redis ``GETDEL`` (needs Redis
    6.2+); production ran 6.0.16, every call raised, a bare except
    swallowed it, and 40,936 scheduled task runs reported success while
    flushing nothing. ``{"flushed": 0, "keys_seen": 0, "errors": 0}`` is
    both the healthy result on a quiet site AND what that defect produced,
    so real traffic cannot distinguish them; a counter this probe writes
    itself can.

    Mirrors ``probe_detectors``'s own freshness note: this package stays
    stateless and does not persist a last-run timestamp, so a consumer
    wiring alerting to this probe must alert on the ABSENCE of the
    structured log line ``run_flush_probe`` emits within the expected
    cadence, not only on its WARNING content.

    This task never raises: like ``probe_detectors``, its entire purpose
    is unattended liveness reporting, so a task that itself crashes
    defeats the reason it exists. Any exception is logged at ERROR with
    the traceback and reported as a failure result rather than propagated.

    Returns:
        On success, the dict ``run_flush_probe`` returns: ``alive``,
        ``flushed``, ``keys_seen``, ``errors``, ``hit_count_delta``,
        ``key_deleted``, ``failure_reason``. On failure, the same shape
        with ``alive=False`` and ``failure_reason`` naming that the task
        itself raised: a probe that could not run proves liveness for
        nothing.

    Scheduled: hourly, matching the detector probe's own cadence
    (BR-ANOM-012 precedent). The flush task itself runs every 5 minutes,
    so an hourly probe gives ample margin to catch sustained breakage
    well inside a single day, without adding alert noise on the same
    schedule as the thing it is checking.
    """
    from django_waf.services.flush_probe import run_flush_probe

    try:
        # run_flush_probe itself logs the alive INFO line or the failure
        # WARNING line; this task does not re-log the same outcome,
        # mirroring probe_detectors's thin delegation above.
        return run_flush_probe()
    except Exception as exc:
        logger.exception("django-waf: probe_flush_path failed to run")
        return {
            "alive": False,
            "flushed": 0,
            "keys_seen": 0,
            "errors": 0,
            "hit_count_delta": 0,
            "key_deleted": False,
            "failure_reason": f"probe_flush_path raised: {exc}",
        }


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


def _parse_nginx_timestamp(timestamp_str: str) -> datetime:
    """Parse an nginx combined-log timestamp into an aware datetime.

    Falls back to the current time if the value cannot be parsed (a
    malformed timestamp on an otherwise-matching line), so a single bad
    line degrades gracefully rather than dropping the record (#32).
    """
    try:
        return datetime.strptime(timestamp_str, _NGINX_LOG_TIME_FORMAT)
    except ValueError:
        logger.warning("django-waf: could not parse access log timestamp %r, using now()", timestamp_str)
        return timezone.now()


def _build_source_event_id(ip_address: str, timestamp_str: str, method: str, path: str, status_code: int) -> str:
    """Build a deterministic event identity for a parsed access-log line.

    Re-ingesting the same log line (e.g. after an offset reset) produces the
    same id, so it collides against the partial unique constraint on
    (source, source_event_id) and bulk_create(ignore_conflicts=True) skips
    the duplicate rather than creating a second row (#32).
    """
    raw = f"{ip_address}|{timestamp_str}|{method}|{path}|{status_code}"
    return hashlib.sha256(raw.encode()).hexdigest()[:64]


def _invalidate_rule_cache_redis() -> None:
    """Increment waf:rules:version in Redis to invalidate the cached rule set.

    Every WafMiddleware process holds an in-process rule cache keyed on this
    version; incrementing it is how a newly expired/created rule reaches
    already-running workers without a restart. The Django cache fallback
    below is per-process, not shared, so it does not actually invalidate
    other workers' caches, only this one's next read. Falling back silently
    previously looked identical to a successful Redis invalidation from the
    caller's side, so an operator watching Redis come back up after an
    outage had no way to see that a chunk of rule-cache invalidations were
    only ever applied locally.
    """
    try:
        from django_redis import get_redis_connection

        from django_waf import conf

        redis_client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
        redis_client.incr("waf:rules:version")
    except Exception:
        # Fall back to Django cache. Per-process only: other WafMiddleware
        # workers do not see this bump, so their rule caches stay stale
        # until Redis recovers and a real invalidation reaches them.
        logger.warning(
            "django-waf: Redis unavailable for rule cache invalidation, falling back to the local Django "
            "cache (other worker processes will not see this invalidation until Redis recovers)"
        )
        from django.core.cache import cache

        version = (cache.get("waf:rules:version") or 0) + 1
        cache.set("waf:rules:version", version)
