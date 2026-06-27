"""Tests for django-waf Celery tasks.

Redis is not available in the test environment. All external calls (Redis,
httpx, filesystem) are mocked using unittest.mock. Database operations use
real SQLite via pytest-django's ``db`` fixture.
"""

from __future__ import annotations

import tempfile
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

import pytest
from django.utils import timezone

from django_waf.enums import Verdict
from django_waf.testing.factories import (
    BlockRuleFactory,
    IPReputationFactory,
    RequestLogFactory,
)

# ---------------------------------------------------------------------------
# generate_blocklist
# ---------------------------------------------------------------------------


class TestGenerateBlocklist:
    def test_calls_generate_and_reload(self):
        """Task calls generate_nginx_blocklist() and reload_nginx(), returns their results."""
        with (
            patch("django_waf.services.blocklist_generator.generate_nginx_blocklist", return_value=42) as mock_gen,
            patch("django_waf.services.blocklist_generator.reload_nginx", return_value=True) as mock_reload,
        ):
            from django_waf.tasks import generate_blocklist

            result = generate_blocklist()

        mock_gen.assert_called_once()
        mock_reload.assert_called_once()
        assert result == {"rules_written": 42, "reload_succeeded": True}

    def test_returns_reload_failure(self):
        """Task surfaces a False reload result without raising."""
        with (
            patch("django_waf.services.blocklist_generator.generate_nginx_blocklist", return_value=0),
            patch("django_waf.services.blocklist_generator.reload_nginx", return_value=False),
        ):
            from django_waf.tasks import generate_blocklist

            result = generate_blocklist()

        assert result == {"rules_written": 0, "reload_succeeded": False}

    def test_does_not_raise_when_service_fails(self):
        """If generate_nginx_blocklist raises an exception the task propagates it.

        Tasks wrap errors in their own retry logic; callers are responsible for
        configuring retry behaviour. Here we simply verify the exception surface.
        """
        with (
            patch(
                "django_waf.services.blocklist_generator.generate_nginx_blocklist",
                side_effect=OSError("disk full"),
            ),
            patch("django_waf.services.blocklist_generator.reload_nginx"),
        ):
            from django_waf.tasks import generate_blocklist

            with pytest.raises(OSError):
                generate_blocklist()


# ---------------------------------------------------------------------------
# detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomalies:
    def test_calls_run_all_detectors_and_returns_result(self):
        """Task delegates entirely to run_all_detectors() and returns its value."""
        expected = {
            "ua_rotation_rules": 3,
            "subnet_burst_rules": 1,
            "challenge_farm_rules": 0,
            "total_rules_created": 4,
        }
        with patch("django_waf.services.anomaly_detector.run_all_detectors", return_value=expected) as mock_det:
            from django_waf.tasks import detect_anomalies

            result = detect_anomalies()

        mock_det.assert_called_once()
        assert result == expected

    def test_returns_zero_counts_when_nothing_detected(self):
        """Task returns detector output unchanged when no anomalies are found."""
        empty = {
            "ua_rotation_rules": 0,
            "subnet_burst_rules": 0,
            "challenge_farm_rules": 0,
            "total_rules_created": 0,
        }
        with patch("django_waf.services.anomaly_detector.run_all_detectors", return_value=empty):
            from django_waf.tasks import detect_anomalies

            result = detect_anomalies()

        assert result == empty


# ---------------------------------------------------------------------------
# parse_access_log
# ---------------------------------------------------------------------------


class TestParseAccessLog:
    def test_skips_when_path_not_given(self):
        """Task returns zero counts when no log path is configured."""
        with patch("django_waf.conf.DJANGO_WAF_ACCESS_LOG_PATH", ""):
            from django_waf.tasks import parse_access_log

            result = parse_access_log()

        assert result == {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}

    def test_skips_when_file_does_not_exist(self):
        """Task returns zero counts when the file at the configured path is absent."""
        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path="/non/existent/access.log")

        assert result == {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}

    @pytest.mark.django_db
    def test_parses_valid_combined_log_lines(self):
        """Valid combined-log-format lines are parsed and RequestLog records are created."""
        log_content = (
            '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /page/1/ HTTP/1.1" 200 1234 '
            '"-" "Mozilla/5.0 (compatible; Googlebot/2.1)"\n'
            '5.6.7.8 - - [07/Apr/2026:10:00:01 +0000] "POST /submit/ HTTP/1.1" 302 0 '
            '"-" "curl/7.68.0"\n'
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        before = RequestLog.objects.count()
        result = parse_access_log(log_path=log_path)

        assert result["parsed_lines"] == 2
        assert result["created_records"] == 2
        assert result["skipped_lines"] == 0
        assert RequestLog.objects.count() == before + 2

    @pytest.mark.django_db
    def test_truncates_overlong_method(self):
        """A scanner method longer than the column width is truncated, not dropped.

        Regression: scanners send junk HTTP methods (>16 chars). The method
        field is max_length=16, so the value must be clipped before insert or
        the record creation raises a varchar overflow.
        """
        long_method = "A" * 50
        log_content = f'9.9.9.9 - - [07/Apr/2026:10:00:00 +0000] "{long_method} /x HTTP/1.1" 400 0 "-" "scanner/1.0"\n'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path=log_path)

        assert result["created_records"] == 1
        record = RequestLog.objects.latest("id")
        assert record.method == "A" * 16
        assert len(record.method) == 16

    @pytest.mark.django_db
    def test_skips_malformed_lines(self):
        """Lines that do not match the log regex are counted as skipped."""
        log_content = "this is not a valid nginx log line\n"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path=log_path)

        assert result["parsed_lines"] == 1
        assert result["skipped_lines"] == 1
        assert result["created_records"] == 0

    @pytest.mark.django_db
    def test_persists_file_offset_in_cache(self):
        """Cache is updated with the new file offset after a successful parse."""
        from django.core.cache import cache

        log_content = '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 100 "-" "ua"\n'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(log_content)
            log_path = fh.name

        from django_waf.tasks import parse_access_log

        parse_access_log(log_path=log_path)

        offset_key = f"django_waf:access_log_offset:{log_path}"
        stored = cache.get(offset_key)
        assert stored is not None
        assert stored > 0

    @pytest.mark.django_db
    def test_resumes_from_stored_offset(self):
        """Task picks up from the cached offset rather than re-parsing from the start."""
        from django.core.cache import cache

        line = '1.2.3.4 - - [07/Apr/2026:10:00:00 +0000] "GET /old/ HTTP/1.1" 200 100 "-" "ua"\n'
        new_line = '9.9.9.9 - - [07/Apr/2026:10:00:01 +0000] "GET /new/ HTTP/1.1" 200 100 "-" "ua"\n'

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write(line)
            fh.write(new_line)
            log_path = fh.name

        # Simulate previous parse having consumed the first line
        offset_key = f"django_waf:access_log_offset:{log_path}"
        cache.set(offset_key, len(line.encode()))

        from django_waf.models import RequestLog
        from django_waf.tasks import parse_access_log

        result = parse_access_log(log_path=log_path)

        # Only the second line should be parsed
        assert result["parsed_lines"] == 1
        assert result["created_records"] == 1
        assert RequestLog.objects.filter(path="/new/").exists()

    def test_handles_os_error_gracefully(self):
        """OSError whilst reading the log is caught and returns zero counts."""
        with (
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", side_effect=OSError("permission denied")),
        ):
            from django_waf.tasks import parse_access_log

            result = parse_access_log(log_path="/fake/access.log")

        assert result == {"parsed_lines": 0, "created_records": 0, "skipped_lines": 0}


# ---------------------------------------------------------------------------
# prune_request_logs
# ---------------------------------------------------------------------------


class TestPruneRequestLogs:
    @pytest.mark.django_db
    def test_deletes_old_records(self):
        """Records older than the retention period are deleted."""
        cutoff = timezone.now() - timedelta(days=31)
        old_log = RequestLogFactory(timestamp=cutoff - timedelta(hours=1))
        recent_log = RequestLogFactory(timestamp=timezone.now())

        from django_waf.tasks import prune_request_logs

        result = prune_request_logs(days=30)

        assert result["deleted_count"] >= 1
        from django_waf.models import RequestLog

        assert not RequestLog.objects.filter(pk=old_log.pk).exists()
        assert RequestLog.objects.filter(pk=recent_log.pk).exists()

    @pytest.mark.django_db
    def test_returns_zero_when_nothing_to_delete(self):
        """Returns zero deleted_count when all records are within the retention window."""
        RequestLogFactory(timestamp=timezone.now())

        from django_waf.tasks import prune_request_logs

        result = prune_request_logs(days=30)

        assert result["deleted_count"] == 0

    @pytest.mark.django_db
    def test_uses_default_retention_days_from_conf(self):
        """Task uses DJANGO_WAF_LOG_RETENTION_DAYS when days argument is omitted."""
        old_timestamp = timezone.now() - timedelta(days=35)
        RequestLogFactory(timestamp=old_timestamp)

        # DJANGO_WAF_LOG_RETENTION_DAYS defaults to 30 in tests
        from django_waf.tasks import prune_request_logs

        result = prune_request_logs()

        assert result["deleted_count"] >= 1

    @pytest.mark.django_db
    def test_custom_days_parameter_respected(self):
        """Explicit days parameter overrides the setting."""
        five_days_ago = timezone.now() - timedelta(days=5)
        log = RequestLogFactory(timestamp=five_days_ago)

        from django_waf.tasks import prune_request_logs

        # Prune anything older than 3 days — should catch the 5-day-old record
        result = prune_request_logs(days=3)

        assert result["deleted_count"] >= 1
        from django_waf.models import RequestLog

        assert not RequestLog.objects.filter(pk=log.pk).exists()


# ---------------------------------------------------------------------------
# expire_rules
# ---------------------------------------------------------------------------


class TestExpireRules:
    @pytest.mark.django_db
    def test_deactivates_expired_rules(self):
        """BlockRules with expires_at in the past are set to is_active=False."""
        expired_rule = BlockRuleFactory(
            is_active=True,
            expires_at=timezone.now() - timedelta(hours=1),
        )
        active_rule = BlockRuleFactory(
            is_active=True,
            expires_at=timezone.now() + timedelta(hours=24),
        )

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        expired_rule.refresh_from_db()
        active_rule.refresh_from_db()

        assert result["expired_count"] >= 1
        assert expired_rule.is_active is False
        assert active_rule.is_active is True

    @pytest.mark.django_db
    def test_returns_zero_when_no_rules_expired(self):
        """Returns expired_count=0 when no rules have passed their expiry."""
        BlockRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        assert result["expired_count"] == 0

    @pytest.mark.django_db
    def test_invalidates_redis_cache_when_rules_expired(self):
        """Cache invalidation helper is called when at least one rule expires."""
        BlockRuleFactory(
            is_active=True,
            expires_at=timezone.now() - timedelta(minutes=1),
        )

        with patch("django_waf.tasks._invalidate_rule_cache_redis") as mock_inval:
            from django_waf.tasks import expire_rules

            expire_rules()

        mock_inval.assert_called_once()

    @pytest.mark.django_db
    def test_does_not_invalidate_cache_when_nothing_expired(self):
        """Cache invalidation is not triggered when no rules are expired."""
        BlockRuleFactory(is_active=True, expires_at=None)

        with patch("django_waf.tasks._invalidate_rule_cache_redis") as mock_inval:
            from django_waf.tasks import expire_rules

            expire_rules()

        mock_inval.assert_not_called()

    @pytest.mark.django_db
    def test_cache_invalidation_failure_does_not_raise(self):
        """A failure in cache invalidation is swallowed; task still returns normally."""
        BlockRuleFactory(
            is_active=True,
            expires_at=timezone.now() - timedelta(minutes=5),
        )

        with patch("django_waf.tasks._invalidate_rule_cache_redis", side_effect=RuntimeError("redis down")):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        assert result["expired_count"] >= 1

    @pytest.mark.django_db
    def test_rules_without_expiry_are_not_deactivated(self):
        """Rules with expires_at=None are never expired."""
        permanent_rule = BlockRuleFactory(is_active=True, expires_at=None)

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        permanent_rule.refresh_from_db()
        assert permanent_rule.is_active is True
        assert result["expired_count"] == 0


# ---------------------------------------------------------------------------
# update_ip_reputation
# ---------------------------------------------------------------------------


class TestUpdateIpReputation:
    @pytest.mark.django_db
    def test_creates_reputation_for_new_ip(self):
        """A new IPReputation record is created for an IP seen in recent logs."""
        RequestLogFactory(
            ip_address="203.0.113.1",
            timestamp=timezone.now(),
            verdict=Verdict.ALLOWED,
        )

        from django_waf.models import IPReputation
        from django_waf.tasks import update_ip_reputation

        result = update_ip_reputation()

        assert IPReputation.objects.filter(ip_address="203.0.113.1").exists()
        assert result["created_count"] >= 1

    @pytest.mark.django_db
    def test_updates_existing_reputation(self):
        """An existing IPReputation record is updated rather than duplicated."""
        ip = "203.0.113.50"
        IPReputationFactory(ip_address=ip, total_requests=5)
        RequestLogFactory(ip_address=ip, timestamp=timezone.now(), verdict=Verdict.ALLOWED)

        from django_waf.models import IPReputation
        from django_waf.tasks import update_ip_reputation

        result = update_ip_reputation()

        assert IPReputation.objects.filter(ip_address=ip).count() == 1
        assert result["updated_count"] >= 1

    @pytest.mark.django_db
    def test_ignores_logs_outside_24h_window(self):
        """Logs older than 24 hours do not contribute to reputation aggregation."""
        ip = "198.51.100.10"
        RequestLogFactory(
            ip_address=ip,
            timestamp=timezone.now() - timedelta(hours=25),
            verdict=Verdict.ALLOWED,
        )

        from django_waf.models import IPReputation
        from django_waf.tasks import update_ip_reputation

        update_ip_reputation()

        assert not IPReputation.objects.filter(ip_address=ip).exists()

    @pytest.mark.django_db
    def test_threat_score_elevated_for_blocked_ip(self):
        """Threat score is greater than zero for an IP with blocked requests."""
        ip = "203.0.113.99"
        # 10 requests, all blocked
        for _ in range(10):
            RequestLogFactory(ip_address=ip, timestamp=timezone.now(), verdict=Verdict.BLOCKED)

        from django_waf.models import IPReputation
        from django_waf.tasks import update_ip_reputation

        update_ip_reputation()

        rep = IPReputation.objects.get(ip_address=ip)
        assert rep.threat_score > Decimal("0.00")

    @pytest.mark.django_db
    def test_returns_zero_counts_when_no_recent_logs(self):
        """Task returns zero counts when there are no logs within the 24-hour window."""
        from django_waf.tasks import update_ip_reputation

        result = update_ip_reputation()

        assert result == {"updated_count": 0, "created_count": 0}

    @pytest.mark.django_db
    def test_counts_challenge_tokens_for_pass_fail(self):
        """challenge_passes/failures are counted from ChallengeToken records."""
        from django_waf.enums import ChallengeStatus
        from django_waf.models import IPReputation
        from django_waf.tasks import update_ip_reputation
        from django_waf.testing.factories import ChallengeTokenFactory

        ip = "203.0.113.77"
        RequestLogFactory(ip_address=ip, timestamp=timezone.now(), verdict=Verdict.CHALLENGED)
        # Create actual challenge tokens
        for _ in range(5):
            ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.SOLVED)
        for _ in range(3):
            ChallengeTokenFactory(ip_address=ip, status=ChallengeStatus.FAILED)

        update_ip_reputation()

        rep = IPReputation.objects.get(ip_address=ip)
        assert rep.challenge_passes == 5
        assert rep.challenge_failures == 3


# ---------------------------------------------------------------------------
# sync_threat_feed
# ---------------------------------------------------------------------------


class TestSyncThreatFeed:
    def test_skips_when_feed_disabled(self):
        """Task returns early with skipped=True when DJANGO_WAF_FEED_ENABLED=False."""
        # settings.py already sets DJANGO_WAF_FEED_ENABLED=False
        with patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", False):
            from django_waf.tasks import sync_threat_feed

            result = sync_threat_feed()

        assert result == {"skipped": True, "reason": "feed disabled"}

    def test_calls_sync_feed_when_enabled(self):
        """Task calls sync_feed() when the feed is enabled and returns its result."""
        expected = {"created": 5, "updated": 2, "expired": 0, "skipped": 0}

        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch("django_waf.services.threat_feed.sync_feed", return_value=expected) as mock_sync,
        ):
            from django_waf.tasks import sync_threat_feed

            result = sync_threat_feed()

        mock_sync.assert_called_once()
        assert result == expected

    def test_does_not_call_sync_feed_when_disabled(self):
        """sync_feed() is never imported or called when the feed is disabled."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", False),
            patch("django_waf.services.threat_feed.sync_feed") as mock_sync,
        ):
            from django_waf.tasks import sync_threat_feed

            sync_threat_feed()

        mock_sync.assert_not_called()

    def test_propagates_sync_feed_exception(self):
        """Exceptions from sync_feed() are not swallowed by the task."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch("django_waf.services.threat_feed.sync_feed", side_effect=RuntimeError("network error")),
        ):
            from django_waf.tasks import sync_threat_feed

            with pytest.raises(RuntimeError, match="network error"):
                sync_threat_feed()


# ---------------------------------------------------------------------------
# report_threat_telemetry
# ---------------------------------------------------------------------------


class TestReportThreatTelemetry:
    def test_skips_when_reporting_disabled(self):
        """Task returns early with skipped=True when DJANGO_WAF_FEED_REPORT=False."""
        # settings.py already sets DJANGO_WAF_FEED_REPORT=False
        with patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", False):
            from django_waf.tasks import report_threat_telemetry

            result = report_threat_telemetry()

        assert result == {"skipped": True, "reason": "reporting disabled"}

    def test_calls_build_and_submit_when_enabled(self):
        """Task calls build_telemetry_payload() then submit_telemetry() when reporting is on."""
        payload = {"ua_hashes": ["abc", "def"], "subnets": ["10.0.0.0/8"]}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", True),
            patch(
                "django_waf.services.threat_feed.build_telemetry_payload",
                return_value=payload,
            ) as mock_build,
            patch(
                "django_waf.services.threat_feed.submit_telemetry",
                return_value=True,
            ) as mock_submit,
        ):
            from django_waf.tasks import report_threat_telemetry

            result = report_threat_telemetry()

        mock_build.assert_called_once()
        mock_submit.assert_called_once_with(payload)
        assert result == {"submitted": True, "ua_hashes_count": 2, "subnets_count": 1}

    def test_returns_correct_counts_from_payload(self):
        """ua_hashes_count and subnets_count reflect the actual payload lengths."""
        payload = {
            "ua_hashes": ["h1", "h2", "h3"],
            "subnets": ["192.168.0.0/16", "10.0.0.0/8"],
        }
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", True),
            patch("django_waf.services.threat_feed.build_telemetry_payload", return_value=payload),
            patch("django_waf.services.threat_feed.submit_telemetry", return_value=True),
        ):
            from django_waf.tasks import report_threat_telemetry

            result = report_threat_telemetry()

        assert result["ua_hashes_count"] == 3
        assert result["subnets_count"] == 2

    def test_returns_zero_counts_for_empty_payload(self):
        """Task handles an empty payload without error, reporting zero counts."""
        payload: dict = {}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", True),
            patch("django_waf.services.threat_feed.build_telemetry_payload", return_value=payload),
            patch("django_waf.services.threat_feed.submit_telemetry", return_value=False),
        ):
            from django_waf.tasks import report_threat_telemetry

            result = report_threat_telemetry()

        assert result == {"submitted": False, "ua_hashes_count": 0, "subnets_count": 0}

    def test_does_not_call_services_when_disabled(self):
        """Neither build nor submit are called when reporting is disabled."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", False),
            patch("django_waf.services.threat_feed.build_telemetry_payload") as mock_build,
            patch("django_waf.services.threat_feed.submit_telemetry") as mock_submit,
        ):
            from django_waf.tasks import report_threat_telemetry

            report_threat_telemetry()

        mock_build.assert_not_called()
        mock_submit.assert_not_called()

    def test_propagates_submit_exception(self):
        """Exceptions from submit_telemetry() are not swallowed by the task."""
        payload = {"ua_hashes": [], "subnets": []}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_REPORT", True),
            patch("django_waf.services.threat_feed.build_telemetry_payload", return_value=payload),
            patch(
                "django_waf.services.threat_feed.submit_telemetry",
                side_effect=ConnectionError("timeout"),
            ),
        ):
            from django_waf.tasks import report_threat_telemetry

            with pytest.raises(ConnectionError, match="timeout"):
                report_threat_telemetry()


# ---------------------------------------------------------------------------
# update_geoip_database
# ---------------------------------------------------------------------------


class TestUpdateGeoipDatabase:
    """Tests for the ``update_geoip_database`` Celery task."""

    def test_delegates_to_service_with_6_day_freshness(self):
        """The task calls install_geoip_database(if_older_than_days=6)."""
        service_result = {
            "path": "/var/lib/django-waf/GeoLite2-Country.mmdb",
            "size_bytes": 6_291_456,
            "skipped": False,
            "edition": "GeoLite2-Country",
            "build_epoch": 1_700_000_000,
        }
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value=service_result,
        ) as mock_install:
            from django_waf.tasks import update_geoip_database

            result = update_geoip_database()

        mock_install.assert_called_once_with(if_older_than_days=6)
        assert result == service_result

    def test_swallows_geoip_error_and_reports_skipped(self):
        """A GeoIPError is caught and converted into a skipped dict so cron never fails loudly."""
        from django_waf.services.geoip import GeoIPLicenseMissingError

        with patch(
            "django_waf.services.geoip.install_geoip_database",
            side_effect=GeoIPLicenseMissingError("No MaxMind licence key configured."),
        ):
            from django_waf.tasks import update_geoip_database

            result = update_geoip_database()

        assert result["skipped"] is True
        assert "No MaxMind" in result["error"]

    def test_swallows_download_error(self):
        """A transient GeoIPDownloadError is caught and logged as skipped."""
        from django_waf.services.geoip import GeoIPDownloadError

        with patch(
            "django_waf.services.geoip.install_geoip_database",
            side_effect=GeoIPDownloadError("MaxMind download failed: timeout"),
        ):
            from django_waf.tasks import update_geoip_database

            result = update_geoip_database()

        assert result["skipped"] is True
        assert "timeout" in result["error"]

    def test_passes_through_skipped_result_from_service(self):
        """If the service itself returns skipped=True (fresh file), the task returns it verbatim."""
        service_result = {
            "path": "/var/lib/django-waf/GeoLite2-Country.mmdb",
            "size_bytes": 6_291_456,
            "skipped": True,
            "edition": "GeoLite2-Country",
            "build_epoch": None,
        }
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value=service_result,
        ):
            from django_waf.tasks import update_geoip_database

            result = update_geoip_database()

        assert result == service_result
        assert "error" not in result
