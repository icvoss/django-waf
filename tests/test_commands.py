"""Tests for icv-waf management commands.

Each command is tested for:
  - ``--dry-run`` mode (should report without side effects)
  - Normal execution (should call the underlying service)
  - Stdout output
  - Argument handling / edge cases
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from icv_waf.testing.factories import RequestLogFactory

# ---------------------------------------------------------------------------
# icv_waf_generate_blocklist
# ---------------------------------------------------------------------------


class TestGenerateBlocklistCommand:
    """Tests for the ``icv_waf_generate_blocklist`` management command."""

    @pytest.mark.django_db
    def test_dry_run_does_not_write_file(self, tmp_path):
        """Dry-run prints the blocklist to stdout and does not create a permanent file."""
        fake_conf = tmp_path / "blocklist.conf"
        fake_conf.write_text("# placeholder\n")

        with patch(
            "icv_waf.services.blocklist_generator.generate_nginx_blocklist",
            return_value=3,
        ) as mock_generate:
            out = StringIO()
            call_command("icv_waf_generate_blocklist", "--dry-run", stdout=out)

        # The service IS called (to populate the temp file), but the permanent
        # output path is not touched.
        mock_generate.assert_called_once()
        output = out.getvalue()
        assert "dry-run" in output
        assert "3 rule(s)" in output

    @pytest.mark.django_db
    def test_normal_run_calls_service_and_reloads_nginx(self, tmp_path):
        """Normal run calls generate_nginx_blocklist and reload_nginx."""
        with (
            patch(
                "icv_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=5,
            ) as mock_generate,
            patch(
                "icv_waf.services.blocklist_generator.reload_nginx",
                return_value=True,
            ) as mock_reload,
        ):
            out = StringIO()
            call_command("icv_waf_generate_blocklist", stdout=out)

        mock_generate.assert_called_once_with(output_path=None)
        mock_reload.assert_called_once()
        output = out.getvalue()
        assert "5 rule(s)" in output
        assert "nginx reloaded" in output

    @pytest.mark.django_db
    def test_normal_run_with_output_path(self, tmp_path):
        """--output-path is forwarded to the service."""
        custom_path = str(tmp_path / "custom.conf")

        with (
            patch(
                "icv_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=1,
            ) as mock_generate,
            patch(
                "icv_waf.services.blocklist_generator.reload_nginx",
                return_value=True,
            ),
        ):
            call_command("icv_waf_generate_blocklist", f"--output-path={custom_path}")

        mock_generate.assert_called_once_with(output_path=custom_path)

    @pytest.mark.django_db
    def test_nginx_reload_failure_shows_warning(self):
        """When nginx reload fails the command emits a warning, not an error."""
        with (
            patch(
                "icv_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=2,
            ),
            patch(
                "icv_waf.services.blocklist_generator.reload_nginx",
                return_value=False,
            ),
        ):
            out = StringIO()
            call_command("icv_waf_generate_blocklist", stdout=out)

        output = out.getvalue()
        assert "reload nginx manually" in output

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        with (
            patch(
                "icv_waf.services.blocklist_generator.generate_nginx_blocklist",
                side_effect=RuntimeError("disk full"),
            ),
            pytest.raises(CommandError, match="Failed to generate blocklist"),
        ):
            call_command("icv_waf_generate_blocklist")


# ---------------------------------------------------------------------------
# icv_waf_detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomaliesCommand:
    """Tests for the ``icv_waf_detect_anomalies`` management command."""

    @pytest.mark.django_db
    def test_dry_run_reports_without_creating_rules(self):
        """Dry-run emits the dry-run notice and displays detector results."""
        results = {"burst_detector": [MagicMock(), MagicMock()], "ua_rotation": []}

        with patch(
            "icv_waf.services.anomaly_detector.run_all_detectors",
            return_value=results,
        ) as mock_detect:
            out = StringIO()
            call_command("icv_waf_detect_anomalies", "--dry-run", stdout=out)

        mock_detect.assert_called_once_with()
        output = out.getvalue()
        assert "dry-run" in output
        assert "would create" in output
        assert "2 rule(s)" in output

    @pytest.mark.django_db
    def test_normal_run_calls_service(self):
        """Normal run calls run_all_detectors and reports created rule counts."""
        results = {"burst_detector": [MagicMock()], "ua_rotation": [MagicMock(), MagicMock()]}

        with patch(
            "icv_waf.services.anomaly_detector.run_all_detectors",
            return_value=results,
        ) as mock_detect:
            out = StringIO()
            call_command("icv_waf_detect_anomalies", stdout=out)

        mock_detect.assert_called_once_with()
        output = out.getvalue()
        assert "created" in output
        assert "3 anomaly rule(s)" in output

    @pytest.mark.django_db
    def test_window_minutes_forwarded_to_service(self):
        """--window-minutes is passed through to run_all_detectors."""
        with patch(
            "icv_waf.services.anomaly_detector.run_all_detectors",
            return_value={},
        ) as mock_detect:
            call_command("icv_waf_detect_anomalies", "--window-minutes=10")

        mock_detect.assert_called_once_with(window_minutes=10)

    @pytest.mark.django_db
    def test_no_anomalies_detected_message(self):
        """When no anomalies are detected the success message is shown."""
        with patch(
            "icv_waf.services.anomaly_detector.run_all_detectors",
            return_value={"burst_detector": [], "ua_rotation": []},
        ):
            out = StringIO()
            call_command("icv_waf_detect_anomalies", stdout=out)

        assert "No anomalies detected" in out.getvalue()

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        with (
            patch(
                "icv_waf.services.anomaly_detector.run_all_detectors",
                side_effect=ValueError("bad window"),
            ),
            pytest.raises(CommandError, match="Anomaly detection failed"),
        ):
            call_command("icv_waf_detect_anomalies")

    @pytest.mark.django_db
    def test_dry_run_with_window_minutes(self):
        """Dry-run correctly forwards --window-minutes."""
        with patch(
            "icv_waf.services.anomaly_detector.run_all_detectors",
            return_value={"ua_rotation": [MagicMock()]},
        ) as mock_detect:
            out = StringIO()
            call_command("icv_waf_detect_anomalies", "--dry-run", "--window-minutes=20", stdout=out)

        mock_detect.assert_called_once_with(window_minutes=20)
        assert "dry-run" in out.getvalue()


# ---------------------------------------------------------------------------
# icv_waf_prune_logs
# ---------------------------------------------------------------------------


class TestPruneLogsCommand:
    """Tests for the ``icv_waf_prune_logs`` management command."""

    @pytest.mark.django_db
    def test_dry_run_counts_without_deleting(self):
        """Dry-run reports stale record count and does not delete anything."""
        cutoff = timezone.now() - timezone.timedelta(days=31)
        # Create 3 old logs and 1 recent log.
        for _ in range(3):
            RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))
        RequestLogFactory()  # recent — should not be counted

        out = StringIO()
        call_command("icv_waf_prune_logs", "--dry-run", "--days=30", stdout=out)

        from icv_waf.models import RequestLog

        # Nothing should have been deleted.
        assert RequestLog.objects.count() == 4
        output = out.getvalue()
        assert "dry-run" in output
        assert "3 log record(s)" in output

    @pytest.mark.django_db
    def test_normal_run_deletes_old_records(self):
        """Normal run deletes records older than the retention window."""
        cutoff = timezone.now() - timezone.timedelta(days=31)
        for _ in range(2):
            RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))
        RequestLogFactory()  # recent — must survive

        from icv_waf.models import RequestLog

        out = StringIO()
        call_command("icv_waf_prune_logs", "--days=30", stdout=out)

        assert RequestLog.objects.count() == 1
        output = out.getvalue()
        assert "Deleted 2 log record(s)" in output

    @pytest.mark.django_db
    def test_days_argument_overrides_default(self):
        """--days overrides the configured retention period."""
        cutoff = timezone.now() - timezone.timedelta(days=8)
        RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))

        from icv_waf.models import RequestLog

        call_command("icv_waf_prune_logs", "--days=7")
        assert RequestLog.objects.count() == 0

    @pytest.mark.django_db
    def test_zero_days_raises_command_error(self):
        """--days=0 is rejected with a CommandError."""
        with pytest.raises(CommandError, match="positive integer"):
            call_command("icv_waf_prune_logs", "--days=0")

    @pytest.mark.django_db
    def test_no_old_records_reports_zero_deleted(self):
        """When there are no stale records the command reports zero deletions."""
        RequestLogFactory()  # recent only

        out = StringIO()
        call_command("icv_waf_prune_logs", "--days=30", stdout=out)

        assert "Deleted 0 log record(s)" in out.getvalue()

    @pytest.mark.django_db
    def test_default_retention_uses_conf_value(self):
        """When --days is omitted the command reads ICV_WAF_LOG_RETENTION_DAYS from conf."""
        from icv_waf import conf

        default_days = conf.ICV_WAF_LOG_RETENTION_DAYS
        cutoff = timezone.now() - timezone.timedelta(days=default_days + 1)
        RequestLogFactory(timestamp=cutoff)

        from icv_waf.models import RequestLog

        call_command("icv_waf_prune_logs")
        assert RequestLog.objects.count() == 0


# ---------------------------------------------------------------------------
# icv_waf_sync_feed
# ---------------------------------------------------------------------------


class TestSyncFeedCommand:
    """Tests for the ``icv_waf_sync_feed`` management command."""

    @pytest.mark.django_db
    def test_skips_when_feed_disabled_and_no_url(self):
        """Command exits early with a warning when feed is disabled and no URL given."""
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", False),
            patch("icv_waf.services.threat_feed.sync_feed") as mock_sync,
        ):
            out = StringIO()
            call_command("icv_waf_sync_feed", stdout=out)

        mock_sync.assert_not_called()
        assert "Skipping sync" in out.getvalue()

    @pytest.mark.django_db
    def test_dry_run_emits_notice(self):
        """Dry-run prints the notice before calling the service."""
        summary = {"created": 0, "updated": 0, "expired": 0, "skipped": 0}
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", True),
            patch("icv_waf.services.threat_feed.sync_feed", return_value=summary),
        ):
            out = StringIO()
            call_command("icv_waf_sync_feed", "--dry-run", stdout=out)

        assert "dry-run" in out.getvalue()

    @pytest.mark.django_db
    def test_normal_run_calls_sync_feed(self):
        """Normal run calls sync_feed and reports the summary."""
        summary = {"created": 4, "updated": 1, "expired": 2, "skipped": 3}
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", True),
            patch("icv_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            out = StringIO()
            call_command("icv_waf_sync_feed", stdout=out)

        mock_sync.assert_called_once_with(feed_url=None, min_confidence=None)
        output = out.getvalue()
        assert "4 created" in output
        assert "1 updated" in output
        assert "2 expired" in output
        assert "3 skipped" in output

    @pytest.mark.django_db
    def test_feed_url_override_bypasses_disabled_check(self):
        """Passing --feed-url overrides the feed-disabled guard and calls the service."""
        summary = {"created": 1, "updated": 0, "expired": 0, "skipped": 0}
        # Feed disabled at conf level — but --feed-url should bypass the guard.
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", False),
            patch("icv_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            out = StringIO()
            call_command(
                "icv_waf_sync_feed",
                "--feed-url=https://example.com/feed.json",
                stdout=out,
            )

        mock_sync.assert_called_once_with(
            feed_url="https://example.com/feed.json",
            min_confidence=None,
        )
        assert "Feed sync complete" in out.getvalue()

    @pytest.mark.django_db
    def test_min_confidence_forwarded_to_service(self):
        """--min-confidence is forwarded to sync_feed."""
        summary = {"created": 0, "updated": 0, "expired": 0, "skipped": 10}
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", True),
            patch("icv_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            call_command("icv_waf_sync_feed", "--min-confidence=0.9")

        mock_sync.assert_called_once_with(feed_url=None, min_confidence=0.9)

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", True),
            patch(
                "icv_waf.services.threat_feed.sync_feed",
                side_effect=ConnectionError("timeout"),
            ),
            pytest.raises(CommandError, match="Feed sync failed"),
        ):
            call_command("icv_waf_sync_feed")

    @pytest.mark.django_db
    def test_partial_summary_keys_default_to_zero(self):
        """A summary dict with missing keys defaults missing counts to zero without error."""
        with (
            patch("icv_waf.conf.ICV_WAF_FEED_ENABLED", True),
            patch(
                "icv_waf.services.threat_feed.sync_feed",
                return_value={"created": 2},
            ),
        ):
            out = StringIO()
            call_command("icv_waf_sync_feed", stdout=out)

        output = out.getvalue()
        assert "2 created" in output
        assert "0 updated" in output
        assert "0 expired" in output
        assert "0 skipped" in output
