"""Tests for django_waf.conf default values.

Focused on settings whose defaults carry operational meaning (the threat-feed
URLs point at a real operated server; telemetry stays opt-in) rather than
exhaustively re-asserting every setting in the module.
"""

from __future__ import annotations

import django_waf.conf as conf_mod


class TestThreatFeedDefaults:
    """DJANGO_WAF_FEED_* defaults point at the operated feed server.

    Regression: pre-1.1.1 the defaults were ``threats.icv.dev``, a spec
    placeholder that never resolved to an operated service (docs/specs/
    django-waf/06-threat-feed-api.md, section 1). Repointed to the real
    server, threats.drystane.com, so a consuming site only needs to flip
    DJANGO_WAF_FEED_REPORT to start reporting.
    """

    def test_feed_url_default_points_at_drystane(self):
        assert conf_mod.DJANGO_WAF_FEED_URL == "https://threats.drystane.com/v1/feed.json"

    def test_feed_report_url_default_points_at_drystane(self):
        assert conf_mod.DJANGO_WAF_FEED_REPORT_URL == "https://threats.drystane.com/v1/report"

    def test_feed_url_default_is_not_the_retired_icv_dev_placeholder(self):
        assert "threats.icv.dev" not in conf_mod.DJANGO_WAF_FEED_URL

    def test_feed_report_url_default_is_not_the_retired_icv_dev_placeholder(self):
        assert "threats.icv.dev" not in conf_mod.DJANGO_WAF_FEED_REPORT_URL

    def test_feed_report_still_defaults_false(self):
        """Telemetry stays opt-in regardless of the URL repoint (ADR-021 point 4)."""
        assert conf_mod.DJANGO_WAF_FEED_REPORT is False


class TestCeleryBeatScheduleDefault:
    """DJANGO_WAF_CELERY_BEAT_SCHEDULE covers every periodic task.

    celery is present in this dev environment, so both the interval
    entries (plain second counts) and the crontab entries are expected.
    """

    def test_contains_an_entry_for_every_periodic_task(self):
        expected_tasks = {
            "django_waf.tasks.generate_blocklist",
            "django_waf.tasks.flush_rule_hit_counts",
            "django_waf.tasks.detect_anomalies",
            "django_waf.tasks.parse_access_log",
            "django_waf.tasks.expire_rules",
            "django_waf.tasks.update_ip_reputation",
            "django_waf.tasks.prune_request_logs",
            "django_waf.tasks.prune_challenge_tokens",
            "django_waf.tasks.sync_threat_feed",
            "django_waf.tasks.report_threat_telemetry",
            "django_waf.tasks.update_geoip_database",
        }
        actual_tasks = {entry["task"] for entry in conf_mod.DJANGO_WAF_CELERY_BEAT_SCHEDULE.values()}
        assert actual_tasks == expected_tasks

    def test_interval_entries_use_plain_second_counts(self):
        entry = conf_mod.DJANGO_WAF_CELERY_BEAT_SCHEDULE["django-waf-generate-blocklist"]
        assert entry["schedule"] == 300.0

    def test_module_is_importable_without_celery(self):
        """conf.py must stay importable even when celery is entirely absent.

        Simulates celery being unavailable by reloading conf with the
        celery.schedules import forced to fail, then restores the real
        module so later tests are unaffected.
        """
        import builtins
        import importlib
        import sys

        real_import = builtins.__import__

        def _blocking_import(name, *args, **kwargs):
            if name == "celery.schedules" or name.startswith("celery.schedules."):
                raise ImportError("celery not installed")
            return real_import(name, *args, **kwargs)

        builtins.__import__ = _blocking_import
        try:
            reloaded = importlib.reload(conf_mod)
            assert reloaded.crontab is None
            # The cron-time entries are omitted; interval entries remain.
            assert "django-waf-prune-request-logs" not in reloaded.DJANGO_WAF_CELERY_BEAT_SCHEDULE
            assert "django-waf-generate-blocklist" in reloaded.DJANGO_WAF_CELERY_BEAT_SCHEDULE
        finally:
            builtins.__import__ = real_import
            importlib.reload(conf_mod)
            sys.modules["django_waf.conf"] = conf_mod
