"""Tests for django_waf.conf default values and call-time resolution (#75).

Focused on settings whose defaults carry operational meaning (the threat-feed
URLs point at a real operated server; telemetry stays opt-in) rather than
exhaustively re-asserting every setting in the module.
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.conf import LazySettings
from django.test import override_settings

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


class TestCallTimeResolution:
    """Every DJANGO_WAF_* name resolves live against django.conf.settings (#75).

    Regression: before this fix, every setting was a module-level constant
    computed once, at conf.py's first import, from ``getattr(settings, ...)``.
    ``override_settings`` and the pytest ``settings`` fixture both mutate
    ``django.conf.settings`` without reloading ``django_waf.conf``, so
    neither had any effect on a value already frozen at import time. These
    tests are written to fail against that old behaviour: each one asserts
    an override takes effect with no reload anywhere in the test body.
    """

    def test_override_settings_takes_effect_without_reload(self):
        before = conf_mod.DJANGO_WAF_LOG_SAMPLE_RATE
        with override_settings(DJANGO_WAF_LOG_SAMPLE_RATE=0.5):
            assert conf_mod.DJANGO_WAF_LOG_SAMPLE_RATE == 0.5
        assert before == conf_mod.DJANGO_WAF_LOG_SAMPLE_RATE

    def test_pytest_settings_fixture_takes_effect_without_reload(self, settings):
        settings.DJANGO_WAF_LOG_SAMPLE_RATE = 0.75
        assert conf_mod.DJANGO_WAF_LOG_SAMPLE_RATE == 0.75

    def test_redis_alias_resolves_live(self, settings):
        """The reported production defect: conf.DJANGO_WAF_REDIS_ALIAS must
        track settings.DJANGO_WAF_REDIS_ALIAS, not the alias frozen at
        whatever moment conf.py first imported.
        """
        assert conf_mod.DJANGO_WAF_REDIS_ALIAS == "default"
        settings.DJANGO_WAF_REDIS_ALIAS = "waf"
        assert conf_mod.DJANGO_WAF_REDIS_ALIAS == "waf"

    def test_patch_object_round_trips_through_the_resolver(self, settings):
        """mock.patch.object(conf_mod, ...) still works exactly as it would
        against a plain module attribute (HAZARD 1): entering the patch
        shadows the resolver, exiting restores live resolution rather than
        permanently freezing the patched value. This is the guard against a
        module-level ``def __getattr__`` that only round-trips today because
        the reload-on-teardown fixture masked the alternative: this test
        proves the resolver is genuinely consulted again after the patch
        exits, not merely that no exception was raised.
        """
        settings.DJANGO_WAF_ENABLED = "live-value-one"
        assert conf_mod.DJANGO_WAF_ENABLED == "live-value-one"

        with mock.patch.object(conf_mod, "DJANGO_WAF_ENABLED", "patched-value"):
            assert conf_mod.DJANGO_WAF_ENABLED == "patched-value"

        # Proves the resolver is consulted again, not that a stale __dict__
        # entry happens to match: change the live setting and confirm the
        # NEW value is seen, which a permanently shadowed name could not do.
        assert conf_mod.DJANGO_WAF_ENABLED == "live-value-one"
        settings.DJANGO_WAF_ENABLED = "live-value-two"
        assert conf_mod.DJANGO_WAF_ENABLED == "live-value-two"

    def test_dir_includes_setting_names(self):
        """__dir__ (PEP 562) so dir() and tab-completion still see the
        settings names, since they are no longer plain module attributes.
        """
        names = dir(conf_mod)
        assert "DJANGO_WAF_ENABLED" in names
        assert "DJANGO_WAF_SITE_PASSWORD_ENABLED" in names

    def test_unknown_name_raises_attribute_error(self):
        with pytest.raises(AttributeError):
            _ = conf_mod.DJANGO_WAF_NOT_A_REAL_SETTING


class TestSitePasswordEnabledDerivation:
    """DJANGO_WAF_SITE_PASSWORD_ENABLED recurses through the resolver for
    DJANGO_WAF_SITE_PASSWORD (HAZARD 2), the one intra-conf cross-reference
    among all 92 settings. BR-SP-001/BR-SP-002 (docs/specs/django-waf/
    02-business-rules.md) require this default to reflect the CURRENT
    password setting, not a value frozen at import time, since BR-SP-002's
    fail-closed guarantee (gate enabled, no password, deny every request)
    depends on the derived default seeing a password that is cleared or set
    after conf.py first imported.
    """

    def test_defaults_false_when_no_password_is_set(self, settings):
        settings.DJANGO_WAF_SITE_PASSWORD = ""
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is False

    def test_defaults_true_once_a_password_is_set_after_import(self, settings):
        """The fail-open direction: setting a password after conf.py's
        import must be enough on its own to flip the derived default, with
        no explicit DJANGO_WAF_SITE_PASSWORD_ENABLED override.
        """
        settings.DJANGO_WAF_SITE_PASSWORD = "hunter2"
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is True

    def test_reverts_to_false_when_the_password_is_cleared(self, settings):
        """The fail-closed direction: clearing the password after it was
        set must revert the derived default, not leave it stuck True from
        an earlier resolution.
        """
        settings.DJANGO_WAF_SITE_PASSWORD = "hunter2"
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is True
        settings.DJANGO_WAF_SITE_PASSWORD = ""
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is False

    def test_explicit_override_wins_over_the_derived_default(self, settings):
        """An explicit DJANGO_WAF_SITE_PASSWORD_ENABLED setting still takes
        priority over the derived default, in both directions.
        """
        settings.DJANGO_WAF_SITE_PASSWORD = "hunter2"
        settings.DJANGO_WAF_SITE_PASSWORD_ENABLED = False
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is False

        settings.DJANGO_WAF_SITE_PASSWORD = ""
        settings.DJANGO_WAF_SITE_PASSWORD_ENABLED = True
        assert conf_mod.DJANGO_WAF_SITE_PASSWORD_ENABLED is True


class TestUnconfiguredSettingsContract:
    """Every DJANGO_WAF_* name resolves to its documented default, never
    raising ImproperlyConfigured, when django.conf.settings is not yet
    configured (#75, hazard 3).

    This is what the README's documented consumer pattern relies on::

        from django_waf.conf import DJANGO_WAF_CELERY_BEAT_SCHEDULE

    executed from inside a consumer's own settings module, before that
    settings module has finished running ``settings.configure()`` /
    ``DJANGO_SETTINGS_MODULE`` resolution. A lazy resolver that unconditionally
    called ``getattr(django.conf.settings, name, default)`` would raise
    ImproperlyConfigured there, turning today's silent import-time-snapshot
    defect into a hard boot failure for anyone following the documented API.

    Honesty note: this test suite runs under pytest-django, which configures
    Django settings once for the whole session, so genuinely un-configuring
    settings mid-suite is not possible without corrupting every other test.
    Instead this patches ``django.conf.LazySettings.configured`` (the real
    property django_waf.conf._get_setting reads) to report ``False`` for the
    duration of the block, which exercises the exact branch
    ``_get_setting`` takes when settings truly are unconfigured, without
    touching ``settings._wrapped`` or any other test's configured state.
    """

    def test_celery_beat_schedule_resolves_to_default_when_unconfigured(self):
        with mock.patch.object(LazySettings, "configured", new_callable=mock.PropertyMock, return_value=False):
            schedule = conf_mod.DJANGO_WAF_CELERY_BEAT_SCHEDULE
        assert "django-waf-generate-blocklist" in schedule
        assert schedule["django-waf-generate-blocklist"]["task"] == "django_waf.tasks.generate_blocklist"

    def test_a_plain_setting_resolves_to_its_default_when_unconfigured(self):
        with mock.patch.object(LazySettings, "configured", new_callable=mock.PropertyMock, return_value=False):
            assert conf_mod.DJANGO_WAF_ENABLED is True

    def test_resolving_while_unconfigured_does_not_touch_settings_at_all(self):
        """A regression against a resolver that reads settings.configured
        but then falls through to getattr(settings, ...) anyway: that would
        still work by accident here (pytest-django keeps settings genuinely
        configured underneath the patch), so this additionally proves
        _get_setting takes the early-return branch by confirming its
        result is the literal default object even when the live settings
        value has been overridden to something else entirely.
        """
        with (
            override_settings(DJANGO_WAF_ENABLED=False),
            mock.patch.object(LazySettings, "configured", new_callable=mock.PropertyMock, return_value=False),
        ):
            # settings.DJANGO_WAF_ENABLED is False here, but _get_setting
            # must never reach it once settings.configured reports False.
            assert conf_mod.DJANGO_WAF_ENABLED is True
