"""Tests for the django_waf Django system checks.

These exist because v0.10.4 shipped with a units mismatch
(``DJANGO_WAF_CHALLENGE_DIFFICULTY`` was counted in bytes while documented in
bits) that made the default unsolvable in a browser and locked legitimate
users out. The check refuses settings that would reproduce that lockout.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import override_settings


def _run_checks():
    from django_waf.checks import check_challenge_difficulty

    return check_challenge_difficulty(app_configs=None)


def _run_middleware_ordering_check():
    from django_waf.checks import check_middleware_ordering

    return check_middleware_ordering(app_configs=None)


def _run_signing_key_check():
    from django_waf.checks import check_signing_key

    return check_signing_key(app_configs=None)


def _run_feed_url_scheme_check():
    from django_waf.checks import check_feed_url_scheme

    return check_feed_url_scheme(app_configs=None)


class TestChallengeDifficultyCheck:
    def test_recommended_defaults_produce_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            assert _run_checks() == []

    def test_difficulty_over_28_errors(self):
        """The v0.10.4 lockout class — refuse to start with this config."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 32),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "django_waf.E002" for m in messages)

    def test_difficulty_over_24_warns(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 26),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "django_waf.W001" for m in messages)

    def test_difficulty_under_8_warns(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 4),
        ):
            messages = _run_checks()

        assert any(m.id == "django_waf.W002" for m in messages)

    def test_none_allowed_for_device_keys(self):
        """Desktop/mobile = None means 'use the fallback' and must not warn."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", None),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", None),
        ):
            assert _run_checks() == []

    def test_negative_is_error(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", -1),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "django_waf.E001" for m in messages)


class TestSigningKeyCheck:
    """W003 — warns when DJANGO_WAF_SIGNING_KEY is unset.

    Falling back to a SECRET_KEY-derived value is supported (and is
    what makes v0.10.x → v0.11.0 upgrades seamless) but it ties WAF
    signature rotation to Django's session secret. The check nudges
    operators toward an explicit dedicated key.
    """

    def test_explicit_key_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "an-explicit-key-value"):
            assert _run_signing_key_check() == []

    def test_empty_key_emits_w003_warning(self):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", ""):
            messages = _run_signing_key_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W003"
        # The hint must tell operators how to fix it — pin the actionable
        # part of the message so future edits don't lose the remediation.
        assert "secrets.token_urlsafe" in messages[0].hint
        assert "DJANGO_WAF_SIGNING_KEY" in messages[0].hint


class TestFeedUrlSchemeCheck:
    """W005 — warns when the threat feed is enabled but not served over HTTPS.

    Feed responses become BlockRules, so a plaintext feed lets an on-path
    attacker inject or suppress rules. The check inspects only the URL
    scheme; it never issues a live request.
    """

    def test_https_feed_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_FEED_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_FEED_URL", "https://threats.drystane.com/v1/feed.json"),
        ):
            assert _run_feed_url_scheme_check() == []

    def test_non_https_feed_emits_w005_warning(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_FEED_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_FEED_URL", "http://threats.drystane.com/v1/feed.json"),
        ):
            messages = _run_feed_url_scheme_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W005"
        # The hint must offer both remediations — switch to https or disable.
        assert "https://" in messages[0].hint
        assert "DJANGO_WAF_FEED_ENABLED" in messages[0].hint

    def test_disabled_feed_skips_scheme_check(self):
        """A non-HTTPS URL is harmless when the feed is off — no warning."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_FEED_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_FEED_URL", "http://threats.drystane.com/v1/feed.json"),
        ):
            assert _run_feed_url_scheme_check() == []


class TestMiddlewareOrderingCheck:
    """W004 — warns when WafMiddleware runs before AuthenticationMiddleware.

    request.user is not available until AuthenticationMiddleware has run,
    so a WAF that evaluates the request first can never see the staff
    bypass, silently blocking/challenging staff and superuser accounts.
    """

    def test_warns_when_waf_runs_before_auth(self):
        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django_waf.middleware.WafMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with override_settings(MIDDLEWARE=middleware):
            messages = _run_middleware_ordering_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W004"
        assert "AuthenticationMiddleware" in messages[0].hint

    def test_passes_when_waf_runs_after_auth(self):
        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django_waf.middleware.WafMiddleware",
        ]

        with override_settings(MIDDLEWARE=middleware):
            assert _run_middleware_ordering_check() == []

    def test_passes_when_waf_middleware_absent(self):
        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with override_settings(MIDDLEWARE=middleware):
            assert _run_middleware_ordering_check() == []

    def test_warns_when_auth_middleware_missing_entirely(self):
        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django_waf.middleware.WafMiddleware",
        ]

        with override_settings(MIDDLEWARE=middleware):
            messages = _run_middleware_ordering_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W004"
