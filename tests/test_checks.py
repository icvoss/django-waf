"""Tests for the django_waf Django system checks.

These exist because v0.10.4 shipped with a units mismatch
(``DJANGO_WAF_CHALLENGE_DIFFICULTY`` was counted in bytes while documented in
bits) that made the default unsolvable in a browser and locked legitimate
users out. The check refuses settings that would reproduce that lockout.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import override_settings


@contextmanager
def _setting_absent(name):
    """Temporarily remove a Django setting attribute entirely, restoring it
    (present or absent, whatever it was) on exit.

    ``override_settings`` can only set/replace a value; it cannot delete an
    attribute that a project's settings module already assigned, and
    ``tests/settings.py`` assigns ``DJANGO_WAF_FEED_REPORT`` explicitly. This
    check's whole distinction is "assigned at all", not "assigned to what
    value", so the test needs to make the attribute genuinely absent, not
    merely falsy.
    """
    from django.conf import settings

    had_value = hasattr(settings, name)
    previous = getattr(settings, name, None)
    if had_value:
        delattr(settings, name)
    try:
        yield
    finally:
        if had_value:
            setattr(settings, name, previous)
        elif hasattr(settings, name):
            delattr(settings, name)


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


def _run_trusted_cookie_trust_level_check():
    from django_waf.checks import check_trusted_cookie_trust_level

    return check_trusted_cookie_trust_level(app_configs=None)


def _run_legacy_xff_trust_check():
    from django_waf.checks import check_legacy_xff_trust

    return check_legacy_xff_trust(app_configs=None)


def _run_observe_only_detector_names_check():
    from django_waf.checks import check_observe_only_detector_names

    return check_observe_only_detector_names(app_configs=None)


def _run_detector_wiring_check():
    from django_waf.checks import check_detector_wiring

    return check_detector_wiring(app_configs=None)


def _run_redis_backend_check():
    from django_waf.checks import check_redis_backend

    return check_redis_backend(app_configs=None)


def _run_redis_version_check():
    from django_waf.checks import check_redis_version

    return check_redis_version(app_configs=None)


def _run_site_password_configured_check():
    from django_waf.checks import check_site_password_configured

    return check_site_password_configured(app_configs=None)


def _run_middleware_present_check():
    from django_waf.checks import check_middleware_present

    return check_middleware_present(app_configs=None)


def _run_challenge_urls_resolvable_check():
    from django_waf.checks import check_challenge_urls_resolvable

    return check_challenge_urls_resolvable(app_configs=None)


def _run_env_only_settings_check():
    from django_waf.checks import check_env_only_settings

    return check_env_only_settings(app_configs=None)


def _run_block_response_handler_check():
    from django_waf.checks import check_block_response_handler_importable

    return check_block_response_handler_importable(app_configs=None)


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

    def test_silent_when_waf_disabled(self):
        """#95: the PoW challenge flow never runs when the WAF is switched
        off, so a difficulty misconfiguration behind it is not a live
        lockout. Uses the same over-28 config as
        test_difficulty_over_28_errors, which fires E002 when the WAF is
        enabled: proof this guard, not an unrelated default, is silencing
        it."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 32),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            assert _run_checks() == []


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

    def test_silent_when_waf_disabled(self):
        """#95: no WAF token is ever signed with this key when the master
        switch is off, so an unset key is not a live weakness in that
        state. Uses the same empty-key config as
        test_empty_key_emits_w003_warning, which fires W003 when the WAF
        is enabled."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", ""),
        ):
            assert _run_signing_key_check() == []


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

    def test_suppressed_when_trusted_cookie_feature_enabled(self):
        """#23: with DJANGO_WAF_TRUSTED_COOKIE_ENABLED True, the staff
        bypass no longer depends on middleware order, so W004 must not
        fire even for the exact bad ordering that triggers it above."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django_waf.middleware.WafMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", True),
        ):
            assert _run_middleware_ordering_check() == []

    def test_still_warns_when_feature_off_and_order_wrong(self):
        """Unchanged behaviour when the feature is off (the default)."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django_waf.middleware.WafMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", False),
        ):
            messages = _run_middleware_ordering_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W004"

    def test_silent_when_waf_disabled(self):
        """#95: request.user has nothing to bypass when WafMiddleware never
        evaluates a request in the first place. Uses the same bad ordering
        as test_warns_when_waf_runs_before_auth, which fires W004 when the
        WAF is enabled."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django_waf.middleware.WafMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
        ):
            assert _run_middleware_ordering_check() == []


class TestMiddlewarePresentCheck:
    """django_waf.E006 -- errors when the WAF is enabled but WafMiddleware
    (or a subclass, matched by class name) is absent from MIDDLEWARE
    entirely (#101). Unlike W004, which only warns about ordering once the
    middleware is found, this check is the one that catches it not being
    there at all."""

    def test_present_and_enabled_is_silent(self):
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django_waf.middleware.WafMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
        ):
            assert _run_middleware_present_check() == []

    def test_absent_and_disabled_is_silent(self):
        """A disabled WAF is not expected to carry the middleware at all
        (#95's own gating rationale) -- absence here is not a
        misconfiguration."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
        ):
            assert _run_middleware_present_check() == []

    def test_present_with_engine_off_is_silent(self):
        """The middleware is wired in but the master switch is off: still
        silent, the same disabled-WAF precondition as the fully-absent
        case above, just with the line still present in MIDDLEWARE."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "django_waf.middleware.WafMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
        ):
            assert _run_middleware_present_check() == []

    def test_subclass_matched_by_class_name_is_silent(self):
        """A subclass under a different dotted path is exactly as live as
        the base class -- it must not be flagged as absent."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
            "myproject.middleware.CustomWafMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
        ):
            assert _run_middleware_present_check() == []

    def test_absent_and_enabled_emits_e006_error(self):
        """The #101 blackout class: WafMiddleware genuinely absent
        from MIDDLEWARE while the WAF is switched on. This is the exact
        brickworkui.com production state: installed, enabled, and
        completely inert with manage.py check passing throughout."""
        import django_waf.conf as conf_mod

        middleware = [
            "django.middleware.security.SecurityMiddleware",
            "django.contrib.sessions.middleware.SessionMiddleware",
            "django.contrib.auth.middleware.AuthenticationMiddleware",
        ]

        with (
            override_settings(MIDDLEWARE=middleware),
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
        ):
            messages = _run_middleware_present_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E006"
        assert "MIDDLEWARE" in messages[0].hint


class TestChallengeUrlsResolvableCheck:
    """django_waf.E007 -- errors when the WAF is enabled and can issue a
    challenge, but neither reverse("django_waf:challenge") nor an explicit
    URL override yields a path to send the challenged visitor to (#102).

    Every case here points ROOT_URLCONF at a real module rather than
    building an approximation: ``tests.urls_no_waf`` genuinely omits the
    include (so Django's own resolver raises NoReverseMatch), and
    ``tests.urls`` genuinely carries it.

    ``override_settings`` is used throughout rather than patching
    ``django_waf.conf`` attributes because ROOT_URLCONF must change too, and
    since #75 conf resolves DJANGO_WAF_* names at call time via module-level
    ``__getattr__``, so ``override_settings`` reaches both in one idiom.
    """

    def test_routes_absent_and_waf_enabled_emits_e007_error(self):
        """The #102 deployment shape: WAF on, challenges reachable from the
        default score band, no explicit URL override, django_waf.urls routed
        nowhere. This is the state that served a 500 to a challenged
        visitor before the middleware guard landed."""
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL="",
            DJANGO_WAF_VERIFY_URL="",
        ):
            messages = _run_challenge_urls_resolvable_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E007"
        # Both remedies must be named, in the operator's terms.
        assert "django_waf.urls" in messages[0].hint
        assert "DJANGO_WAF_CHALLENGE_URL" in messages[0].hint
        assert "DJANGO_WAF_VERIFY_URL" in messages[0].hint

    def test_routes_present_and_waf_enabled_is_silent(self):
        """Passing case (a): the ordinary correctly-wired deployment.
        tests/urls.py includes django_waf.urls under the namespace, so both
        routes reverse and there is nothing to report."""
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls",
            DJANGO_WAF_CHALLENGE_URL="",
            DJANGO_WAF_VERIFY_URL="",
        ):
            assert _run_challenge_urls_resolvable_check() == []

    def test_routes_absent_and_waf_disabled_is_silent(self):
        """Passing case (b): with DJANGO_WAF_ENABLED = False the middleware
        returns at BR-EVAL-002 before any verdict is produced, so no
        challenge is ever issued and there is no routing gap to report. The
        #95 gating rationale, and the mistake E004 made before 1.8.1."""
        with override_settings(
            DJANGO_WAF_ENABLED=False,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL="",
            DJANGO_WAF_VERIFY_URL="",
        ):
            assert _run_challenge_urls_resolvable_check() == []

    def test_routes_absent_but_explicit_urls_set_is_silent(self):
        """Passing case (c): _get_challenge_paths is ``setting or
        reverse(...)``, so with both overrides set reverse() is never
        called and the unrouted urlconf is harmless. This is the documented
        escape for per-host and per-request urlconfs, and the reason E007
        can be an Error at all rather than a Warning."""
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL="/custom/challenge/",
            DJANGO_WAF_VERIFY_URL="/custom/verify/",
        ):
            assert _run_challenge_urls_resolvable_check() == []

    def test_routes_absent_but_challenges_not_issuable_is_silent(self):
        """Passing case (d): DJANGO_WAF_ENABLED alone does not imply a
        challenge can be issued. With the challenge score threshold raised
        to the block threshold the band in rule_engine._score_to_verdict is
        empty (a score at or above 7.0 goes straight to BLOCKED, below it to
        LOGGED), and with DJANGO_WAF_CHALLENGE_NO_REFERER off the other
        settings-readable producer is gone too. A WAF run purely for
        blocking and throttling has no challenge to route."""
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL="",
            DJANGO_WAF_VERIFY_URL="",
            DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE=7.0,
            DJANGO_WAF_SCORE_THRESHOLD_BLOCK=7.0,
            DJANGO_WAF_CHALLENGE_NO_REFERER=False,
        ):
            assert _run_challenge_urls_resolvable_check() == []

    def test_no_referer_challenge_alone_keeps_the_check_live(self):
        """The discriminator for case (d): the empty score band is not on
        its own enough to silence the check. With no-referer challenges
        switched on, a CHALLENGED verdict is still reachable
        (rule_engine step 8) and the routing gap is still real, so E007
        must fire. Without this, case (d) would pass against a check that
        keyed on the score band alone and wrongly went quiet for every
        no-referer deployment."""
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL="",
            DJANGO_WAF_VERIFY_URL="",
            DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE=7.0,
            DJANGO_WAF_SCORE_THRESHOLD_BLOCK=7.0,
            DJANGO_WAF_CHALLENGE_NO_REFERER=True,
        ):
            messages = _run_challenge_urls_resolvable_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E007"

    @pytest.mark.parametrize(
        ("challenge_url", "verify_url", "expected_route"),
        [
            ("/custom/challenge/", "", "django_waf:verify"),
            ("", "/custom/verify/", "django_waf:challenge"),
        ],
    )
    def test_only_one_explicit_url_set_still_fires(self, challenge_url, verify_url, expected_route):
        """Setting one override is not an escape, and this is the case where
        E007 matters most while being least visible to the operator.

        ``_get_challenge_paths`` consumes the two settings on separate
        lines, each ``setting or reverse(...)`` in its own right::

            challenge = conf.DJANGO_WAF_CHALLENGE_URL or reverse("django_waf:challenge")
            verify = conf.DJANGO_WAF_VERIFY_URL or reverse("django_waf:verify")

        so they silence ``reverse()`` one route at a time, never as a pair.
        A project that sets only ``DJANGO_WAF_CHALLENGE_URL`` still runs the
        verify line, still calls ``reverse("django_waf:verify")``, and still
        raises ``NoReverseMatch`` on an unrouted urlconf: a 500 before the
        middleware guard landed, a silent fail-open pass-through after it.
        The operator believes they have configured the URLs, so nothing
        else will tell them.

        The message must name only the genuinely unresolvable route, not the
        one already pointed somewhere valid.
        """
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            ROOT_URLCONF="tests.urls_no_waf",
            DJANGO_WAF_CHALLENGE_URL=challenge_url,
            DJANGO_WAF_VERIFY_URL=verify_url,
        ):
            messages = _run_challenge_urls_resolvable_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E007"
        assert expected_route in messages[0].msg
        # The configured route is not reported: it resolves via its own
        # override and reverse() is never attempted for it.
        other_route = "django_waf:challenge" if expected_route == "django_waf:verify" else "django_waf:verify"
        assert other_route not in messages[0].msg


class TestTrustedCookieTrustLevelCheck:
    """W006 warns when DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL is neither
    "staff" nor "authenticated" while the feature is enabled."""

    def test_staff_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "staff"),
        ):
            assert _run_trusted_cookie_trust_level_check() == []

    def test_authenticated_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "authenticated"),
        ):
            assert _run_trusted_cookie_trust_level_check() == []

    def test_invalid_value_emits_w006_warning(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "everyone"),
        ):
            messages = _run_trusted_cookie_trust_level_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W006"
        assert "everyone" in messages[0].msg

    def test_invalid_value_silent_when_feature_disabled(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "everyone"),
        ):
            assert _run_trusted_cookie_trust_level_check() == []


class TestLegacyXffTrustCheck:
    """W007 warns when DJANGO_WAF_TRUST_X_FORWARDED_FOR is enabled with no
    DJANGO_WAF_TRUSTED_PROXIES configured (#42)."""

    def test_disabled_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUST_X_FORWARDED_FOR", False),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_PROXIES", []),
        ):
            assert _run_legacy_xff_trust_check() == []

    def test_enabled_with_trusted_proxies_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUST_X_FORWARDED_FOR", True),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_PROXIES", ["10.0.0.0/8"]),
        ):
            assert _run_legacy_xff_trust_check() == []

    def test_enabled_with_no_trusted_proxies_emits_w007_warning(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUST_X_FORWARDED_FOR", True),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_PROXIES", []),
        ):
            messages = _run_legacy_xff_trust_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W007"

    def test_disabled_with_no_trusted_proxies_is_silent(self):
        """The default combination (both settings at their defaults) must
        not warn: this check only fires when the spoofable legacy path is
        actually reachable."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_TRUST_X_FORWARDED_FOR", False),
            patch.object(conf_mod, "DJANGO_WAF_TRUSTED_PROXIES", []),
        ):
            assert _run_legacy_xff_trust_check() == []


class TestObserveOnlyDetectorNamesCheck:
    """W008 warns when DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS names an
    unrecognised detector (#45)."""

    def test_empty_default_is_silent(self):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", []):
            assert _run_observe_only_detector_names_check() == []

    def test_valid_detector_name_is_silent(self):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", ["detect_cloud_spray"]):
            assert _run_observe_only_detector_names_check() == []

    def test_unknown_detector_name_emits_w008_warning(self):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", ["detect_typo_name"]):
            messages = _run_observe_only_detector_names_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W008"


class TestDetectorWiringCheck:
    """W009 warns when anomaly_detector.DETECTOR_NAMES and
    DETECTOR_NAME_TO_RESULT_KEY disagree on membership (wave 2, #99's
    sibling defect class): a detector hand-added to one dict and not the
    other reads as a permanently silent detector to
    django_waf_probe_detectors and the detector outcome report, rather
    than the wiring bug it actually is.
    """

    def test_current_wiring_is_silent(self):
        """The real, un-patched anomaly_detector module is the baseline
        this check must pass against: if this fails, DETECTOR_NAMES and
        DETECTOR_NAME_TO_RESULT_KEY have genuinely desynced in the
        package, independent of anything this test class patches.
        """
        assert _run_detector_wiring_check() == []

    def test_name_in_detector_names_missing_from_result_key_map_emits_w009(self):
        """The more dangerous direction (see the check's own docstring):
        a name added to DETECTOR_NAMES without a matching entry in
        DETECTOR_NAME_TO_RESULT_KEY reads as a permanently silent detector
        to run_detector_probe, indistinguishable from a genuinely dead one
        without reading the code.
        """
        import django_waf.services.anomaly_detector as anomaly_detector_mod

        broken_names = frozenset(anomaly_detector_mod.DETECTOR_NAMES | {"detect_phantom"})
        with patch.object(anomaly_detector_mod, "DETECTOR_NAMES", broken_names):
            messages = _run_detector_wiring_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W009"
        assert "detect_phantom" in messages[0].msg

    def test_result_key_entry_missing_from_detector_names_emits_w009(self):
        """The reverse direction: a result-key entry with no matching
        DETECTOR_NAMES member is invisible to W008 and observe-only mode
        alike, with nothing else in the package catching it.
        """
        import django_waf.services.anomaly_detector as anomaly_detector_mod

        broken_map = dict(anomaly_detector_mod.DETECTOR_NAME_TO_RESULT_KEY)
        broken_map["detect_phantom"] = "phantom_rules"
        with patch.object(anomaly_detector_mod, "DETECTOR_NAME_TO_RESULT_KEY", broken_map):
            messages = _run_detector_wiring_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W009"
        assert "detect_phantom" in messages[0].msg

    def test_removing_a_name_from_the_result_key_map_also_trips_the_check(self):
        """Confirmed falsifiable the other way too: dropping a real,
        currently-wired name out of DETECTOR_NAME_TO_RESULT_KEY (rather
        than adding a phantom one) reproduces the exact shape a careless
        edit to the map would produce, and the check must still catch it.
        """
        import django_waf.services.anomaly_detector as anomaly_detector_mod

        broken_map = dict(anomaly_detector_mod.DETECTOR_NAME_TO_RESULT_KEY)
        del broken_map["detect_cloud_spray"]
        with patch.object(anomaly_detector_mod, "DETECTOR_NAME_TO_RESULT_KEY", broken_map):
            messages = _run_detector_wiring_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W009"
        assert "detect_cloud_spray" in messages[0].msg


class TestRedisBackendCheck:
    """django_waf.E004: the alias must be a django-redis backend."""

    def test_errors_when_alias_is_not_a_redis_backend(self):
        """The misconfiguration E004 exists to catch (#44)."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=False),
        ):
            messages = _run_redis_backend_check()

        assert any(m.id == "django_waf.E004" for m in messages)

    def test_silent_when_alias_is_a_redis_backend(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
        ):
            assert _run_redis_backend_check() == []

    def test_silent_when_waf_disabled(self):
        """#67: E004 fired as a hard Error regardless of DJANGO_WAF_ENABLED,
        so a settings profile that switches the WAF off and uses LocMemCache
        could not run manage.py check at all. A project not using the feature
        is not misconfigured for it."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=False),
        ):
            assert _run_redis_backend_check() == []


class TestRedisVersionCheck:
    """E005 errors when the connected Redis server reports a version below
    MIN_REDIS_VERSION (currently 6.0, see #78: getdel silently failed on a
    6.0.16 production server for 40,936 task runs with no boot-time signal
    at all)."""

    def test_below_floor_emits_e005_error(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
            patch("django_waf.services.redis_client.get_redis_server_version", return_value=(5, 0, 14)),
        ):
            messages = _run_redis_version_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E005"

    def test_at_or_above_floor_is_silent(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
            patch("django_waf.services.redis_client.get_redis_server_version", return_value=(6, 0, 16)),
        ):
            assert _run_redis_version_check() == []

    def test_silent_when_waf_disabled(self):
        """Guards against repeating #67: E004 fired regardless of
        DJANGO_WAF_ENABLED. E005 must not repeat that mistake."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
            patch("django_waf.services.redis_client.get_redis_server_version", return_value=(5, 0, 0)),
        ):
            assert _run_redis_version_check() == []

    def test_silent_when_alias_is_not_a_redis_backend(self):
        """E004 already covers this misconfiguration; E005 stays quiet
        rather than duplicating it or opening a connection unnecessarily."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=False),
            patch("django_waf.services.redis_client.get_redis_server_version") as mock_version,
        ):
            assert _run_redis_version_check() == []
            mock_version.assert_not_called()

    def test_silent_when_version_cannot_be_read(self):
        """An unreachable server or unparseable INFO response is not this
        check's concern: that is the outage BR-EVAL-007 handles at runtime."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
            patch("django_waf.services.redis_client.get_redis_server_version", return_value=None),
        ):
            assert _run_redis_version_check() == []


class TestEnvOnlySettingsCheck:
    """django_waf.W010: warns when a DJANGO_WAF_* name is present in
    os.environ but has no matching Django setting, so it has no effect
    (issue #106). A real deployment set DJANGO_WAF_FEED_REPORT=True in
    .env, believed reporting was on, and no telemetry was ever sent."""

    def test_env_set_and_setting_absent_emits_w010_warning(self):
        with (
            _setting_absent("DJANGO_WAF_FEED_REPORT"),
            patch.dict(os.environ, {"DJANGO_WAF_FEED_REPORT": "True"}),
        ):
            messages = _run_env_only_settings_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.W010"

    def test_message_names_the_offending_variable(self):
        with (
            _setting_absent("DJANGO_WAF_FEED_REPORT"),
            patch.dict(os.environ, {"DJANGO_WAF_FEED_REPORT": "True"}),
        ):
            messages = _run_env_only_settings_check()

        assert "DJANGO_WAF_FEED_REPORT" in messages[0].msg

    def test_env_set_and_setting_also_set_is_silent(self):
        """The operator has taken the deliberate step of assigning the
        Django setting too, so the environment variable's presence
        alongside it is redundant, not a misconfiguration this check
        should flag."""
        with (
            override_settings(DJANGO_WAF_FEED_REPORT=True),
            patch.dict(os.environ, {"DJANGO_WAF_FEED_REPORT": "True"}),
        ):
            assert _run_env_only_settings_check() == []

    def test_neither_set_is_silent(self):
        with _setting_absent("DJANGO_WAF_FEED_REPORT"), patch.dict(os.environ):
            os.environ.pop("DJANGO_WAF_FEED_REPORT", None)
            assert _run_env_only_settings_check() == []

    def test_env_var_with_no_django_waf_prefix_is_ignored(self):
        """Only names django-waf actually resolves are in scope: an
        unrelated FEED_REPORT-shaped variable with no DJANGO_WAF_ prefix
        is not one of its settings and must not be reported."""
        with patch.dict(os.environ, {"FEED_REPORT": "True"}):
            assert _run_env_only_settings_check() == []

    def test_covers_a_setting_other_than_feed_report(self):
        """Issue #106 asked for every DJANGO_WAF_* name to be covered, not
        only DJANGO_WAF_FEED_REPORT: the same trap applies to any of them.
        DJANGO_WAF_SIGNING_KEY is not set in tests/settings.py, so it is
        already absent without needing _setting_absent."""
        with patch.dict(os.environ, {"DJANGO_WAF_SIGNING_KEY": "some-key"}):
            messages = _run_env_only_settings_check()

        assert any(m.id == "django_waf.W010" and "DJANGO_WAF_SIGNING_KEY" in m.msg for m in messages)


class TestBlockResponseHandlerImportableCheck:
    """django_waf.E008: errors when DJANGO_WAF_BLOCK_RESPONSE_HANDLER is
    set to a dotted path that cannot be imported (#121).

    The teeth test below (``test_non_importerror_on_import_is_still_caught``)
    is the one that matters most: it proves the except clause is broader
    than ``ImportError``, agreeing with the runtime guard in
    ``WafMiddleware._build_block_response``. A check narrower than the
    runtime guard would pass at boot for a handler that fails on every
    blocked request afterwards.
    """

    def test_unresolvable_path_emits_e008_error(self):
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.does_not_exist.handler",
        ):
            messages = _run_block_response_handler_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E008"

    def test_message_names_the_setting_and_the_dotted_path(self):
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.does_not_exist.handler",
        ):
            messages = _run_block_response_handler_check()

        assert "DJANGO_WAF_BLOCK_RESPONSE_HANDLER" in messages[0].msg
        assert "tests.does_not_exist.handler" in messages[0].msg
        assert "403" in messages[0].msg

    def test_resolvable_path_is_silent(self):
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
        ):
            assert _run_block_response_handler_check() == []

    def test_empty_setting_is_silent(self):
        """The default. Not a misconfiguration: it means "use the built-in
        block response"."""
        with override_settings(DJANGO_WAF_ENABLED=True, DJANGO_WAF_BLOCK_RESPONSE_HANDLER=""):
            assert _run_block_response_handler_check() == []

    def test_waf_disabled_is_silent(self):
        """A disabled WAF issues no BLOCKED verdicts, so
        _build_block_response never runs and an unresolvable handler can
        never fire. Same #95 gating rationale as every other check here."""
        with override_settings(
            DJANGO_WAF_ENABLED=False,
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.does_not_exist.handler",
        ):
            assert _run_block_response_handler_check() == []

    def test_non_importerror_on_import_is_still_caught(self):
        """The teeth test. ``tests.block_handler_import_boom`` is a real
        module whose top-level code raises ``ImproperlyConfigured``, not
        ``ImportError``. ``import_string`` propagates whatever the module
        itself raises, so a check written as ``except ImportError`` would
        let this straight through and report ``[]``: a green boot check for
        a handler that fails on every single blocked request afterwards.
        This test fails against that narrower except.
        """
        with override_settings(
            DJANGO_WAF_ENABLED=True,
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.block_handler_import_boom.handler",
        ):
            messages = _run_block_response_handler_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E008"


class TestSitePasswordConfiguredCheck:
    """django_waf.E003: errors when the site-password gate is enabled with
    an empty password (issue #40, BR-SP-002), unless the WAF is disabled
    (#95).

    This check had no test coverage at all before #95: no runner helper,
    no test class. That gap is what let the E003-fires-when-WAF-disabled
    defect survive as long as it did, the same class of gap #92 closed
    for E004.
    """

    def test_enabled_with_password_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD", "correct-horse-battery-staple"),
        ):
            assert _run_site_password_configured_check() == []

    def test_disabled_gate_produces_no_messages(self):
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD", ""),
        ):
            assert _run_site_password_configured_check() == []

    def test_enabled_with_empty_password_emits_e003_error(self):
        """The BR-SP-002 lockout class: the gate fails closed and denies
        every gated request. This is the exact misconfiguration #95 exists
        for; without a WAF-disabled guard, it also fires on a settings
        profile that has switched the WAF off entirely."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD", ""),
        ):
            messages = _run_site_password_configured_check()

        assert len(messages) == 1
        assert messages[0].id == "django_waf.E003"
        assert "DJANGO_WAF_SITE_PASSWORD" in messages[0].hint

    def test_silent_when_waf_disabled(self):
        """#95: the site-password gate is evaluated by WafMiddleware
        (BR-SP-008), so it cannot fail closed on a request the middleware
        never evaluates. Uses the same misconfigured combination as
        test_enabled_with_empty_password_emits_e003_error, which fires
        E003 when the WAF is enabled: proof this guard, not an unrelated
        default, is silencing it. Consumers personal-site and JOBU hit
        this exact combination under LocMemCache."""
        import django_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "DJANGO_WAF_ENABLED", False),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD_ENABLED", True),
            patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD", ""),
        ):
            assert _run_site_password_configured_check() == []


class TestManagePyCheckWithWafDisabled:
    """End-to-end regression for #95: every other test in this module calls
    a check function directly with app_configs=None, patching
    django_waf.conf attributes. That never exercises the registry path
    Django's own ``check`` framework uses, or the behaviour that an Error
    aborts ``manage.py check`` outright (``SystemCheckError``) rather than
    just being returned as a value in a list. Consumers personal-site and
    JOBU hit this exact failure under LocMemCache: DJANGO_WAF_ENABLED=False
    with an empty DJANGO_WAF_SITE_PASSWORD and DJANGO_WAF_SITE_PASSWORD_ENABLED
    left at its True default aborted ``manage.py check`` via E003, and a
    misconfigured DJANGO_WAF_REDIS_ALIAS under a non-Redis test cache did
    the same via E004 before #92.

    tests/conftest.py's pytest_configure sets DJANGO_WAF_ENABLED=True as a
    fallback default (only applied via setattr when the attribute is
    absent), and tests/settings.py sets it True explicitly, so this test
    must override it itself rather than relying on either.

    Uses ``override_settings`` rather than mutating ``django.conf.settings``
    directly: since #75, ``django_waf.conf`` resolves every DJANGO_WAF_* name
    at call time via module-level ``__getattr__``, so ``override_settings``
    reaches it with no reload required. Before #75, conf.py's names were
    plain module constants frozen at first import, so this test predated
    that fix and reload was the only way to force a fresh snapshot; that
    idiom leaked state on manual restore. ``override_settings`` deletes any
    attribute it added and restores any it shadowed, whichever is
    correct, avoiding that leak.
    """

    def test_check_command_completes_with_waf_disabled_and_locmem_cache(self):
        # tests/settings.py's CACHES["default"] is already LocMemCache
        # (never a django-redis backend), and DJANGO_WAF_SITE_PASSWORD is
        # unset there, so DJANGO_WAF_SITE_PASSWORD_ENABLED resolves False
        # by BR-SP-001's own default rule. The only override this test
        # needs is the master switch itself.
        with override_settings(DJANGO_WAF_ENABLED=False):
            # call_command("check") raises SystemCheckError (not a return
            # value) the instant any registered check returns an Error.
            # Before #95's guards, E003 (and, before #92, E004) would
            # raise here on this exact profile; a clean return is the
            # regression assertion.
            call_command("check")

    def test_check_command_aborts_when_site_password_misconfigured_even_disabled_guard_removed(self):
        """Sanity check that this test harness can actually detect the
        SystemCheckError abort this module guards against, so a silent
        assertion-that-never-fails is not hiding a broken test. Exercises
        the registry path with the WAF enabled and the exact BR-SP-002
        misconfiguration, without touching the disabled-WAF guard itself."""
        with (
            override_settings(
                DJANGO_WAF_ENABLED=True,
                DJANGO_WAF_SITE_PASSWORD_ENABLED=True,
                DJANGO_WAF_SITE_PASSWORD="",
            ),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
        ):
            try:
                call_command("check")
            except SystemCheckError as exc:
                assert "django_waf.E003" in str(exc)
            else:
                raise AssertionError("expected SystemCheckError from django_waf.E003")


class TestManagePyCheckWithUnroutedChallengeUrls:
    """End-to-end regression pair for django_waf.E007 (#102), mirroring what
    ``TestManagePyCheckWithWafDisabled`` provides for E003/E004.

    Every other E007 test in this module calls
    ``check_challenge_urls_resolvable`` directly with ``app_configs=None``,
    which never exercises the registry path Django's own ``check`` framework
    uses, nor the behaviour that an Error aborts ``manage.py check``
    outright via ``SystemCheckError`` rather than being returned as a value
    in a list. That distinction is the whole cost of shipping this as an
    Error rather than a Warning, so it is asserted directly.

    Both halves override ``DJANGO_WAF_SITE_PASSWORD_ENABLED = False``
    explicitly and patch ``is_redis_backend`` to True: with the WAF
    enabled, E003's gate and E004's gate are each a second possible source
    of ``SystemCheckError``, so without both the positive half below aborts
    on E004 (tests/settings.py uses LocMemCache, never django-redis) and
    the negative half could pass for the wrong reason. This mirrors what
    ``TestManagePyCheckWithWafDisabled`` does for the same reason.
    """

    def test_check_command_completes_when_challenge_urls_are_routed(self):
        """tests/urls.py includes django_waf.urls under its namespace, which
        is the project default: ``manage.py check`` must complete cleanly
        with the WAF fully enabled. A clean return is the regression
        assertion, since an over-eager E007 would abort here."""
        with (
            override_settings(
                DJANGO_WAF_ENABLED=True,
                ROOT_URLCONF="tests.urls",
                DJANGO_WAF_CHALLENGE_URL="",
                DJANGO_WAF_VERIFY_URL="",
                DJANGO_WAF_SITE_PASSWORD_ENABLED=False,
            ),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
        ):
            call_command("check")

    def test_check_command_aborts_when_challenge_urls_are_unroutable(self):
        """The positive control for the test above, so a silent
        assertion-that-never-fails is not hiding an inert check: the same
        registry path, with django_waf.urls genuinely unrouted, must abort
        with E007 named in the SystemCheckError."""
        with (
            override_settings(
                DJANGO_WAF_ENABLED=True,
                ROOT_URLCONF="tests.urls_no_waf",
                DJANGO_WAF_CHALLENGE_URL="",
                DJANGO_WAF_VERIFY_URL="",
                DJANGO_WAF_SITE_PASSWORD_ENABLED=False,
            ),
            patch("django_waf.services.redis_client.is_redis_backend", return_value=True),
        ):
            try:
                call_command("check")
            except SystemCheckError as exc:
                assert "django_waf.E007" in str(exc)
            else:
                raise AssertionError("expected SystemCheckError from django_waf.E007")
