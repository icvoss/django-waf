"""Tests for the site password gate (django_waf.services.site_password_service,
WafMiddleware._check_site_password, and SitePasswordVerifyView).

See docs/specs/site-password/PRD.md for the BR-SP rules and acceptance
criteria this file covers.

Uses Django's test Client (real DB) for the integration-level gate
behaviour. The verified flag is the gate's own signed cookie
(django_waf.services.site_password_service.SITE_PASSWORD_COOKIE), not
Django's session -- WafMiddleware is documented to run before
SessionMiddleware, so the gate must not depend on request.session (see
TestNoSessionMiddlewareRegression below, which reproduces the shipped
defect with SessionMiddleware removed from the stack entirely). Unit-level
checks on the service module use direct calls with patched conf
attributes, mirroring tests/test_services.py's TestCheckRateLimit pattern
(django_waf.conf reads values at call time from a local import, so
patch.object works without importlib.reload).

By default DJANGO_WAF_SITE_PASSWORD is unset in tests/settings.py, so the
gate is off unless a test explicitly enables it via override_settings +
patch.object(conf_mod, ...).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.test import Client, RequestFactory, override_settings

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_gate(password="correct-horse", **extra):
    """Context manager patching django_waf.conf so the gate is on.

    Returns the patch.multiple context manager; use as:
        with _enable_gate():
            ...
    """
    import django_waf.conf as conf_mod

    defaults = {
        "DJANGO_WAF_SITE_PASSWORD": password,
        "DJANGO_WAF_SITE_PASSWORD_ENABLED": True,
        "DJANGO_WAF_SITE_PASSWORD_TTL": 43200,
        "DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS": [
            "/health/",
            "/.well-known/",
            "/robots.txt",
            "/waf/challenge/",
            "/waf/verify/",
        ],
        "DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH": "/waf/site-password/",
    }
    defaults.update(extra)
    return patch.multiple(conf_mod, **defaults)


def _mock_redis():
    redis = MagicMock()
    pipeline = MagicMock()
    pipeline.execute.return_value = [1, 0, 1, True]  # low count, never throttled by default
    redis.pipeline.return_value = pipeline
    return redis


# ---------------------------------------------------------------------------
# BR-SP-001: gate off by default -- regression guard
# ---------------------------------------------------------------------------


class TestGateOffByDefault:
    """With DJANGO_WAF_SITE_PASSWORD unset, every request proceeds unchanged."""

    def test_root_path_returns_200_when_gate_unset(self):
        client = Client()
        response = client.get("/")
        assert response.status_code == 200

    def test_waf_challenge_path_unaffected_when_gate_unset(self, settings):
        settings.ROOT_URLCONF = "tests.urls"
        with (
            patch("django_waf.views._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            token = MagicMock()
            token.token = "tok"
            token.difficulty = 10
            mock_issue.return_value = token

            client = Client()
            response = client.get("/waf/challenge/")

        assert response.status_code == 200

    def test_no_site_password_prompt_rendered_when_gate_unset(self):
        client = Client()
        response = client.get("/")
        assert b"password protected" not in response.content


# ---------------------------------------------------------------------------
# BR-SP-002: fail-closed on misconfiguration
# ---------------------------------------------------------------------------


class TestFailClosedMisconfiguration:
    """Enabled with an empty password denies every gated request."""

    def test_empty_password_denies_request(self):
        with _enable_gate(password=""):
            client = Client()
            response = client.get("/")

        assert response.status_code == 401

    def test_empty_password_never_falls_through_to_open(self):
        """A misconfigured gate must not behave like 'gate off'."""
        with _enable_gate(password=""):
            client = Client()
            response = client.get("/")

        assert b"OK" not in response.content

    def test_system_check_warns_on_empty_password(self):
        import django_waf.conf as conf_mod
        from django_waf.checks import check_site_password_configured

        with patch.multiple(
            conf_mod,
            DJANGO_WAF_SITE_PASSWORD_ENABLED=True,
            DJANGO_WAF_SITE_PASSWORD="",
        ):
            messages = check_site_password_configured(app_configs=None)

        assert any(m.id == "django_waf.E003" for m in messages)

    def test_system_check_silent_when_password_set(self):
        import django_waf.conf as conf_mod
        from django_waf.checks import check_site_password_configured

        with patch.multiple(
            conf_mod,
            DJANGO_WAF_SITE_PASSWORD_ENABLED=True,
            DJANGO_WAF_SITE_PASSWORD="s3cret",
        ):
            messages = check_site_password_configured(app_configs=None)

        assert messages == []

    def test_system_check_silent_when_gate_disabled(self):
        import django_waf.conf as conf_mod
        from django_waf.checks import check_site_password_configured

        with patch.multiple(
            conf_mod,
            DJANGO_WAF_SITE_PASSWORD_ENABLED=False,
            DJANGO_WAF_SITE_PASSWORD="",
        ):
            messages = check_site_password_configured(app_configs=None)

        assert messages == []


# ---------------------------------------------------------------------------
# BR-SP-003 / AC: un-verified request gets the prompt, not the app
# ---------------------------------------------------------------------------


class TestUnverifiedRequestGetsPrompt:
    def test_non_exempt_path_returns_401(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")

        assert response.status_code == 401

    def test_prompt_is_not_the_app_response(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")

        assert b"OK" not in response.content
        assert b"password" in response.content.lower()

    def test_prompt_uses_site_password_template(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")

        assert "django_waf/site_password.html" in [t.name for t in response.templates]

    def test_prompt_preserves_next_as_current_path(self):
        with _enable_gate():
            client = Client()
            response = client.get("/some/deep/path/")

        assert response.status_code == 401
        assert b"/some/deep/path/" in response.content


# ---------------------------------------------------------------------------
# BR-SP-006: prompt is 401 and noindex
# ---------------------------------------------------------------------------


class TestPromptIsNoindex401:
    def test_status_is_401(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")
        assert response.status_code == 401

    def test_x_robots_tag_header_present(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")
        assert response["X-Robots-Tag"] == "noindex, nofollow, noarchive"

    def test_meta_robots_tag_in_body(self):
        with _enable_gate():
            client = Client()
            response = client.get("/")
        assert b'name="robots" content="noindex, nofollow, noarchive"' in response.content


# ---------------------------------------------------------------------------
# BR-SP-004: correct password sets the cookie and lets verified visitors through
# ---------------------------------------------------------------------------


class TestCorrectPasswordVerifies:
    def test_correct_password_redirects_to_next(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/dashboard-page/"},
            )

        assert response.status_code == 302
        assert response["Location"] == "/dashboard-page/"

    def test_correct_password_defaults_next_to_root(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post("/waf/site-password/", {"password": "letmein"})

        assert response.status_code == 302
        assert response["Location"] == "/"

    def test_correct_password_sets_verified_cookie(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/"},
            )

        from django_waf.services.site_password_service import SITE_PASSWORD_COOKIE

        assert SITE_PASSWORD_COOKIE in response.cookies
        cookie = response.cookies[SITE_PASSWORD_COOKIE]
        assert cookie["httponly"] is True
        assert cookie["samesite"] == "Lax"

    def test_verified_cookie_passes_without_reprompt(self):
        with _enable_gate(password="letmein"):
            client = Client()
            verify_response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/"},
            )
            assert verify_response.status_code == 302

            # Same client -- its cookiejar carries the verified cookie, so
            # the subsequent request within TTL is not gated.
            response = client.get("/")

        assert response.status_code == 200
        assert response.content == b"OK"

    def test_within_ttl_multiple_requests_pass(self):
        with _enable_gate(password="letmein", DJANGO_WAF_SITE_PASSWORD_TTL=43200):
            client = Client()
            client.post("/waf/site-password/", {"password": "letmein", "next": "/"})

            first = client.get("/")
            second = client.get("/")

        assert first.status_code == 200
        assert second.status_code == 200

    def test_past_ttl_reprompts(self):
        with _enable_gate(password="letmein", DJANGO_WAF_SITE_PASSWORD_TTL=1):
            client = Client()
            client.post("/waf/site-password/", {"password": "letmein", "next": "/"})

            import time

            time.sleep(1.1)

            response = client.get("/")

        assert response.status_code == 401


# ---------------------------------------------------------------------------
# BR-SP-005 / AC: wrong password re-prompts with error, constant-time compare
# ---------------------------------------------------------------------------


class TestWrongPasswordReprompts:
    def test_wrong_password_returns_401_with_error(self):
        with _enable_gate(password="correct-horse"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "wrong-guess", "next": "/"},
            )

        assert response.status_code == 401
        assert b"Incorrect password" in response.content

    def test_wrong_password_does_not_set_verified_cookie(self):
        with _enable_gate(password="correct-horse"):
            client = Client()
            client.post("/waf/site-password/", {"password": "wrong-guess", "next": "/"})

            response = client.get("/")

        assert response.status_code == 401

    def test_comparison_uses_hmac_compare_digest(self):
        """Assert the password check goes through hmac.compare_digest, not ==."""
        import django_waf.services.site_password_service as sp_mod

        with (
            patch.object(sp_mod.hmac, "compare_digest", wraps=sp_mod.hmac.compare_digest) as spy,
            _enable_gate(password="correct-horse"),
        ):
            result = sp_mod.check_password("wrong-guess")

        assert result is False
        spy.assert_called_once_with("wrong-guess", "correct-horse")

    def test_wrong_length_password_fails_cleanly(self):
        """A submission shorter/longer than the stored password still fails
        (no exception, no timing shortcut visible in behaviour)."""
        with _enable_gate(password="a-fairly-long-password-value"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "x", "next": "/"},
            )

        assert response.status_code == 401

    def test_empty_submission_never_matches_empty_stored_password(self):
        """Guard: an empty stored password (misconfigured) must not
        validate an empty submitted password."""
        import django_waf.services.site_password_service as sp_mod

        with _enable_gate(password=""):
            assert sp_mod.check_password("") is False


# ---------------------------------------------------------------------------
# BR-SP-007: guess throttling reuses the WAF limiter
# ---------------------------------------------------------------------------


class TestGuessThrottling:
    def test_failed_attempt_records_a_rate_limiter_hit(self):
        with (
            _enable_gate(password="correct-horse"),
            patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.rate_limiter.check_rate_limit") as mock_check,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_check.return_value = MagicMock(exceeded=False, window=None, retry_after=None)

            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "wrong-guess", "next": "/"},
            )

        assert response.status_code == 401
        mock_check.assert_called_once()

    def test_throttle_exceeded_returns_429(self):
        with (
            _enable_gate(password="correct-horse"),
            patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.rate_limiter.check_rate_limit") as mock_check,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_check.return_value = MagicMock(exceeded=True, window="1m", retry_after=42)

            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "wrong-guess", "next": "/"},
            )

        assert response.status_code == 429
        assert "Retry-After" in response

    def test_throttle_check_reuses_rate_limiter_module_not_a_new_limiter(self):
        """BR-SP-007: guess throttling must go through
        django_waf.services.rate_limiter.check_rate_limit -- no parallel
        limiter implementation."""
        import django_waf.services.site_password_service as sp_mod
        from django_waf.services import rate_limiter as rl_mod

        assert sp_mod.record_guess_throttle_hit.__module__ == "django_waf.services.site_password_service"
        # The service delegates to the shared limiter function object.
        with patch.object(rl_mod, "check_rate_limit") as mock_check:
            mock_check.return_value = MagicMock(exceeded=False, window=None, retry_after=None)
            with _enable_gate(password="correct-horse"):
                sp_mod.record_guess_throttle_hit("1.2.3.4", _mock_redis())

        mock_check.assert_called_once()

    def test_redis_unavailable_fails_open_on_throttle_check(self):
        import django_waf.services.site_password_service as sp_mod

        with _enable_gate(password="correct-horse"):
            result = sp_mod.record_guess_throttle_hit("1.2.3.4", None)

        assert result is False


# ---------------------------------------------------------------------------
# BR-SP-003: exempt paths always pass, even when locked
# ---------------------------------------------------------------------------


class TestExemptPaths:
    def test_health_path_bypasses_gate(self, settings):
        settings.ROOT_URLCONF = "tests.urls"
        with _enable_gate():
            client = Client()
            response = client.get("/health/")

        # Not gated by the site-password check -- falls through to normal
        # URL resolution (404 here, since /health/ is not routed in
        # tests.urls, but critically not the 401 prompt).
        assert response.status_code != 401

    def test_well_known_path_bypasses_gate(self):
        with _enable_gate():
            client = Client()
            response = client.get("/.well-known/acme-challenge/token123")

        assert response.status_code != 401

    def test_robots_txt_bypasses_gate(self):
        with _enable_gate():
            client = Client()
            response = client.get("/robots.txt")

        assert response.status_code != 401

    def test_waf_challenge_path_bypasses_gate(self, settings):
        settings.ROOT_URLCONF = "tests.urls"
        with (
            _enable_gate(),
            patch("django_waf.views._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            token = MagicMock()
            token.token = "tok"
            token.difficulty = 10
            mock_issue.return_value = token

            client = Client()
            response = client.get("/waf/challenge/")

        assert response.status_code != 401

    def test_waf_verify_path_bypasses_gate(self, settings):
        settings.ROOT_URLCONF = "tests.urls"
        with _enable_gate():
            client = Client()
            response = client.post("/waf/verify/", {"token": "x", "nonce": "0"})

        # Reaches VerifyView's own logic (400 for an invalid/unknown token),
        # not the site-password 401 prompt.
        assert response.status_code != 401


# ---------------------------------------------------------------------------
# AC: the password never appears in a response/log/error
# ---------------------------------------------------------------------------


class TestPasswordNeverLeaks:
    def test_password_not_in_prompt_html(self):
        with _enable_gate(password="super-secret-value"):
            client = Client()
            response = client.get("/")

        assert b"super-secret-value" not in response.content

    def test_password_not_in_error_response(self):
        with _enable_gate(password="super-secret-value"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "wrong-guess", "next": "/"},
            )

        assert b"super-secret-value" not in response.content

    def test_misconfiguration_log_names_setting_not_value(self, caplog):
        """The misconfiguration path has no password value to leak (it is
        empty by definition), but confirm the log line only ever names the
        setting, not a stored value."""
        import logging

        with _enable_gate(password=""), caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            client = Client()
            client.get("/")

        messages = [record.getMessage() for record in caplog.records]
        assert any("DJANGO_WAF_SITE_PASSWORD_ENABLED is True but" in m for m in messages)

    def test_password_not_logged_on_failed_guess(self, caplog):
        import logging

        with _enable_gate(password="super-secret-value"), caplog.at_level(logging.DEBUG):
            client = Client()
            client.post(
                "/waf/site-password/",
                {"password": "wrong-guess", "next": "/"},
            )

        for record in caplog.records:
            assert "super-secret-value" not in record.getMessage()


# ---------------------------------------------------------------------------
# AC: open-redirect via `next` is prevented
# ---------------------------------------------------------------------------


class TestOpenRedirectPrevented:
    def test_external_next_url_is_rejected(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "https://evil.example.com/phish"},
            )

        assert response.status_code == 302
        assert response["Location"] == "/"
        assert "evil.example.com" not in response["Location"]

    def test_protocol_relative_next_url_is_rejected(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "//evil.example.com/phish"},
            )

        assert response.status_code == 302
        assert "evil.example.com" not in response["Location"]

    def test_relative_same_host_next_url_is_allowed(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/some/safe/path/"},
            )

        assert response.status_code == 302
        assert response["Location"] == "/some/safe/path/"


# ---------------------------------------------------------------------------
# Middleware unit-level: _check_site_password short-circuit shape
# ---------------------------------------------------------------------------


class TestCheckSitePasswordShortCircuitShape:
    """_check_site_password returns None to continue, or a response to
    short-circuit -- mirrors _check_country_block's contract."""

    def test_returns_none_when_gate_disabled(self):
        import django_waf.conf as conf_mod
        from django_waf.middleware import WafMiddleware

        with patch.object(conf_mod, "DJANGO_WAF_SITE_PASSWORD_ENABLED", False):
            middleware = WafMiddleware(get_response=lambda r: None)
            factory = RequestFactory()
            request = factory.get("/")

            result = middleware._check_site_password(request, "/")

        assert result is None

    def test_returns_response_when_gate_enabled_and_unverified(self):
        with _enable_gate(password="letmein"):
            client = Client()
            response = client.get("/")

        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Middleware ordering: gate runs relative to DJANGO_WAF_ENABLED
# ---------------------------------------------------------------------------


class TestGateRunsWithinMiddlewareEnabledCheck:
    """Per PRD 2.1 / BR-SP-008: the gate check sits after the WAF's own
    enabled/exempt-path/exempt-host short-circuits. When the whole WAF
    middleware is disabled, the site-password gate does not run either.

    DJANGO_WAF_SITE_PASSWORD_ENABLED is set directly via override_settings
    (not patch.multiple) here because DJANGO_WAF_ENABLED must go through a
    real importlib.reload(conf_mod) for the master kill switch to take
    effect -- reload() re-executes the module body and would silently wipe
    any patch.multiple-patched attributes in the same block (they are
    class/module attribute patches, not settings-backed).
    """

    @override_settings(
        DJANGO_WAF_ENABLED=False,
        DJANGO_WAF_SITE_PASSWORD_ENABLED=True,
        DJANGO_WAF_SITE_PASSWORD="letmein",
    )
    def test_gate_does_not_run_when_waf_disabled(self):
        import importlib

        import django_waf.conf as conf_mod

        importlib.reload(conf_mod)
        try:
            client = Client()
            response = client.get("/")
            assert response.status_code == 200
        finally:
            importlib.reload(conf_mod)


# ---------------------------------------------------------------------------
# Signed-cookie unit tests: site_password_service.has_valid_cookie /
# set_verified_cookie
# ---------------------------------------------------------------------------


class TestSignedCookieService:
    """Unit-level checks on the cookie signing/verification helpers,
    independent of the middleware/view integration above."""

    def test_set_verified_cookie_sets_signed_value(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            set_verified_cookie,
        )

        with _enable_gate(password="letmein"):
            request = RequestFactory().get("/")
            response = HttpResponse()
            set_verified_cookie(response, request)

        assert SITE_PASSWORD_COOKIE in response.cookies
        # The cookie value is opaque signed data, not the marker/password.
        raw_value = response.cookies[SITE_PASSWORD_COOKIE].value
        assert raw_value != "verified"
        assert "letmein" not in raw_value

    def test_has_valid_cookie_true_for_freshly_set_cookie(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            has_valid_cookie,
            set_verified_cookie,
        )

        with _enable_gate(password="letmein"):
            factory = RequestFactory()
            response = HttpResponse()
            set_verified_cookie(response, factory.get("/"))
            signed_value = response.cookies[SITE_PASSWORD_COOKIE].value

            request = factory.get("/")
            request.COOKIES[SITE_PASSWORD_COOKIE] = signed_value

            assert has_valid_cookie(request) is True

    def test_has_valid_cookie_false_when_missing(self):
        from django.test import RequestFactory

        from django_waf.services.site_password_service import has_valid_cookie

        with _enable_gate(password="letmein"):
            request = RequestFactory().get("/")
            assert has_valid_cookie(request) is False

    def test_has_valid_cookie_false_when_tampered(self):
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            has_valid_cookie,
        )

        with _enable_gate(password="letmein"):
            request = RequestFactory().get("/")
            request.COOKIES[SITE_PASSWORD_COOKIE] = "not-a-real-signed-value"
            assert has_valid_cookie(request) is False

    def test_has_valid_cookie_false_when_expired(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            has_valid_cookie,
            set_verified_cookie,
        )

        with _enable_gate(password="letmein", DJANGO_WAF_SITE_PASSWORD_TTL=1):
            factory = RequestFactory()
            response = HttpResponse()
            set_verified_cookie(response, factory.get("/"))
            signed_value = response.cookies[SITE_PASSWORD_COOKIE].value

            import time

            time.sleep(1.1)

            request = factory.get("/")
            request.COOKIES[SITE_PASSWORD_COOKIE] = signed_value

            assert has_valid_cookie(request) is False

    def test_cookie_signed_with_django_waf_signing_key_not_secret_key(self):
        """The cookie must use the package's own signing key convention
        (DJANGO_WAF_SIGNING_KEY / tokens.get_signing_key), not Django's
        SECRET_KEY-backed session/cookie signer directly."""
        import django_waf.services.site_password_service as sp_mod
        from django_waf.forms.services import tokens as tokens_mod

        with (
            patch.object(tokens_mod, "get_signing_key", wraps=tokens_mod.get_signing_key) as spy,
            _enable_gate(password="letmein"),
        ):
            sp_mod._get_signer()

        spy.assert_called_once()

    def test_cookie_scoped_to_session_cookie_domain_by_default(self):
        from django.http import HttpResponse
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            set_verified_cookie,
        )

        with (
            _enable_gate(password="letmein"),
            override_settings(SESSION_COOKIE_DOMAIN=".example.com"),
        ):
            response = HttpResponse()
            set_verified_cookie(response, RequestFactory().get("/"))

        assert response.cookies[SITE_PASSWORD_COOKIE]["domain"] == ".example.com"

    def test_cookie_domain_setting_overrides_session_cookie_domain(self):
        import django_waf.conf as conf_mod
        from django.http import HttpResponse
        from django.test import RequestFactory

        from django_waf.services.site_password_service import (
            SITE_PASSWORD_COOKIE,
            set_verified_cookie,
        )

        with (
            _enable_gate(
                password="letmein",
                DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN=".gate-only.example.com",
            ),
            override_settings(SESSION_COOKIE_DOMAIN=".example.com"),
        ):
            assert conf_mod.DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN == ".gate-only.example.com"
            response = HttpResponse()
            set_verified_cookie(response, RequestFactory().get("/"))

        assert response.cookies[SITE_PASSWORD_COOKIE]["domain"] == ".gate-only.example.com"


# ---------------------------------------------------------------------------
# Regression: WafMiddleware runs before SessionMiddleware in production
# (README-documented order). request.session must never be touched.
# ---------------------------------------------------------------------------


class TestNoSessionMiddlewareRegression:
    """Reproduces the shipped 1.5.0 defect: site_password_service used
    request.session, but WafMiddleware is documented to run BEFORE
    SessionMiddleware (README: 'placing it after SecurityMiddleware and
    before other middleware'), so request.session does not exist when the
    gate runs and mark_session_verified() raised AttributeError.

    Builds a middleware stack matching the documented production order
    (WafMiddleware immediately after SecurityMiddleware, with no session
    middleware anywhere in the chain) via override_settings(MIDDLEWARE=...),
    rather than relying on tests/settings.py's MIDDLEWARE (which -- unlike
    production -- puts SessionMiddleware before WafMiddleware and would
    mask this exact bug).
    """

    _NO_SESSION_MIDDLEWARE = [
        "django.middleware.security.SecurityMiddleware",
        "django_waf.middleware.WafMiddleware",
        "django.middleware.common.CommonMiddleware",
    ]

    def test_full_gate_round_trip_with_no_session_middleware(self):
        """Prompt -> POST password -> get signed cookie -> next request
        with the cookie passes -- all without SessionMiddleware installed
        and without raising AttributeError."""
        with (
            _enable_gate(password="letmein"),
            override_settings(MIDDLEWARE=self._NO_SESSION_MIDDLEWARE),
        ):
            client = Client()

            prompt_response = client.get("/")
            assert prompt_response.status_code == 401

            verify_response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/"},
            )
            assert verify_response.status_code == 302

            from django_waf.services.site_password_service import SITE_PASSWORD_COOKIE

            assert SITE_PASSWORD_COOKIE in verify_response.cookies

            next_response = client.get("/")

        assert next_response.status_code == 200
        assert next_response.content == b"OK"

    def test_request_has_no_session_attribute_during_verify(self):
        """Explicit guard: a request with no .session attribute at all
        (not merely an empty one) must not raise when POSTed to the verify
        path with the correct password."""
        with (
            _enable_gate(password="letmein"),
            override_settings(MIDDLEWARE=self._NO_SESSION_MIDDLEWARE),
        ):
            client = Client()
            response = client.post(
                "/waf/site-password/",
                {"password": "letmein", "next": "/"},
            )

        assert response.status_code == 302
