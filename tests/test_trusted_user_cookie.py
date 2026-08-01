"""Tests for the trusted-user cookie (#23,
docs/DESIGN-trusted-user-cookie.md).

Covers django_waf.services.trusted_user_service (signing/verification),
django_waf.middleware._is_staff_user's cookie-first preference,
django_waf.receivers.set_trusted_cookie_flag_on_login, and the
WafMiddleware response-side hook that actually writes the cookie
(WafMiddleware._get_response).

Mirrors tests/test_site_password.py's patterns: django_waf.conf reads
settings at call time via a local import, so patch.object(conf_mod, ...)
toggles behaviour without importlib.reload. The feature defaults off
(DJANGO_WAF_TRUSTED_COOKIE_ENABLED=False in tests/settings.py), so every
test that needs it on enables it explicitly.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

pytestmark = pytest.mark.django_db

User = get_user_model()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _enable_feature(trust_level="staff", **extra):
    """Context manager patching django_waf.conf so the feature is on.

    Mirrors tests/test_site_password.py's _enable_gate helper. Use as:
        with _enable_feature():
            ...
    """
    import django_waf.conf as conf_mod

    defaults = {
        "DJANGO_WAF_TRUSTED_COOKIE_ENABLED": True,
        "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL": trust_level,
        "DJANGO_WAF_TRUSTED_COOKIE_TTL": 3600,
        "DJANGO_WAF_TRUSTED_COOKIE_DOMAIN": None,
    }
    defaults.update(extra)
    return patch.multiple(conf_mod, **defaults)


def _make_user(*, is_staff=False, is_superuser=False, username="alice"):
    return User.objects.create_user(
        username=username,
        email=f"{username}@example.com",
        password="irrelevant",  # noqa: S106
        is_staff=is_staff,
        is_superuser=is_superuser,
    )


def _make_middleware(get_response=None):
    from django_waf.middleware import WafMiddleware

    if get_response is None:
        get_response = MagicMock(return_value=HttpResponse("ok"))
    return WafMiddleware(get_response)


# ---------------------------------------------------------------------------
# django_waf.services.trusted_user_service, signing/verification
# ---------------------------------------------------------------------------


class TestSetAndReadTrustedCookie:
    def test_set_trusted_cookie_sets_signed_value(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with _enable_feature():
            request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.9")
            response = HttpResponse()
            set_trusted_cookie(response, request)

        assert TRUSTED_USER_COOKIE in response.cookies
        raw_value = response.cookies[TRUSTED_USER_COOKIE].value
        # The cookie value is opaque signed data, not the plain marker/IP.
        assert raw_value != "trusted:203.0.113.9"

    def test_has_valid_trusted_cookie_true_for_freshly_set_cookie(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
            set_trusted_cookie,
        )

        with _enable_feature():
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

            request = factory.get("/", REMOTE_ADDR="203.0.113.9")
            request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

            assert has_valid_trusted_cookie(request) is True

    def test_has_valid_trusted_cookie_false_when_missing(self):
        from django_waf.services.trusted_user_service import has_valid_trusted_cookie

        with _enable_feature():
            request = RequestFactory().get("/")
            assert has_valid_trusted_cookie(request) is False

    def test_has_valid_trusted_cookie_false_when_tampered(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
        )

        with _enable_feature():
            request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.9")
            request.COOKIES[TRUSTED_USER_COOKIE] = "not-a-real-signed-value"
            assert has_valid_trusted_cookie(request) is False

    def test_has_valid_trusted_cookie_false_when_expired(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
            set_trusted_cookie,
        )

        with _enable_feature(DJANGO_WAF_TRUSTED_COOKIE_TTL=1):
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

            time.sleep(1.1)

            request = factory.get("/", REMOTE_ADDR="203.0.113.9")
            request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

            assert has_valid_trusted_cookie(request) is False

    def test_has_valid_trusted_cookie_false_on_ip_mismatch(self):
        """A cookie issued to one IP must not validate from another."""
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
            set_trusted_cookie,
        )

        with _enable_feature():
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

            request = factory.get("/", REMOTE_ADDR="198.51.100.4")
            request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

            assert has_valid_trusted_cookie(request) is False

    def test_cookie_flags_httponly_samesite_secure(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with _enable_feature():
            request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.9", secure=True)
            response = HttpResponse()
            set_trusted_cookie(response, request)

        morsel = response.cookies[TRUSTED_USER_COOKIE]
        assert morsel["httponly"] is True
        assert morsel["samesite"] == "Lax"
        assert morsel["secure"] is True

    def test_cookie_secure_flag_false_over_plain_http(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with _enable_feature():
            request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.9")
            response = HttpResponse()
            set_trusted_cookie(response, request)

        assert not response.cookies[TRUSTED_USER_COOKIE]["secure"]

    def test_cookie_scoped_to_session_cookie_domain_by_default(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with (
            _enable_feature(),
            override_settings(SESSION_COOKIE_DOMAIN=".example.com"),
        ):
            response = HttpResponse()
            set_trusted_cookie(response, RequestFactory().get("/", REMOTE_ADDR="203.0.113.9"))

        assert response.cookies[TRUSTED_USER_COOKIE]["domain"] == ".example.com"

    def test_cookie_domain_setting_overrides_session_cookie_domain(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with (
            _enable_feature(DJANGO_WAF_TRUSTED_COOKIE_DOMAIN=".waf-only.example.com"),
            override_settings(SESSION_COOKIE_DOMAIN=".example.com"),
        ):
            response = HttpResponse()
            set_trusted_cookie(response, RequestFactory().get("/", REMOTE_ADDR="203.0.113.9"))

        assert response.cookies[TRUSTED_USER_COOKIE]["domain"] == ".waf-only.example.com"

    def test_cookie_binds_to_resolve_client_ip_not_raw_remote_addr(self):
        """The cookie must bind to django_waf.services.client_ip.resolve_client_ip's
        result, not request.META["REMOTE_ADDR"] directly, so it matches
        whatever IP the rest of the WAF treats as authoritative."""
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
            set_trusted_cookie,
        )

        with (
            _enable_feature(),
            patch("django_waf.services.client_ip.resolve_client_ip", return_value="203.0.113.9"),
        ):
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="10.0.0.1"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

            request = factory.get("/", REMOTE_ADDR="10.0.0.1")
            request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

            assert has_valid_trusted_cookie(request) is True


class TestFeatureOffIsANoOp:
    """DJANGO_WAF_TRUSTED_COOKIE_ENABLED=False (the default), a stray,
    otherwise-valid-looking cookie must never grant the bypass."""

    def test_has_valid_trusted_cookie_false_even_with_freshly_signed_cookie(self):
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            has_valid_trusted_cookie,
            set_trusted_cookie,
        )

        with _enable_feature():
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

        # Feature now off, the cookie above is real and unexpired.
        request = factory.get("/", REMOTE_ADDR="203.0.113.9")
        request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

        assert has_valid_trusted_cookie(request) is False


# ---------------------------------------------------------------------------
# django_waf.middleware._is_staff_user, cookie-first, request.user fallback
# ---------------------------------------------------------------------------


class TestIsStaffUserPrefersTrustedCookie:
    def test_valid_trusted_cookie_returns_true_with_no_request_user(self):
        """Simulates WafMiddleware running before AuthenticationMiddleware:
        request.user is absent entirely, yet the cookie alone must make
        _is_staff_user return True."""
        from django_waf.middleware import _is_staff_user
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with _enable_feature():
            factory = RequestFactory()
            response = HttpResponse()
            set_trusted_cookie(response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = response.cookies[TRUSTED_USER_COOKIE].value

            request = factory.get("/", REMOTE_ADDR="203.0.113.9")
            request.COOKIES[TRUSTED_USER_COOKIE] = signed_value
            # No request.user attribute at all, pre-AuthenticationMiddleware.
            assert not hasattr(request, "user")

            assert _is_staff_user(request) is True

    def test_falls_back_to_request_user_when_no_cookie(self):
        """Feature-off / no-cookie behaviour is unchanged: still driven by
        request.user, exactly as before #23."""
        from django_waf.middleware import _is_staff_user

        request = RequestFactory().get("/")
        request.user = MagicMock(is_authenticated=True, is_staff=True, is_superuser=False)

        assert _is_staff_user(request) is True

    def test_feature_off_falls_back_to_request_user_only(self):
        """With the feature off, behaviour must be byte-identical to
        pre-#23: driven purely by request.user, cookie ignored entirely."""
        from django_waf.middleware import _is_staff_user
        from django_waf.services.trusted_user_service import TRUSTED_USER_COOKIE

        request = RequestFactory().get("/")
        request.COOKIES[TRUSTED_USER_COOKIE] = "irrelevant-value"
        request.user = MagicMock(is_authenticated=False)

        assert _is_staff_user(request) is False

    def test_no_cookie_no_user_attribute_returns_false(self):
        from django_waf.middleware import _is_staff_user

        request = RequestFactory().get("/")
        assert _is_staff_user(request) is False


# ---------------------------------------------------------------------------
# django_waf.receivers.set_trusted_cookie_flag_on_login
# ---------------------------------------------------------------------------


class TestLoginReceiverFlagsRequest:
    def test_staff_user_login_flags_request_under_staff_trust_level(self):
        from django_waf.receivers import set_trusted_cookie_flag_on_login

        with _enable_feature(trust_level="staff"):
            user = _make_user(is_staff=True)
            request = RequestFactory().get("/accounts/login/")

            set_trusted_cookie_flag_on_login(sender=User, request=request, user=user)

        assert getattr(request, "_waf_set_trusted_cookie", False) is True

    def test_superuser_login_flags_request_under_staff_trust_level(self):
        from django_waf.receivers import set_trusted_cookie_flag_on_login

        with _enable_feature(trust_level="staff"):
            user = _make_user(is_superuser=True)
            request = RequestFactory().get("/accounts/login/")

            set_trusted_cookie_flag_on_login(sender=User, request=request, user=user)

        assert getattr(request, "_waf_set_trusted_cookie", False) is True

    def test_non_staff_user_never_flagged_under_staff_trust_level(self):
        from django_waf.receivers import set_trusted_cookie_flag_on_login

        with _enable_feature(trust_level="staff"):
            user = _make_user()
            request = RequestFactory().get("/accounts/login/")

            set_trusted_cookie_flag_on_login(sender=User, request=request, user=user)

        assert getattr(request, "_waf_set_trusted_cookie", False) is False

    def test_non_staff_user_flagged_under_authenticated_trust_level(self):
        from django_waf.receivers import set_trusted_cookie_flag_on_login

        with _enable_feature(trust_level="authenticated"):
            user = _make_user()
            request = RequestFactory().get("/accounts/login/")

            set_trusted_cookie_flag_on_login(sender=User, request=request, user=user)

        assert getattr(request, "_waf_set_trusted_cookie", False) is True

    def test_receiver_no_op_when_feature_disabled(self):
        import django_waf.conf as conf_mod
        from django_waf.receivers import set_trusted_cookie_flag_on_login

        with patch.object(conf_mod, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", False):
            user = _make_user(is_staff=True)
            request = RequestFactory().get("/accounts/login/")

            set_trusted_cookie_flag_on_login(sender=User, request=request, user=user)

        assert getattr(request, "_waf_set_trusted_cookie", False) is False


# ---------------------------------------------------------------------------
# End-to-end: login receiver -> middleware response hook -> cookie set
# ---------------------------------------------------------------------------


class TestLoginToResponseCookieFlow:
    def test_flagged_request_gets_cookie_set_by_middleware_response_hook(self):
        """The receiver only stashes a flag; WafMiddleware._get_response is
        what actually writes the cookie onto whatever response the view
        produced. This is the full receiver-flag-to-cookie wiring."""
        from django_waf.services.trusted_user_service import TRUSTED_USER_COOKIE

        with _enable_feature():
            get_response = MagicMock(return_value=HttpResponse("logged in"))
            middleware = _make_middleware(get_response)

            request = RequestFactory().get("/dashboard/", REMOTE_ADDR="203.0.113.9")
            request.user = MagicMock(is_authenticated=True, is_staff=True, is_superuser=False)
            request._waf_set_trusted_cookie = True

            with patch("django_waf.middleware._get_redis_client") as mock_redis_fn:
                mock_redis_fn.return_value = None
                response = middleware(request)

        assert TRUSTED_USER_COOKIE in response.cookies

    def test_unflagged_request_gets_no_cookie(self):
        from django_waf.services.trusted_user_service import TRUSTED_USER_COOKIE

        with _enable_feature():
            get_response = MagicMock(return_value=HttpResponse("ok"))
            middleware = _make_middleware(get_response)

            request = RequestFactory().get("/dashboard/", REMOTE_ADDR="203.0.113.9")
            request.user = MagicMock(is_authenticated=True, is_staff=True, is_superuser=False)
            # No _waf_set_trusted_cookie flag set.

            with patch("django_waf.middleware._get_redis_client") as mock_redis_fn:
                mock_redis_fn.return_value = None
                response = middleware(request)

        assert TRUSTED_USER_COOKIE not in response.cookies

    def test_subsequent_request_with_resulting_cookie_bypasses_before_auth(self):
        """Full acceptance-criteria round trip: sign a cookie via
        set_trusted_cookie (as the middleware response hook would), then a
        fresh request carrying only that cookie -- no request.user at all --
        must make _is_staff_user (and therefore the WAF bypass) return True."""
        from django_waf.middleware import _is_staff_user
        from django_waf.services.trusted_user_service import (
            TRUSTED_USER_COOKIE,
            set_trusted_cookie,
        )

        with _enable_feature():
            factory = RequestFactory()
            login_response = HttpResponse("logged in")
            set_trusted_cookie(login_response, factory.get("/", REMOTE_ADDR="203.0.113.9"))
            signed_value = login_response.cookies[TRUSTED_USER_COOKIE].value

            next_request = factory.get("/dashboard/", REMOTE_ADDR="203.0.113.9")
            next_request.COOKIES[TRUSTED_USER_COOKIE] = signed_value

            assert _is_staff_user(next_request) is True
