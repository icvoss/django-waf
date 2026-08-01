"""Tests for the waf_pass cookie: issuance, validation, and IPv6 safety.

Regression coverage for GH #26 (proof-of-work pass cookies were not
IPv6-safe): the pre-fix cookie format joined ``token:ip:expiry:signature``
with ":", which an IPv6 address also contains, so validation mis-parsed the
payload and every solved IPv6 client was re-challenged forever despite
holding a validly signed cookie. The fix moves to a versioned "|"-delimited
payload (see ``django_waf.services.challenge_service.issue_pass_cookie``)
and normalises IP addresses via the ``ipaddress`` module before comparing.

Redis is not available in the test environment; the middleware integration
test mocks it the same way tests/test_middleware.py does. validate_pass_cookie
and issue_pass_cookie themselves are pure functions with no Redis/DB access.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from django_waf.services.challenge_service import (
    _hmac_sign,
    issue_pass_cookie,
    validate_pass_cookie,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issued_cookie_value(token: str, ip: str, ttl: int = 3600, secure: bool = False) -> str:
    """Issue a pass cookie and return the raw value that would be sent to the client."""
    import django_waf.conf as conf_mod

    response = MagicMock()
    captured = {}

    def capture_cookie(name, value, **kwargs):
        captured["value"] = value

    response.set_cookie.side_effect = capture_cookie

    with patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", ttl):
        issue_pass_cookie(response, token, ip, secure=secure)

    return captured["value"]


# ---------------------------------------------------------------------------
# IPv4 round trip
# ---------------------------------------------------------------------------


class TestPassCookieIPv4:
    def test_round_trip_valid(self):
        """A cookie issued for an IPv4 address validates for that same address."""
        ip = "10.0.0.1"
        token = "abc123def456abc123def456abc123"

        cookie_value = _issued_cookie_value(token, ip)

        assert validate_pass_cookie(cookie_value, ip) is True

    def test_wrong_ip_returns_false(self):
        """Cookie issued for one IPv4 address does not validate for a different one."""
        ip = "10.0.0.1"
        other_ip = "10.0.0.2"
        token = "some-token-value"

        cookie_value = _issued_cookie_value(token, ip)

        assert validate_pass_cookie(cookie_value, other_ip) is False


# ---------------------------------------------------------------------------
# IPv6 round trip (GH #26)
# ---------------------------------------------------------------------------


class TestPassCookieIPv6:
    def test_compressed_ipv6_round_trip(self):
        """A cookie issued and validated with the same compressed IPv6 address works."""
        ip = "2001:db8::1"
        token = "compressed-ipv6-token"

        cookie_value = _issued_cookie_value(token, ip)

        assert validate_pass_cookie(cookie_value, ip) is True

    def test_expanded_ipv6_round_trip(self):
        """A cookie issued and validated with the same expanded IPv6 address works."""
        ip = "2001:0db8:0000:0000:0000:0000:0000:0001"
        token = "expanded-ipv6-token"

        cookie_value = _issued_cookie_value(token, ip)

        assert validate_pass_cookie(cookie_value, ip) is True

    def test_issued_compressed_validated_expanded(self):
        """A cookie issued with the compressed form validates against the expanded form.

        This is the exact defect from GH #26: the two forms are the same
        address, so they must compare equal regardless of which form the
        client is seen in on each request.
        """
        compressed = "2001:db8::1"
        expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
        token = "mixed-form-token"

        cookie_value = _issued_cookie_value(token, compressed)

        assert validate_pass_cookie(cookie_value, expanded) is True

    def test_issued_expanded_validated_compressed(self):
        """A cookie issued with the expanded form validates against the compressed form."""
        compressed = "2001:db8::1"
        expanded = "2001:0db8:0000:0000:0000:0000:0000:0001"
        token = "mixed-form-token-2"

        cookie_value = _issued_cookie_value(token, expanded)

        assert validate_pass_cookie(cookie_value, compressed) is True

    def test_wrong_ipv6_returns_false(self):
        """Cookie issued for one IPv6 address does not validate for a different one."""
        ip = "2001:db8::1"
        other_ip = "2001:db8::2"
        token = "some-ipv6-token"

        cookie_value = _issued_cookie_value(token, ip)

        assert validate_pass_cookie(cookie_value, other_ip) is False


# ---------------------------------------------------------------------------
# Tamper / expiry / malformed rejection
# ---------------------------------------------------------------------------


class TestPassCookieRejection:
    def test_tampered_payload_returns_false(self):
        """A cookie whose payload was altered after signing is rejected.

        The signature was computed over the original IP; changing the IP in
        the payload (while leaving the signature as-is) must not validate.
        """
        ip = "10.0.0.1"
        token = "some-token"
        cookie_value = _issued_cookie_value(token, ip)

        prefix, signature = cookie_value.rsplit("|", 1)
        version, tok, _original_ip, expiry = prefix.split("|", 3)
        tampered_prefix = "|".join([version, tok, "10.0.0.99", expiry])
        tampered_cookie = f"{tampered_prefix}|{signature}"

        assert validate_pass_cookie(tampered_cookie, ip) is False
        assert validate_pass_cookie(tampered_cookie, "10.0.0.99") is False

    def test_tampered_signature_returns_false(self):
        """A cookie with a modified signature is rejected."""
        future_ts = int(time.time()) + 3600
        bad_cookie = f"v2|some-token|10.0.0.1|{future_ts}|invalidsignature"

        assert validate_pass_cookie(bad_cookie, "10.0.0.1") is False

    def test_tampered_signature_returns_false_ipv6(self):
        """A cookie with a modified signature is rejected for an IPv6 payload too.

        This is the shape that previously slipped through undetected: the
        signature check on the old format never ran because the parse step
        after it raised first (GH #26).
        """
        future_ts = int(time.time()) + 3600
        bad_cookie = f"v2|some-token|2001:db8::1|{future_ts}|invalidsignature"

        assert validate_pass_cookie(bad_cookie, "2001:db8::1") is False

    def test_expired_cookie_returns_false(self):
        """A cookie with a past expiry timestamp is rejected, even with a valid signature."""
        ip = "10.0.0.1"
        token = "some-token"
        expired_ts = int(time.time()) - 1

        value_prefix = f"v2|{token}|{ip}|{expired_ts}"
        sig = _hmac_sign(value_prefix)
        bad_cookie = f"{value_prefix}|{sig}"

        assert validate_pass_cookie(bad_cookie, ip) is False

    def test_expired_cookie_returns_false_ipv6(self):
        """A cookie with a past expiry timestamp is rejected for an IPv6 payload."""
        ip = "2001:db8::1"
        token = "some-token"
        expired_ts = int(time.time()) - 1

        value_prefix = f"v2|{token}|{ip}|{expired_ts}"
        sig = _hmac_sign(value_prefix)
        bad_cookie = f"{value_prefix}|{sig}"

        assert validate_pass_cookie(bad_cookie, ip) is False

    def test_ip_mismatch_returns_false(self):
        """A validly signed, unexpired cookie is still rejected if the requesting IP differs."""
        ip = "10.0.0.1"
        token = "some-token"
        future_ts = int(time.time()) + 3600

        value_prefix = f"v2|{token}|{ip}|{future_ts}"
        sig = _hmac_sign(value_prefix)
        cookie_value = f"{value_prefix}|{sig}"

        assert validate_pass_cookie(cookie_value, "10.0.0.2") is False

    def test_malformed_cookie_returns_false(self):
        """A cookie with the wrong shape is gracefully rejected, not raised."""
        assert validate_pass_cookie("", "1.2.3.4") is False
        assert validate_pass_cookie("notacookie", "1.2.3.4") is False
        assert validate_pass_cookie("a|b", "1.2.3.4") is False

    def test_old_colon_format_cookie_is_rejected(self):
        """A cookie issued by the pre-fix colon-joined format fails validation.

        No legacy parsing is added (see the module docstring): a client
        holding an old-format cookie simply re-solves the challenge once
        after upgrade rather than being silently trusted or crashing.
        """
        future_ts = int(time.time()) + 3600
        old_format_prefix = f"some-token:10.0.0.1:{future_ts}"
        old_format_sig = _hmac_sign(old_format_prefix)
        old_cookie = f"{old_format_prefix}:{old_format_sig}"

        assert validate_pass_cookie(old_cookie, "10.0.0.1") is False

    def test_old_colon_format_cookie_is_rejected_ipv6(self):
        """An old-format cookie for an IPv6 client also fails cleanly rather than mis-parsing.

        This is the exact GH #26 failure mode: ``split(":", 2)`` on an IPv6
        address produces more than 3 parts, so the un-fixed code raised
        ValueError parsing the expiry and (before the try/except) could
        return an incorrect result. The fixed parser must reject this
        outright via the version tag, not attempt to interpret it.
        """
        future_ts = int(time.time()) + 3600
        old_format_prefix = f"some-token:2001:db8::1:{future_ts}"
        old_format_sig = _hmac_sign(old_format_prefix)
        old_cookie = f"{old_format_prefix}:{old_format_sig}"

        assert validate_pass_cookie(old_cookie, "2001:db8::1") is False


# ---------------------------------------------------------------------------
# issue_pass_cookie cookie attributes
# ---------------------------------------------------------------------------


class TestIssuePassCookieAttributes:
    def test_sets_cookie_with_expected_attributes(self):
        """issue_pass_cookie calls response.set_cookie with the expected flags."""
        import django_waf.conf as conf_mod

        response = MagicMock()

        with patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 86400):
            issue_pass_cookie(response, "my-token", "10.0.0.1", secure=True)

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args
        assert call_kwargs.args[0] == "waf_pass"
        assert call_kwargs.kwargs.get("httponly") is True
        assert call_kwargs.kwargs.get("samesite") == "Lax"
        assert call_kwargs.kwargs.get("secure") is True

    def test_sets_cookie_for_ipv6_client(self):
        """issue_pass_cookie works unchanged for an IPv6 client IP."""
        import django_waf.conf as conf_mod

        response = MagicMock()

        with patch.object(conf_mod, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 86400):
            issue_pass_cookie(response, "my-token", "2001:db8::1", secure=True)

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args
        assert call_kwargs.args[0] == "waf_pass"
        cookie_value = call_kwargs.args[1]
        assert cookie_value.startswith("v2|my-token|2001:db8::1|")


# ---------------------------------------------------------------------------
# Middleware integration: a solved IPv6 client's cookie bypasses evaluation
# ---------------------------------------------------------------------------


def _make_middleware(get_response=None):
    """Instantiate WafMiddleware with a trivial get_response (matches test_middleware.py)."""
    from django_waf.middleware import WafMiddleware

    if get_response is None:
        get_response = lambda req: HttpResponse("ok")  # noqa: E731
    return WafMiddleware(get_response)


def _mock_redis():
    """Return a MagicMock that behaves like a basic Redis client (matches test_middleware.py)."""
    redis = MagicMock()
    redis.get.return_value = None
    return redis


class TestMiddlewareIPv6PassCookie:
    """A solved IPv6 client's real waf_pass cookie bypasses evaluation on later requests.

    Unlike tests/test_middleware.py's TestWafPassCookie, this does not mock
    validate_pass_cookie: it issues a real cookie via issue_pass_cookie and
    feeds it back through the middleware as an IPv6 client would send it,
    proving the fix end-to-end rather than at the unit level only.
    """

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_solved_ipv6_client_cookie_bypasses_evaluation(self):
        import importlib

        import django_waf.conf as conf_mod

        importlib.reload(conf_mod)

        ip = "2001:db8::1"
        cookie_value = _issued_cookie_value("ipv6-client-token", ip, secure=False)

        factory = RequestFactory()
        request = factory.get("/page/", REMOTE_ADDR=ip)
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {"waf_pass": cookie_value}
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with (
            patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.rule_engine.evaluate_request") as mock_eval,
        ):
            mock_redis_fn.return_value = _mock_redis()

            response = middleware(request)

        # The cookie must short-circuit evaluation entirely: get_response is
        # called directly and evaluate_request is never reached.
        get_response.assert_called_once_with(request)
        mock_eval.assert_not_called()
        assert response.status_code == 200

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_solved_ipv6_client_cookie_rejected_for_different_ip(self):
        """A pass cookie issued to one IPv6 client does not bypass evaluation for another."""
        import importlib

        import django_waf.conf as conf_mod

        importlib.reload(conf_mod)

        issued_ip = "2001:db8::1"
        requesting_ip = "2001:db8::2"
        cookie_value = _issued_cookie_value("ipv6-client-token", issued_ip, secure=False)

        factory = RequestFactory()
        request = factory.get("/page/", REMOTE_ADDR=requesting_ip)
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {"waf_pass": cookie_value}

        with (
            patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.rule_engine.evaluate_request") as mock_eval,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_eval.return_value = MagicMock(
                verdict="allowed",
                matched_rule_id=None,
                matched_rule_type="",
                anomaly_score=None,
                action=None,
            )

            middleware = _make_middleware()
            middleware(request)

        # Cookie is for a different IP, so evaluation must still run.
        mock_eval.assert_called_once()
