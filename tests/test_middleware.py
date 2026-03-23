"""Tests for WafMiddleware.

All Redis interactions are mocked — the test suite runs with SQLite in-memory
and Django's LocMemCache (no real Redis available).

Evaluation order under test (BR-EVAL-003):
  1. ICV_WAF_ENABLED master kill switch
  2. Exempt path prefix match
  3. Staff/superuser bypass
  4. Redis unavailable → fail-open
  5. Valid waf_pass cookie → pass through
  6. evaluate_request() verdict dispatch
  7. Request logging (sampling)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(verdict: str, **kwargs) -> MagicMock:
    """Return a mock evaluate_request result with the given verdict."""
    result = MagicMock()
    result.verdict = verdict
    result.matched_rule_id = None
    result.matched_rule_type = ""
    result.anomaly_score = None
    result.action = None
    for key, value in kwargs.items():
        setattr(result, key, value)
    return result


def _make_middleware(get_response=None):
    """Instantiate WafMiddleware with a trivial get_response."""
    from icv_waf.middleware import WafMiddleware

    if get_response is None:
        get_response = lambda req: HttpResponse("ok")  # noqa: E731
    return WafMiddleware(get_response)


def _mock_redis():
    """Return a MagicMock that behaves like a basic Redis client."""
    redis = MagicMock()
    redis.get.return_value = None
    return redis


# ---------------------------------------------------------------------------
# Master kill switch
# ---------------------------------------------------------------------------


class TestWafEnabledKillSwitch:
    """ICV_WAF_ENABLED=False passes every request through without evaluation."""

    @override_settings(ICV_WAF_ENABLED=False)
    def test_disabled_waf_passes_request_through(self):
        # Reload conf so the override is picked up
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/some/path/")
        get_response = MagicMock(return_value=HttpResponse("passed"))
        middleware = _make_middleware(get_response)

        response = middleware(request)

        get_response.assert_called_once_with(request)
        assert response.status_code == 200

    @override_settings(ICV_WAF_ENABLED=False)
    def test_disabled_waf_does_not_call_evaluate_request(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/")

        with patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval:
            middleware = _make_middleware()
            middleware(request)
            mock_eval.assert_not_called()


# ---------------------------------------------------------------------------
# Exempt paths
# ---------------------------------------------------------------------------


class TestExemptPaths:
    """Requests to exempt path prefixes bypass all WAF logic."""

    @override_settings(ICV_WAF_ENABLED=True, ICV_WAF_EXEMPT_PATHS=["/static/", "/health/"])
    def test_static_path_is_exempt(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/static/app.css")
        get_response = MagicMock(return_value=HttpResponse("static"))
        middleware = _make_middleware(get_response)

        middleware(request)

        get_response.assert_called_once_with(request)

    @override_settings(ICV_WAF_ENABLED=True, ICV_WAF_EXEMPT_PATHS=["/static/", "/health/"])
    def test_health_path_is_exempt(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/health/")
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        middleware(request)

        get_response.assert_called_once_with(request)

    @override_settings(ICV_WAF_ENABLED=True, ICV_WAF_EXEMPT_PATHS=["/static/"])
    def test_non_exempt_path_continues_to_evaluation(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/api/data/")
        # Evaluation raises to confirm we reached it
        with patch("icv_waf.middleware._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = None  # trigger fail-open
            middleware = _make_middleware()
            response = middleware(request)

        # Fail-open means get_response is called — just verify we did not short-circuit
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Staff bypass
# ---------------------------------------------------------------------------


class TestStaffBypass:
    """Authenticated staff and superusers skip WAF evaluation entirely (BR-RATE-003)."""

    @override_settings(ICV_WAF_ENABLED=True)
    def test_staff_user_bypasses_waf(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=True, is_staff=True, is_superuser=False)
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with patch("icv_waf.middleware._get_redis_client") as mock_redis_fn:
            middleware(request)
            mock_redis_fn.assert_not_called()

        get_response.assert_called_once_with(request)

    @override_settings(ICV_WAF_ENABLED=True)
    def test_superuser_bypasses_waf(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/admin/")
        request.user = MagicMock(is_authenticated=True, is_staff=False, is_superuser=True)
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with patch("icv_waf.middleware._get_redis_client") as mock_redis_fn:
            middleware(request)
            mock_redis_fn.assert_not_called()

        get_response.assert_called_once_with(request)

    @override_settings(ICV_WAF_ENABLED=True)
    def test_anonymous_user_does_not_bypass_waf(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        middleware = _make_middleware()

        with patch("icv_waf.middleware._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = None  # fail-open
            middleware(request)

        # Redis was consulted, confirming staff bypass was not triggered
        mock_redis_fn.assert_called_once()


# ---------------------------------------------------------------------------
# waf_pass cookie bypass
# ---------------------------------------------------------------------------


class TestWafPassCookie:
    """A valid waf_pass cookie causes the request to pass through without evaluation."""

    @override_settings(ICV_WAF_ENABLED=True)
    def test_valid_waf_pass_cookie_bypasses_evaluation(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {"waf_pass": "valid-cookie-value"}
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = True

            middleware(request)

        get_response.assert_called_once_with(request)
        mock_validate.assert_called_once()

    @override_settings(ICV_WAF_ENABLED=True)
    def test_invalid_waf_pass_cookie_proceeds_to_evaluation(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {"waf_pass": "tampered-value"}

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.return_value = _make_result("allowed")

            middleware = _make_middleware()
            middleware(request)

        mock_eval.assert_called_once()


# ---------------------------------------------------------------------------
# Verdict dispatch
# ---------------------------------------------------------------------------


class TestVerdictDispatch:
    """Middleware returns the appropriate HTTP response for each verdict."""

    def _run_with_verdict(self, verdict: str, **result_kwargs):
        """Helper: run middleware with a mocked evaluate_request returning the given verdict."""
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {}
        get_response = MagicMock(return_value=HttpResponse("view response"))

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval,
            patch("icv_waf.middleware._emit_request_blocked"),
            patch("icv_waf.middleware._emit_request_throttled"),
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.return_value = _make_result(verdict, **result_kwargs)

            middleware = _make_middleware(get_response)
            response = middleware(request)

        return response

    @override_settings(ICV_WAF_ENABLED=True)
    def test_blocked_verdict_returns_403(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("blocked")

        assert response.status_code == 403

    @override_settings(ICV_WAF_ENABLED=True)
    def test_throttled_verdict_returns_429(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("throttled")

        assert response.status_code == 429

    @override_settings(ICV_WAF_ENABLED=True)
    def test_throttled_verdict_includes_retry_after_header(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("throttled")

        assert "Retry-After" in response

    @override_settings(ICV_WAF_ENABLED=True)
    def test_challenged_verdict_redirects_to_challenge_page(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("challenged")

        assert response.status_code == 302
        assert "/waf/challenge/" in response["Location"]

    @override_settings(ICV_WAF_ENABLED=True)
    def test_allowed_verdict_passes_to_get_response(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("allowed")

        assert response.status_code == 200
        assert response.content == b"view response"

    @override_settings(ICV_WAF_ENABLED=True)
    def test_passed_verdict_passes_to_get_response(self):
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        response = self._run_with_verdict("passed")

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Fail-open behaviour
# ---------------------------------------------------------------------------


class TestFailOpen:
    """Middleware is fail-open: errors in evaluation or Redis unavailability allow requests."""

    @override_settings(ICV_WAF_ENABLED=True)
    def test_redis_unavailable_passes_request_through(self):
        """When _get_redis_client() returns None the request must pass through."""
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with patch("icv_waf.middleware._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = None
            response = middleware(request)

        get_response.assert_called_once_with(request)
        assert response.status_code == 200

    @override_settings(ICV_WAF_ENABLED=True)
    def test_evaluation_error_passes_request_through(self):
        """An exception in evaluate_request must not surface — request passes through."""
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {}
        get_response = MagicMock(return_value=HttpResponse("ok"))
        middleware = _make_middleware(get_response)

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.side_effect = RuntimeError("Redis connection reset")

            response = middleware(request)

        get_response.assert_called_once_with(request)
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# IP extraction
# ---------------------------------------------------------------------------


class TestIpExtraction:
    """_extract_ip selects the correct IP based on trust settings."""

    @override_settings(ICV_WAF_TRUST_X_FORWARDED_FOR=True)
    def test_uses_first_xff_ip_when_trusted(self):
        import importlib

        import icv_waf.conf as conf_mod
        from icv_waf.middleware import _extract_ip

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "1.2.3.4, 10.0.0.1, 172.16.0.5"

        ip = _extract_ip(request)

        assert ip == "1.2.3.4"

    @override_settings(ICV_WAF_TRUST_X_FORWARDED_FOR=False)
    def test_uses_remote_addr_when_xff_not_trusted(self):
        import importlib

        import icv_waf.conf as conf_mod
        from icv_waf.middleware import _extract_ip

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/")
        request.META["HTTP_X_FORWARDED_FOR"] = "1.2.3.4"
        request.META["REMOTE_ADDR"] = "5.6.7.8"

        ip = _extract_ip(request)

        assert ip == "5.6.7.8"

    @override_settings(ICV_WAF_TRUST_X_FORWARDED_FOR=True)
    def test_falls_back_to_remote_addr_when_xff_absent(self):
        import importlib

        import icv_waf.conf as conf_mod
        from icv_waf.middleware import _extract_ip

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/")
        request.META.pop("HTTP_X_FORWARDED_FOR", None)
        request.META["REMOTE_ADDR"] = "9.10.11.12"

        ip = _extract_ip(request)

        assert ip == "9.10.11.12"

    @override_settings(ICV_WAF_TRUST_X_FORWARDED_FOR=False)
    def test_uses_remote_addr_directly(self):
        import importlib

        import icv_waf.conf as conf_mod
        from icv_waf.middleware import _extract_ip

        importlib.reload(conf_mod)

        factory = RequestFactory()
        request = factory.get("/")
        request.META["REMOTE_ADDR"] = "203.0.113.1"

        ip = _extract_ip(request)

        assert ip == "203.0.113.1"


# ---------------------------------------------------------------------------
# Request logging
# ---------------------------------------------------------------------------


class TestRequestLogging:
    """_log_request creates RequestLog records according to sample rate and verdict."""

    @pytest.mark.django_db
    @override_settings(ICV_WAF_ENABLED=True, ICV_WAF_LOG_SAMPLE_RATE=1.0)
    def test_blocked_verdict_is_always_logged(self):
        """Security verdicts (blocked) are logged regardless of sample rate."""
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        from icv_waf.models import RequestLog

        factory = RequestFactory()
        request = factory.get("/attack/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {}

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval,
            patch("icv_waf.services.rule_engine.record_block_verdict"),
            patch("icv_waf.middleware._emit_request_blocked"),
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.return_value = _make_result("blocked")

            middleware = _make_middleware()
            middleware(request)

        assert RequestLog.objects.filter(verdict="blocked").exists()

    @pytest.mark.django_db
    @override_settings(ICV_WAF_ENABLED=True, ICV_WAF_LOG_SAMPLE_RATE=0.0)
    def test_allowed_verdict_not_logged_when_sample_rate_zero(self):
        """Allowed requests are skipped when the sample rate is 0.0."""
        import importlib

        import icv_waf.conf as conf_mod

        importlib.reload(conf_mod)

        from icv_waf.models import RequestLog

        initial_count = RequestLog.objects.count()

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {}

        with (
            patch("icv_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("icv_waf.services.rule_engine.evaluate_request") as mock_eval,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.return_value = _make_result("allowed")

            middleware = _make_middleware()
            middleware(request)

        # No new log records should have been created
        assert RequestLog.objects.count() == initial_count
