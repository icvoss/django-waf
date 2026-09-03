"""Tests for DJANGO_WAF_THROTTLE_RESPONSE_HANDLER, the throttle-response hook.

BR-EVAL-014. Mirrors ``test_block_response_hook.py`` (#74, BR-EVAL-012)
exactly: a consumer needing a different throttle-response shape sets a
dotted path here instead of subclassing ``WafMiddleware`` and overriding
the private ``_handle_verdict``.

Scope under test:

- unset setting is byte-identical to the pre-hook behaviour, including the
  existing Retry-After logic (accurate value when present, "60" fallback
  otherwise);
- a handler set by dotted path replaces the throttle response, and can read
  ``result.retry_after`` (populated here, unlike the BLOCKED path);
- all three failure modes (path will not import, handler raises, handler
  returns a non-response) fall back to the built-in response and log at
  ERROR rather than 500ing;
- scope is THROTTLED only: BLOCKED and CHALLENGED verdicts ignore the
  setting.

The handlers live at module level in this file precisely so the tests can
address them by a real dotted path (``tests.test_throttle_response_hook.X``)
and exercise ``import_string`` for real, rather than patching it out.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpResponse, HttpResponseNotFound
from django.test import RequestFactory, override_settings

# ---------------------------------------------------------------------------
# Handlers addressed by dotted path from the tests below
# ---------------------------------------------------------------------------

CALLS: list[tuple] = []


def working_handler(request, result):
    """The documented happy path: return a consumer-shaped response that
    reads the accurate retry_after off the result."""
    CALLS.append((request, result))
    response = HttpResponseNotFound(f"Slow down, retry in {result.retry_after}s.")
    return response


def raising_handler(request, result):
    """A handler with a bug in it."""
    CALLS.append((request, result))
    raise RuntimeError("handler exploded")


def non_response_handler(request, result):
    """A handler returning the wrong type."""
    CALLS.append((request, result))
    return "<html>throttled</html>"


@pytest.fixture(autouse=True)
def _reset_calls():
    CALLS.clear()
    yield
    CALLS.clear()


# ---------------------------------------------------------------------------
# Helpers (mirroring tests/test_block_response_hook.py's conventions)
# ---------------------------------------------------------------------------


def _make_result(verdict: str, **kwargs) -> MagicMock:
    result = MagicMock()
    result.verdict = verdict
    result.matched_rule_id = None
    result.matched_rule_type = ""
    result.anomaly_score = None
    result.action = None
    result.retry_after = None
    for key, value in kwargs.items():
        setattr(result, key, value)
    return result


def _mock_redis():
    redis = MagicMock()
    redis.get.return_value = None
    return redis


def _run_throttled_request(retry_after=None):
    """Drive a full THROTTLED request through the middleware and return the
    response.

    Goes through ``__call__`` rather than calling ``_build_throttle_response``
    directly, so the test proves the hook is wired into the real request
    path and not merely that a helper method works in isolation.
    """
    from django_waf.middleware import WafMiddleware

    factory = RequestFactory()
    request = factory.get("/page/")
    request.user = MagicMock(is_authenticated=False)
    request.COOKIES = {}
    get_response = MagicMock(return_value=HttpResponse("view response"))

    with (
        patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
        patch("django_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
        patch("django_waf.services.rule_engine.evaluate_request") as mock_eval,
        patch("django_waf.middleware._emit_request_throttled"),
    ):
        mock_redis_fn.return_value = _mock_redis()
        mock_validate.return_value = False
        mock_eval.return_value = _make_result("throttled", retry_after=retry_after)

        middleware = WafMiddleware(get_response)
        response = middleware(request)

    # The throttle must still be a throttle: the view is never reached,
    # whichever branch of the hook ran. Without this every test below would
    # pass if the hook accidentally failed the request open.
    get_response.assert_not_called()
    return response


# ---------------------------------------------------------------------------
# The default: unset setting is byte-identical to the pre-hook behaviour
# ---------------------------------------------------------------------------


class TestUnsetHandlerIsUnchanged:
    """With the setting unset the response is exactly what every release
    before the hook returned: a 429 with the fixed body text and the
    existing Retry-After logic.
    """

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_default_is_429_with_fixed_body(self):
        response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."

    @override_settings(DJANGO_WAF_ENABLED=True, DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="")
    def test_empty_string_handler_is_the_same_as_unset(self):
        response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_no_handler_is_ever_called_when_unset(self):
        _run_throttled_request(retry_after=None)

        assert CALLS == []

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_default_retry_after_uses_accurate_value_when_present(self):
        """Retry-After logic must survive the refactor untouched: an
        accurate result.retry_after value is sent, not the 60s fallback."""
        response = _run_throttled_request(retry_after=23)

        assert response["Retry-After"] == "23"

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_default_retry_after_falls_back_to_60_when_absent(self):
        response = _run_throttled_request(retry_after=None)

        assert response["Retry-After"] == "60"


# ---------------------------------------------------------------------------
# A configured handler replaces the throttle response
# ---------------------------------------------------------------------------


class TestConfiguredHandler:
    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
    )
    def test_handler_response_replaces_the_default(self):
        response = _run_throttled_request(retry_after=42)

        assert response.status_code == 404
        assert response.content == b"Slow down, retry in 42s."

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
    )
    def test_handler_receives_the_request_and_the_evaluation_result(self):
        """The documented signature is ``(request, result)``, and
        result.retry_after is populated here (unlike the BLOCKED path)."""
        _run_throttled_request(retry_after=15)

        assert len(CALLS) == 1
        request, result = CALLS[0]
        assert request.path == "/page/"
        assert result.verdict == "throttled"
        assert result.retry_after == 15

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_setting_is_read_at_call_time_not_import_time(self):
        """Two requests in one process, differing only by an
        ``override_settings`` block, must get different responses."""
        default_response = _run_throttled_request(retry_after=None)
        assert default_response.status_code == 429

        with override_settings(
            DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
        ):
            hooked_response = _run_throttled_request(retry_after=5)

        assert hooked_response.status_code == 404

        after_response = _run_throttled_request(retry_after=None)
        assert after_response.status_code == 429


# ---------------------------------------------------------------------------
# Failure modes: never 500, always fall back, always log distinctly
# ---------------------------------------------------------------------------


class TestHandlerFailureFallsBack:
    """A misconfigured hook must not break a request, and must not turn a
    throttle into a pass either.

    Every case asserts three things: the built-in response comes back
    byte-identical, an ERROR is logged naming the dotted path so the
    operator can find it, and no exception escapes the middleware.
    """

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.does_not_exist",
    )
    def test_unimportable_path_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."
        assert any("could not be imported" in message for message in caplog.messages)
        assert any("does_not_exist" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.no_such_module_at_all.handler",
    )
    def test_unimportable_module_falls_back_and_logs(self, caplog):
        """A missing module, not just a missing attribute."""
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."
        assert any("could not be imported" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.throttle_handler_import_boom.handler",
    )
    def test_module_raising_a_non_importerror_on_import_falls_back(self, caplog):
        """The import guard is deliberately broader than ``ImportError``,
        mirroring the block-response hook. This test fails against a narrow
        ``except ImportError``.
        """
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."
        assert any("could not be imported" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.raising_handler",
    )
    def test_raising_handler_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."
        assert len(CALLS) == 1
        assert any("raised" in message for message in caplog.messages)
        assert any("raising_handler" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.raising_handler",
    )
    def test_raising_handler_does_not_propagate(self):
        response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.non_response_handler",
    )
    def test_non_response_return_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_throttled_request(retry_after=None)

        assert response.status_code == 429
        assert response.content == b"Too many requests. Please retry later."
        assert len(CALLS) == 1
        assert any("not an HttpResponse" in message for message in caplog.messages)
        assert any("str" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.raising_handler",
    )
    def test_failure_classifications_are_distinct(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            _run_throttled_request(retry_after=None)
        raised_messages = list(caplog.messages)

        caplog.clear()
        CALLS.clear()

        with (
            override_settings(
                DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.does_not_exist",
            ),
            caplog.at_level(logging.ERROR, logger="django_waf.middleware"),
        ):
            _run_throttled_request(retry_after=None)
        import_messages = list(caplog.messages)

        assert not any("could not be imported" in message for message in raised_messages)
        assert not any("raised" in message for message in import_messages)


# ---------------------------------------------------------------------------
# Scope: THROTTLED only
# ---------------------------------------------------------------------------


class TestHookScope:
    """The hook covers THROTTLED verdicts only.

    Without these, a later change that routed BLOCKED or CHALLENGED through
    the hook would go unnoticed, and a consumer's throttle-shaped handler
    would start answering blocks.
    """

    def _run_with_verdict(self, verdict: str, **result_kwargs):
        from django_waf.middleware import WafMiddleware

        factory = RequestFactory()
        request = factory.get("/page/")
        request.user = MagicMock(is_authenticated=False)
        request.COOKIES = {}
        get_response = MagicMock(return_value=HttpResponse("view response"))

        with (
            patch("django_waf.middleware._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.challenge_service.validate_pass_cookie") as mock_validate,
            patch("django_waf.services.rule_engine.evaluate_request") as mock_eval,
            patch("django_waf.middleware._emit_request_blocked"),
            patch("django_waf.middleware._emit_request_throttled"),
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_validate.return_value = False
            mock_eval.return_value = _make_result(verdict, **result_kwargs)

            middleware = WafMiddleware(get_response)
            return middleware(request)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
    )
    def test_blocked_verdict_ignores_the_handler(self):
        response = self._run_with_verdict("blocked", retry_after=None)

        assert response.status_code == 403
        assert CALLS == []

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
    )
    def test_challenged_verdict_ignores_the_handler(self):
        response = self._run_with_verdict("challenged")

        assert response.status_code == 302
        assert CALLS == []

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="tests.test_throttle_response_hook.working_handler",
    )
    def test_throttled_verdict_is_the_positive_control(self):
        """Pins the two absence assertions above.

        Without this the handler could be dead entirely (a broken setting
        name, an unwired branch) and both would still pass.
        """
        response = self._run_with_verdict("throttled", retry_after=9)

        assert response.status_code == 404
        assert len(CALLS) == 1


# ---------------------------------------------------------------------------
# The setting itself
# ---------------------------------------------------------------------------


class TestSettingDefault:
    def test_default_is_empty_string(self):
        from django_waf import conf

        assert conf.DJANGO_WAF_THROTTLE_RESPONSE_HANDLER == ""

    @override_settings(DJANGO_WAF_THROTTLE_RESPONSE_HANDLER="some.dotted.path")
    def test_override_settings_is_visible_to_conf(self):
        from django_waf import conf

        assert conf.DJANGO_WAF_THROTTLE_RESPONSE_HANDLER == "some.dotted.path"
