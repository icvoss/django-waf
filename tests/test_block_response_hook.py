"""Tests for DJANGO_WAF_BLOCK_RESPONSE_HANDLER, the block-response hook (#74).

BR-EVAL-011. A consumer needing a different block-response shape (a
multi-tenant host returning its own anonymous 404 rather than the WAF's
fingerprinting 403) sets a dotted path here instead of subclassing
``WafMiddleware`` and overriding the private ``_handle_verdict``.

Scope under test:

- unset setting is byte-identical to the pre-hook behaviour;
- a handler set by dotted path replaces the block response;
- all three failure modes (path will not import, handler raises, handler
  returns a non-response) fall back to the built-in response and log at
  ERROR rather than 500ing.

The handlers live at module level in this file precisely so the tests can
address them by a real dotted path (``tests.test_block_response_hook.X``)
and exercise ``import_string`` for real, rather than patching it out. A
patched ``import_string`` would prove the middleware calls something, not
that a consumer's setting actually resolves.
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

# Records what each handler was called with, so a test can assert the
# signature the middleware actually passes rather than trusting the
# docstring. Reset by the autouse fixture.
CALLS: list[tuple] = []


def working_handler(request, result):
    """The documented happy path: return a consumer-shaped 404."""
    CALLS.append((request, result))
    return HttpResponseNotFound("Not found.")


def raising_handler(request, result):
    """A handler with a bug in it."""
    CALLS.append((request, result))
    raise RuntimeError("handler exploded")


def non_response_handler(request, result):
    """A handler returning the wrong type (a common consumer mistake: a
    template string, or forgetting to wrap a render)."""
    CALLS.append((request, result))
    return "<html>blocked</html>"


@pytest.fixture(autouse=True)
def _reset_calls():
    CALLS.clear()
    yield
    CALLS.clear()


# ---------------------------------------------------------------------------
# Helpers (mirroring tests/test_middleware.py's conventions)
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


def _run_blocked_request():
    """Drive a full BLOCKED request through the middleware and return the
    response.

    Goes through ``__call__`` rather than calling ``_build_block_response``
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
        patch("django_waf.middleware._emit_request_blocked"),
    ):
        mock_redis_fn.return_value = _mock_redis()
        mock_validate.return_value = False
        mock_eval.return_value = _make_result("blocked")

        middleware = WafMiddleware(get_response)
        response = middleware(request)

    # The block must still be a block: the view is never reached, whichever
    # branch of the hook ran. Without this every test below would pass if
    # the hook accidentally failed the request open.
    get_response.assert_not_called()
    return response


# ---------------------------------------------------------------------------
# The default: unset setting is byte-identical to the pre-hook behaviour
# ---------------------------------------------------------------------------


class TestUnsetHandlerIsUnchanged:
    """With the setting unset the response is exactly what every release
    before the hook returned: a 403 whose body is ``Access denied.``.

    Asserted as literal status code and literal bytes, not "some 4xx", so
    the test is falsifiable by any drift in the default shape. A consumer's
    own tests and monitoring key on this exact string.
    """

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_default_is_403_access_denied(self):
        response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."

    @override_settings(DJANGO_WAF_ENABLED=True, DJANGO_WAF_BLOCK_RESPONSE_HANDLER="")
    def test_empty_string_handler_is_the_same_as_unset(self):
        response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_no_handler_is_ever_called_when_unset(self):
        _run_blocked_request()

        assert CALLS == []


# ---------------------------------------------------------------------------
# A configured handler replaces the block response
# ---------------------------------------------------------------------------


class TestConfiguredHandler:
    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
    )
    def test_handler_response_replaces_the_default(self):
        response = _run_blocked_request()

        assert response.status_code == 404
        assert response.content == b"Not found."

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
    )
    def test_handler_receives_the_request_and_the_evaluation_result(self):
        """The documented signature is ``(request, result)``.

        Asserting the arguments, not just the response, pins the contract
        the docstring promises: a handler written against it must keep
        working.
        """
        _run_blocked_request()

        assert len(CALLS) == 1
        request, result = CALLS[0]
        assert request.path == "/page/"
        assert result.verdict == "blocked"

    @override_settings(DJANGO_WAF_ENABLED=True)
    def test_setting_is_read_at_call_time_not_import_time(self):
        """Two requests in one process, differing only by an
        ``override_settings`` block, must get different responses.

        This is what call-time ``import_string`` resolution buys: a value
        frozen at module import would make the second assertion fail, and
        would silently break every consumer test using ``override_settings``.
        """
        default_response = _run_blocked_request()
        assert default_response.status_code == 403

        with override_settings(
            DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
        ):
            hooked_response = _run_blocked_request()

        assert hooked_response.status_code == 404

        after_response = _run_blocked_request()
        assert after_response.status_code == 403


# ---------------------------------------------------------------------------
# Failure modes: never 500, always fall back, always log distinctly
# ---------------------------------------------------------------------------


class TestHandlerFailureFallsBack:
    """A misconfigured hook must not break a request (BR-EVAL-007's
    fail-open posture), and must not turn a block into a pass either.

    Every case asserts three things: the built-in response comes back
    byte-identical, an ERROR is logged naming the dotted path so the
    operator can find it, and no exception escapes the middleware.
    """

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.does_not_exist",
    )
    def test_unimportable_path_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."
        assert any("could not be imported" in message for message in caplog.messages)
        assert any("does_not_exist" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.no_such_module_at_all.handler",
    )
    def test_unimportable_module_falls_back_and_logs(self, caplog):
        """A missing module, not just a missing attribute. ``import_string``
        raises ``ImportError`` for both, but a consumer typo is far more
        often the module half of the path."""
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."
        assert any("could not be imported" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.block_handler_import_boom.handler",
    )
    def test_module_raising_a_non_importerror_on_import_falls_back(self, caplog):
        """The import guard is deliberately broader than ``ImportError``.

        Importing a handler module runs that module's top-level code, which
        can raise anything: ``ImproperlyConfigured`` from a settings read,
        ``AppRegistryNotReady``, a ``SyntaxError`` under a stale ``.pyc``.
        An ``except ImportError`` would let all of those escape as a 500 on
        a request the WAF had already decided to block, which is the exact
        failure this hook must not introduce. This test fails against a
        narrow ``except ImportError``.
        """
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."
        assert any("could not be imported" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.raising_handler",
    )
    def test_raising_handler_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."
        # The handler really did run and really did raise: without this the
        # test would also pass if the path had simply failed to import,
        # which is a different failure with a different log line.
        assert len(CALLS) == 1
        assert any("raised" in message for message in caplog.messages)
        assert any("raising_handler" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.raising_handler",
    )
    def test_raising_handler_does_not_propagate(self):
        """No exception escapes into a 500. Asserted separately from the
        logging test because a bare ``pytest.raises``-free call proves the
        absence directly."""
        response = _run_blocked_request()

        assert response.status_code == 403

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.non_response_handler",
    )
    def test_non_response_return_falls_back_and_logs(self, caplog):
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            response = _run_blocked_request()

        assert response.status_code == 403
        assert response.content == b"Access denied."
        assert len(CALLS) == 1
        assert any("not an HttpResponse" in message for message in caplog.messages)
        # The log names the offending type so the operator does not have to
        # guess what the handler returned.
        assert any("str" in message for message in caplog.messages)

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.raising_handler",
    )
    def test_failure_classifications_are_distinct(self, caplog):
        """A raising handler and an unimportable path must not produce the
        same log line: an operator has to be able to tell which one
        happened without reading the source.
        """
        with caplog.at_level(logging.ERROR, logger="django_waf.middleware"):
            _run_blocked_request()
        raised_messages = list(caplog.messages)

        caplog.clear()
        CALLS.clear()

        with (
            override_settings(
                DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.does_not_exist",
            ),
            caplog.at_level(logging.ERROR, logger="django_waf.middleware"),
        ):
            _run_blocked_request()
        import_messages = list(caplog.messages)

        assert not any("could not be imported" in message for message in raised_messages)
        assert not any("raised" in message for message in import_messages)


# ---------------------------------------------------------------------------
# Scope: BLOCKED only
# ---------------------------------------------------------------------------


class TestHookScope:
    """The hook covers BLOCKED verdicts only (the #74 decision).

    Without these, a later change that routed THROTTLED or CHALLENGED
    through the hook would go unnoticed, and a consumer's block-shaped
    handler would start answering rate limits.
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
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
    )
    def test_throttled_verdict_ignores_the_handler(self):
        response = self._run_with_verdict("throttled", retry_after=30)

        assert response.status_code == 429
        assert CALLS == []

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
    )
    def test_challenged_verdict_ignores_the_handler(self):
        response = self._run_with_verdict("challenged")

        assert response.status_code == 302
        assert CALLS == []

    @override_settings(
        DJANGO_WAF_ENABLED=True,
        DJANGO_WAF_BLOCK_RESPONSE_HANDLER="tests.test_block_response_hook.working_handler",
    )
    def test_blocked_verdict_is_the_positive_control(self):
        """Pins the two absence assertions above.

        Without this the handler could be dead entirely (a broken setting
        name, an unwired branch) and both would still pass.
        """
        response = self._run_with_verdict("blocked")

        assert response.status_code == 404
        assert len(CALLS) == 1


# ---------------------------------------------------------------------------
# The setting itself
# ---------------------------------------------------------------------------


class TestSettingDefault:
    def test_default_is_empty_string(self):
        from django_waf import conf

        assert conf.DJANGO_WAF_BLOCK_RESPONSE_HANDLER == ""

    @override_settings(DJANGO_WAF_BLOCK_RESPONSE_HANDLER="some.dotted.path")
    def test_override_settings_is_visible_to_conf(self):
        from django_waf import conf

        assert conf.DJANGO_WAF_BLOCK_RESPONSE_HANDLER == "some.dotted.path"
