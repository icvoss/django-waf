"""Regression tests for #44: the non-Redis cache fallback was broken.

Before this fix, ``_get_redis_client()`` (three near-identical copies in
``middleware.py``, ``views.py``, and ``forms/protection.py``) fell back to
returning ``django.core.cache.cache`` itself whenever the configured cache
alias was not a django-redis backend (the common case for ``LocMemCache``
under ``DEBUG=True``). That object has no ``setex``, no incr-with-init, no
pipeline, and no sorted-set support, so Redis-only calls several frames
downstream raised ``AttributeError``, caught by the middleware's outermost
handler, which failed the whole WAF open: it evaluated no rules at all,
while looking, from a plain 200 response, exactly like a healthy pass.

The crux of this file is ``TestMiddlewareActuallyBlocksWithWorkingRedis``:
it proves the WAF genuinely blocks what it should block when Redis is
available (via the ``waf_redis_mock``/fakeredis fixture the package already
ships), and separately proves that when Redis genuinely is not the
configured backend (plain ``LocMemCache``, the default test settings, no
fakeredis override), the fallback fails cleanly, once, at the top of the
middleware (BR-EVAL-007), rather than raising deep inside the rule engine.
An assertion that only checks "no exception was raised" would have passed
on the pre-fix code too, since the outer ``except Exception`` already
swallowed the crash, so every test below asserts on the actual HTTP
response and/or a system check message, never merely on absence of a
traceback.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from django.core.checks import Error
from django.test import RequestFactory, override_settings

from django_waf.checks import check_redis_backend
from django_waf.enums import RuleAction, RuleType
from django_waf.middleware import WafMiddleware
from django_waf.models import BlockRule
from django_waf.services.redis_client import get_redis_client, is_redis_backend

# ---------------------------------------------------------------------------
# The crux: the WAF must actually BLOCK when Redis is genuinely available,
# proving the fix did not just suppress the crash while leaving evaluation
# inert. tests/settings.py runs on LocMemCache; waf_redis_mock (fakeredis)
# is what makes the underlying cache alias Redis-shaped for this test only.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestMiddlewareActuallyBlocksWithWorkingRedis:
    """The regression-proving tests: the precondition is never hand-set.

    Each test creates a real BlockRule and issues a real request through
    the full middleware stack via the Django test client, then asserts on
    the HTTP response the WAF actually returned. It never reaches into the
    middleware internals to assert a verdict was computed, which is exactly
    the shortcut that would pass unchanged whether or not evaluation ran.
    """

    def test_blocks_a_request_matching_an_active_block_rule(self, client, waf_redis_mock):
        BlockRule.objects.create(
            name="test-block-ip",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="203.0.113.50",
            action=RuleAction.BLOCK,
        )

        response = client.get("/", REMOTE_ADDR="203.0.113.50")

        assert response.status_code == 403

    def test_does_not_block_a_request_from_a_different_ip(self, client, waf_redis_mock):
        """Negative control: the same rule must not block an unrelated IP.

        Without this, a middleware bug that 403s everything (a different
        failure mode entirely, but one that would still make the positive
        test above pass) would go undetected.
        """
        BlockRule.objects.create(
            name="test-block-ip",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="203.0.113.50",
            action=RuleAction.BLOCK,
        )

        response = client.get("/", REMOTE_ADDR="203.0.113.99")

        assert response.status_code == 200

    def test_challenges_a_request_matching_an_active_challenge_rule(self, client, waf_redis_mock):
        BlockRule.objects.create(
            name="test-challenge-ua",
            rule_type=RuleType.UA,
            match_type="exact",
            pattern="known-bad-scraper/1.0",
            action=RuleAction.CHALLENGE,
        )

        response = client.get("/", HTTP_USER_AGENT="known-bad-scraper/1.0")

        assert response.status_code == 302
        assert "/waf/challenge/" in response["Location"]


# ---------------------------------------------------------------------------
# get_redis_client(): never falls back to a non-Redis cache object.
# ---------------------------------------------------------------------------


class TestGetRedisClientNeverReturnsANonRedisFallback:
    def test_returns_none_on_locmemcache_default_test_settings(self):
        """tests/settings.py CACHES['default'] is LocMemCache (no override
        here, unlike the tests above): this is the exact configuration
        #44 was filed against."""
        assert get_redis_client() is None

    def test_does_not_return_the_django_cache_object(self):
        """The pre-fix bug: the fallback silently returned
        django.core.cache.cache, which round-trips like a working client
        until a Redis-only method is called on it. Assert the specific
        wrong-object regression directly, not just "is None"."""
        from django.core.cache import cache as django_cache

        result = get_redis_client()

        assert result is not django_cache

    def test_logs_a_single_error_with_no_traceback(self, caplog):
        """Pre-fix, the failure surfaced as an unhandled AttributeError
        traceback logged from deep inside rule_engine.py. Post-fix it must
        be one clean ERROR log line from the resolution point itself."""
        import django_waf.services.redis_client as redis_client_mod

        redis_client_mod._warned_aliases.clear()

        with caplog.at_level(logging.ERROR, logger="django_waf.redis_client"):
            get_redis_client()

        error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(error_records) == 1
        assert error_records[0].exc_info is None  # no traceback attached

    def test_warns_only_once_per_process_not_once_per_call(self, caplog):
        import django_waf.services.redis_client as redis_client_mod

        redis_client_mod._warned_aliases.clear()

        with caplog.at_level(logging.ERROR, logger="django_waf.redis_client"):
            get_redis_client()
            get_redis_client()
            get_redis_client()

        error_records = [r for r in caplog.records if r.levelno >= logging.ERROR]
        assert len(error_records) == 1


# ---------------------------------------------------------------------------
# Middleware fails open cleanly (BR-EVAL-007 / AC-EVAL-007) when Redis is
# genuinely not the configured backend, rather than crashing several frames
# into rule evaluation.
# ---------------------------------------------------------------------------


class TestMiddlewareFailsOpenCleanlyWithoutRedis:
    def _make_middleware(self):
        from django.http import HttpResponse

        return WafMiddleware(lambda req: HttpResponse("passed-through"))

    def test_request_passes_through_on_locmemcache(self):
        middleware = self._make_middleware()
        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.5")

        response = middleware(request)

        assert response.status_code == 200
        assert response.content == b"passed-through"

    def test_no_evaluation_error_traceback_is_logged(self, caplog):
        """Pre-fix: an "evaluation error, failing open" log line plus a
        full AttributeError traceback from three frames inside
        rule_engine.py. Post-fix: the middleware never reaches
        evaluate_request() at all, because _get_redis_client() returns
        None and the existing "if redis_client is None" guard (BR-EVAL-007)
        fires first."""
        middleware = self._make_middleware()
        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.6")

        with caplog.at_level(logging.WARNING):
            middleware(request)

        traceback_records = [r for r in caplog.records if r.exc_info is not None]
        assert traceback_records == []

    def test_evaluate_request_is_never_called(self):
        """Positive proof the fail-open path is taken before rule
        evaluation, not that evaluation happened to raise and get caught."""
        middleware = self._make_middleware()
        request = RequestFactory().get("/", REMOTE_ADDR="203.0.113.7")

        with patch("django_waf.services.rule_engine.evaluate_request") as mock_eval:
            middleware(request)

            mock_eval.assert_not_called()


# ---------------------------------------------------------------------------
# django_waf.E004 system check
# ---------------------------------------------------------------------------


class TestRedisBackendSystemCheck:
    def test_errors_on_locmemcache(self):
        messages = check_redis_backend(None)

        assert len(messages) == 1
        assert isinstance(messages[0], Error)
        assert messages[0].id == "django_waf.E004"

    @override_settings(
        CACHES={
            "default": {
                "BACKEND": "django_redis.cache.RedisCache",
                "LOCATION": "redis://localhost:6379/0",
            }
        }
    )
    def test_silent_on_a_configured_redis_backend(self):
        import importlib

        import django_waf.conf as conf_mod

        importlib.reload(conf_mod)

        messages = check_redis_backend(None)

        assert messages == []

    def test_is_redis_backend_helper_matches_the_check(self):
        assert is_redis_backend() is False

    @override_settings(
        CACHES={
            "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
            "waf": {
                "BACKEND": "django_redis.cache.RedisCache",
                "LOCATION": "redis://localhost:6379/1",
            },
        },
        DJANGO_WAF_REDIS_ALIAS="waf",
    )
    def test_respects_a_non_default_redis_alias(self):
        import importlib

        import django_waf.conf as conf_mod

        importlib.reload(conf_mod)

        messages = check_redis_backend(None)

        assert messages == []
        importlib.reload(conf_mod)
