"""Tests for the dedicated POST /waf/verify/ rate limit (issue #81).

POST /waf/verify/ accepted proof-of-work solutions with no rate limit of
its own. Each solve attempt costs a signature check and Redis work, so an
unbounded submission rate is a cheap way to consume server resources.

DJANGO_WAF_RATE_LIMIT_PATHS cannot cover this endpoint in the deployment
shape the WAF itself recommends: the challenge and verify paths are
typically listed in DJANGO_WAF_EXEMPT_PATHS so a challenged user can
always clear themselves, and WafMiddleware.__call__ returns on the
exempt-path match before rule evaluation, where check_rate_limit runs, is
ever reached. So the limit lives inside VerifyView itself, calling the
dedicated django_waf.services.rate_limiter.check_verify_rate_limit
function directly.

Redis is not available in the test environment; all Redis calls are
mocked, matching the pattern in test_retry_after.py and test_views.py.
Per #75 (still open), every django_waf.conf value is an import-time
snapshot: tests overriding a DJANGO_WAF_VERIFY_RATE_LIMIT_* setting use
patch.object(conf, "NAME", ...), not Django's settings fixture or
pytest's settings override, which would not be seen.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from django.test import Client

import django_waf.conf as conf_mod
from django_waf.services.rate_limiter import check_verify_rate_limit

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_redis() -> MagicMock:
    """A basic Redis client mock for the paths that don't exercise the
    rate-limit pipeline (matches tests/test_views.py's _mock_redis)."""
    r = MagicMock()
    r.get.return_value = None
    return r


def _mock_redis_with_pipeline(count: int, oldest_in_window: list | None = None) -> MagicMock:
    """A Redis client mock whose pipeline().execute() returns a fixed
    ZCARD count and ZRANGE result, matching the 5-step pipeline
    check_verify_rate_limit runs (ZADD, ZREMRANGEBYSCORE, ZCARD, ZRANGE,
    EXPIRE)."""
    redis = _mock_redis()
    pipeline = MagicMock()
    pipeline.execute.return_value = [1, 0, count, oldest_in_window or [], True]
    redis.pipeline.return_value = pipeline
    return redis


@pytest.fixture(autouse=True)
def waf_urls(settings):
    settings.ROOT_URLCONF = "tests.urls"


# ---------------------------------------------------------------------------
# check_verify_rate_limit: pure unit tests against the pipeline
# ---------------------------------------------------------------------------


class TestCheckVerifyRateLimit:
    def test_under_threshold_is_not_exceeded(self):
        redis = _mock_redis_with_pipeline(count=5)

        with (
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
        ):
            result = check_verify_rate_limit("1.2.3.4", redis)

        assert result.exceeded is False
        assert result.retry_after is None

    def test_over_threshold_is_exceeded_with_verify_window_name(self):
        now = time.time()
        oldest = now - 10
        redis = _mock_redis_with_pipeline(count=21, oldest_in_window=[(str(oldest), oldest)])

        with (
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
            patch("django_waf.services.rate_limiter.time.time", return_value=now),
        ):
            result = check_verify_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "verify"
        assert result.retry_after == 290  # 300 - 10

    def test_exactly_at_threshold_is_not_exceeded(self):
        """count == max_requests must not breach, only count > max_requests
        does, matching check_rate_limit's own boundary."""
        redis = _mock_redis_with_pipeline(count=20)

        with (
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
        ):
            result = check_verify_rate_limit("1.2.3.4", redis)

        assert result.exceeded is False

    def test_uses_a_dedicated_redis_key_independent_of_global_windows(self):
        """The verify limiter must not share a key with check_rate_limit's
        global per-IP windows or the per-path limiter, so a burst of normal
        page traffic from an IP cannot count towards, or be counted by,
        its verify-solve budget."""
        redis = _mock_redis_with_pipeline(count=1)

        with (
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
        ):
            check_verify_rate_limit("9.9.9.9", redis)

        pipeline = redis.pipeline.return_value
        zadd_key = pipeline.zadd.call_args[0][0]
        assert zadd_key == "waf:rate:verify:9.9.9.9"
        assert "path" not in zadd_key


# ---------------------------------------------------------------------------
# VerifyView integration: breach returns 429, never a block
# ---------------------------------------------------------------------------


class TestVerifyViewRateLimit:
    def test_breach_returns_429_with_retry_after(self, settings):
        settings.DJANGO_WAF_ENABLED = True

        client = Client()
        now = time.time()
        oldest = now - 5
        redis = _mock_redis_with_pipeline(count=21, oldest_in_window=[(str(oldest), oldest)])

        with (
            patch("django_waf.views._get_redis_client", return_value=redis),
            patch("django_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
            patch("django_waf.services.rate_limiter.time.time", return_value=now),
        ):
            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "nonce99"},
            )

        assert response.status_code == 429
        assert response["Retry-After"] == "295"  # 300 - 5
        # The signature/PoW check is never reached once the limit is breached.
        mock_verify.assert_not_called()

    def test_breach_never_blocks_only_returns_429(self, settings):
        """A breach must degrade to friction (429 + Retry-After), never an
        outright block: the endpoint that exonerates a challenged user must
        stay recoverable for a false positive, per the issue's safety
        constraint."""
        settings.DJANGO_WAF_ENABLED = True

        client = Client()
        redis = _mock_redis_with_pipeline(count=999)

        with (
            patch("django_waf.views._get_redis_client", return_value=redis),
            patch("django_waf.services.challenge_service.verify_challenge_solution"),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
        ):
            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "nonce99"},
            )

        assert response.status_code == 429
        assert response.status_code != 403

    def test_under_threshold_reaches_verify_challenge_solution(self, settings):
        """A normal solve, well under the limit, is unaffected: proves the
        limit does not starve a legitimate user's 2-3 round trips."""
        settings.DJANGO_WAF_ENABLED = True

        client = Client()
        redis = _mock_redis_with_pipeline(count=1)

        with (
            patch("django_waf.views._get_redis_client", return_value=redis),
            patch("django_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("django_waf.services.challenge_service.issue_pass_cookie"),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20),
            patch.object(conf_mod, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300),
        ):
            mock_verify.return_value = True

            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "nonce99", "next": "/target/"},
            )

        assert response.status_code == 302
        mock_verify.assert_called_once()

    def test_rate_limit_redis_error_fails_open(self, settings, caplog):
        """BR-EVAL-007: if the rate-limit check itself raises (a mid-request
        Redis error distinct from the earlier "Redis unavailable" check),
        the request must still be allowed through to verify_challenge_solution,
        not blocked or 503'd. A legitimate user solving a challenge must
        never be locked out by a rate-limiter outage."""
        import logging

        settings.DJANGO_WAF_ENABLED = True

        client = Client()
        redis = _mock_redis()
        redis.pipeline.side_effect = RuntimeError("redis down mid-request")

        with (
            patch("django_waf.views._get_redis_client", return_value=redis),
            patch("django_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("django_waf.services.challenge_service.issue_pass_cookie"),
            caplog.at_level(logging.WARNING, logger="django_waf.views"),
        ):
            mock_verify.return_value = True

            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "nonce99", "next": "/target/"},
            )

        assert response.status_code == 302
        mock_verify.assert_called_once()
        assert any("rate-limit" in message for message in caplog.messages)

    def test_default_max_and_window_clear_a_real_users_round_trips(self):
        """The shipped default must comfortably exceed the 2-3 round trips
        (GET challenge, POST solution, follow redirect) a real client needs,
        with headroom for a retry after a wrong answer."""
        assert conf_mod.DJANGO_WAF_VERIFY_RATE_LIMIT_MAX >= 10
        assert conf_mod.DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS >= 60
