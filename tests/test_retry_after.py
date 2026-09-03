"""Tests for accurate Retry-After from sliding-window rate limiting (#30).

Previously ``retry_after = window_seconds - (now - cutoff)`` where
``cutoff = now - window_seconds`` algebraically collapses to a constant
``0`` every time, so ``max(1, 0)`` always sent a fixed 1 second internally
and the middleware sent a fixed 60-second header regardless of real state
(EvaluationResult had no retry_after field at all, so
``hasattr(result, "retry_after")`` was always False on the real NamedTuple
too, a double bug).

The fix makes the sliding-window limiter return
``oldest_event_in_window + window_seconds - now``: the real number of
seconds until the window's oldest counted event ages out, computed via a
``ZRANGE(0, 0, withscores=True)`` in the same Redis pipeline (atomic with
the ZADD/ZREMRANGEBYSCORE/ZCARD it already ran). ``EvaluationResult`` now
carries a ``retry_after`` field populated on THROTTLED verdicts, and the
middleware sends that value instead of a fixed fallback.

Redis is not available in the test environment; all Redis calls are mocked
using unittest.mock, matching the pattern in test_services.py.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from django.http import HttpResponse
from django.test import RequestFactory

from django_waf.enums import RuleAction, Verdict
from django_waf.services.rate_limiter import RateLimitResult, _retry_after_from_oldest, check_rate_limit
from django_waf.services.rule_engine import EvaluationResult


def _make_redis() -> MagicMock:
    redis = MagicMock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 1
    redis.incr.return_value = 1
    redis.zcount.return_value = 0
    return redis


# ---------------------------------------------------------------------------
# _retry_after_from_oldest, pure maths, no Redis
# ---------------------------------------------------------------------------


class TestRetryAfterFromOldest:
    def test_computes_seconds_until_oldest_event_ages_out(self):
        """retry_after is oldest_timestamp + window_seconds - now, not a constant."""
        now = 1_000_000.0
        oldest_timestamp = now - 45  # added 45 seconds ago
        window_seconds = 60

        retry_after = _retry_after_from_oldest([(str(oldest_timestamp), oldest_timestamp)], window_seconds, now)

        # Ages out at oldest_timestamp + 60 = now + 15
        assert retry_after == 15

    def test_freshly_added_event_gives_nearly_full_window(self):
        """An event added right now must retry after ~the full window, not 1 second."""
        now = 1_000_000.0

        retry_after = _retry_after_from_oldest([(str(now), now)], 60, now)

        assert retry_after == 60

    def test_floors_at_one_second(self):
        """A window boundary computed as <=0 (clock skew, rounding) floors at 1."""
        now = 1_000_000.0
        oldest_timestamp = now - 61  # already past a 60s window

        retry_after = _retry_after_from_oldest([(str(oldest_timestamp), oldest_timestamp)], 60, now)

        assert retry_after == 1

    def test_empty_oldest_falls_back_to_full_window(self):
        """No ZRANGE result (should not happen with a real Redis, but a
        stub might) falls back to the full window rather than raising."""
        retry_after = _retry_after_from_oldest([], 60, time.time())

        assert retry_after == 60


# ---------------------------------------------------------------------------
# check_rate_limit, concrete Retry-After values via the pipeline
# ---------------------------------------------------------------------------


class TestCheckRateLimitConcreteRetryAfter:
    def test_global_window_retry_after_matches_oldest_event_age(self):
        """When the 1s burst window is breached, retry_after reflects the
        oldest surviving event's age, not a fixed 1."""
        import django_waf.conf as conf_mod

        redis = _make_redis()
        now = time.time()
        oldest = now - 0.4  # added 0.4s ago, inside the 1s window

        pipeline = MagicMock()
        pipeline.execute.return_value = [1, 0, 6, [(str(oldest), oldest)], True]
        redis.pipeline.return_value = pipeline

        with (
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600),
            patch("django_waf.services.rate_limiter.time.time", return_value=now),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "1s"
        # Ages out at oldest + 1s = now + 0.6s → rounds down to 0? No: int()
        # truncates toward zero, and 0 would violate the floor, so this
        # must be at least 1.
        assert result.retry_after >= 1
        # The oldest event is 0.4s old in a 1s window, so ~0.6s remain,
        # truncated to 0 by int(), then floored to 1. Assert the exact
        # floored value to catch a regression to the old constant-0 maths.
        assert result.retry_after == 1

    def test_retry_after_scales_with_window_occupancy(self):
        """A per-path window whose oldest event is fresher yields a longer
        retry_after than one whose oldest event is stale, proving the
        value tracks real occupancy rather than being a fixed constant."""
        import django_waf.conf as conf_mod

        now = 1_500_000_000.0
        window_seconds = 60

        def _run_with_oldest_age(age_seconds: float) -> int:
            redis = _make_redis()
            oldest = now - age_seconds
            pipeline = MagicMock()
            pipeline.execute.return_value = [1, 0, 11, [(str(oldest), oldest)], True]
            redis.pipeline.return_value = pipeline

            with (
                patch.object(conf_mod, "DJANGO_WAF_RATE_LIMIT_PATHS", {"/api/": (10, window_seconds)}),
                patch("django_waf.services.rate_limiter.time.time", return_value=now),
            ):
                result = check_rate_limit("9.9.9.9", redis, path="/api/widgets/")
            return result.retry_after

        fresh_retry_after = _run_with_oldest_age(5)  # oldest event 5s old
        stale_retry_after = _run_with_oldest_age(55)  # oldest event 55s old

        assert fresh_retry_after == 55  # 60 - 5
        assert stale_retry_after == 5  # 60 - 55
        assert fresh_retry_after > stale_retry_after


# ---------------------------------------------------------------------------
# EvaluationResult.retry_after, populated on THROTTLED, absent elsewhere
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEvaluationResultRetryAfter:
    def test_throttled_verdict_carries_rate_limiter_retry_after(self):
        from django_waf.services.rule_engine import evaluate_request

        redis = _make_redis()
        with patch(
            "django_waf.services.rate_limiter.check_rate_limit",
            return_value=RateLimitResult(exceeded=True, window="1m", retry_after=37),
        ):
            result = evaluate_request(
                ip_address="16.16.16.16",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.THROTTLED
        assert result.retry_after == 37

    def test_non_throttled_verdict_has_no_retry_after(self):
        """Every other verdict path leaves retry_after at its None default."""
        redis = _make_redis()
        pipeline = MagicMock()
        now = time.time()
        pipeline.execute.return_value = [1, 0, 1, [(str(now), now)], True]
        redis.pipeline.return_value = pipeline
        redis.zcount.return_value = 5

        from django_waf.services.rule_engine import evaluate_request

        result = evaluate_request(
            ip_address="17.17.17.17",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.ALLOWED
        assert result.retry_after is None

    def test_evaluation_result_default_retry_after_is_none(self):
        """Construction sites that predate #30 (positional/keyword without
        retry_after) still work, defaulting to None."""
        result = EvaluationResult(
            verdict=Verdict.BLOCKED,
            action=RuleAction.BLOCK,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
        )

        assert result.retry_after is None


# ---------------------------------------------------------------------------
# Middleware, sends the real Retry-After header, not a fixed fallback
# ---------------------------------------------------------------------------


class TestMiddlewareSendsAccurateRetryAfter:
    def _run_with_result(self, result: EvaluationResult) -> HttpResponse:
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
            mock_redis_fn.return_value = _make_redis()
            mock_validate.return_value = False
            mock_eval.return_value = result

            middleware = WafMiddleware(get_response)
            with patch("django_waf.conf.DJANGO_WAF_ENABLED", True):
                response = middleware(request)

        return response

    def test_sends_real_retry_after_value(self):
        result = EvaluationResult(
            verdict=Verdict.THROTTLED,
            action=RuleAction.THROTTLE,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
            retry_after=23,
        )

        response = self._run_with_result(result)

        assert response.status_code == 429
        assert response["Retry-After"] == "23"

    def test_falls_back_to_60_when_retry_after_is_none(self):
        result = EvaluationResult(
            verdict=Verdict.THROTTLED,
            action=RuleAction.THROTTLE,
            matched_rule_id=None,
            matched_rule_type="",
            anomaly_score=None,
            retry_after=None,
        )

        response = self._run_with_result(result)

        assert response.status_code == 429
        assert response["Retry-After"] == "60"
