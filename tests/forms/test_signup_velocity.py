"""Tests for SignupVelocityDefence + the signup counter."""

from __future__ import annotations

from unittest.mock import MagicMock


def _redis():
    r = MagicMock(name="redis")
    pipe = MagicMock()
    pipe.execute.return_value = [1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _ctx(*, ip="1.2.3.4", config=None):
    from icv_waf.forms.defences.base import EvaluateContext

    request = MagicMock()
    request.META = {"REMOTE_ADDR": ip}
    return EvaluateContext(
        form_id="signup",
        request=request,
        submitted_data={},
        config=config or {},
    )


class TestSignupCounter:
    def test_record_signup_returns_new_count(self):
        from icv_waf.forms.services.counters import record_signup

        redis = _redis()
        redis.pipeline.return_value.execute.return_value = [4, True]
        assert record_signup(redis, ip="1.2.3.4", window_seconds=86400) == 4

    def test_record_signup_redis_failure_returns_zero(self):
        from icv_waf.forms.services.counters import record_signup

        redis = _redis()
        redis.pipeline.return_value.execute.side_effect = RuntimeError("redis down")
        assert record_signup(redis, ip="1.2.3.4", window_seconds=86400) == 0

    def test_signup_count_reads_without_incrementing(self):
        from icv_waf.forms.services.counters import signup_count

        redis = _redis()
        redis.get.return_value = b"7"
        assert signup_count(redis, ip="1.2.3.4") == 7
        # pipeline / incr should not have been touched.
        redis.pipeline.assert_not_called()

    def test_empty_ip_returns_zero(self):
        from icv_waf.forms.services.counters import record_signup, signup_count

        redis = _redis()
        assert record_signup(redis, ip="", window_seconds=86400) == 0
        assert signup_count(redis, ip="") == 0


class TestSignupVelocityDefence:
    def test_passes_when_below_threshold(self):
        from icv_waf.forms.defences.signup_velocity import SignupVelocityDefence

        redis = _redis()
        redis.get.return_value = b"3"
        defence = SignupVelocityDefence(redis_client_factory=lambda: redis)

        assert defence.evaluate(_ctx()).verdict == "pass"

    def test_flags_when_threshold_crossed(self):
        from icv_waf.forms.defences.signup_velocity import SignupVelocityDefence

        redis = _redis()
        redis.get.return_value = b"10"  # well over default limit of 5
        defence = SignupVelocityDefence(redis_client_factory=lambda: redis)
        outcome = defence.evaluate(_ctx())

        assert outcome.verdict == "flag"
        assert outcome.reason == "signup_velocity:ip"
        assert outcome.score == 5.0

    def test_per_form_limit_override(self):
        from icv_waf.forms.defences.signup_velocity import SignupVelocityDefence

        redis = _redis()
        redis.get.return_value = b"5"
        defence = SignupVelocityDefence(redis_client_factory=lambda: redis)
        # Tighter limit (2) — 5 trips it.
        assert defence.evaluate(_ctx(config={"limit": 2})).verdict == "flag"
        # Looser limit (10) — 5 doesn't trip.
        assert defence.evaluate(_ctx(config={"limit": 10})).verdict == "pass"

    def test_redis_failure_passes(self):
        from icv_waf.forms.defences.signup_velocity import SignupVelocityDefence

        redis = _redis()
        redis.get.side_effect = RuntimeError("redis down")
        defence = SignupVelocityDefence(redis_client_factory=lambda: redis)

        assert defence.evaluate(_ctx()).verdict == "pass"

    def test_missing_ip_passes(self):
        from icv_waf.forms.defences.signup_velocity import SignupVelocityDefence

        redis = _redis()
        defence = SignupVelocityDefence(redis_client_factory=lambda: redis)
        assert defence.evaluate(_ctx(ip="")).verdict == "pass"
