"""Tests for CredentialThrottleDefence and the credential-counter service.

The enumeration-safety constraint (PRD §3.6.1) is the most important
property to pin. Tests below verify that:

* The defence's verdict is identical whether the typed identifier
  exists in the system or not — the defence never consults a user
  table.
* The challenge fires on the per-IP counter only; the per-account
  counter is observation-only and never changes the user-facing
  outcome.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _redis():
    r = MagicMock(name="redis")
    # Default: pipeline().execute() returns sensible counter values.
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None  # no existing counter by default
    return r


def _ctx(*, ip="1.2.3.4", config=None):
    from django_waf.forms.defences.base import EvaluateContext

    request = MagicMock()
    request.META = {"REMOTE_ADDR": ip}
    return EvaluateContext(
        form_id="login",
        request=request,
        submitted_data={},
        config=config or {},
    )


# ---------------------------------------------------------------------------
# counters service
# ---------------------------------------------------------------------------


class TestCounters:
    def test_record_credential_failure_increments_both_counters(self):
        from django_waf.forms.services.counters import record_credential_failure

        redis = _redis()
        redis.pipeline.return_value.execute.return_value = [3, True, 7, True]
        acct, ip = record_credential_failure(redis, identifier="user@example.com", ip="1.2.3.4", window_seconds=900)

        assert acct == 3
        assert ip == 7
        # Pipeline calls: incr(acct), expire(acct), incr(ip), expire(ip)
        calls = redis.pipeline.return_value.method_calls
        method_names = [c[0] for c in calls]
        assert method_names.count("incr") == 2
        assert method_names.count("expire") == 2

    def test_record_credential_failure_hashes_identifier(self):
        """The Redis key for the account counter must contain a HASH,
        not the plain typed identifier."""
        from django_waf.forms.services.counters import record_credential_failure

        redis = _redis()
        record_credential_failure(redis, identifier="admin@example.com", ip="1.2.3.4", window_seconds=900)

        pipe_calls = redis.pipeline.return_value.method_calls
        # Find the first incr() call (account key) and inspect its argument.
        incr_calls = [c for c in pipe_calls if c[0] == "incr"]
        assert incr_calls, "no incr call recorded"
        account_key = incr_calls[0][1][0]  # first arg of first incr
        assert "admin@example.com" not in account_key
        assert account_key.startswith("waf:form:cred_fail:account:")

    def test_redis_failure_returns_zero_zero(self):
        """Redis pipeline failure must return (0, 0), not raise."""
        from django_waf.forms.services.counters import record_credential_failure

        redis = _redis()
        redis.pipeline.return_value.execute.side_effect = RuntimeError("redis down")
        acct, ip = record_credential_failure(redis, identifier="u", ip="1.2.3.4", window_seconds=900)

        assert (acct, ip) == (0, 0)

    def test_empty_identifier_does_not_touch_redis(self):
        """No identifier → no-op (defensive)."""
        from django_waf.forms.services.counters import record_credential_failure

        redis = _redis()
        record_credential_failure(redis, identifier="", ip="1.2.3.4", window_seconds=900)

        redis.pipeline.assert_not_called()

    def test_credential_ip_count_reads_without_incrementing(self):
        from django_waf.forms.services.counters import credential_ip_count

        redis = _redis()
        redis.get.return_value = b"15"
        assert credential_ip_count(redis, ip="1.2.3.4") == 15

    def test_credential_ip_count_missing_key_returns_zero(self):
        from django_waf.forms.services.counters import credential_ip_count

        redis = _redis()
        redis.get.return_value = None
        assert credential_ip_count(redis, ip="1.2.3.4") == 0


# ---------------------------------------------------------------------------
# CredentialThrottleDefence
# ---------------------------------------------------------------------------


class TestCredentialThrottleDefence:
    def _defence(self, redis_client):
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        return CredentialThrottleDefence(redis_client_factory=lambda: redis_client)

    def test_passes_when_below_threshold(self):
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        redis.get.return_value = b"5"  # well below default limit of 20
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)

        assert defence.evaluate(_ctx()).verdict == "pass"

    def test_flags_when_ip_threshold_crossed(self):
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        redis.get.return_value = b"25"  # above default limit of 20
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)
        outcome = defence.evaluate(_ctx())

        assert outcome.verdict == "flag"
        assert outcome.reason == "credential_throttle:ip"
        assert outcome.score == 5.0

    def test_per_form_ip_limit_override(self):
        """Per-form config can lower the threshold for tighter forms."""
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        redis.get.return_value = b"5"
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)
        outcome = defence.evaluate(_ctx(config={"ip_limit": 3}))

        assert outcome.verdict == "flag"

    def test_redis_failure_passes(self):
        """Counter unreadable → fail-open (don't block legitimate logins)."""
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        redis.get.side_effect = RuntimeError("redis down")
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)

        assert defence.evaluate(_ctx()).verdict == "pass"

    def test_missing_ip_passes(self):
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)
        outcome = defence.evaluate(_ctx(ip=""))

        assert outcome.verdict == "pass"

    def test_enumeration_safety_identical_verdict_regardless_of_identifier(self):
        """Critical: the verdict depends on the per-IP counter ONLY.

        The defence must not consult any user-account state. We pin
        this behaviourally by checking that two evaluations with
        wildly different identifiers but the same per-IP count
        produce identical outcomes.
        """
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        redis = _redis()
        redis.get.return_value = b"25"
        defence = CredentialThrottleDefence(redis_client_factory=lambda: redis)

        # The defence doesn't even read the identifier from submitted_data —
        # it has no API surface that would let it leak account existence.
        # We verify by constructing two contexts with the same IP and
        # asserting the outcome is byte-identical.
        ctx_a = _ctx(ip="1.2.3.4")
        ctx_b = _ctx(ip="1.2.3.4")
        ctx_a.submitted_data["username"] = "admin"
        ctx_b.submitted_data["username"] = "definitely_nonexistent_user"

        outcome_a = defence.evaluate(ctx_a)
        outcome_b = defence.evaluate(ctx_b)

        assert outcome_a == outcome_b
