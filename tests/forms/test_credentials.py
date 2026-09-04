"""Tests for waf_record_credential_failure, the public login-flow hook.

Before this fix (#141) the per-account credential counter could never
increment: no caller existed anywhere in ``src/``. These tests pin the
new public entry point that closes that gap, exercised through the
package's public import path (``from django_waf.forms import ...``)
per the PRD's documented usage.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _redis():
    r = MagicMock(name="redis")
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request(ip="1.2.3.4"):
    req = MagicMock()
    req.META = {"REMOTE_ADDR": ip}
    return req


class TestWafRecordCredentialFailure:
    def test_increments_both_counters_via_public_import(self):
        from django_waf.forms import waf_record_credential_failure

        redis = _redis()
        redis.pipeline.return_value.execute.return_value = [3, True, 7, True]

        with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
            acct, ip = waf_record_credential_failure(_request(), "user@example.com")

        assert (acct, ip) == (3, 7)
        calls = redis.pipeline.return_value.method_calls
        method_names = [c[0] for c in calls]
        assert method_names.count("incr") == 2
        assert method_names.count("expire") == 2

    def test_signal_fires_exactly_on_the_crossing(self):
        """credential_attack_observed fires only when account_count == limit.

        Not before (count < limit) and not after (count > limit, an
        attempt beyond the crossing during an ongoing attack).
        """
        import django_waf.conf as conf_mod
        from django_waf.forms import waf_record_credential_failure
        from django_waf.forms.signals import credential_attack_observed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        credential_attack_observed.connect(handler, dispatch_uid="test_crossing")
        try:
            with patch.object(conf_mod, "DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT", 5):
                for attempt_count in (3, 4, 5, 6):
                    redis = _redis()
                    redis.pipeline.return_value.execute.return_value = [attempt_count, True, 1, True]
                    with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
                        waf_record_credential_failure(_request(), "user@example.com")
        finally:
            credential_attack_observed.disconnect(dispatch_uid="test_crossing")

        assert len(received) == 1
        kwargs = received[0]
        assert kwargs["attempt_count"] == 5
        assert kwargs["window_seconds"] == conf_mod.DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW
        assert kwargs["ip"] == "1.2.3.4"
        assert "identifier_hash" in kwargs
        assert kwargs["identifier_hash"] != "user@example.com"

    def test_signal_kwargs_match_hash_identifier(self):
        from django_waf.forms import waf_record_credential_failure
        from django_waf.forms.services.counters import hash_identifier
        from django_waf.forms.signals import credential_attack_observed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        credential_attack_observed.connect(handler, dispatch_uid="test_hash_match")
        try:
            redis = _redis()
            redis.pipeline.return_value.execute.return_value = [5, True, 1, True]
            with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
                waf_record_credential_failure(_request(), "admin@example.com")
        finally:
            credential_attack_observed.disconnect(dispatch_uid="test_hash_match")

        assert len(received) == 1
        assert received[0]["identifier_hash"] == hash_identifier("admin@example.com")

    def test_redis_pipeline_failure_fails_open(self):
        """Redis outage: (0, 0), no signal, no exception."""
        from django_waf.forms import waf_record_credential_failure
        from django_waf.forms.signals import credential_attack_observed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        credential_attack_observed.connect(handler, dispatch_uid="test_fail_open")
        try:
            redis = _redis()
            redis.pipeline.return_value.execute.side_effect = RuntimeError("redis down")
            with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
                result = waf_record_credential_failure(_request(), "user@example.com")
        finally:
            credential_attack_observed.disconnect(dispatch_uid="test_fail_open")

        assert result == (0, 0)
        assert received == []

    def test_no_redis_client_available_fails_open(self):
        """get_redis_client() returning None (misconfigured backend) is a no-op."""
        from django_waf.forms import waf_record_credential_failure

        with patch("django_waf.services.redis_client.get_redis_client", return_value=None):
            result = waf_record_credential_failure(_request(), "user@example.com")

        assert result == (0, 0)

    def test_empty_identifier_no_ops(self):
        from django_waf.forms import waf_record_credential_failure

        redis = _redis()
        with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
            result = waf_record_credential_failure(_request(), "")

        assert result == (0, 0)
        redis.pipeline.assert_not_called()

    def test_missing_ip_no_ops(self):
        from django_waf.forms import waf_record_credential_failure

        redis = _redis()
        request = _request(ip="")
        with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
            result = waf_record_credential_failure(request, "user@example.com")

        assert result == (0, 0)
        redis.pipeline.assert_not_called()

    def test_signal_receiver_exception_does_not_propagate(self):
        """A misbehaving receiver must NOT break the caller's login flow."""
        from django_waf.forms import waf_record_credential_failure
        from django_waf.forms.signals import credential_attack_observed

        def broken_handler(sender, **kwargs):
            raise RuntimeError("receiver bug")

        credential_attack_observed.connect(broken_handler, dispatch_uid="test_broken_cred")
        try:
            redis = _redis()
            redis.pipeline.return_value.execute.return_value = [5, True, 1, True]
            with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
                # Must NOT raise.
                result = waf_record_credential_failure(_request(), "user@example.com")
        finally:
            credential_attack_observed.disconnect(dispatch_uid="test_broken_cred")

        assert result == (5, 1)

    def test_account_count_zero_does_not_emit(self):
        """A (0, 0) fail-open result must never emit, even if LIMIT were 0."""
        import django_waf.conf as conf_mod
        from django_waf.forms import waf_record_credential_failure
        from django_waf.forms.signals import credential_attack_observed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        credential_attack_observed.connect(handler, dispatch_uid="test_zero_no_emit")
        try:
            with patch.object(conf_mod, "DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT", 0):
                redis = _redis()
                redis.pipeline.return_value.execute.side_effect = RuntimeError("redis down")
                with patch("django_waf.services.redis_client.get_redis_client", return_value=redis):
                    result = waf_record_credential_failure(_request(), "user@example.com")
        finally:
            credential_attack_observed.disconnect(dispatch_uid="test_zero_no_emit")

        assert result == (0, 0)
        assert received == []
