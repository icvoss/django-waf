"""Tests for the challenge-replay services."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Sensitive-field detection
# ---------------------------------------------------------------------------


class TestSensitiveFieldDetection:
    def test_password_fields_are_sensitive(self):
        from django_waf.forms.services.replay import is_sensitive_field

        assert is_sensitive_field("password")
        assert is_sensitive_field("user_password")
        assert is_sensitive_field("password1")  # Django default
        # Patterns are anchored on word boundaries, but the regex
        # we ship intentionally matches '_password', 'password_',
        # or bare. Pin the cases that matter.
        assert is_sensitive_field("Password")  # case-insensitive

    def test_secret_token_csrf_are_sensitive(self):
        from django_waf.forms.services.replay import is_sensitive_field

        assert is_sensitive_field("secret_key")
        assert is_sensitive_field("api_key")
        assert is_sensitive_field("csrfmiddlewaretoken")

    def test_normal_fields_pass(self):
        from django_waf.forms.services.replay import is_sensitive_field

        for name in ("email", "name", "message", "subject", "title", "body"):
            assert not is_sensitive_field(name), name


class TestFilterSensitiveFields:
    def test_strips_passwords_keeps_others(self):
        from django_waf.forms.services.replay import filter_sensitive_fields

        data = {"username": "alice", "password": "hunter2", "subject": "hi"}
        filtered = filter_sensitive_fields(data)

        assert "password" not in filtered
        assert filtered["username"] == "alice"
        assert filtered["subject"] == "hi"


# ---------------------------------------------------------------------------
# Replay-token signing
# ---------------------------------------------------------------------------


class TestReplayToken:
    def test_round_trip(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.services.replay import (
            issue_replay_token,
            verify_replay_token,
        )

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token = issue_replay_token(form_id="contact", ip="1.2.3.4", session_key="abc")
            payload = verify_replay_token(token, current_ip="1.2.3.4")

        assert payload is not None
        assert payload["form_id"] == "contact"
        assert payload["session_key"] == "abc"

    def test_ip_mismatch_fails(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.services.replay import issue_replay_token, verify_replay_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token = issue_replay_token(form_id="c", ip="1.2.3.4", session_key="abc")
            payload = verify_replay_token(token, current_ip="9.9.9.9")

        assert payload is None

    def test_tampered_token_fails(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.services.replay import issue_replay_token, verify_replay_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token = issue_replay_token(form_id="c", ip="1.2.3.4", session_key="abc")
            # Flip a character mid-token.
            tampered = token[:-3] + ("A" if token[-3] != "A" else "B") + token[-2:]
            payload = verify_replay_token(tampered, current_ip="1.2.3.4")

        assert payload is None

    def test_wrong_key_fails(self, settings):
        """Token issued under key A doesn't verify under key B."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.replay import issue_replay_token, verify_replay_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-a"):
            token = issue_replay_token(form_id="c", ip="1.2.3.4", session_key="abc")
        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-b"):
            payload = verify_replay_token(token, current_ip="1.2.3.4")

        assert payload is None

    def test_expired_token_fails(self, settings):
        """Tokens past their 60s TTL must not verify."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.replay import issue_replay_token, verify_replay_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token = issue_replay_token(form_id="c", ip="1.2.3.4", session_key="abc")
            # Patch time.time so the verifier sees the token as expired.
            with patch("django_waf.forms.services.replay.time.time", return_value=time.time() + 120):
                payload = verify_replay_token(token, current_ip="1.2.3.4")

        assert payload is None

    def test_empty_or_garbage_returns_none(self):
        from django_waf.forms.services.replay import verify_replay_token

        assert verify_replay_token("", current_ip="1.2.3.4") is None
        assert verify_replay_token("not!!base64!!", current_ip="1.2.3.4") is None


# ---------------------------------------------------------------------------
# Session storage
# ---------------------------------------------------------------------------


class _FakeSession(dict):
    """A dict that also supports the ``.modified`` attribute Django uses."""

    modified = False


class TestSessionStorage:
    def _request_with_session(self):
        req = MagicMock()
        req.session = _FakeSession()
        return req

    def test_store_and_fetch_round_trip(self):
        from django_waf.forms.services.replay import fetch_from_session, store_in_session

        req = self._request_with_session()
        key = store_in_session(
            req,
            form_id="contact",
            post_url="/contact/",
            data={"name": "alice", "email": "a@b.com"},
        )
        record = fetch_from_session(req, session_key=key)

        assert record["form_id"] == "contact"
        assert record["data"]["name"] == "alice"

    def test_passwords_stripped_before_storage(self):
        from django_waf.forms.services.replay import fetch_from_session, store_in_session

        req = self._request_with_session()
        key = store_in_session(
            req,
            form_id="login",
            post_url="/login/",
            data={"username": "alice", "password": "hunter2"},
        )
        record = fetch_from_session(req, session_key=key)

        assert "password" not in record["data"]
        assert record["data"]["username"] == "alice"

    def test_session_missing_returns_none(self):
        from django_waf.forms.services.replay import store_in_session

        req = MagicMock(spec=[])  # no .session attr
        assert store_in_session(req, form_id="c", post_url="/c/", data={}) is None

    def test_discard_removes_record(self):
        from django_waf.forms.services.replay import (
            discard_from_session,
            fetch_from_session,
            store_in_session,
        )

        req = self._request_with_session()
        key = store_in_session(req, form_id="c", post_url="/c/", data={"a": "1"})
        assert fetch_from_session(req, session_key=key) is not None
        discard_from_session(req, session_key=key)
        assert fetch_from_session(req, session_key=key) is None

    def test_cap_keeps_at_most_five_records(self):
        """Session bloat protection — don't let stale flagged forms
        accumulate indefinitely under one session."""
        from django_waf.forms.services.replay import store_in_session

        req = self._request_with_session()
        keys = []
        for i in range(7):
            k = store_in_session(req, form_id=f"f{i}", post_url="/", data={"i": str(i)})
            keys.append(k)
            # Walk the timer so the cap's age-sort is meaningful.
            time.sleep(0.001)

        stash = req.session["waf_form_replay"]
        assert len(stash) == 5
