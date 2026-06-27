"""Tests for RenderTokenDefence.

The foundation defence — three other defences depend on its parsed
payload. These tests pin every transition in the truth table from PRD
§3.3 (missing, invalid, expired, replayed, ip_changed, pass).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _fake_request(*, ip="1.2.3.4", ua="Mozilla/5.0", user=None):
    """Build a request-like object with the META fields the defence reads."""
    req = MagicMock()
    req.META = {"REMOTE_ADDR": ip, "HTTP_USER_AGENT": ua}
    req.user = user or MagicMock(is_authenticated=False)
    return req


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1  # marker present by default
    return r


def _defence(redis_client):
    from django_waf.forms.defences.render_token import RenderTokenDefence

    return RenderTokenDefence(redis_client_factory=lambda: redis_client)


def _render_ctx(req, form_id="contact", config=None):
    from django_waf.forms.defences.base import RenderContext

    return RenderContext(form_id=form_id, request=req, config=config or {})


def _eval_ctx(req, submitted_data, form_id="contact", config=None):
    from django_waf.forms.defences.base import EvaluateContext

    return EvaluateContext(form_id=form_id, request=req, submitted_data=submitted_data, config=config or {})


# ---------------------------------------------------------------------------
# render_fields
# ---------------------------------------------------------------------------


class TestRenderFields:
    def test_returns_token_hidden_input_tag(self, settings):
        """The fragment must be a hidden <input>, not the raw token.

        Regression: v0.11.0 returned ``mark_safe(token)`` — the bare
        base64url string. The orchestrator concatenated it into the
        DOM as visible text, no <input> ever rendered, and every real
        user POST was rejected with render_token:missing. The
        original test only checked the fragment was 'a string longer
        than 20 chars', which the raw token satisfies. Tightened to
        assert the actual DOM contract.
        """
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.render_token import TOKEN_FIELD_NAME

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = _defence(_redis())
            fields = defence.render_fields(_render_ctx(_fake_request()))

        assert TOKEN_FIELD_NAME == "waf_token"
        assert TOKEN_FIELD_NAME in fields
        fragment = fields[TOKEN_FIELD_NAME]

        # Must be a complete hidden <input>, named correctly, with a
        # non-empty value attribute.
        assert fragment.startswith(f'<input type="hidden" name="{TOKEN_FIELD_NAME}"'), (
            f"expected hidden input tag, got: {fragment!r}"
        )
        assert 'value="' in fragment
        assert fragment.rstrip().endswith(">")

        # The token must be inside value="...", not bare in the
        # fragment text — defends against a future regression that
        # leaves the token sitting next to (rather than inside) the
        # input tag.
        import re

        match = re.search(r'value="([^"]+)"', fragment)
        assert match, "no value attribute found"
        token = match.group(1)
        # base64url-ish (some implementations include padding `=`).
        assert len(token) > 20

    def test_issues_redis_marker_for_token(self, settings):
        """A fresh render must SETEX the one-shot marker."""
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            defence = _defence(redis)
            defence.render_fields(_render_ctx(_fake_request()))

        assert redis.setex.called
        key = redis.setex.call_args.args[0]
        assert key.startswith("waf:form:token:")

    def test_marker_failure_does_not_break_render(self, settings):
        """Redis down at render time must not block form rendering.

        Fail-open is the project-wide policy. Worst case: replay
        protection weakens to the token's TTL.
        """
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            redis.setex.side_effect = RuntimeError("redis down")
            defence = _defence(redis)
            fields = defence.render_fields(_render_ctx(_fake_request()))

        # Token still rendered.
        from django_waf.forms.defences.render_token import TOKEN_FIELD_NAME

        assert TOKEN_FIELD_NAME in fields


# ---------------------------------------------------------------------------
# evaluate — truth table
# ---------------------------------------------------------------------------


class TestEvaluateMissingOrInvalid:
    def test_missing_token_blocks(self, settings):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = _defence(_redis())
            outcome = defence.evaluate(_eval_ctx(_fake_request(), submitted_data={}))

        assert outcome.verdict == "block"
        assert outcome.reason == "render_token:missing"

    def test_empty_string_token_blocks(self, settings):
        """A present-but-empty token is just as bad as missing."""
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = _defence(_redis())
            outcome = defence.evaluate(_eval_ctx(_fake_request(), submitted_data={"waf_token": ""}))
        assert outcome.reason == "render_token:missing"

    def test_malformed_token_blocks(self, settings):
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = _defence(_redis())
            outcome = defence.evaluate(_eval_ctx(_fake_request(), submitted_data={"waf_token": "not-a-valid-token"}))
        assert outcome.verdict == "block"
        assert outcome.reason == "render_token:invalid"

    def test_wrong_signature_blocks(self, settings):
        """A token signed under key A doesn't validate when verified under key B."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-a"):
            token, _ = issue_token(form_id="contact", ip="1.2.3.4")

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-b"):
            defence = _defence(_redis())
            outcome = defence.evaluate(_eval_ctx(_fake_request(), submitted_data={"waf_token": token}))
        assert outcome.reason == "render_token:invalid"


class TestEvaluateExpiry:
    def test_expired_token_blocks(self, settings):
        """render_time + TTL < now → expired."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        # Token issued an hour ago, with TTL 60s — clearly expired.
        old_time = datetime.now(tz=UTC) - timedelta(hours=1)
        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="contact", ip="1.2.3.4", render_time=old_time)
            defence = _defence(_redis())
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 60},
                )
            )

        assert outcome.reason == "render_token:expired"

    def test_within_ttl_does_not_expire(self, settings):
        """A token render_time + TTL > now → not expired (other checks apply)."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="contact", ip="1.2.3.4")
            defence = _defence(_redis())
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        # Marker present (default), IP matches → pass.
        assert outcome.verdict == "pass"


class TestEvaluateReplay:
    def test_missing_marker_outside_grace_window_blocks(self, settings):
        """Marker gone + render_time older than 5s → replay."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        # Render 10 seconds ago (outside the 5s grace window).
        old_time = datetime.now(tz=UTC) - timedelta(seconds=10)
        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.2.3.4", render_time=old_time)
            redis = _redis()
            redis.exists.return_value = 0  # marker consumed
            defence = _defence(redis)
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        assert outcome.reason == "render_token:replayed"

    def test_missing_marker_inside_grace_window_passes(self, settings):
        """5s grace handles the marker-delete race between near-simultaneous submits."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        # Render 1 second ago — within the 5s grace.
        recent = datetime.now(tz=UTC) - timedelta(seconds=1)
        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.2.3.4", render_time=recent)
            redis = _redis()
            redis.exists.return_value = 0  # marker absent
            defence = _defence(redis)
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        assert outcome.verdict == "pass"

    def test_redis_unavailable_fails_open_on_replay_check(self, settings):
        """If Redis raises on exists(), treat the marker as present (fail-open).

        Project-wide policy: infrastructure outages must not lock
        legitimate users out.
        """
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.2.3.4")
            redis = _redis()
            redis.exists.side_effect = RuntimeError("redis down")
            defence = _defence(redis)
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        assert outcome.verdict == "pass"


class TestEvaluateIpBinding:
    def test_changed_ip_flags(self, settings):
        """Token issued from 1.2.3.4 then submitted from 9.9.9.9 → flag."""
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.2.3.4")
            defence = _defence(_redis())
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(ip="9.9.9.9"),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        assert outcome.verdict == "flag"
        assert outcome.reason == "render_token:ip_changed"
        assert outcome.score > 0  # actual weight pinned in PRD §3.3 — 3.0

    def test_same_ip_passes(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.2.3.4")
            defence = _defence(_redis())
            outcome = defence.evaluate(
                _eval_ctx(
                    _fake_request(ip="1.2.3.4"),
                    submitted_data={"waf_token": token},
                    config={"token_ttl": 3600},
                )
            )

        assert outcome.verdict == "pass"


# ---------------------------------------------------------------------------
# parse_submitted_payload — helper used by the orchestrator
# ---------------------------------------------------------------------------


class TestParseSubmittedPayload:
    def test_valid_token_returns_payload(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.render_token import parse_submitted_payload
        from django_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="contact", ip="1.2.3.4")
            payload = parse_submitted_payload({"waf_token": token})

        assert payload is not None
        assert payload.form_id == "contact"

    def test_missing_token_returns_none(self):
        from django_waf.forms.defences.render_token import parse_submitted_payload

        assert parse_submitted_payload({}) is None

    def test_invalid_token_returns_none(self):
        """parse_submitted_payload swallows ValueError — orchestrator
        treats None as 'no verifiable token; don't compound penalties'."""
        from django_waf.forms.defences.render_token import parse_submitted_payload

        assert parse_submitted_payload({"waf_token": "garbage"}) is None
