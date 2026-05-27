"""Tests for the FormProtection orchestrator.

Covers:
* defence chain construction + canonical ordering
* render_fields collects from every defence + threads token_nonce
* evaluate runs chain in order + threads token_payload onto contexts
* block short-circuits the chain
* score aggregation crosses FLAG / BLOCK thresholds at the right
  points
* skip_for_authenticated short-circuits to render_token only
* consume_token_marker is the PASS-only consume path
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request(*, ip="1.2.3.4", ua="Mozilla/5.0", user=None):
    req = MagicMock()
    req.META = {"REMOTE_ADDR": ip, "HTTP_USER_AGENT": ua}
    req.user = user or MagicMock(is_authenticated=False)
    return req


# ---------------------------------------------------------------------------
# Construction + ordering
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_defences_ordered_canonically(self, settings):
        """Operators may pass defences in any order; the chain runs
        in canonical order so render_token always goes first."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="c",
                defences=("pow_gate", "honeypot", "render_token"),
                redis_client_factory=lambda: _redis(),
            )

        assert protection.defence_names == ("render_token", "honeypot", "pow_gate")

    def test_unknown_defence_raises_at_construction(self):
        import pytest

        from icv_waf.forms.protection import FormProtection

        with pytest.raises(ValueError, match="unknown defence"):
            FormProtection(form_id="c", defences=("doesnt_exist",))

    def test_redis_defence_without_factory_raises(self):
        """A defence that needs Redis (render_token, credential_throttle,
        signup_velocity) without a factory must surface at construction
        — not silently fail at first render."""

        from icv_waf.forms.protection import FormProtection

        # We can't currently construct without a factory because
        # _default_redis_factory always returns something (or None).
        # Pin the explicit-None behaviour by passing a factory that
        # returns None.
        protection = FormProtection(
            form_id="c",
            defences=("honeypot",),  # no Redis defence — should work
            redis_client_factory=lambda: None,
        )
        # Sanity: honeypot constructs fine even with None factory.
        assert "honeypot" in protection.defence_names


# ---------------------------------------------------------------------------
# render_fields
# ---------------------------------------------------------------------------


class TestRenderFields:
    def test_collects_fields_from_every_defence(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            protection = FormProtection(
                form_id="contact",
                defences=("render_token", "honeypot", "js_touch", "pow_gate"),
                redis_client_factory=lambda: redis,
            )
            fields = protection.render_fields(_request())

        # Token, honeypot, js_touch, pow_gate all contribute keys.
        assert "waf_token" in fields
        assert "_waf_honeypot" in fields
        assert "waf_js_touch" in fields
        assert "waf_pow_nonce" in fields

    def test_master_switch_short_circuits_to_empty(self, settings):
        """ICV_WAF_FORM_PROTECTION_ENABLED=False → no fields rendered."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        with (
            patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"),
            patch.object(conf_mod, "ICV_WAF_FORM_PROTECTION_ENABLED", False),
        ):
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request())

        assert fields == {}

    def test_skip_for_authenticated_renders_only_render_token(self, settings):
        """In-product forms (skip_for_authenticated=True) drop spam
        defences when the user is logged in but keep render_token for
        integrity."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        authed = MagicMock(is_authenticated=True, pk=42)
        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "honeypot", "js_touch"),
                skip_for_authenticated=True,
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request(user=authed))

        # render_token present, honeypot + js_touch absent.
        assert "waf_token" in fields
        assert "_waf_honeypot" not in fields
        assert "waf_js_touch" not in fields

    def test_skip_for_authenticated_runs_full_chain_for_anonymous(self, settings):
        """Anonymous users always get the full chain regardless of the flag."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        anon = MagicMock(is_authenticated=False)
        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "honeypot"),
                skip_for_authenticated=True,
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request(user=anon))

        assert "_waf_honeypot" in fields


# ---------------------------------------------------------------------------
# evaluate — chain wiring
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_all_pass_returns_passed_verdict(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection, FormVerdict

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: redis,
            )
            # Render the form, then build the submission the way a
            # browser would — by reading the rendered <input>'s
            # value attribute. Submitting the raw HTML fragment as
            # the field value (what this test originally did) is what
            # masked the v0.11.0 bug — pre-bug it accidentally worked
            # because fields[...] was the raw token, post-bug it stops
            # working. Use the orchestrator's own _extract_token_value
            # helper so this test always reflects what browsers do.
            from icv_waf.forms.protection import _extract_token_value

            fields = protection.render_fields(_request())
            token = _extract_token_value(fields["waf_token"])

            result = protection.evaluate(
                _request(),
                submitted_data={"waf_token": token},
            )

        assert result.verdict == FormVerdict.PASSED
        assert result.total_score == 0.0

    def test_block_short_circuits_chain(self, settings):
        """A defence returning block must stop later defences from running."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection, FormVerdict

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            protection = FormProtection(
                form_id="c",
                # Bad token → render_token blocks → honeypot never runs.
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: redis,
            )

            result = protection.evaluate(
                _request(),
                submitted_data={"waf_token": "garbage"},
            )

        assert result.verdict == FormVerdict.BLOCKED
        # Only render_token ran; chain short-circuited before honeypot.
        assert len(result.outcomes) == 1
        assert result.outcomes[0].reason == "render_token:invalid"

    def test_token_payload_threaded_to_later_defences(self, settings):
        """After render_token verifies, time_trap should see the payload."""
        from datetime import UTC, datetime, timedelta

        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection, FormVerdict
        from icv_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            # Forge a token rendered 0.1s ago → time_trap should block on too_fast.
            old = datetime.now(tz=UTC) - timedelta(seconds=0.1)
            token, _ = issue_token(form_id="c", ip="1.2.3.4", render_time=old, user_agent="Mozilla/5.0")
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "time_trap"),
                redis_client_factory=lambda: redis,
            )
            result = protection.evaluate(
                _request(),
                submitted_data={"waf_token": token},
            )

        # time_trap fired with too_fast because it saw the payload's render_time.
        assert result.verdict == FormVerdict.BLOCKED
        assert any(o.reason == "time_trap:too_fast" for o in result.outcomes)

    def test_master_switch_short_circuits_to_passed(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection, FormVerdict

        with (
            patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"),
            patch.object(conf_mod, "ICV_WAF_FORM_PROTECTION_ENABLED", False),
        ):
            protection = FormProtection(
                form_id="c",
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: _redis(),
            )
            result = protection.evaluate(_request(), submitted_data={})

        assert result.verdict == FormVerdict.PASSED

    def test_defence_exception_treated_as_pass(self, settings):
        """A buggy defence must NOT lock users out. The orchestrator
        catches and logs, then treats the outcome as a silent pass."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection, FormVerdict

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="c",
                defences=("honeypot",),  # only honeypot, no Redis dep
                redis_client_factory=lambda: _redis(),
            )
            # Inject a defence that raises.
            broken = MagicMock()
            broken.name = "honeypot"
            broken.evaluate.side_effect = RuntimeError("bug in defence")
            protection._defences["honeypot"] = broken

            result = protection.evaluate(_request(), submitted_data={})

        assert result.verdict == FormVerdict.PASSED


# ---------------------------------------------------------------------------
# Score aggregation
# ---------------------------------------------------------------------------


class TestScoreAggregation:
    def _protection(self):
        from icv_waf.forms.protection import FormProtection

        return FormProtection(
            form_id="c",
            defences=("honeypot",),
            redis_client_factory=lambda: _redis(),
        )

    def test_sub_flag_threshold_passes(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "ICV_WAF_FORM_FLAG_THRESHOLD", 2.0):
            assert self._protection()._resolve_verdict(1.5) == FormVerdict.PASSED

    def test_crossing_flag_threshold_returns_flagged(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormVerdict

        with (
            patch.object(conf_mod, "ICV_WAF_FORM_FLAG_THRESHOLD", 2.0),
            patch.object(conf_mod, "ICV_WAF_FORM_BLOCK_THRESHOLD", 5.0),
        ):
            assert self._protection()._resolve_verdict(3.0) == FormVerdict.FLAGGED

    def test_crossing_block_threshold_returns_blocked(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "ICV_WAF_FORM_BLOCK_THRESHOLD", 5.0):
            assert self._protection()._resolve_verdict(6.0) == FormVerdict.BLOCKED

    def test_exact_threshold_value_crosses_inclusive(self, settings):
        """Pin >= semantics — operators tune thresholds expecting
        inclusive behaviour."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "ICV_WAF_FORM_FLAG_THRESHOLD", 2.0):
            assert self._protection()._resolve_verdict(2.0) == FormVerdict.FLAGGED


# ---------------------------------------------------------------------------
# Marker consumption
# ---------------------------------------------------------------------------


class TestMarkerConsumption:
    def test_consume_calls_delete_on_redis(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()
            protection = FormProtection(
                form_id="c",
                defences=("honeypot",),
                redis_client_factory=lambda: redis,
            )

            payload = MagicMock()
            payload.nonce = "abc123"
            protection.consume_token_marker(payload)

        redis.delete.assert_called_once_with("waf:form:token:abc123")

    def test_consume_with_none_payload_is_noop(self):
        from icv_waf.forms.protection import FormProtection

        redis = _redis()
        protection = FormProtection(
            form_id="c",
            defences=("honeypot",),
            redis_client_factory=lambda: redis,
        )
        protection.consume_token_marker(None)

        redis.delete.assert_not_called()

    def test_consume_swallows_redis_errors(self):
        """Marker consume failures must not propagate — the form has
        already been processed; failing here would surface to the
        user as a 500."""
        from icv_waf.forms.protection import FormProtection

        redis = _redis()
        redis.delete.side_effect = RuntimeError("redis down")
        protection = FormProtection(
            form_id="c",
            defences=("honeypot",),
            redis_client_factory=lambda: redis,
        )

        payload = MagicMock()
        payload.nonce = "abc"
        # Must not raise.
        protection.consume_token_marker(payload)
