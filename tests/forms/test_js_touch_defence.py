"""Tests for JsTouchDefence."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _ctx_render(form_id="c", config=None):
    from django_waf.forms.defences.base import RenderContext

    return RenderContext(form_id=form_id, request=MagicMock(), config=config or {})


def _ctx_eval(submitted_data, *, payload_nonce=None, config=None):
    """Build EvaluateContext. payload_nonce sets ctx.token_payload.nonce."""
    from django_waf.forms.defences.base import EvaluateContext

    payload = None
    if payload_nonce is not None:
        payload = MagicMock()
        payload.nonce = payload_nonce

    return EvaluateContext(
        form_id="c",
        request=MagicMock(),
        submitted_data=submitted_data,
        config=config or {},
        token_payload=payload,
    )


class TestRenderFields:
    def test_renders_hidden_field_with_sentinel(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            html = defence.render_fields(_ctx_render())[FIELD_NAME]

        assert f'name="{FIELD_NAME}"' in html
        assert 'value="unset"' in html
        assert "aria-hidden=" in html
        assert "tabindex=" in html

    def test_includes_inline_script_that_clears_sentinel(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            html = defence.render_fields(_ctx_render())[FIELD_NAME]

        # The script must reference the input and reassign its value.
        assert "<script" in html
        assert "_waf_js_touch_input" in html
        assert ".value=" in html

    def test_uses_offscreen_positioning_not_display_none(self, settings):
        """Same accessibility-friendly hiding pattern as honeypot."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            html = defence.render_fields(_ctx_render())[FIELD_NAME]

        assert "position:absolute" in html
        assert "display:none" not in html


class TestEvaluate:
    def test_sentinel_unchanged_flags(self, settings):
        """JS didn't run → field is still 'unset' → flag."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            outcome = defence.evaluate(_ctx_eval({FIELD_NAME: "unset"}, payload_nonce="n"))

        assert outcome.verdict == "flag"
        assert outcome.reason == "js_touch:not_set"
        assert outcome.score == 1.5

    def test_correct_value_passes(self, settings):
        """Browser executed the script → field contains the expected MAC → pass."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence, _expected_value

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            expected = _expected_value("nonce-xyz")
            outcome = defence.evaluate(_ctx_eval({FIELD_NAME: expected}, payload_nonce="nonce-xyz"))

        assert outcome.verdict == "pass"

    def test_missing_field_flags(self, settings):
        """Field entirely absent → suspicious (hand-crafted POST)."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            outcome = defence.evaluate(_ctx_eval({}, payload_nonce="n"))

        assert outcome.verdict == "flag"
        assert outcome.reason == "js_touch:missing"

    def test_arbitrary_value_flags(self, settings):
        """A non-empty value that isn't the correct MAC → bot wrote junk."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import FIELD_NAME, JsTouchDefence

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            defence = JsTouchDefence()
            outcome = defence.evaluate(_ctx_eval({FIELD_NAME: "definitely-not-the-right-value"}, payload_nonce="n"))

        assert outcome.verdict == "flag"
        assert outcome.reason == "js_touch:invalid"

    def test_expected_value_is_signing_key_dependent(self, settings):
        """Same nonce + different signing keys → different expected values.

        Otherwise a bot could compute the expected value once and reuse.
        """
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.js_touch import _expected_value

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-a"):
            value_a = _expected_value("same-nonce")
        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "key-b"):
            value_b = _expected_value("same-nonce")

        assert value_a != value_b
