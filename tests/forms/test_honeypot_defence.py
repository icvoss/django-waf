"""Tests for HoneypotDefence.

The simplest defence by mechanism but the one most likely to produce
false positives if the rendered HTML is wrong (password manager
autofill, accessibility-tool interaction). These tests pin the
accessibility attributes alongside the verdict logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _ctx_render(form_id="contact", config=None):
    from django_waf.forms.defences.base import RenderContext

    return RenderContext(form_id=form_id, request=MagicMock(), config=config or {})


def _ctx_eval(submitted_data, form_id="contact", config=None):
    from django_waf.forms.defences.base import EvaluateContext

    return EvaluateContext(
        form_id=form_id,
        request=MagicMock(),
        submitted_data=submitted_data,
        config=config or {},
    )


# ---------------------------------------------------------------------------
# Field-name rotation
# ---------------------------------------------------------------------------


class TestFieldNameRotation:
    def test_same_form_id_picks_same_names(self):
        """Idempotent — must be stable across renders so caches don't break."""
        from django_waf.forms.defences.honeypot import _pick_field_names

        pool = ["url", "website", "homepage", "email_confirm"]
        a = _pick_field_names("contact", pool, 2)
        b = _pick_field_names("contact", pool, 2)
        assert a == b

    def test_different_form_ids_can_pick_different_names(self):
        """Some pair of form_ids in the pool must yield different selections.

        We assert 'at least one pair differs' rather than 'every pair
        differs' because a 4-element pool with 2-name picks has a
        non-trivial collision rate by design.
        """
        from django_waf.forms.defences.honeypot import _pick_field_names

        pool = ["url", "website", "homepage", "email_confirm"]
        picks = {fid: _pick_field_names(fid, pool, 2) for fid in ("a", "b", "c", "d", "e", "f")}
        assert len({tuple(v) for v in picks.values()}) > 1

    def test_empty_pool_returns_no_fields(self):
        """An operator who configures an empty pool gets no honeypot."""
        from django_waf.forms.defences.honeypot import _pick_field_names

        assert _pick_field_names("contact", [], 2) == []

    def test_count_larger_than_pool_caps_at_pool_size(self):
        """No duplicate names if the operator asks for more than the pool has."""
        from django_waf.forms.defences.honeypot import _pick_field_names

        pool = ["a", "b"]
        names = _pick_field_names("contact", pool, 10)
        assert len(names) == len(pool)
        assert len(set(names)) == len(names)


# ---------------------------------------------------------------------------
# render_fields
# ---------------------------------------------------------------------------


class TestRenderFields:
    def test_returns_hidden_inputs(self):
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        fields = defence.render_fields(_ctx_render())

        assert "_waf_honeypot" in fields
        html = fields["_waf_honeypot"]
        assert html.count("<input") == 2  # default _FIELDS_PER_FORM

    def test_html_includes_accessibility_attributes(self):
        """Hidden inputs must have autocomplete=off, tabindex=-1, aria-label.

        Pin behaviour — accessibility is non-negotiable and the
        attributes are what make honeypots safe for screen reader
        users.
        """
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        html = defence.render_fields(_ctx_render())["_waf_honeypot"]

        assert 'autocomplete="off"' in html
        assert 'tabindex="-1"' in html
        assert "aria-label=" in html

    def test_uses_offscreen_positioning_not_display_none(self):
        """`display:none` is what bots check for — must use off-screen instead."""
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        html = defence.render_fields(_ctx_render())["_waf_honeypot"]

        assert "position:absolute" in html
        assert "display:none" not in html

    def test_unsafe_pool_names_are_silently_dropped(self):
        """HTML-special characters in a pool name must NOT survive into the DOM.

        We assert the structural characters are gone (no `<`, `>`,
        `"`, `'`, `/` that could escape the input attribute or open a
        new tag). The plain-letter remnants left behind by aggressive
        stripping are harmless — they'd just produce a weirdly-named
        input field.
        """
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        html = defence.render_fields(_ctx_render(config={"field_names": ['"><script>alert(1)</script>']}))[
            "_waf_honeypot"
        ]

        # No tag injection possible — these are the characters that
        # would let the name field escape its attribute context.
        for char in ('"', "'", "<", ">", "/", "\\"):
            assert char not in _name_attribute_value(html), f"unsafe char {char!r} survived into name attribute"

    def test_empty_pool_renders_no_fields(self):
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        fields = defence.render_fields(_ctx_render(config={"field_names": []}))

        assert fields == {}


def _name_attribute_value(html: str) -> str:
    """Extract the substring inside name=\"...\" — what the browser sees."""
    import re

    m = re.search(r'name="([^"]*)"', html)
    return m.group(1) if m else ""


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_empty_honeypot_fields_pass(self):
        """Default case — humans don't fill hidden fields."""
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        outcome = defence.evaluate(_ctx_eval({}))

        assert outcome.verdict == "pass"

    def test_any_filled_honeypot_field_blocks(self):
        """Bot fills every input → the honeypot fields are non-empty → block."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.honeypot import HoneypotDefence, _pick_field_names

        pool = conf_mod.DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES
        names = _pick_field_names("contact", pool, 2)
        defence = HoneypotDefence()
        # Simulate a bot filling the first honeypot.
        outcome = defence.evaluate(_ctx_eval({names[0]: "spam value"}))

        assert outcome.verdict == "block"
        assert outcome.reason == f"honeypot:{names[0]}"
        assert outcome.score == 5.0

    def test_reason_carries_specific_field_name(self):
        """Operators tune the pool when one name keeps tripping —
        the reason needs the specific field name."""
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.honeypot import HoneypotDefence, _pick_field_names

        pool = conf_mod.DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES
        names = _pick_field_names("contact", pool, 2)
        defence = HoneypotDefence()

        # Fill the second honeypot, not the first.
        outcome = defence.evaluate(_ctx_eval({names[1]: "spam"}))

        assert outcome.reason == f"honeypot:{names[1]}"

    def test_whitespace_only_value_is_not_a_block(self):
        """A field whose value is whitespace-only is treated as empty.

        Some browsers / autofill tools insert a single space. Don't
        block on that; the real signal is meaningful content.
        """
        import django_waf.conf as conf_mod
        from django_waf.forms.defences.honeypot import HoneypotDefence, _pick_field_names

        pool = conf_mod.DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES
        names = _pick_field_names("contact", pool, 2)
        defence = HoneypotDefence()
        outcome = defence.evaluate(_ctx_eval({names[0]: ""}))

        assert outcome.verdict == "pass"

    def test_filled_field_not_in_this_forms_pool_is_ignored(self):
        """A POST containing a value under a name that ISN'T this form's
        honeypot must pass — bots that submit a global field set would
        otherwise always be blocked, which is the desired behaviour for
        the configured names, but unrelated form fields with the same
        name shouldn't accidentally trip the defence."""
        from django_waf.forms.defences.honeypot import HoneypotDefence

        defence = HoneypotDefence()
        # Custom pool of one unused name — the defence picks 'unused' as
        # the honeypot. A POST with 'something_else' should not match.
        outcome = defence.evaluate(
            _ctx_eval(
                {"something_else": "totally unrelated"},
                config={"field_names": ["unused_field"]},
            )
        )

        assert outcome.verdict == "pass"
