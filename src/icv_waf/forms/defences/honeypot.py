"""HoneypotDefence — hidden fields that humans can't fill in.

Renders one or more hidden ``<input>`` fields with names drawn from
``ICV_WAF_FORM_HONEYPOT_FIELD_NAMES``. The name set is rotated
per-form by hashing the ``form_id``, so:

* the same form always shows the same names (cache-friendly), and
* different forms show different subsets (bots can't learn one global
  list and skip it).

A bot that fills every input field on the form trips this; a real
user never sees the fields (visually hidden, ``autocomplete=off``,
``tabindex=-1``, screen-reader label explicitly telling AT users to
skip).

Per PRD §3.1.
"""

from __future__ import annotations

import hashlib

from django.utils.safestring import SafeString, mark_safe

from icv_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    blocked,
    passed,
)

# How many honeypot fields to render per form. Two is enough to make
# random-fill bots fail reliably without producing a visually-jarring
# DOM. Operators don't get to override this — it's a coverage choice,
# not a security knob.
_FIELDS_PER_FORM = 2

# CSS used for the visually-hidden style. Specifically NOT
# ``display:none`` — most scrapers detect that. The position-off-screen
# pattern is the long-standing accessibility-friendly honeypot recipe.
_HIDDEN_STYLE = "position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;"


def _pick_field_names(form_id: str, pool: list[str], count: int) -> list[str]:
    """Pick ``count`` field names from ``pool`` for a given ``form_id``.

    Deterministic: same form_id + same pool → same names. Uses
    SHA-256(form_id) to derive a starting offset and then walks the
    pool, so two forms with similar names map to different honeypot
    subsets.
    """
    if not pool:
        return []
    digest = hashlib.sha256(form_id.encode("utf-8")).digest()
    offset = int.from_bytes(digest[:4], "big") % len(pool)
    # Walk the pool starting at offset. If count > len(pool), the names
    # will repeat — operators who really want more than the pool size
    # should expand the pool, not get duplicates rendered.
    return [pool[(offset + i) % len(pool)] for i in range(min(count, len(pool)))]


def _render_field(name: str) -> str:
    """Render a single honeypot hidden input as escaped HTML.

    Built from a constant template; only the field name varies, and
    we strip anything outside an aggressive whitelist before injection
    so a misconfigured pool can't introduce XSS.
    """
    # Restrict the name to a safe subset. Any name containing
    # characters outside [a-z0-9_-] is silently dropped — operators
    # who add weird names to the pool find out via the unit test, not
    # an injection.
    safe_name = "".join(c for c in name if c.isalnum() or c in "_-")
    if not safe_name:
        return ""
    return (
        f'<input type="text" name="{safe_name}" value="" '
        f'autocomplete="off" tabindex="-1" '
        f'aria-label="Leave this field empty (anti-spam check)" '
        f'style="{_HIDDEN_STYLE}">'
    )


class HoneypotDefence:
    """Hidden honeypot inputs detect form-filling bots.

    Stateless across requests — the defence reads its config from the
    ``RenderContext``/``EvaluateContext`` rather than holding any
    instance state.
    """

    name = "honeypot"

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        from icv_waf import conf

        pool = ctx.config.get("field_names", conf.ICV_WAF_FORM_HONEYPOT_FIELD_NAMES)
        names = _pick_field_names(ctx.form_id, pool, _FIELDS_PER_FORM)

        if not names:
            return {}

        # Concatenate the inputs under a single synthetic key. The
        # template tag / mixin renders all values as raw HTML, so the
        # key is just for de-duplication when multiple defences
        # contribute to the same form.
        html = "".join(_render_field(n) for n in names)
        return {"_waf_honeypot": mark_safe(html)}  # noqa: S308 — constant template, escaped name

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        from icv_waf import conf

        pool = ctx.config.get("field_names", conf.ICV_WAF_FORM_HONEYPOT_FIELD_NAMES)
        names = _pick_field_names(ctx.form_id, pool, _FIELDS_PER_FORM)

        for name in names:
            value = ctx.submitted_data.get(name) or ""
            if value:
                # Any non-empty value is a hard block. Use the field
                # name in the reason so logs distinguish 'bot filled
                # url' from 'bot filled email_confirm' — operators
                # tune the pool when they see one consistently.
                return blocked(f"honeypot:{name}", score=5.0)

        return passed()
