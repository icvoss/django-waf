"""JsTouchDefence — flag submissions from clients that didn't execute JS.

The classic non-JS detector. A hidden field starts with a known
sentinel value; a tiny inline script writes a different value to it on
page load. Bots that POST the form without running JS submit the
field still containing the sentinel.

Low score (1.5) — assistive tools and some password managers
occasionally interact with hidden fields in surprising ways, so this
must never block alone. It only contributes when a real bot also
trips another flag.

Per PRD §3.5.
"""

from __future__ import annotations

import hashlib
import hmac

from django.utils.safestring import SafeString, mark_safe

from django_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    flagged,
    passed,
)
from django_waf.forms.services.tokens import get_signing_key

# Field name + sentinel. Both stable for grep — operators see
# ``waf_js_touch`` in their form's DOM and can identify it.
FIELD_NAME = "waf_js_touch"
_SENTINEL_UNSET = "unset"
_FLAG_SCORE = 1.5

# CSS — same off-screen pattern as the honeypot (display:none is
# bot-detectable; off-screen is the accessibility-friendly recipe).
_HIDDEN_STYLE = "position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;"


def _expected_value(token_nonce: str) -> str:
    """Compute the value the JS solver should write into the field.

    Derived from the render-token nonce + the signing key so a bot
    can't precompute the expected value without seeing the token.
    Truncated to 16 hex chars — full SHA-256 would bloat the DOM
    unnecessarily; 16 chars = 64 bits is plenty for this purpose
    (the field isn't a security primitive, just a behavioural one).
    """
    mac = hmac.new(get_signing_key(), f"js_touch:{token_nonce}".encode(), hashlib.sha256)
    return mac.hexdigest()[:16]


def _render_html(nonce: str) -> str:
    """Render the hidden field + inline script that clears it.

    The script is intentionally inline (no external src) so the
    behaviour is self-contained — a CSP that blocks external scripts
    still permits this. ``nonce`` in the JS is a JS string literal,
    not a CSP nonce.
    """
    expected = _expected_value(nonce)
    # Both the field name and expected value are constant-template
    # interpolations of non-user-controlled values, so mark_safe is
    # XSS-safe by construction.
    return (
        f'<input type="hidden" name="{FIELD_NAME}" id="_waf_js_touch_input" '
        f'value="{_SENTINEL_UNSET}" aria-hidden="true" tabindex="-1" '
        f'style="{_HIDDEN_STYLE}">'
        '<script type="text/javascript">'
        f'(function(){{var el=document.getElementById("_waf_js_touch_input");'
        f'if(el){{el.value="{expected}";}}}})();'
        "</script>"
    )


class JsTouchDefence:
    """Detects clients that POST without executing JS."""

    name = "js_touch"

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        # We need the token nonce to derive the expected value. The
        # token is rendered by RenderTokenDefence — but defences
        # render independently and we don't have the payload here.
        # Instead, derive a per-form nonce from form_id + a fresh
        # secret. The expected value will be re-derived at evaluate
        # time the same way.
        #
        # Actually, the orchestrator will provide the token's nonce
        # via ctx.config so the values can be linked. Until that's
        # wired (block 4 — orchestrator), fall back to form_id alone.
        # The defence still detects no-JS clients; it just doesn't
        # rotate per-render.
        nonce = ctx.config.get("token_nonce", ctx.form_id)
        return {FIELD_NAME: mark_safe(_render_html(nonce))}  # noqa: S308 — constant template

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        value = ctx.submitted_data.get(FIELD_NAME) or ""

        # Sentinel never overwritten → JS didn't run.
        if value == _SENTINEL_UNSET:
            return flagged(_FLAG_SCORE, "js_touch:not_set")

        # Missing field entirely is suspicious in a different way —
        # the form was either constructed by hand or had the field
        # stripped. Same low-score flag.
        if not value:
            return flagged(_FLAG_SCORE, "js_touch:missing")

        # Wrong value → bot wrote *something* but didn't compute the
        # expected derivation. Same score.
        payload = ctx.token_payload
        nonce = payload.nonce if payload is not None else ctx.config.get("token_nonce", ctx.form_id)
        if value != _expected_value(nonce):
            return flagged(_FLAG_SCORE, "js_touch:invalid")

        return passed()
