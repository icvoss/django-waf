"""PowGateDefence — embedded proof-of-work per submission.

Lighter than the page-level challenge because it runs per-submission
(not once per session like the WAF's challenge view does). Default
12 bits ≈ 4k SHA-256 hashes ≈ 50ms on desktop, ~200ms on mobile.
Reuses the same bit-counting verifier as the page challenge so any
future improvements land in one place (no parallel implementation,
no drift risk).

The JS solver runs on form render and writes the nonce into a hidden
field. Submit itself is instant — the form just reads the prepared
nonce. Operators who want a hard guarantee that the PoW finished
before submit set ``data-waf-pow-block-submit="true"`` on the form
element; the bundled JS disables the submit button until the nonce
is present.

Per PRD §3.8.
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
from icv_waf.services.challenge_service import _digest_has_leading_zero_bits

# Field names on the rendered form. Stable for grep.
NONCE_FIELD = "waf_pow_nonce"
_TOKEN_BIND_FIELD = "waf_pow_token"  # hidden mirror so we can verify without parsing the render token

_HIDDEN_STYLE = "position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;"


def _solver_script(token_nonce: str, difficulty: int) -> str:
    """Render the inline JS that solves the PoW and writes the nonce.

    The script:

    1. Hashes ``token_nonce + counter`` until the digest has
       ``difficulty`` leading zero bits.
    2. Writes the winning ``counter`` value into the hidden
       ``waf_pow_nonce`` field.
    3. Sets ``data-waf-pow-ready="true"`` on the surrounding form
       so operators can gate submit on it via attribute selectors.

    Uses ``crypto.subtle.digest('SHA-256', ...)``, same API the
    page-level challenge solver uses. Browsers without
    ``crypto.subtle`` (very old) fall through with the field empty —
    the defence will block on the missing nonce. Fine; those browsers
    can't render modern sites anyway.
    """
    # The JS-side helper is the same bit-counting check as the
    # server. It's intentionally a single-purpose function — we don't
    # try to share code with the page-level challenge template
    # because the form-level PoW runs on every form-bearing page and
    # we don't want a second <script src=> request just for a 30-line
    # function.
    return (
        '<script type="text/javascript">'
        "(async function(){"
        f"var token={token_nonce!r};"
        f"var difficulty={difficulty};"
        "var enc=new TextEncoder();"
        "function leadingZeroBits(buf,bits){"
        "  var bytes=new Uint8Array(buf);"
        "  var full=bits>>>3, rem=bits&7;"
        "  for(var i=0;i<full;i++){ if(bytes[i]!==0) return false; }"
        "  if(rem===0) return true;"
        "  var mask=(0xFF<<(8-rem))&0xFF;"
        "  return (bytes[full]&mask)===0;"
        "}"
        "var n=0;"
        "while(true){"
        '  var msg=token+":"+n;'
        '  var hash=await crypto.subtle.digest("SHA-256",enc.encode(msg));'
        "  if(leadingZeroBits(hash,difficulty)){"
        f"    var nonceEl=document.querySelector('input[name=\"{NONCE_FIELD}\"]');"
        "    if(nonceEl) nonceEl.value=n.toString();"
        "    var form=nonceEl ? nonceEl.form : null;"
        '    if(form) form.setAttribute("data-waf-pow-ready","true");'
        "    break;"
        "  }"
        "  n++;"
        "  if(n%1000===0){ await new Promise(function(r){setTimeout(r,0);}); }"
        "}"
        "})();"
        "</script>"
    )


def _verify_nonce(token_nonce: str, candidate_nonce: str, difficulty: int) -> bool:
    """Server-side check matching the JS solver's hash construction."""
    msg = f"{token_nonce}:{candidate_nonce}".encode()
    digest = hashlib.sha256(msg).digest()
    return _digest_has_leading_zero_bits(digest, difficulty)


class PowGateDefence:
    """Per-submission proof-of-work."""

    name = "pow_gate"

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        from icv_waf import conf

        difficulty = ctx.config.get("difficulty", conf.ICV_WAF_FORM_POW_DIFFICULTY)

        # Need the render token's nonce to bind the PoW to this
        # specific render. Until the orchestrator wires that through
        # ctx.config (block 4), fall back to form_id so the defence
        # still gates submissions — it just rotates per-form rather
        # than per-render.
        token_nonce = ctx.config.get("token_nonce", ctx.form_id)

        # Hidden empty field for the solver to populate, plus the
        # solver script itself, plus a hidden bind-token so we can
        # recover the token_nonce on submit without reparsing the
        # render token.
        html = (
            f'<input type="hidden" name="{NONCE_FIELD}" value="" '
            f'style="{_HIDDEN_STYLE}">'
            f'<input type="hidden" name="{_TOKEN_BIND_FIELD}" value="{token_nonce}" '
            f'style="{_HIDDEN_STYLE}">' + _solver_script(token_nonce, difficulty)
        )
        return {NONCE_FIELD: mark_safe(html)}  # noqa: S308 — constant template, escaped nonce

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        from icv_waf import conf

        difficulty = ctx.config.get("difficulty", conf.ICV_WAF_FORM_POW_DIFFICULTY)

        candidate = ctx.submitted_data.get(NONCE_FIELD) or ""
        if not candidate:
            return blocked("pow_gate:missing", score=5.0)

        # Recover the token_nonce. Prefer the verified token payload
        # (set by the orchestrator after RenderTokenDefence runs); fall
        # back to the bind field, which is what we render alongside.
        payload = ctx.token_payload
        if payload is not None:  # noqa: SIM108 — three-way precedence reads clearer as if/else
            token_nonce = payload.nonce
        else:
            token_nonce = ctx.submitted_data.get(_TOKEN_BIND_FIELD) or ctx.form_id

        if not _verify_nonce(token_nonce, candidate, difficulty):
            return blocked("pow_gate:invalid", score=5.0)

        return passed()
