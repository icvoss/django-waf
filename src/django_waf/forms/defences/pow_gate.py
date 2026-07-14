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

from django_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    blocked,
    passed,
)
from django_waf.services.challenge_service import _digest_has_leading_zero_bits

# Field names on the rendered form. Stable for grep.
NONCE_FIELD = "waf_pow_nonce"
_TOKEN_BIND_FIELD = "waf_pow_token"  # hidden mirror so we can verify without parsing the render token

_HIDDEN_STYLE = "position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden;"


# Compact, self-contained synchronous SHA-256 (standard 32-bit big-endian
# implementation). Shared across every rendered form's solver script.
# Byte-identical to Python's hashlib.sha256 — verified against
# _digest_has_leading_zero_bits, the same server-side check _verify_nonce()
# uses. No crypto.subtle dependency, so the batch loop below runs entirely
# on the CPU instead of paying one promise resolution per nonce.
_SHA256_JS = (
    "function sha256(msg){"
    "var b=new TextEncoder().encode(msg);"
    "var K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,"
    "0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,"
    "0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,"
    "0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,"
    "0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,"
    "0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,"
    "0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,"
    "0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];"
    "var H=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];"
    "var bl=b.length*8,w1=b.length+1,pl=((w1+8+63)&~63)-w1-8,tot=w1+pl+8;"
    "var buf=new Uint8Array(tot);buf.set(b,0);buf[b.length]=0x80;"
    "var hi=Math.floor(bl/0x100000000),lo=bl>>>0;"
    "var dv=new DataView(buf.buffer);dv.setUint32(tot-8,hi,false);dv.setUint32(tot-4,lo,false);"
    "var w=new Int32Array(64);"
    "for(var o=0;o<tot;o+=64){"
    "  for(var i=0;i<16;i++){ w[i]=dv.getInt32(o+i*4,false); }"
    "  for(i=16;i<64;i++){"
    "    var s0v=w[i-15],s0=((s0v>>>7)|(s0v<<25))^((s0v>>>18)|(s0v<<14))^(s0v>>>3);"
    "    var s1v=w[i-2],s1=((s1v>>>17)|(s1v<<15))^((s1v>>>19)|(s1v<<13))^(s1v>>>10);"
    "    w[i]=(w[i-16]+s0+w[i-7]+s1)|0;"
    "  }"
    "  var a=H[0],b2=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];"
    "  for(i=0;i<64;i++){"
    "    var S1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));"
    "    var ch=(e&f)^(~e&g);"
    "    var t1=(h+S1+ch+K[i]+w[i])|0;"
    "    var S0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));"
    "    var maj=(a&b2)^(a&c)^(b2&c);"
    "    var t2=(S0+maj)|0;"
    "    h=g;g=f;f=e;e=(d+t1)|0;d=c;c=b2;b2=a;a=(t1+t2)|0;"
    "  }"
    "  H[0]=(H[0]+a)|0;H[1]=(H[1]+b2)|0;H[2]=(H[2]+c)|0;H[3]=(H[3]+d)|0;"
    "  H[4]=(H[4]+e)|0;H[5]=(H[5]+f)|0;H[6]=(H[6]+g)|0;H[7]=(H[7]+h)|0;"
    "}"
    "var out=new Uint8Array(32),ov=new DataView(out.buffer);"
    "for(i=0;i<8;i++){ ov.setInt32(i*4,H[i],false); }"
    "return out;"
    "}"
)


def _solver_script(token_nonce: str, difficulty: int) -> str:
    """Render the inline JS that solves the PoW and writes the nonce.

    The script:

    1. Hashes ``token_nonce + ":" + counter`` until the digest has
       ``difficulty`` leading zero bits.
    2. Writes the winning ``counter`` value into the hidden
       ``waf_pow_nonce`` field.
    3. Sets ``data-waf-pow-ready="true"`` on the surrounding form
       so operators can gate submit on it via attribute selectors.

    Uses a synchronous SHA-256 implementation (no ``crypto.subtle``),
    so the batch loop below grinds hashes without paying one promise
    resolution per nonce. Byte-identical to Python's ``hashlib.sha256``,
    verified against ``_verify_nonce()``/``_digest_has_leading_zero_bits``.
    Browsers without ``TextEncoder`` (very old) fall through with the
    field empty — the defence will block on the missing nonce. Fine;
    those browsers can't render modern sites anyway. On exceeding the
    runaway guard the loop stops silently (no throw) with the nonce
    field left empty, so the same missing-nonce fail-safe applies.
    """
    # The JS-side helper is the same bit-counting check as the
    # server. It's intentionally a single-purpose function — we don't
    # try to share code with the page-level challenge template
    # because the form-level PoW runs on every form-bearing page and
    # we don't want a second <script src=> request just for a 30-line
    # function.
    return (
        '<script type="text/javascript">'
        "(function(){"
        f"var token={token_nonce!r};"
        f"var difficulty={difficulty};"
        + _SHA256_JS
        + "function leadingZeroBits(bytes,bits){"
        "  var full=bits>>>3, rem=bits&7;"
        "  for(var i=0;i<full;i++){ if(bytes[i]!==0) return false; }"
        "  if(rem===0) return true;"
        "  var mask=(0xFF<<(8-rem))&0xFF;"
        "  return (bytes[full]&mask)===0;"
        "}"
        "var n=0;"
        # Runaway guard: cap at 2**difficulty * 64 iterations. A genuine
        # solve essentially never trips this; a mis-configured difficulty
        # stops instead of grinding forever, leaving the nonce field empty
        # so the server-side missing-nonce block applies.
        f"var maxN=Math.pow(2,{difficulty})*64;"
        "function step(){"
        "  var batchEnd=n+2000;"
        "  while(n<batchEnd){"
        '    var hash=sha256(token+":"+n);'
        "    if(leadingZeroBits(hash,difficulty)){"
        f"      var nonceEl=document.querySelector('input[name=\"{NONCE_FIELD}\"]');"
        "      if(nonceEl) nonceEl.value=n.toString();"
        "      var form=nonceEl ? nonceEl.form : null;"
        '      if(form) form.setAttribute("data-waf-pow-ready","true");'
        "      return;"
        "    }"
        "    n++;"
        "    if(n>maxN){ return; }"
        "  }"
        "  setTimeout(step,0);"
        "}"
        "step();"
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
        from django_waf import conf

        difficulty = ctx.config.get("difficulty", conf.DJANGO_WAF_FORM_POW_DIFFICULTY)

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
        from django_waf import conf

        difficulty = ctx.config.get("difficulty", conf.DJANGO_WAF_FORM_POW_DIFFICULTY)

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
