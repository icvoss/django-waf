"""Django system checks for icv-waf configuration.

These checks catch settings combinations that would lock legitimate users
out of the site (the v0.10.4 regression motivating their introduction:
``ICV_WAF_CHALLENGE_DIFFICULTY`` was implemented in bytes while documented
in bits, so the default of 4 became unsolvable).

Difficulty here is counted in **leading zero bits** of the SHA-256 digest.
Expected attempts is ``2 ** difficulty``. Thresholds:

* ``> 28`` (~268M hashes, > 60s on most laptops) — Error.
* ``> 24`` (~16M hashes, ~5–20s on phones) — Warning.
* ``< 8``  (256 hashes, no real bot deterrence) — Warning.
"""

from __future__ import annotations

from django.core.checks import Error, Warning, register


@register()
def check_challenge_difficulty(app_configs, **kwargs):
    from icv_waf import conf

    messages = []
    # (name, value, allow_none) — desktop/mobile may be None to fall through
    # to the single-value ICV_WAF_CHALLENGE_DIFFICULTY.
    fields = (
        ("ICV_WAF_CHALLENGE_DIFFICULTY", conf.ICV_WAF_CHALLENGE_DIFFICULTY, False),
        ("ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", conf.ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP, True),
        ("ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", conf.ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE, True),
    )

    for name, value, allow_none in fields:
        if value is None and allow_none:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            messages.append(
                Error(
                    f"{name} must be a non-negative integer (got {value!r}).",
                    hint="Difficulty is the number of leading zero bits required in the SHA-256(token+nonce) digest.",
                    id="icv_waf.E001",
                )
            )
            continue
        if value > 28:
            messages.append(
                Error(
                    f"{name}={value} is effectively unsolvable in a browser "
                    f"(~{2**value:,} hashes on average). Legitimate users will "
                    "fail the challenge and be auto-blocked.",
                    hint="Set to 22 for desktops, 18 for mobile, or lower.",
                    id="icv_waf.E002",
                )
            )
        elif value > 24:
            messages.append(
                Warning(
                    f"{name}={value} (~{2**value:,} hashes) may exceed 10s on "
                    "low-end phones, causing visible delay or timeouts.",
                    hint="22 (desktop) / 18 (mobile) are the recommended defaults.",
                    id="icv_waf.W001",
                )
            )
        elif 0 < value < 8:
            messages.append(
                Warning(
                    f"{name}={value} (~{2**value} hashes) offers little bot "
                    "deterrence — the PoW is effectively instant.",
                    hint="Raise to 18+ for meaningful proof-of-work cost.",
                    id="icv_waf.W002",
                )
            )

    return messages
