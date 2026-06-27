"""Django system checks for django-waf configuration.

These checks catch settings combinations that would lock legitimate users
out of the site (the v0.10.4 regression motivating their introduction:
``DJANGO_WAF_CHALLENGE_DIFFICULTY`` was implemented in bytes while documented
in bits, so the default of 4 became unsolvable).

Difficulty here is counted in **leading zero bits** of the SHA-256 digest.
Expected attempts is ``2 ** difficulty``. Thresholds:

* ``> 28`` (~268M hashes, > 60s on most laptops) — Error.
* ``> 24`` (~16M hashes, ~5–20s on phones) — Warning.
* ``< 8``  (256 hashes, no real bot deterrence) — Warning.

The signing-key check (``django_waf.W003``) was added in v0.11.0 alongside
the form-protection subsystem. It surfaces when the package is falling
back to a ``SECRET_KEY``-derived signing key — fine for development but
worth a deliberate decision in production.
"""

from __future__ import annotations

from django.core.checks import Error, Warning, register


@register()
def check_challenge_difficulty(app_configs, **kwargs):
    from django_waf import conf

    messages = []
    # (name, value, allow_none) — desktop/mobile may be None to fall through
    # to the single-value DJANGO_WAF_CHALLENGE_DIFFICULTY.
    fields = (
        ("DJANGO_WAF_CHALLENGE_DIFFICULTY", conf.DJANGO_WAF_CHALLENGE_DIFFICULTY, False),
        ("DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", conf.DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP, True),
        ("DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", conf.DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE, True),
    )

    for name, value, allow_none in fields:
        if value is None and allow_none:
            continue
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            messages.append(
                Error(
                    f"{name} must be a non-negative integer (got {value!r}).",
                    hint="Difficulty is the number of leading zero bits required in the SHA-256(token+nonce) digest.",
                    id="django_waf.E001",
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
                    id="django_waf.E002",
                )
            )
        elif value > 24:
            messages.append(
                Warning(
                    f"{name}={value} (~{2**value:,} hashes) may exceed 10s on "
                    "low-end phones, causing visible delay or timeouts.",
                    hint="22 (desktop) / 18 (mobile) are the recommended defaults.",
                    id="django_waf.W001",
                )
            )
        elif 0 < value < 8:
            messages.append(
                Warning(
                    f"{name}={value} (~{2**value} hashes) offers little bot "
                    "deterrence — the PoW is effectively instant.",
                    hint="Raise to 18+ for meaningful proof-of-work cost.",
                    id="django_waf.W002",
                )
            )

    return messages


@register()
def check_signing_key(app_configs, **kwargs):
    """Warn when ``DJANGO_WAF_SIGNING_KEY`` is unset and the package falls back
    to a ``SECRET_KEY``-derived value.

    Falling back is supported — it's how v0.10.x → v0.11.0 upgrades stay
    seamless — but tying WAF signatures to ``SECRET_KEY`` means rotating
    one forces rotating the other and logs every user out. The W003
    warning nudges operators toward an explicit dedicated key.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_SIGNING_KEY:
        return [
            Warning(
                "DJANGO_WAF_SIGNING_KEY is not set — falling back to a SECRET_KEY-derived signing key for WAF tokens.",
                hint=(
                    'Generate a dedicated key with `python -c "import '
                    'secrets; print(secrets.token_urlsafe(64))"` and set '
                    "DJANGO_WAF_SIGNING_KEY in your environment. Keeping the "
                    "WAF key separate from SECRET_KEY lets you rotate "
                    "either independently."
                ),
                id="django_waf.W003",
            )
        ]
    return []
