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

The feed-URL scheme check (``django_waf.W005``) warns when the threat feed
is enabled but its URL is not ``https://``. The feed drives BlockRule
creation; fetching it over plaintext lets a network attacker inject or
suppress rules in transit. Scheme validation only — the check never issues
a live HTTP request.

The middleware-ordering check (``django_waf.W004``) warns when
``WafMiddleware`` is placed before ``AuthenticationMiddleware`` in
``MIDDLEWARE``, or when ``AuthenticationMiddleware`` is missing entirely.
``request.user`` is not available at that point, so the staff bypass
silently fails and staff/superuser accounts can be blocked or challenged
like anonymous traffic.

The site-password check (``django_waf.E003``) errors when
``DJANGO_WAF_SITE_PASSWORD_ENABLED`` is truthy but
``DJANGO_WAF_SITE_PASSWORD`` is empty. Per BR-SP-002 the gate fails closed
at runtime in this state (every request is denied), so this is an Error
rather than a Warning -- it flags an operator's site as permanently locked
rather than a soft misconfiguration.
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


@register()
def check_feed_url_scheme(app_configs, **kwargs):
    """Warn (``django_waf.W005``) when the threat feed is enabled but
    ``DJANGO_WAF_FEED_URL`` is not served over HTTPS.

    The feed response is turned directly into ``BlockRule`` records, so an
    on-path attacker who can tamper with a plaintext feed can inject rules
    that block legitimate traffic or suppress rules that would block theirs.
    Only the URL scheme is inspected; no request is made.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_FEED_ENABLED:
        return []

    url = conf.DJANGO_WAF_FEED_URL or ""
    if url.startswith("https://"):
        return []

    return [
        Warning(
            f"DJANGO_WAF_FEED_URL is not HTTPS ({url!r}) while "
            "DJANGO_WAF_FEED_ENABLED is True — feed rules would be fetched "
            "over an untrusted channel.",
            hint=(
                "Use an https:// feed URL so an on-path attacker cannot "
                "inject or suppress BlockRules in transit, or set "
                "DJANGO_WAF_FEED_ENABLED = False to disable feed syncing."
            ),
            id="django_waf.W005",
        )
    ]


@register()
def check_middleware_ordering(app_configs, **kwargs):
    """Warn (``django_waf.W004``) when ``WafMiddleware`` runs before
    Django's ``AuthenticationMiddleware``.

    The staff dashboard bypass and any authenticated-user logic in the WAF
    middleware reads ``request.user``, which ``AuthenticationMiddleware``
    attaches. If the WAF runs first, ``request.user`` is not yet available
    (or not yet resolved), so the staff bypass silently fails and staff
    users can be blocked/challenged like anyone else.

    Investigated (#18) and rejected: making the bypass "self-sufficient" by
    calling ``django.contrib.auth.get_user(request)`` directly reads
    ``request.session``, which does not exist until ``SessionMiddleware``
    has run. The README's own recommended stack places ``WafMiddleware``
    before ``SessionMiddleware`` (to reject bad traffic before any other
    work runs), so a lazy ``get_user()`` call at that position would raise
    ``AttributeError`` exactly as the site-password gate's session lookup
    did before v1.5.1 (fixed by moving that gate to its own signed cookie,
    independent of the session framework). This check's remedy therefore
    stays "move WafMiddleware after AuthenticationMiddleware", not "resolve
    the user yourself" -- see the v1.5.1 CHANGELOG entry for the precedent.
    """
    from django.conf import settings

    middleware = list(getattr(settings, "MIDDLEWARE", []))
    waf_name = "django_waf.middleware.WafMiddleware"
    auth_name = "django.contrib.auth.middleware.AuthenticationMiddleware"

    if waf_name not in middleware:
        return []

    waf_index = middleware.index(waf_name)
    auth_index = middleware.index(auth_name) if auth_name in middleware else None

    if auth_index is None or auth_index > waf_index:
        return [
            Warning(
                "django_waf.middleware.WafMiddleware runs before "
                "django.contrib.auth.middleware.AuthenticationMiddleware "
                "(or AuthenticationMiddleware is missing) — request.user is "
                "not available when the WAF evaluates the request, so the "
                "staff bypass silently fails and staff/superuser accounts "
                "can be blocked or challenged like anonymous traffic.",
                hint=(
                    "Place django_waf.middleware.WafMiddleware after "
                    "django.contrib.auth.middleware.AuthenticationMiddleware "
                    "in MIDDLEWARE."
                ),
                id="django_waf.W004",
            )
        ]

    return []


@register()
def check_site_password_configured(app_configs, **kwargs):
    """Error (``django_waf.E003``) when the site-password gate is enabled
    with an empty password.

    Per BR-SP-002, this configuration fails closed at runtime -- every
    gated request is denied, effectively taking the whole site offline.
    Surfaced as an Error (not a Warning) because it blocks the site rather
    than merely weakening a defence.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_SITE_PASSWORD_ENABLED:
        return []

    if conf.DJANGO_WAF_SITE_PASSWORD:
        return []

    return [
        Error(
            "DJANGO_WAF_SITE_PASSWORD_ENABLED is True but "
            "DJANGO_WAF_SITE_PASSWORD is empty — the site-password gate "
            "will fail closed and deny every non-exempt request.",
            hint=(
                "Set DJANGO_WAF_SITE_PASSWORD to a non-empty value (load it "
                "from environment in production), or set "
                "DJANGO_WAF_SITE_PASSWORD_ENABLED = False to disable the gate."
            ),
            id="django_waf.E003",
        )
    ]
