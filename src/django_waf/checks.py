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

Silent when the WAF is disabled (``DJANGO_WAF_ENABLED = False``, #95): the
challenge flow this check protects never runs when the master switch is
off, so a difficulty misconfiguration behind it is not a live lockout.

The signing-key check (``django_waf.W003``) was added in v0.11.0 alongside
the form-protection subsystem. It surfaces when the package is falling
back to a ``SECRET_KEY``-derived signing key, fine for development but
worth a deliberate decision in production. Silent when the WAF is disabled
(#95): no WAF token is ever signed with this key when the master switch is
off.

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
like anonymous traffic. Silent when the WAF is disabled (#95): the staff
bypass this check protects has nothing to bypass when the middleware is
not evaluating requests.

The site-password check (``django_waf.E003``) errors when
``DJANGO_WAF_SITE_PASSWORD_ENABLED`` is truthy but
``DJANGO_WAF_SITE_PASSWORD`` is empty. Per BR-SP-002 the gate fails closed
at runtime in this state (every request is denied), so this is an Error
rather than a Warning -- it flags an operator's site as permanently locked
rather than a soft misconfiguration. Silent when the WAF is disabled (#95):
the site-password gate is evaluated by ``WafMiddleware``, so it cannot
fail closed on a request the middleware never evaluates.

The trust-level check (``django_waf.W006``) warns when
``DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL`` is set to anything other than
``"staff"`` or ``"authenticated"`` while the trusted-user-cookie feature
(#23) is enabled. The service layer already fails safe on this
(``django_waf.services.trusted_user_service.get_trust_level`` coerces an
unrecognised value to ``"staff"``), so this is a Warning about an
ineffective setting, not an Error about a lockout.

Deliberately NOT gated on ``DJANGO_WAF_ENABLED`` (#95): the trusted-user
cookie is purely a request-time feature with no independent Celery path,
which is the same rationale gating the other four checks in this module.
It stays ungated because it is a Warning behind its own explicit opt-in
flag (``DJANGO_WAF_TRUSTED_COOKIE_ENABLED``), so a disabled WAF combined
with the feature flag left on cannot abort ``manage.py check`` the way an
Error can; this is a considered exception, not an oversight.

The Redis backend check (``django_waf.E004``) is silent when the WAF is
disabled (``DJANGO_WAF_ENABLED = False``, #67), and otherwise errors when
``DJANGO_WAF_REDIS_ALIAS`` is not configured as a ``django-redis`` cache
backend (#44). Rule evaluation, rate limiting, and challenge state have no
safe equivalent on a generic Django cache backend (rate limiting alone uses
Redis sorted sets and pipelines), so a misconfigured alias means the WAF
fails open (BR-EVAL-007) for every single request, silently, from process
start. This is an Error, not a Warning, deliberately: a security control
that reports healthy while blocking nothing is worse than one that refuses
to start, and this check exists so an operator catches the misconfiguration
at ``manage.py check`` rather than discovering it from a stream of
per-request log lines.

The leftmost-XFF check (``django_waf.W007``) warns when
``DJANGO_WAF_TRUST_X_FORWARDED_FOR`` is enabled and
``DJANGO_WAF_TRUSTED_PROXIES`` is empty (#42), the configuration under
which ``client_ip.resolve_client_ip`` (BR-EVAL-008) falls back to trusting
the leftmost ``X-Forwarded-For`` entry unconditionally: exactly the hop a
client controls, and therefore spoofable by design. The resolver already
logs a warning on every such request; this check surfaces the same risk
once, at boot, so it is not only discoverable by noticing a per-request log
line.

The observe-only detector-name check (``django_waf.W008``) warns when
``DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS`` (BR-ANOM-008, #45) names a
value that does not match any of the five anomaly detector function names.
The setting is checked against
``django_waf.services.anomaly_detector.DETECTOR_NAMES``, the same constant
``_get_or_create_auto_rule`` reads to decide observe-only status, so a
detector rename cannot silently desync the two: a typo or a stale name from
a renamed detector would otherwise mean the operator believes a detector is
running observe-only when it is, in fact, enforcing.

The Redis version check (``django_waf.E005``) errors when the connected
Redis server reports a version below the package's own floor, currently
6.0 (see ``django_waf.services.redis_client.MIN_REDIS_VERSION``, the
single source of truth this check reads). Redis 6.2 introduced ``GETDEL``;
before this check existed, ``flush_rule_hit_counts`` called it
unconditionally and, on a 6.0/6.1 server, ``ResponseError`` was raised on
every key and swallowed by a bare ``except Exception: continue``, so hit
counts silently never flushed. The task itself no longer calls ``GETDEL``
(it uses a GET+DEL pipeline instead, so the package's floor stays 6.0
rather than rising to 6.2), but the package has no other way to warn an
operator running an older, unsupported server that other Redis-version
assumptions elsewhere in the codebase may not hold. This is an Error
rather than a Warning because an unsupported server version is a
deployment fact, not a soft preference, mirroring ``django_waf.E004``'s
reasoning. Like every other check in this module it must stay cheap and
side-effect-free: it opens a connection only when the alias is already
confirmed to be a django-redis backend, and does nothing at all when the
WAF is disabled (``DJANGO_WAF_ENABLED = False``) or the connection cannot
be made, since neither of those is the misconfiguration this check exists
to catch (see issue #67, where ``django_waf.E004`` wrongly fired under
``DJANGO_WAF_ENABLED = False`` with no Redis available; this check guards
against repeating that).

The middleware-presence check (``django_waf.E006``) errors when
``DJANGO_WAF_ENABLED = True`` but ``WafMiddleware`` (or a subclass of it,
matched by class name -- see the function docstring) is absent from
``MIDDLEWARE`` entirely (#101). ``check_middleware_ordering``
(``django_waf.W004``) only ever inspects ordering: it returns ``[]``
unconditionally the moment ``WafMiddleware`` is not found in
``MIDDLEWARE``, on the reasoning that there is no ordering to warn about.
That silence was never a deliberate finding of "nothing wrong here"; it was
simply the absence case no check was written for. A brickworkui.com
production deployment had ``django_waf`` installed, ``DJANGO_WAF_ENABLED =
True``, and no ``WafMiddleware`` anywhere in ``MIDDLEWARE`` for its entire
deployed life, and ``manage.py check`` passed throughout: the WAF inspected
no traffic at all while reporting a clean bill of health. This is an
Error, not a Warning, for the same reason ``django_waf.E004`` is: a
security control that reports healthy while blocking nothing is worse than
one that refuses to start, and an operator who believes the WAF is live
when it has never evaluated a single request is worse off than one told
plainly at boot that it is not wired up. Gated on ``DJANGO_WAF_ENABLED``
being ``True``: a disabled WAF is not expected to be in ``MIDDLEWARE`` at
all (BR-EVAL-002 already makes a present-but-enabled middleware a total
pass-through), so the absence of a middleware nobody asked to run is not a
misconfiguration, matching the gating rationale #95 established for every
other check in this module.
"""

from __future__ import annotations

from django.core.checks import Error, Warning, register


@register()
def check_challenge_difficulty(app_configs, **kwargs):
    from django_waf import conf

    # #95: the PoW challenge flow this check protects never runs when the
    # WAF is switched off, so a difficulty misconfiguration behind it is
    # not a live lockout. Without this, a settings profile that disables
    # the WAF (e.g. under LocMemCache in a test or CI profile) can still
    # abort manage.py check on E001/E002, exactly the class of boot-time
    # false positive #95 was filed to close.
    if not conf.DJANGO_WAF_ENABLED:
        return []

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
    to a ``SECRET_KEY``-derived value, unless the WAF is disabled (#95).

    Falling back is supported — it's how v0.10.x → v0.11.0 upgrades stay
    seamless — but tying WAF signatures to ``SECRET_KEY`` means rotating
    one forces rotating the other and logs every user out. The W003
    warning nudges operators toward an explicit dedicated key.
    """
    from django_waf import conf

    # #95: no WAF token (waf_pass, trusted-user cookie, form-protection
    # render token) is ever signed with this key when the master switch is
    # off, so an unset key is not a live weakness in that state.
    if not conf.DJANGO_WAF_ENABLED:
        return []

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
    Django's ``AuthenticationMiddleware``, unless the WAF is disabled (#95).

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

    #23 dissolves this tension for sites that opt in:
    ``DJANGO_WAF_TRUSTED_COOKIE_ENABLED`` gives the staff bypass a signed,
    WAF-owned cookie (``django_waf.services.trusted_user_service``) that
    does not depend on ``request.user`` at all, so the WAF can stay
    security-first (before auth) without losing the bypass. When that
    setting is True, this check no longer fires: the ordering it warns
    about is no longer a defect for that site. It is unchanged, and still
    fires exactly as before, when the feature is off.
    """
    from django.conf import settings

    from django_waf import conf

    # #95: cheapest guard first. request.user has nothing to bypass when
    # WafMiddleware never evaluates a request in the first place, so the
    # ordering this check warns about is not a live defect when the WAF is
    # switched off.
    if not conf.DJANGO_WAF_ENABLED:
        return []

    if conf.DJANGO_WAF_TRUSTED_COOKIE_ENABLED:
        return []

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
                    "in MIDDLEWARE, or set DJANGO_WAF_TRUSTED_COOKIE_ENABLED "
                    "= True and wire the login receiver (see "
                    "docs/DESIGN-trusted-user-cookie.md) so the staff bypass "
                    "no longer depends on middleware order."
                ),
                id="django_waf.W004",
            )
        ]

    return []


@register()
def check_middleware_present(app_configs, **kwargs):
    """Error (``django_waf.E006``) when the WAF is enabled but
    ``WafMiddleware`` is absent from ``MIDDLEWARE`` entirely (#101).

    ``check_middleware_ordering`` (``django_waf.W004``) only ever warns
    about *where* ``WafMiddleware`` sits relative to
    ``AuthenticationMiddleware``; it returns ``[]`` the instant the
    middleware is not found at all, because there is no ordering left to
    judge. Nothing else registered in this module inspects ``MIDDLEWARE``
    for the WAF's own presence, so a project that installs the app,
    flips ``DJANGO_WAF_ENABLED = True``, and simply forgets the
    ``MIDDLEWARE`` line gets a silent, fully inert WAF and a green
    ``manage.py check`` -- exactly what happened on brickworkui.com for
    its entire deployed life. A misordered WAF still inspects every
    request; an absent one inspects none, which is the more serious
    failure and the one this module had no check for.

    Matching is by class name (the last dotted component ends with
    ``"WafMiddleware"``), not exact dotted-path equality to
    ``django_waf.middleware.WafMiddleware``. ``WafMiddleware`` is a plain
    ``__init__``/``__call__`` class with no metaclass or registration
    step, so subclassing it to add project-specific behaviour around
    ``get_response`` is an ordinary, unremarkable way to use it, and such
    a subclass is exactly as live as the base class: it still evaluates
    every request. A subclass conventionally keeps ``WafMiddleware`` as a
    suffix of its own name (``CustomWafMiddleware``, ``TenantWafMiddleware``)
    rather than the exact name, so an equality match on the class name
    would repeat the same false positive an exact dotted-path match would,
    only one layer further out; a suffix match tolerates the rename a
    subclass almost always makes. Matching by class name is cheap to state
    and does not attempt to verify the subclass actually calls into
    ``WafMiddleware`` behaviour (an ``isinstance`` check would need the
    class imported and instantiated, which a system check must not do); a
    project naming an unrelated class to end in ``WafMiddleware`` on
    purpose is choosing a confusing name, not a case this check is obliged
    to protect against.

    Gated on ``DJANGO_WAF_ENABLED = True`` (#95's own precedent, and #95's
    acceptance criterion for this exact case): when the WAF is switched
    off, ``MIDDLEWARE`` is not expected to carry it at all, so absence is
    not a misconfiguration to flag, only the enabled-but-inert combination
    is.
    """
    from django.conf import settings

    from django_waf import conf

    # Cheapest guard first, matching every other check in this module: a
    # disabled WAF has nothing to be inert about, so there is nothing here
    # for #101 to catch.
    if not conf.DJANGO_WAF_ENABLED:
        return []

    middleware = list(getattr(settings, "MIDDLEWARE", []))
    if any(entry.rsplit(".", 1)[-1].endswith("WafMiddleware") for entry in middleware):
        return []

    return [
        Error(
            "DJANGO_WAF_ENABLED is True but django_waf.middleware.WafMiddleware "
            "(or a subclass of it) is not present in MIDDLEWARE -- the WAF is "
            "installed and switched on but evaluates no traffic at all.",
            hint=(
                "Add 'django_waf.middleware.WafMiddleware' to MIDDLEWARE (see "
                "the README for recommended placement), or set "
                "DJANGO_WAF_ENABLED = False if this project is not meant to "
                "run the WAF yet."
            ),
            id="django_waf.E006",
        )
    ]


@register()
def check_site_password_configured(app_configs, **kwargs):
    """Error (``django_waf.E003``) when the site-password gate is enabled
    with an empty password, unless the WAF is disabled (#95).

    Per BR-SP-002, this configuration fails closed at runtime -- every
    gated request is denied, effectively taking the whole site offline.
    Surfaced as an Error (not a Warning) because it blocks the site rather
    than merely weakening a defence.
    """
    from django_waf import conf

    # #95: the site-password gate is evaluated by WafMiddleware (BR-SP-008),
    # so it cannot fail closed on a request the middleware never evaluates.
    # This is the same class of false positive #67 fixed for E004: a
    # settings profile that switches the WAF off (a test or CI profile
    # under LocMemCache, say) is not misconfigured for having no password
    # set, it simply is not using the feature this check guards.
    if not conf.DJANGO_WAF_ENABLED:
        return []

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


@register()
def check_trusted_cookie_trust_level(app_configs, **kwargs):
    """Warn (``django_waf.W006``) when ``DJANGO_WAF_TRUSTED_COOKIE_ENABLED``
    is True and ``DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL`` is set to
    anything other than ``"staff"`` or ``"authenticated"``.

    Not an Error: ``django_waf.services.trusted_user_service.get_trust_level``
    already fails safe, coercing an unrecognised value to ``"staff"`` (the
    narrower, safer population) rather than raising or silently widening
    the bypass. This check exists so the misconfiguration is visible at
    boot rather than only discoverable by noticing the setting has no
    effect.
    """
    from django_waf import conf

    # #95: NOT gated on DJANGO_WAF_ENABLED, unlike E001/E002/W001/W002/W003/
    # E003. This is a considered exception, not an oversight: it is a
    # Warning behind its own explicit opt-in flag
    # (DJANGO_WAF_TRUSTED_COOKIE_ENABLED), so it cannot abort manage.py
    # check the way an Error can, and the module docstring records why it
    # stays ungated.
    if not conf.DJANGO_WAF_TRUSTED_COOKIE_ENABLED:
        return []

    level = conf.DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL
    if level in ("staff", "authenticated"):
        return []

    return [
        Warning(
            f"DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL={level!r} is not "
            '"staff" or "authenticated"; the trusted-user-cookie login '
            'receiver is falling back to "staff" (the narrower, safer '
            "population) rather than honouring this value.",
            hint='Set DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL to "staff" or "authenticated".',
            id="django_waf.W006",
        )
    ]


@register()
def check_redis_backend(app_configs, **kwargs):
    """Error (``django_waf.E004``) when ``DJANGO_WAF_REDIS_ALIAS`` is not a
    django-redis cache backend (#44), unless the WAF is disabled (#67).

    Only inspects ``settings.CACHES``, never opens a connection: this check
    must be cheap and side-effect-free like every other check in this
    module, and must not be confused with a live Redis health check (a
    correctly configured backend that is merely unreachable right now is
    the outage BR-EVAL-007 already handles at runtime, not a misconfigured
    one this check should flag).
    """
    from django_waf import conf
    from django_waf.services.redis_client import is_redis_backend

    # Cheapest guard first, and the one #67 was filed for: a project that
    # has switched the WAF off entirely is not misconfigured for having a
    # non-Redis cache, it simply is not using the feature this check
    # guards. Without this, E004 fires as a hard Error during
    # `manage.py check` on any settings profile that disables the WAF, so a
    # test or CI profile using LocMemCache cannot boot at all. django_waf.E005
    # already guards this way; E004 predates it and did not.
    if not conf.DJANGO_WAF_ENABLED:
        return []

    if is_redis_backend(conf.DJANGO_WAF_REDIS_ALIAS):
        return []

    return [
        Error(
            f"DJANGO_WAF_REDIS_ALIAS={conf.DJANGO_WAF_REDIS_ALIAS!r} is not "
            "configured as a django-redis cache backend. The WAF has no "
            "safe fallback for rule evaluation, rate limiting, or "
            "challenge state on a generic Django cache backend, and will "
            "fail open (pass every request through without evaluation) "
            "for the lifetime of this process.",
            hint=(
                f"Set CACHES[{conf.DJANGO_WAF_REDIS_ALIAS!r}]['BACKEND'] to "
                "'django_redis.cache.RedisCache' pointing at a real Redis "
                "instance, or point DJANGO_WAF_REDIS_ALIAS at a cache alias "
                "that is."
            ),
            id="django_waf.E004",
        )
    ]


@register()
def check_legacy_xff_trust(app_configs, **kwargs):
    """Warn (``django_waf.W007``) when ``DJANGO_WAF_TRUST_X_FORWARDED_FOR``
    is enabled with no ``DJANGO_WAF_TRUSTED_PROXIES`` configured (#42).

    Under this combination, ``client_ip.resolve_client_ip`` (BR-EVAL-008)
    falls back to trusting the leftmost ``X-Forwarded-For`` entry
    unconditionally: exactly the entry a client controls, and therefore
    spoofable by design. The resolver already logs a warning on every
    request that takes this path; this check surfaces the same
    configuration risk once, at boot.
    """
    from django_waf import conf

    if not conf.DJANGO_WAF_TRUST_X_FORWARDED_FOR:
        return []

    if conf.DJANGO_WAF_TRUSTED_PROXIES:
        return []

    return [
        Warning(
            "DJANGO_WAF_TRUST_X_FORWARDED_FOR is True and "
            "DJANGO_WAF_TRUSTED_PROXIES is empty: the client-IP resolver "
            "is trusting the leftmost X-Forwarded-For entry unconditionally, "
            "which is exactly the entry a client controls and can spoof to "
            "choose its own block or rate-limit identity.",
            hint=(
                "Set DJANGO_WAF_TRUSTED_PROXIES to the CIDR ranges of your "
                "actual reverse proxies so the resolver walks "
                "X-Forwarded-For from a trusted boundary instead, or set "
                "DJANGO_WAF_TRUST_X_FORWARDED_FOR = False if you do not sit "
                "behind a proxy that sets this header."
            ),
            id="django_waf.W007",
        )
    ]


@register()
def check_observe_only_detector_names(app_configs, **kwargs):
    """Warn (``django_waf.W008``) when ``DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS``
    names a value that is not a known anomaly detector function name (#45).

    Validated against ``anomaly_detector.DETECTOR_NAMES``, the single source
    of truth also used by ``_get_or_create_auto_rule`` to decide observe-only
    status, so this check and the runtime behaviour it validates cannot
    desync if a detector is ever renamed.
    """
    from django_waf import conf
    from django_waf.services.anomaly_detector import DETECTOR_NAMES

    unknown = [name for name in conf.DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS if name not in DETECTOR_NAMES]
    if not unknown:
        return []

    known = ", ".join(sorted(DETECTOR_NAMES))
    return [
        Warning(
            f"DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS names an unrecognised "
            f"detector: {unknown!r}. It will never match a real detector run, "
            "so no detector will actually be forced into observe-only mode "
            "for this entry.",
            hint=f"Known detector names are: {known}.",
            id="django_waf.W008",
        )
    ]


@register()
def check_redis_version(app_configs, **kwargs):
    """Error (``django_waf.E005``) when the connected Redis server reports a
    version below ``redis_client.MIN_REDIS_VERSION`` (currently 6.0).

    Guards, cheapest first, exactly like ``check_redis_backend``
    (``django_waf.E004``): does nothing when the WAF is disabled (fixing
    #67's mistake, where E004 fired regardless of
    ``DJANGO_WAF_ENABLED``), does nothing when the configured alias is not
    even a django-redis backend (E004 already covers that misconfiguration
    on its own), and does nothing when a live version cannot be read
    (unreachable server, or an ``INFO`` response this check cannot parse).
    Only "reachable, correctly configured, and reporting an unsupported
    version" is flagged: everything else is either not this check's
    concern or the transient outage BR-EVAL-007 already handles at
    runtime, not a boot-time misconfiguration.
    """
    from django_waf import conf
    from django_waf.services.redis_client import (
        MIN_REDIS_VERSION,
        get_redis_server_version,
        is_redis_backend,
    )

    if not conf.DJANGO_WAF_ENABLED:
        return []

    if not is_redis_backend(conf.DJANGO_WAF_REDIS_ALIAS):
        return []

    version = get_redis_server_version(conf.DJANGO_WAF_REDIS_ALIAS)
    if version is None or version >= MIN_REDIS_VERSION:
        return []

    version_str = ".".join(str(part) for part in version)
    floor_str = ".".join(str(part) for part in MIN_REDIS_VERSION)
    return [
        Error(
            f"Redis server on alias {conf.DJANGO_WAF_REDIS_ALIAS!r} reports "
            f"version {version_str}, below this package's floor of "
            f"{floor_str}.",
            hint=(
                f"Upgrade the Redis server backing "
                f"CACHES[{conf.DJANGO_WAF_REDIS_ALIAS!r}] to {floor_str} or "
                "newer, or point DJANGO_WAF_REDIS_ALIAS at one that already "
                "meets the floor."
            ),
            id="django_waf.E005",
        )
    ]
