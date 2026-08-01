"""
Trusted-user cookie service for django-waf.

Implements #23 (see docs/DESIGN-trusted-user-cookie.md): a signed,
WAF-owned cookie that lets ``WafMiddleware`` recognise a trusted (staff)
user without reading ``request.user``, so the staff/superuser bypass
(BR-RATE-003, ``django_waf.middleware._is_staff_user``) works even when
``WafMiddleware`` runs before
``django.contrib.auth.middleware.AuthenticationMiddleware`` — the
security-first ordering the package's own README recommends, and the
ordering ``django_waf.checks.check_middleware_ordering`` (``django_waf.W004``)
has historically warned against.

This mirrors ``django_waf.services.site_password_service`` exactly: a
``django.core.signing.TimestampSigner`` keyed with the package's own
signing key (``django_waf.forms.services.tokens.get_signing_key``), a
distinct salt, and a fixed marker payload rather than a JSON blob (the
signer's own timestamp already gives the age used for the TTL check). The
TTL is enforced live by passing ``max_age`` to ``TimestampSigner.unsign``
on every request, so a ``DJANGO_WAF_TRUSTED_COOKIE_TTL`` change takes
effect immediately without needing every existing cookie re-issued.

Unlike the site-password cookie, this cookie also binds to the client IP
(the same ``resolve_client_ip`` the rest of the WAF uses, see
``django_waf.services.client_ip``) as part of the signed payload. A signed
cookie is unforgeable but a *stolen* one grants the bypass until expiry;
binding it to the issuing IP means a copy used from a different address is
rejected, and the deliberately short default TTL
(``DJANGO_WAF_TRUSTED_COOKIE_TTL``) bounds the remaining exposure. Neither
control makes a stolen cookie harmless on a shared/NAT'd network, so the
short TTL is the primary control, not the IP binding.

This module is DB-free, session-free, and auth-free by design — it must be
safe to call from ``WafMiddleware`` at a point in the stack before
``SessionMiddleware`` and ``AuthenticationMiddleware`` have run.
"""

from __future__ import annotations

from django.core import signing
from django.http import HttpRequest, HttpResponse

# Name of the trusted-user cookie. Distinct from the site-password gate's
# cookie (django_waf.services.site_password_service.SITE_PASSWORD_COOKIE)
# and from the challenge-pass cookie ("waf_pass") — each signed artefact
# the WAF issues owns its own cookie name and salt.
TRUSTED_USER_COOKIE = "waf_trusted"

# Salt namespacing this cookie's signatures from any other
# django.core.signing use in the project.
_SIGNING_SALT = "django_waf.trusted_user"

# The cookie proves "a trusted user issued this cookie from this IP"; the
# TimestampSigner's own timestamp gives the age used for the TTL check, so
# the payload is a fixed marker plus the bound IP rather than a JSON blob.
_TRUSTED_MARKER = "trusted"


def is_feature_enabled() -> bool:
    """Return True if the trusted-user cookie feature is switched on.

    Read live (not cached) so tests can toggle it with ``patch.object``
    without a module reload, and so a disabled feature is a true no-op:
    ``has_valid_trusted_cookie`` short-circuits on this before touching any
    cookie, meaning a stray cookie left over from the feature previously
    being enabled grants nothing while it is off.
    """
    from django_waf import conf

    return bool(conf.DJANGO_WAF_TRUSTED_COOKIE_ENABLED)


def get_trust_level() -> str:
    """Return the configured trust level, coerced to a known value.

    ``DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL`` should be "staff" or
    "authenticated" (see conf.py). Any other configured value fails to the
    narrower, safer population ("staff") rather than raising — a typo in
    settings must never silently widen the bypass to every authenticated
    user. ``django_waf.checks.check_trusted_cookie_trust_level``
    (``django_waf.W006``) surfaces the misconfiguration at boot.
    """
    from django_waf import conf

    level = conf.DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL
    if level == "authenticated":
        return "authenticated"
    return "staff"


def user_meets_trust_level(user) -> bool:
    """Return True if ``user`` meets the configured trust level.

    "staff" (default): ``is_staff`` or ``is_superuser`` — the same
    population ``django_waf.middleware._is_staff_user`` already trusted via
    ``request.user`` before this feature existed. "authenticated": any
    ``is_authenticated`` user, an explicit opt-in broadening of the bypass.
    """
    if not getattr(user, "is_authenticated", False):
        return False

    if get_trust_level() == "authenticated":
        return True

    return bool(getattr(user, "is_staff", False) or getattr(user, "is_superuser", False))


def _get_signer() -> signing.TimestampSigner:
    """Return a TimestampSigner keyed with the package's own signing key.

    Uses ``django_waf.forms.services.tokens.get_signing_key`` (the same key
    convention as ``site_password_service._get_signer``), independent of
    Django's session/cookie signer.
    """
    from django_waf.forms.services.tokens import get_signing_key

    return signing.TimestampSigner(key=get_signing_key(), salt=_SIGNING_SALT)


def _build_payload(ip_address: str) -> str:
    """Build the signed payload: the fixed marker bound to the issuing IP."""
    return f"{_TRUSTED_MARKER}:{ip_address}"


def set_trusted_cookie(response: HttpResponse, request: HttpRequest) -> None:
    """Set the signed trusted-user cookie on the response.

    Binds the cookie to the client IP resolved via
    ``django_waf.services.client_ip.resolve_client_ip`` — the same hardened
    resolver the rest of the WAF uses (#29) — rather than
    ``request.META["REMOTE_ADDR"]`` directly, so the binding matches
    whatever IP the WAF itself treats as authoritative for this request
    (trusted-proxy chains, ``X-Forwarded-For`` handling, and so on).

    Set on the *response*, not the request: this is normally called from
    the login receiver via the middleware's response-side hook (see
    ``django_waf.middleware.WafMiddleware`` and ``django_waf.receivers``),
    because the cookie can only be written once the login response exists.

    ``domain`` defaults to ``DJANGO_WAF_TRUSTED_COOKIE_DOMAIN`` if set, else
    ``settings.SESSION_COOKIE_DOMAIN`` — mirrors
    ``site_password_service.set_verified_cookie``.
    """
    from django.conf import settings

    from django_waf import conf
    from django_waf.services.client_ip import resolve_client_ip

    ttl = conf.DJANGO_WAF_TRUSTED_COOKIE_TTL
    cookie_domain = conf.DJANGO_WAF_TRUSTED_COOKIE_DOMAIN
    if cookie_domain is None:
        cookie_domain = getattr(settings, "SESSION_COOKIE_DOMAIN", None)

    ip_address = resolve_client_ip(request)
    signed_value = _get_signer().sign(_build_payload(ip_address))
    response.set_cookie(
        TRUSTED_USER_COOKIE,
        signed_value,
        max_age=ttl,
        domain=cookie_domain,
        httponly=True,
        secure=request.is_secure(),
        samesite="Lax",
    )


def has_valid_trusted_cookie(request: HttpRequest) -> bool:
    """Return True if the request carries an unexpired, correctly signed
    trusted-user cookie issued to the request's own client IP.

    Returns False (never raises) when: the feature is disabled (so a stray
    cookie left over from the feature previously being enabled grants
    nothing); the cookie is missing; the signature is tampered or expired
    (``signing.BadSignature`` covers both — ``SignatureExpired`` is a
    subclass); or the bound IP does not match
    ``django_waf.services.client_ip.resolve_client_ip(request)`` for this
    request (rejects a cookie replayed from a different address).

    Reads ``DJANGO_WAF_TRUSTED_COOKIE_TTL`` live via the ``max_age`` passed
    to ``unsign`` so a TTL change takes effect immediately, mirroring
    ``site_password_service.has_valid_cookie``.
    """
    if not is_feature_enabled():
        return False

    from django_waf import conf
    from django_waf.services.client_ip import resolve_client_ip

    cookie_value = request.COOKIES.get(TRUSTED_USER_COOKIE)
    if not cookie_value:
        return False

    ttl = conf.DJANGO_WAF_TRUSTED_COOKIE_TTL
    try:
        payload = _get_signer().unsign(cookie_value, max_age=ttl)
    except signing.BadSignature:
        return False

    marker, _, bound_ip = payload.partition(":")
    if marker != _TRUSTED_MARKER:
        return False

    return bound_ip == resolve_client_ip(request)

