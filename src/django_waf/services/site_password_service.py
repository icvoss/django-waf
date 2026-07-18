"""
Site password gate service for django-waf.

Implements the BR-SP series (see docs/specs/site-password/PRD.md): a
shared-password wall gating the whole site before any application view.
Shared by the middleware short-circuit (django_waf.middleware) and the
routed verify view (django_waf.views) so there is one implementation of
the verified-flag and password-check logic, not two.

The verified flag is the gate's own signed cookie, not Django's session.
``WafMiddleware`` is documented (README) to sit before
``SessionMiddleware`` in the middleware stack so it can block requests as
early as possible — ``request.session`` does not exist at that point, so
the gate cannot depend on it (this was a real defect: see the regression
test ``TestNoSessionMiddlewareRegression`` in tests/test_site_password.py).
Instead, the flag is a ``django.core.signing.TimestampSigner``-signed
marker stored in a cookie the gate owns, verified independently of the
session framework. The signature uses the package's own signing key
(``django_waf.forms.services.tokens.get_signing_key``, i.e.
``DJANGO_WAF_SIGNING_KEY`` with a ``SECRET_KEY``-derived fallback) — the
same key every other signed artefact in this package uses — rather than
Django's session/cookie signer. The TTL is enforced live by passing
``max_age`` to ``TimestampSigner.unsign`` on every request, so a
``DJANGO_WAF_SITE_PASSWORD_TTL`` change takes effect immediately without
needing every existing cookie re-issued. The password itself is never
stored in the cookie.
"""

from __future__ import annotations

import hmac

from django.core import signing
from django.http import HttpRequest, HttpResponse

# Name of the gate's own verified-flag cookie. Deliberately not the Django
# session cookie -- see the module docstring.
SITE_PASSWORD_COOKIE = "waf_site_password"

# Salt namespacing this cookie's signatures from any other
# django.core.signing use in the project (e.g. Django's own session/cookie
# signing, or other django-waf signed artefacts).
_SIGNING_SALT = "django_waf.site_password"

# The cookie only needs to prove "a correct password was submitted"; the
# TimestampSigner's own timestamp gives the age used for the TTL check, so
# the payload is a fixed marker rather than a JSON blob.
_VERIFIED_MARKER = "verified"


def is_gate_enabled() -> bool:
    """Return True if the site password gate is switched on.

    Per BR-SP-001: unset/empty password and DJANGO_WAF_SITE_PASSWORD_ENABLED
    both defaulting False means no gate — this must be cheap and side-effect
    free since it runs on every request via the middleware.
    """
    from django_waf import conf

    return bool(conf.DJANGO_WAF_SITE_PASSWORD_ENABLED)


def is_misconfigured() -> bool:
    """Return True if the gate is enabled but has no password set (BR-SP-002).

    Fail-closed: the caller must deny every gated request in this state
    rather than silently opening the gate.
    """
    from django_waf import conf

    return bool(conf.DJANGO_WAF_SITE_PASSWORD_ENABLED) and not conf.DJANGO_WAF_SITE_PASSWORD


def is_exempt_path(path: str) -> bool:
    """Return True if the path bypasses the gate (BR-SP-003)."""
    from django_waf import conf

    return any(path.startswith(prefix) for prefix in conf.DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS)


def _get_signer() -> signing.TimestampSigner:
    """Return a TimestampSigner keyed with the package's own signing key.

    Uses ``django_waf.forms.services.tokens.get_signing_key`` (DJANGO_WAF_SIGNING_KEY
    with a SECRET_KEY-derived fallback) so the site-password cookie is
    signed with the same key convention as every other signed artefact
    django-waf issues, independent of Django's session/cookie signer.
    """
    from django_waf.forms.services.tokens import get_signing_key

    return signing.TimestampSigner(key=get_signing_key(), salt=_SIGNING_SALT)


def has_valid_cookie(request: HttpRequest) -> bool:
    """Return True if the request carries an unexpired, correctly signed
    verified-flag cookie.

    Per BR-SP-004. Reads DJANGO_WAF_SITE_PASSWORD_TTL live (not cached) via
    the ``max_age`` passed to ``unsign`` so a TTL change in settings takes
    effect for existing cookies on their next request without needing every
    one re-issued. A missing, tampered, or expired cookie returns False
    (never raises) so the caller simply re-prompts.
    """
    from django_waf import conf

    cookie_value = request.COOKIES.get(SITE_PASSWORD_COOKIE)
    if not cookie_value:
        return False

    ttl = conf.DJANGO_WAF_SITE_PASSWORD_TTL
    try:
        # SignatureExpired is a subclass of BadSignature -- catching the
        # base class covers both "tampered" and "expired" in one branch.
        payload = _get_signer().unsign(cookie_value, max_age=ttl)
    except signing.BadSignature:
        return False

    return payload == _VERIFIED_MARKER


def set_verified_cookie(response: HttpResponse, request: HttpRequest) -> None:
    """Set the signed verified-flag cookie on the response.

    Never stores the password itself — only a signed marker (BR-SP-005:
    the password is never rendered, logged, or persisted anywhere beyond
    the settings value it is read from). Set on the *response*, not the
    request, and independent of Django's session -- this cookie is the
    gate's whole trust boundary (see module docstring).

    ``domain`` defaults to ``DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN`` if
    set, else ``settings.SESSION_COOKIE_DOMAIN`` -- so a verified cookie
    spans subdomains exactly as the PRD documents for the (now retired)
    session-based approach, without introducing a new operator setting
    most sites won't need.
    """
    from django.conf import settings

    from django_waf import conf

    ttl = conf.DJANGO_WAF_SITE_PASSWORD_TTL
    cookie_domain = conf.DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN
    if cookie_domain is None:
        cookie_domain = getattr(settings, "SESSION_COOKIE_DOMAIN", None)

    signed_value = _get_signer().sign(_VERIFIED_MARKER)
    response.set_cookie(
        SITE_PASSWORD_COOKIE,
        signed_value,
        max_age=ttl,
        domain=cookie_domain,
        httponly=True,
        secure=request.is_secure(),
        samesite="Lax",
    )


def check_password(submitted: str) -> bool:
    """Constant-time comparison of the submitted password against config.

    Per BR-SP-005. Returns False (never raises) for an empty submission or
    a misconfigured (empty) stored password — an empty stored password
    must never compare equal to an empty submission, which would otherwise
    let a blank form field through.
    """
    from django_waf import conf

    stored = conf.DJANGO_WAF_SITE_PASSWORD
    if not stored or not submitted:
        return False
    return hmac.compare_digest(submitted, stored)


def record_guess_throttle_hit(ip_address: str, redis_client) -> bool:
    """Record a failed password guess and return True if the IP should now
    be throttled (BR-SP-007).

    Reuses the existing WAF rate-limit surface
    (django_waf.services.rate_limiter.check_rate_limit) rather than a new
    limiter, keyed on the verify path so guess attempts are counted
    independently of the IP's ordinary browsing traffic. Fails open (returns
    False) on any Redis error, matching the WAF's existing fail-open policy
    for infrastructure failures — a throttling outage must never turn into
    a site-wide lockout on its own.
    """
    from django_waf import conf
    from django_waf.services.rate_limiter import check_rate_limit

    if redis_client is None:
        return False

    try:
        result = check_rate_limit(ip_address, redis_client, path=conf.DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH)
    except Exception:
        return False

    return result.exceeded
