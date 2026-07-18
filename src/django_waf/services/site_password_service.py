"""
Site password gate service for django-waf.

Implements the BR-SP series (see docs/specs/site-password/PRD.md): a
shared-password wall gating the whole site before any application view.
Shared by the middleware short-circuit (django_waf.middleware) and the
routed verify view (django_waf.views) so there is one implementation of
the session-flag and password-check logic, not two.

The session flag is a dict stored under a single session key: a boolean
marker plus an issued-at Unix timestamp. It is not itself cryptographically
signed beyond what Django's session backend already provides (signed
cookies for the default backend; a server-side store otherwise) — the
session framework is the trust boundary, matching how Django's own
``request.session`` is used elsewhere in this codebase (e.g. the
CSRF-protected form-replay flow). The password itself is never stored in
the session.
"""

from __future__ import annotations

import hmac
import time

from django.http import HttpRequest

SESSION_KEY = "waf_site_password_verified"


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


def has_valid_session_flag(request: HttpRequest) -> bool:
    """Return True if the request carries an unexpired verified-session flag.

    Per BR-SP-004. Reads DJANGO_WAF_SITE_PASSWORD_TTL live (not cached) so a
    TTL change in settings takes effect for sessions on their next request
    without needing every existing session flag re-issued.
    """
    from django_waf import conf

    if not hasattr(request, "session"):
        return False

    flag = request.session.get(SESSION_KEY)
    if not flag or not isinstance(flag, dict):
        return False

    issued_at = flag.get("issued_at")
    if not isinstance(issued_at, (int, float)):
        return False

    ttl = conf.DJANGO_WAF_SITE_PASSWORD_TTL
    return (time.time() - issued_at) < ttl


def mark_session_verified(request: HttpRequest) -> None:
    """Set the verified-session flag with the current time as issued-at.

    Never stores the password itself — only a boolean marker and a
    timestamp (BR-SP-005: the password is never rendered, logged, or
    persisted anywhere beyond the settings value it is read from).
    """
    request.session[SESSION_KEY] = {"verified": True, "issued_at": time.time()}
    request.session.modified = True


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
