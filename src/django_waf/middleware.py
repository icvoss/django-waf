"""
WAF middleware for django-waf.

Evaluates every Django request against the active rule set and enforces
block/challenge/throttle verdicts. Clean requests (<0.5ms overhead) are
handled via Redis lookups and in-memory regex. The middleware is fail-open:
if Redis is unreachable the request always passes through.
"""

from __future__ import annotations

import logging
import random

from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect
from django.urls import reverse
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger("django_waf.middleware")

# Applied to every site-password prompt/verify response -- these pages must
# never be indexed (BR-SP-006). Mirrors django_waf.views._NOINDEX_ROBOTS_HEADER.
_SITE_PASSWORD_NOINDEX_HEADER = "noindex, nofollow, noarchive"

_SITE_PASSWORD_INCORRECT_ERROR = _("Incorrect password. Please try again.")
_SITE_PASSWORD_MISCONFIGURED_ERROR = _("This site is temporarily unavailable.")


class WafMiddleware:
    """Django WAF middleware — new-style __init__/__call__ pattern.

    Evaluation order per BR-EVAL-003:
    1. Exempt paths and hosts bypass all WAF checks (BR-EVAL-001)
    2. Master switch DJANGO_WAF_ENABLED (BR-EVAL-002)
    3. Staff/superuser bypass rate limiting (BR-RATE-003)
    4. Valid waf_pass cookie → pass through (BR-CHAL-006)
    5. evaluate_request() — allow / block / challenge / throttle / log
    6. Handle verdict, log, emit signals
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def _get_challenge_paths(self) -> tuple[str, str]:
        """Return (challenge_path, verify_path) for the current request.

        Resolved fresh on every call rather than cached on the middleware
        instance, because projects using per-request urlconf routing (e.g.
        django-hosts) need ``reverse()`` to consult the active thread-local
        urlconf each time. Caching would freeze whichever host first hit a
        challenge into the resolved path for the lifetime of the process.

        Operators can short-circuit ``reverse()`` entirely by setting
        ``DJANGO_WAF_CHALLENGE_URL`` / ``DJANGO_WAF_VERIFY_URL`` to literal paths,
        which is the recommended approach for multi-urlconf projects that
        don't mount the django_waf URLs on every host.
        """
        from django_waf import conf

        challenge = conf.DJANGO_WAF_CHALLENGE_URL or reverse("django_waf:challenge")
        verify = conf.DJANGO_WAF_VERIFY_URL or reverse("django_waf:verify")
        return challenge, verify

    def __call__(self, request):
        from django_waf import conf

        # BR-EVAL-002: master kill switch
        if not conf.DJANGO_WAF_ENABLED:
            return self.get_response(request)

        # BR-EVAL-001: exempt paths — prefix match
        path = request.path_info

        for prefix in conf.DJANGO_WAF_EXEMPT_PATHS:
            if path.startswith(prefix):
                return self.get_response(request)

        # BR-EVAL-001: exempt hosts — exact or subdomain match
        if conf.DJANGO_WAF_EXEMPT_HOSTS and _is_exempt_host(request, conf.DJANGO_WAF_EXEMPT_HOSTS):
            return self.get_response(request)

        # BR-SP-008: site password gate — after the enabled/exempt/health
        # short-circuits above, before country-block/threat evaluation
        # below. A locked site prompts for the password before spending any
        # WAF evaluation effort; the prompt and verify paths must themselves
        # stay reachable, which is why this runs ahead of everything else.
        gate_response = self._check_site_password(request, path)
        if gate_response is not None:
            return gate_response

        # HTTP method filtering — 405 for disallowed methods
        allowed = conf.DJANGO_WAF_ALLOWED_METHODS
        if allowed is not None and request.method not in allowed:
            response = HttpResponse("Method not allowed.", status=405)
            response["Allow"] = ", ".join(allowed)
            return response

        # Extract client IP — fail-open if unavailable
        ip_address = _extract_ip(request)
        if not ip_address:
            return self.get_response(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Country blocking — fail-open on any GeoIP error or missing database.
        if conf.DJANGO_WAF_BLOCKED_COUNTRIES:
            blocked_response = self._check_country_block(request, ip_address, user_agent, path)
            if blocked_response is not None:
                return blocked_response

        # BR-RATE-003: staff/superuser bypass — skip WAF entirely
        if _is_staff_user(request):
            return self.get_response(request)

        # Get Redis connection — fail-open if unavailable
        redis_client = _get_redis_client()
        if redis_client is None:
            return self.get_response(request)

        # BR-CHAL-006: check for valid waf_pass cookie before evaluation
        try:
            from django_waf.services.challenge_service import validate_pass_cookie

            cookie_value = request.COOKIES.get("waf_pass", "")
            if cookie_value and validate_pass_cookie(cookie_value, ip_address):
                # Cookie is valid — pass through
                response = self.get_response(request)
                return response
        except Exception:
            logger.exception("django-waf: error validating waf_pass cookie")

        # Core evaluation
        try:
            from django_waf.services.rule_engine import evaluate_request

            result = evaluate_request(
                ip_address=ip_address,
                user_agent=user_agent,
                path=path,
                method=request.method,
                redis_client=redis_client,
                referer=request.META.get("HTTP_REFERER", ""),
                request_meta=request.META,
            )
        except Exception:
            # Fail-open: if evaluation raises, pass the request through
            logger.exception("django-waf: evaluation error — failing open")
            return self.get_response(request)

        # Build and return verdict-specific response
        response = self._handle_verdict(
            request=request,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            path=path,
            redis_client=redis_client,
        )

        # Log the request (sampling for allowed/passed, always for security events)
        self._log_request(
            request=request,
            result=result,
            ip_address=ip_address,
            user_agent=user_agent,
            path=path,
            response_code=response.status_code,
        )

        return response

    def _check_country_block(self, request, ip_address, user_agent, path):
        """Return a 403 response if the request's country is blocked, else None.

        Fails open: any error resolving the country (missing database,
        geoip2 not installed, lookup exception) falls through to normal
        evaluation rather than blocking. Logging the block is best-effort —
        a logging failure never prevents the 403 from being returned.
        """
        from django_waf import conf

        try:
            from django_waf.services.geoip import lookup_country

            country = lookup_country(ip_address)
            if not country:
                # No database / lookup failure — fail open.
                return None

            blocked_countries = {c.upper() for c in conf.DJANGO_WAF_BLOCKED_COUNTRIES}
            if country.upper() not in blocked_countries:
                return None

            self._log_country_block(request, ip_address, user_agent, path, country)
            return HttpResponseForbidden("Access denied.")
        except Exception:
            logger.exception("django-waf: error during country-block check — failing open")
            return None

    def _check_site_password(self, request, path):
        """Return a response to short-circuit the site-password gate, or
        None to continue evaluation.

        Per PRD docs/specs/site-password/PRD.md section 2.1 / BR-SP series:

        1. Gate off (DJANGO_WAF_SITE_PASSWORD_ENABLED falsy) → None,
           zero-cost (BR-SP-001).
        2. Exempt path → None (BR-SP-003).
        3. Fail-closed misconfiguration (enabled, empty password) → always
           deny, never fall through to "no gate" (BR-SP-002).
        4. Valid, unexpired session flag → None (BR-SP-004).
        5. POST to the verify path → check the password and either set the
           flag + redirect, or re-prompt with an error and a throttle hit.
        6. Otherwise → render the noindex 401 prompt.
        """
        from django_waf import conf
        from django_waf.services import site_password_service as sp

        if not sp.is_gate_enabled():
            return None

        if sp.is_exempt_path(path):
            return None

        if sp.is_misconfigured():
            logger.error(
                "django-waf: DJANGO_WAF_SITE_PASSWORD_ENABLED is True but "
                "DJANGO_WAF_SITE_PASSWORD is empty — failing closed (BR-SP-002)."
            )
            return self._render_site_password_prompt(request, error=_SITE_PASSWORD_MISCONFIGURED_ERROR)

        if sp.has_valid_session_flag(request):
            return None

        verify_path = conf.DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH
        if request.method == "POST" and path == verify_path:
            return self._handle_site_password_verify(request)

        return self._render_site_password_prompt(request)

    def _handle_site_password_verify(self, request):
        """Handle a POST to the site-password verify path.

        On success: set the session flag and redirect to a validated
        ``next`` (BR-SP-004). On failure: re-render the prompt with an
        error and record a throttle hit against the WAF's existing
        rate-limit surface (BR-SP-007).
        """
        from django.utils.http import url_has_allowed_host_and_scheme

        from django_waf.services import site_password_service as sp

        submitted = request.POST.get("password", "")
        next_param = request.POST.get("next", "")

        if sp.check_password(submitted):
            sp.mark_session_verified(request)
            safe_next = "/"
            if next_param and url_has_allowed_host_and_scheme(
                url=next_param,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                safe_next = next_param
            return HttpResponseRedirect(safe_next)

        ip_address = _extract_ip(request) or "0.0.0.0"
        redis_client = _get_redis_client()
        throttled = sp.record_guess_throttle_hit(ip_address, redis_client)
        if throttled:
            response = HttpResponse("Too many attempts. Please retry later.", status=429)
            response["Retry-After"] = "60"
            response["X-Robots-Tag"] = _SITE_PASSWORD_NOINDEX_HEADER
            return response

        return self._render_site_password_prompt(request, error=_SITE_PASSWORD_INCORRECT_ERROR, next_url=next_param)

    def _render_site_password_prompt(self, request, error=None, next_url=None):
        """Render the noindex 401 site-password prompt (BR-SP-006)."""
        from django.shortcuts import render

        from django_waf import conf

        if next_url is None:
            next_url = request.get_full_path()

        response = render(
            request,
            "django_waf/site_password.html",
            {
                "error": error,
                "next_url": next_url,
                "verify_path": conf.DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH,
            },
            status=401,
        )
        response["X-Robots-Tag"] = _SITE_PASSWORD_NOINDEX_HEADER
        return response

    def _log_country_block(self, request, ip_address, user_agent, path, country):
        """Best-effort RequestLog entry for a country-blocked request."""
        try:
            from django.utils import timezone

            from django_waf.enums import Verdict
            from django_waf.models import RequestLog

            RequestLog.objects.create(
                timestamp=timezone.now(),
                ip_address=ip_address,
                user_agent=user_agent[:1024],
                path=path[:2048],
                method=request.method,
                verdict=Verdict.BLOCKED,
                matched_rule_id=None,
                matched_rule_type="",
                anomaly_score=None,
                response_code=403,
                referer=request.META.get("HTTP_REFERER", "")[:2048],
                http_fingerprint=_compute_fingerprint(request),
                fingerprint_verdict=_classify_fingerprint(request),
                country_code=country,
            )
        except Exception:
            logger.exception("django-waf: error creating RequestLog record for country block")

    def _handle_verdict(self, request, result, ip_address, user_agent, path, redis_client):
        from django_waf.enums import Verdict

        verdict = result.verdict

        if verdict == Verdict.BLOCKED:
            try:
                from django_waf.services.rule_engine import record_block_verdict

                # Thread the matched rule id through so the fast-path can
                # attribute subsequent cached blocks back to the rule, not
                # just block them anonymously (regression fixed in v0.10.6).
                record_block_verdict(
                    ip_address,
                    redis_client,
                    rule_id=str(result.matched_rule_id) if result.matched_rule_id else None,
                )
            except Exception:
                logger.exception("django-waf: error recording block verdict")
            _emit_request_blocked(result, ip_address, user_agent, path)
            return HttpResponseForbidden("Access denied.")

        if verdict == Verdict.THROTTLED:
            _emit_request_throttled(result, ip_address)
            response = HttpResponse("Too many requests. Please retry later.", status=429)
            if result.action and hasattr(result, "retry_after"):
                response["Retry-After"] = str(result.retry_after)
            else:
                # Default Retry-After — 60 seconds
                response["Retry-After"] = "60"
            return response

        if verdict == Verdict.CHALLENGED:
            challenge_path, verify_path = self._get_challenge_paths()

            # Suppress challenge redirect when already on a challenge/verify
            # path to prevent infinite redirect loops. BLOCKED and THROTTLED
            # verdicts still apply — only the redirect is suppressed.
            if path.startswith(challenge_path) or path.startswith(verify_path):
                return self.get_response(request)

            # Increment unsolved-challenge counter for escalation tracking
            try:
                key = f"waf:challenged:{ip_address}"
                redis_client.incr(key)
                redis_client.expire(key, 3600)  # 1-hour window
            except Exception:
                pass
            challenge_url = f"{challenge_path}?next={path}"
            return HttpResponseRedirect(challenge_url)

        # ALLOWED, PASSED, LOGGED — pass through to the view
        return self.get_response(request)

    def _log_request(self, request, result, ip_address, user_agent, path, response_code):
        from django_waf import conf
        from django_waf.enums import Verdict

        verdict = result.verdict
        always_log = verdict in (Verdict.BLOCKED, Verdict.CHALLENGED, Verdict.THROTTLED, Verdict.LOGGED)

        if not always_log and random.random() >= conf.DJANGO_WAF_LOG_SAMPLE_RATE:
            # Sample allowed/passed requests (BR-LOG-002)
            return

        try:
            from django.utils import timezone

            from django_waf.models import RequestLog

            RequestLog.objects.create(
                timestamp=timezone.now(),
                ip_address=ip_address,
                user_agent=user_agent[:1024],
                path=path[:2048],
                method=request.method,
                verdict=verdict,
                matched_rule_id=result.matched_rule_id,
                matched_rule_type=result.matched_rule_type,
                anomaly_score=result.anomaly_score,
                response_code=response_code,
                referer=request.META.get("HTTP_REFERER", "")[:2048],
                http_fingerprint=_compute_fingerprint(request),
                fingerprint_verdict=_classify_fingerprint(request),
                country_code=_lookup_country(ip_address),
            )
        except Exception:
            logger.exception("django-waf: error creating RequestLog record")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _lookup_country(ip_address: str) -> str:
    """Backwards-compatibility shim — the real implementation lives in
    ``django_waf.services.geoip.lookup_country`` (moved in v0.10.6 so the
    admin can share the same lazy reader)."""
    from django_waf.services.geoip import lookup_country

    return lookup_country(ip_address)


def _compute_fingerprint(request) -> str:
    """Compute an HTTP fingerprint hash for the request."""
    try:
        from django_waf.services.fingerprint import compute_fingerprint

        return compute_fingerprint(request.META)
    except Exception:
        return ""


def _classify_fingerprint(request) -> str:
    """Classify the request fingerprint as browser/bot/suspicious/unknown."""
    try:
        from django_waf.services.fingerprint import classify_fingerprint

        return classify_fingerprint(
            request.META.get("HTTP_USER_AGENT", ""),
            request.META,
        )
    except Exception:
        return ""


def _extract_ip(request) -> str:
    """Extract the client IP address from the request.

    If DJANGO_WAF_TRUST_X_FORWARDED_FOR is True and the header is present, use the
    first IP in the X-Forwarded-For chain. Otherwise use REMOTE_ADDR.
    """
    from django_waf import conf

    if conf.DJANGO_WAF_TRUST_X_FORWARDED_FOR:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            # Take the first (leftmost) IP — the original client
            return forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR", "")


def _is_exempt_host(request, exempt_hosts) -> bool:
    """Return True if the request host matches an entry in exempt_hosts.

    Matching mirrors Django's ALLOWED_HOSTS: an exact host match, or a
    leading-dot entry (".example.com") matching the domain and any subdomain.
    The port is stripped before matching. Falls back to the raw HTTP_HOST
    header if get_host() raises (e.g. host not in ALLOWED_HOSTS).
    """
    try:
        host = request.get_host()
    except Exception:
        host = request.META.get("HTTP_HOST", "")

    # Strip port. IPv6 literals are bracketed ("[::1]:8000") so split on the
    # last colon only when it follows a closing bracket or there is no bracket.
    if host.startswith("["):
        host = host.partition("]")[0].lstrip("[")
    else:
        host = host.rsplit(":", 1)[0] if ":" in host else host
    host = host.lower()

    for entry in exempt_hosts:
        entry = entry.lower()
        if entry.startswith("."):
            if host == entry[1:] or host.endswith(entry):
                return True
        elif host == entry:
            return True
    return False


def _is_staff_user(request) -> bool:
    """Return True if the request is from an authenticated staff or superuser.

    Per BR-RATE-003.
    """
    return (
        hasattr(request, "user")
        and request.user.is_authenticated
        and (request.user.is_staff or request.user.is_superuser)
    )


def _get_redis_client():
    """Return a Redis client instance.

    Tries django-redis's get_redis_connection first; falls back to the default
    Django cache. Returns None if Redis is unavailable (fail-open policy).
    """
    from django_waf import conf

    try:
        from django_redis import get_redis_connection

        return get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except Exception:
        pass

    try:
        from django.core.cache import cache

        # For non-redis cache backends this returns the cache object — callers
        # that need Redis-specific commands will raise and be caught.
        return cache
    except Exception:
        pass

    logger.warning("django-waf: Redis unavailable — failing open")
    return None


def _emit_request_blocked(result, ip_address: str, user_agent: str, path: str) -> None:
    """Emit the request_blocked signal without raising."""
    try:
        from django_waf.signals import request_blocked

        request_blocked.send(
            sender=None,
            ip_address=ip_address,
            user_agent=user_agent,
            path=path,
            rule=None,
            verdict=result.verdict,
        )
    except Exception:
        logger.exception("django-waf: failed to emit request_blocked signal")


def _emit_request_throttled(result, ip_address: str) -> None:
    """Emit the request_throttled signal without raising."""
    try:
        from django_waf.signals import request_throttled

        request_throttled.send(
            sender=None,
            ip_address=ip_address,
            window=getattr(result, "window", None),
        )
    except Exception:
        logger.exception("django-waf: failed to emit request_throttled signal")
