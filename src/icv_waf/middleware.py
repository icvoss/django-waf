"""
WAF middleware for icv-waf.

Evaluates every Django request against the active rule set and enforces
block/challenge/throttle verdicts. Clean requests (<0.5ms overhead) are
handled via Redis lookups and in-memory regex. The middleware is fail-open:
if Redis is unreachable the request always passes through.
"""

from __future__ import annotations

import logging
import random

from django.http import HttpResponse, HttpResponseForbidden, HttpResponseRedirect

logger = logging.getLogger("icv_waf.middleware")


class WafMiddleware:
    """Django WAF middleware — new-style __init__/__call__ pattern.

    Evaluation order per BR-EVAL-003:
    1. Exempt paths bypass all WAF checks (BR-EVAL-001)
    2. Master switch ICV_WAF_ENABLED (BR-EVAL-002)
    3. Staff/superuser bypass rate limiting (BR-RATE-003)
    4. Valid waf_pass cookie → pass through (BR-CHAL-006)
    5. evaluate_request() — allow / block / challenge / throttle / log
    6. Handle verdict, log, emit signals
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        from icv_waf import conf

        # BR-EVAL-002: master kill switch
        if not conf.ICV_WAF_ENABLED:
            return self.get_response(request)

        # BR-EVAL-001: exempt paths — prefix match
        path = request.path_info
        for prefix in conf.ICV_WAF_EXEMPT_PATHS:
            if path.startswith(prefix):
                return self.get_response(request)

        # HTTP method filtering — 405 for disallowed methods
        allowed = conf.ICV_WAF_ALLOWED_METHODS
        if allowed is not None and request.method not in allowed:
            response = HttpResponse("Method not allowed.", status=405)
            response["Allow"] = ", ".join(allowed)
            return response

        # Extract client IP — fail-open if unavailable
        ip_address = _extract_ip(request)
        if not ip_address:
            return self.get_response(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # BR-RATE-003: staff/superuser bypass — skip WAF entirely
        if _is_staff_user(request):
            return self.get_response(request)

        # Get Redis connection — fail-open if unavailable
        redis_client = _get_redis_client()
        if redis_client is None:
            return self.get_response(request)

        # BR-CHAL-006: check for valid waf_pass cookie before evaluation
        try:
            from icv_waf.services.challenge_service import validate_pass_cookie

            cookie_value = request.COOKIES.get("waf_pass", "")
            if cookie_value and validate_pass_cookie(cookie_value, ip_address):
                # Cookie is valid — pass through
                response = self.get_response(request)
                return response
        except Exception:
            logger.exception("icv-waf: error validating waf_pass cookie")

        # Core evaluation
        try:
            from icv_waf.services.rule_engine import evaluate_request

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
            logger.exception("icv-waf: evaluation error — failing open")
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

    def _handle_verdict(self, request, result, ip_address, user_agent, path, redis_client):
        from icv_waf.enums import Verdict

        verdict = result.verdict

        if verdict == Verdict.BLOCKED:
            try:
                from icv_waf.services.rule_engine import record_block_verdict

                record_block_verdict(ip_address, redis_client)
            except Exception:
                logger.exception("icv-waf: error recording block verdict")
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
            # Increment unsolved-challenge counter for escalation tracking
            try:
                key = f"waf:challenged:{ip_address}"
                redis_client.incr(key)
                redis_client.expire(key, 3600)  # 1-hour window
            except Exception:
                pass
            next_path = path
            challenge_url = f"/waf/challenge/?next={next_path}"
            return HttpResponseRedirect(challenge_url)

        # ALLOWED, PASSED, LOGGED — pass through to the view
        return self.get_response(request)

    def _log_request(self, request, result, ip_address, user_agent, path, response_code):
        from icv_waf import conf
        from icv_waf.enums import Verdict

        verdict = result.verdict
        always_log = verdict in (Verdict.BLOCKED, Verdict.CHALLENGED, Verdict.THROTTLED, Verdict.LOGGED)

        if not always_log and random.random() >= conf.ICV_WAF_LOG_SAMPLE_RATE:
            # Sample allowed/passed requests (BR-LOG-002)
            return

        try:
            from django.utils import timezone

            from icv_waf.models import RequestLog

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
            logger.exception("icv-waf: error creating RequestLog record")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


# GeoIP reader — lazily initialised, cached for the process lifetime.
_geoip_reader = None
_geoip_checked = False


def _lookup_country(ip_address: str) -> str:
    """Return the 2-letter ISO country code for an IP, or '' if unavailable.

    Uses MaxMind GeoLite2-Country database at the path specified by
    ICV_WAF_GEOIP_PATH. Degrades gracefully if the database is missing,
    geoip2 is not installed, or the IP is not found.
    """
    global _geoip_reader, _geoip_checked  # noqa: PLW0603

    from icv_waf import conf

    if not conf.ICV_WAF_GEOIP_PATH:
        return ""

    if not _geoip_checked:
        _geoip_checked = True
        try:
            import geoip2.database

            _geoip_reader = geoip2.database.Reader(conf.ICV_WAF_GEOIP_PATH)
        except Exception:
            logger.warning("icv-waf: GeoIP database not available at %s", conf.ICV_WAF_GEOIP_PATH)

    if _geoip_reader is None:
        return ""

    try:
        response = _geoip_reader.country(ip_address)
        return response.country.iso_code or ""
    except Exception:
        return ""


def _compute_fingerprint(request) -> str:
    """Compute an HTTP fingerprint hash for the request."""
    try:
        from icv_waf.services.fingerprint import compute_fingerprint

        return compute_fingerprint(request.META)
    except Exception:
        return ""


def _classify_fingerprint(request) -> str:
    """Classify the request fingerprint as browser/bot/suspicious/unknown."""
    try:
        from icv_waf.services.fingerprint import classify_fingerprint

        return classify_fingerprint(
            request.META.get("HTTP_USER_AGENT", ""),
            request.META,
        )
    except Exception:
        return ""


def _extract_ip(request) -> str:
    """Extract the client IP address from the request.

    If ICV_WAF_TRUST_X_FORWARDED_FOR is True and the header is present, use the
    first IP in the X-Forwarded-For chain. Otherwise use REMOTE_ADDR.
    """
    from icv_waf import conf

    if conf.ICV_WAF_TRUST_X_FORWARDED_FOR:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            # Take the first (leftmost) IP — the original client
            return forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR", "")


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
    from icv_waf import conf

    try:
        from django_redis import get_redis_connection

        return get_redis_connection(conf.ICV_WAF_REDIS_ALIAS)
    except Exception:
        pass

    try:
        from django.core.cache import cache

        # For non-redis cache backends this returns the cache object — callers
        # that need Redis-specific commands will raise and be caught.
        return cache
    except Exception:
        pass

    logger.warning("icv-waf: Redis unavailable — failing open")
    return None


def _emit_request_blocked(result, ip_address: str, user_agent: str, path: str) -> None:
    """Emit the request_blocked signal without raising."""
    try:
        from icv_waf.signals import request_blocked

        request_blocked.send(
            sender=None,
            ip_address=ip_address,
            user_agent=user_agent,
            path=path,
            rule=None,
        )
    except Exception:
        logger.exception("icv-waf: failed to emit request_blocked signal")


def _emit_request_throttled(result, ip_address: str) -> None:
    """Emit the request_throttled signal without raising."""
    try:
        from icv_waf.signals import request_throttled

        request_throttled.send(
            sender=None,
            ip_address=ip_address,
            window=getattr(result, "window", None),
        )
    except Exception:
        logger.exception("icv-waf: failed to emit request_throttled signal")
