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
from django.urls import NoReverseMatch, reverse
from django.utils.module_loading import import_string
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger("django_waf.middleware")

# Applied to every site-password prompt/verify response -- these pages must
# never be indexed (BR-SP-006). Mirrors django_waf.views._NOINDEX_ROBOTS_HEADER.
_SITE_PASSWORD_NOINDEX_HEADER = "noindex, nofollow, noarchive"

_SITE_PASSWORD_INCORRECT_ERROR = _("Incorrect password. Please try again.")
_SITE_PASSWORD_MISCONFIGURED_ERROR = _("This site is temporarily unavailable.")


class WafMiddleware:
    """Django WAF middleware, new-style __init__/__call__ pattern.

    Evaluation order per BR-EVAL-003:
    1. Exempt paths and hosts bypass all WAF checks (BR-EVAL-001)
    2. Master switch DJANGO_WAF_ENABLED (BR-EVAL-002)
    3. Staff/superuser bypass rate limiting (BR-RATE-003)
    4. Valid waf_pass cookie → pass through (BR-CHAL-006)
    5. evaluate_request(), allow / block / challenge / throttle / log
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

        Raises ``NoReverseMatch`` when neither setting is set and the
        ``django_waf`` namespace is not routed. Callers on the request path
        must catch it and fail open (BR-EVAL-007); ``_handle_verdict``'s
        CHALLENGED branch does. ``django_waf.E007`` reports the same
        misconfiguration at boot.
        """
        from django_waf import conf

        challenge = conf.DJANGO_WAF_CHALLENGE_URL or reverse("django_waf:challenge")
        verify = conf.DJANGO_WAF_VERIFY_URL or reverse("django_waf:verify")
        return challenge, verify

    def __call__(self, request):
        from django_waf import conf

        # BR-EVAL-002: master kill switch
        if not conf.DJANGO_WAF_ENABLED:
            return self._get_response(request)

        # BR-EVAL-001: exempt paths, prefix match
        path = request.path_info

        for prefix in conf.DJANGO_WAF_EXEMPT_PATHS:
            if path.startswith(prefix):
                return self._get_response(request)

        # BR-EVAL-001: exempt hosts, exact or subdomain match
        if conf.DJANGO_WAF_EXEMPT_HOSTS and _is_exempt_host(request, conf.DJANGO_WAF_EXEMPT_HOSTS):
            return self._get_response(request)

        # BR-SP-008: site password gate, after the enabled/exempt/health
        # short-circuits above, before country-block/threat evaluation
        # below. A locked site prompts for the password before spending any
        # WAF evaluation effort; the prompt and verify paths must themselves
        # stay reachable, which is why this runs ahead of everything else.
        gate_response = self._check_site_password(request, path)
        if gate_response is not None:
            return gate_response

        # HTTP method filtering, 405 for disallowed methods
        allowed = conf.DJANGO_WAF_ALLOWED_METHODS
        if allowed is not None and request.method not in allowed:
            response = HttpResponse("Method not allowed.", status=405)
            response["Allow"] = ", ".join(allowed)
            return response

        # Extract client IP, fail-open if unavailable
        ip_address = _extract_ip(request)
        if not ip_address:
            return self._get_response(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        # Country blocking, fail-open on any GeoIP error or missing database.
        if conf.DJANGO_WAF_BLOCKED_COUNTRIES:
            blocked_response = self._check_country_block(request, ip_address, user_agent, path)
            if blocked_response is not None:
                return blocked_response

        # BR-RATE-003: staff/superuser bypass, skip WAF entirely
        if _is_staff_user(request):
            return self._get_response(request)

        # Get Redis connection, fail-open if unavailable
        redis_client = _get_redis_client()
        if redis_client is None:
            return self._get_response(request)

        # BR-CHAL-006: check for valid waf_pass cookie before evaluation
        try:
            from django_waf.services.challenge_service import validate_pass_cookie

            cookie_value = request.COOKIES.get("waf_pass", "")
            if cookie_value and validate_pass_cookie(cookie_value, ip_address):
                # Cookie is valid, pass through
                return self._get_response(request)
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
            logger.exception("django-waf: evaluation error, failing open")
            return self._get_response(request)

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

    def _get_response(self, request):
        """Call ``get_response(request)`` and apply the trusted-user-cookie
        response hook (#23) before returning.

        ``django.contrib.auth.signals.user_logged_in`` fires during login
        processing and only gives us ``request``, not the response the
        login view is about to return -- so the cookie cannot be set from
        the signal receiver directly. Instead, the receiver
        (``django_waf.receivers.set_trusted_cookie_flag_on_login``) stashes
        a flag on the request (``request._waf_set_trusted_cookie``); every
        call to ``get_response`` in this middleware routes through this
        method so that flag is checked and the cookie is set on whatever
        response the view produced, wherever in ``__call__`` that happened.

        A no-op when the flag is absent (the overwhelming majority of
        requests, and every request when the feature is disabled: the
        receiver that sets the flag is itself only connected when
        ``DJANGO_WAF_TRUSTED_COOKIE_ENABLED`` is True, see
        ``DjangoWafConfig.ready()``), so this changes nothing about the
        response path for sites that don't use the feature.
        """
        response = self.get_response(request)

        if getattr(request, "_waf_set_trusted_cookie", False):
            from django_waf.services.trusted_user_service import set_trusted_cookie

            set_trusted_cookie(response, request)

        return response

    def _check_country_block(self, request, ip_address, user_agent, path):
        """Return a 403 response if the request's country is blocked, else None.

        Fails open: any error resolving the country (missing database,
        geoip2 not installed, lookup exception) falls through to normal
        evaluation rather than blocking. Logging the block is best-effort,
        a logging failure never prevents the block response from being
        returned. The block response itself goes through
        ``_build_block_response`` (#76), which guards every failure of its
        own handler path internally and never raises, so a broken block
        response handler cannot escape into this method's own
        fail-open except clause and turn a country block into a pass.
        """
        from django_waf import conf

        try:
            from django_waf.services.geoip import lookup_country

            country = lookup_country(ip_address)
            if not country:
                # No database / lookup failure, fail open.
                return None

            blocked_countries = {c.upper() for c in conf.DJANGO_WAF_BLOCKED_COUNTRIES}
            if country.upper() not in blocked_countries:
                return None

            self._log_country_block(request, ip_address, user_agent, path, country)

            # Routed through DJANGO_WAF_BLOCK_RESPONSE_HANDLER (#76). This
            # path has no EvaluationResult from evaluate_request(): the
            # country decision is taken here, before evaluate_request() ever
            # runs. But the values below are not a fake result invented to
            # satisfy the signature: they are exactly what _log_country_block,
            # five lines above, already writes to RequestLog for this same
            # path. That is the code's own honest description of a country
            # block, so building the same EvaluationResult and handing it to
            # the same hook is correct, not a synthesis.
            #
            # The country code itself has no field on EvaluationResult (the
            # NamedTuple is a public type consumers unpack, so widening it
            # is a bigger API change than this fix). It is carried instead
            # as request.waf_blocked_country, set just before the handler
            # runs, so a handler wanting it reads
            # getattr(request, "waf_blocked_country", None).
            from django_waf.enums import RuleAction, Verdict
            from django_waf.services.rule_engine import EvaluationResult

            request.waf_blocked_country = country
            result = EvaluationResult(
                verdict=Verdict.BLOCKED,
                action=RuleAction.BLOCK,
                matched_rule_id=None,
                matched_rule_type="",
                anomaly_score=None,
            )
            return self._build_block_response(request, result)
        except Exception:
            logger.exception("django-waf: error during country-block check, failing open")
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
        4. Valid, unexpired signed verified-flag cookie → None (BR-SP-004).
        5. POST to the verify path → check the password and either set the
           cookie + redirect, or re-prompt with an error and a throttle hit.
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
                "DJANGO_WAF_SITE_PASSWORD is empty, failing closed (BR-SP-002)."
            )
            return self._render_site_password_prompt(request, error=_SITE_PASSWORD_MISCONFIGURED_ERROR)

        if sp.has_valid_cookie(request):
            return None

        verify_path = conf.DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH
        if request.method == "POST" and path == verify_path:
            return self._handle_site_password_verify(request)

        return self._render_site_password_prompt(request)

    def _handle_site_password_verify(self, request):
        """Handle a POST to the site-password verify path.

        On success: build the redirect response to a validated ``next``
        and set the gate's signed verified cookie on *that* response
        (BR-SP-004). On failure: re-render the prompt with an error and
        record a throttle hit against the WAF's existing rate-limit
        surface (BR-SP-007).

        Never touches ``request.session`` -- ``WafMiddleware`` runs before
        ``SessionMiddleware`` in the documented middleware order, so the
        session is not available here. See site_password_service module
        docstring.
        """
        from django.utils.http import url_has_allowed_host_and_scheme

        from django_waf.services import site_password_service as sp

        submitted = request.POST.get("password", "")
        next_param = request.POST.get("next", "")

        if sp.check_password(submitted):
            safe_next = "/"
            if next_param and url_has_allowed_host_and_scheme(
                url=next_param,
                allowed_hosts={request.get_host()},
                require_https=request.is_secure(),
            ):
                safe_next = next_param
            response = HttpResponseRedirect(safe_next)
            sp.set_verified_cookie(response, request)
            return response

        ip_address = _extract_ip(request) or "0.0.0.0"
        redis_client = _get_redis_client()
        throttle_result = sp.record_guess_throttle_hit_detailed(ip_address, redis_client)
        if throttle_result.exceeded:
            response = HttpResponse("Too many attempts. Please retry later.", status=429)
            # Accurate sliding-window value (#30), falls back to 60 only
            # when the limiter genuinely returned none (fail-open path).
            retry_after = throttle_result.retry_after
            response["Retry-After"] = str(retry_after) if retry_after is not None else "60"
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

    def _default_block_response(self) -> HttpResponse:
        """Return the package's built-in BLOCKED response.

        Kept as a single named source so the hook's fallback path and the
        no-hook path cannot drift apart: both return this, byte for byte.
        """
        return HttpResponseForbidden("Access denied.")

    def _build_block_response(self, request, result) -> HttpResponse:
        """Return the response for a BLOCKED verdict (BR-EVAL-011).

        With ``DJANGO_WAF_BLOCK_RESPONSE_HANDLER`` unset (the default) this
        is exactly ``HttpResponseForbidden("Access denied.")``, unchanged
        from every release before the hook existed.

        HANDLER CONTRACT

        ``DJANGO_WAF_BLOCK_RESPONSE_HANDLER`` is a dotted path to a
        callable with this signature::

            def handler(request: HttpRequest, result: EvaluationResult) -> HttpResponse

        ``request`` is the live ``HttpRequest``. The handler runs before the
        view, so nothing downstream has touched it.

        ``result`` is the ``EvaluationResult`` NamedTuple from
        ``django_waf.services.rule_engine``, carrying ``verdict``,
        ``action``, ``matched_rule_id``, ``matched_rule_type``,
        ``anomaly_score`` and ``retry_after``. ``verdict`` is always
        ``Verdict.BLOCKED`` here, and ``retry_after`` is always ``None``
        (it is populated on THROTTLED verdicts only).

        **``result.matched_rule_id`` is a ``UUID`` or ``None``, not a
        ``BlockRule`` instance.** The rule object is never loaded on this
        path, deliberately: the block decision comes from the Redis fast
        path, and reading the rule row per blocked request would hand an
        attacker a query amplifier. A handler that needs the rule itself
        must query for it, and should weigh that cost against the traffic
        it is blocking.

        ``request.waf_blocked_country`` is present, holding the ISO 3166-1
        alpha-2 country code, only when this call came from
        ``_check_country_block`` (#76). It is absent on every other BLOCKED
        verdict: ``EvaluationResult`` carries no country field, deliberately
        (it is a public NamedTuple that consumers unpack, so widening it is
        a larger API change than this attribute), so a handler that wants
        to branch on it must read it defensively::

            country = getattr(request, "waf_blocked_country", None)

        The return value must be an ``HttpResponse``, of any subclass and
        any status code. The middleware returns it unaltered.

        The dotted path is resolved with ``import_string`` on each blocked
        request rather than once at import time, following the package's
        call-time settings resolution (see ``django_waf.conf``), so
        ``override_settings`` and the pytest ``settings`` fixture work.
        Blocked requests are the rare path, so the import-cache lookup this
        costs is nowhere near the clean-request hot path.

        FAILURE BEHAVIOUR

        A misconfigured WAF must never break a request. That is the same
        fail-open posture BR-EVAL-007 sets for evaluation. All three
        failure modes fall back to ``_default_block_response()`` and log at
        ERROR, classified distinctly so an operator can tell which one
        happened:

        1. the dotted path will not import, for any reason: a typo, a moved
           module, or the handler module's own top-level code raising
           something that is not an ``ImportError``;
        2. the handler raises;
        3. the handler returns something that is not an ``HttpResponse``.

        The request is still blocked in all three cases. Falling back to
        the built-in 403 is the safe direction: a broken hook must not turn
        a block into a pass.

        SCOPE

        BLOCKED verdicts only, which now includes country blocks (#76):
        ``_check_country_block`` builds its own ``EvaluationResult`` and
        calls this method too, rather than returning a hardcoded response
        directly. THROTTLED and CHALLENGED keep their own responses.
        """
        from django_waf import conf

        dotted_path = conf.DJANGO_WAF_BLOCK_RESPONSE_HANDLER
        if not dotted_path:
            return self._default_block_response()

        try:
            handler = import_string(dotted_path)
        except Exception:
            # Deliberately broader than ImportError. import_string raises
            # ImportError for a bad path, but importing the handler's module
            # runs that module's own top-level code, which can raise anything
            # (ImproperlyConfigured from a settings read, a SyntaxError under
            # a stale .pyc, an AppRegistryNotReady). None of those may reach
            # the client as a 500 on a request the WAF is already blocking.
            logger.exception(
                "django-waf: DJANGO_WAF_BLOCK_RESPONSE_HANDLER %r could not be imported. "
                "Falling back to the built-in block response.",
                dotted_path,
            )
            return self._default_block_response()

        try:
            response = handler(request, result)
        except Exception:
            logger.exception(
                "django-waf: block response handler %r raised. Falling back to the built-in block response.",
                dotted_path,
            )
            return self._default_block_response()

        if not isinstance(response, HttpResponse):
            logger.error(
                "django-waf: block response handler %r returned %s, not an HttpResponse. "
                "Falling back to the built-in block response.",
                dotted_path,
                type(response).__name__,
            )
            return self._default_block_response()

        return response

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
            return self._build_block_response(request, result)

        if verdict == Verdict.THROTTLED:
            _emit_request_throttled(result, ip_address)
            response = HttpResponse("Too many requests. Please retry later.", status=429)
            # hasattr() was always True for the real EvaluationResult
            # NamedTuple even before it carried a real retry_after value, so
            # this always sent the fixed fallback (#30). Use the accurate
            # sliding-window value when present; only fall back to a fixed
            # 60 seconds when the result genuinely carries none (e.g. a
            # test double or a pre-#30 caller).
            retry_after = getattr(result, "retry_after", None)
            response["Retry-After"] = str(retry_after) if retry_after is not None else "60"
            return response

        if verdict == Verdict.CHALLENGED:
            try:
                challenge_path, verify_path = self._get_challenge_paths()
            except NoReverseMatch:
                # BR-EVAL-007: the WAF must never break a request because of
                # its own misconfiguration. With django_waf.urls routed
                # nowhere and no explicit URL override set,
                # _get_challenge_paths() calls reverse("django_waf:challenge")
                # and raises NoReverseMatch, which before #102 escaped
                # __call__ uncaught and served a 500 to a legitimate visitor
                # who merely tripped a detector. There is no route to send
                # them to, so half-blocking them behind a redirect to a page
                # that does not exist is strictly worse than letting the
                # request through: fail open and tell the operator loudly
                # what to fix. Caught narrowly rather than as a bare
                # Exception so any other failure in this branch still
                # surfaces.
                logger.error(
                    "django-waf: cannot resolve the challenge/verify URLs, so a CHALLENGED "
                    "verdict for %s on %s is being passed through to the view instead "
                    "(BR-EVAL-007 fail-open). Route django_waf.urls in your URLconf under "
                    "the 'django_waf' namespace, or set DJANGO_WAF_CHALLENGE_URL and "
                    "DJANGO_WAF_VERIFY_URL to literal paths if this project mounts the WAF "
                    "views elsewhere (or on only some hosts).",
                    ip_address,
                    path,
                )
                return self._get_response(request)

            # Suppress challenge redirect when already on a challenge/verify
            # path to prevent infinite redirect loops. BLOCKED and THROTTLED
            # verdicts still apply, only the redirect is suppressed.
            if path.startswith(challenge_path) or path.startswith(verify_path):
                return self._get_response(request)

            # Increment unsolved-challenge counter for escalation tracking.
            # This is the producer half of the counter
            # rule_engine._get_unsolved_challenge_count reads: a silent
            # failure here has the same effect as a failure on the read
            # side, challenge escalation goes blind for this IP, so it is
            # logged rather than swallowed.
            try:
                key = f"waf:challenged:{ip_address}"
                redis_client.incr(key)
                redis_client.expire(key, 3600)  # 1-hour window
            except Exception:
                logger.warning(
                    "django-waf: failed to record challenge for %s, escalation count will under-report",
                    ip_address,
                )
            challenge_url = f"{challenge_path}?next={path}"
            return HttpResponseRedirect(challenge_url)

        # ALLOWED, PASSED, LOGGED, pass through to the view
        return self._get_response(request)

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
    """Backwards-compatibility shim, the real implementation lives in
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

    Thin wrapper over ``django_waf.services.client_ip.resolve_client_ip``
    (#29), kept so existing call sites within this module don't need to
    change. See that function for the full trusted-proxy resolution
    behaviour.
    """
    from django_waf.services.client_ip import resolve_client_ip

    return resolve_client_ip(request)


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
    """Return True if the request is from a trusted staff or superuser.

    Per BR-RATE-003. Prefers the signed trusted-user cookie (#23,
    ``django_waf.services.trusted_user_service.has_valid_trusted_cookie``)
    so the bypass works even when ``WafMiddleware`` runs before
    ``django.contrib.auth.middleware.AuthenticationMiddleware`` and
    ``request.user`` is not yet available. Falls back to the original
    ``request.user`` check so the bypass keeps working unchanged when the
    WAF *is* placed after auth, or when the cookie feature is disabled
    (``has_valid_trusted_cookie`` is then a guaranteed no-op, so this
    fallback is the only path exercised, behaviour is unchanged from
    before #23).
    """
    from django_waf.services.trusted_user_service import has_valid_trusted_cookie

    if has_valid_trusted_cookie(request):
        return True

    return (
        hasattr(request, "user")
        and request.user.is_authenticated
        and (request.user.is_staff or request.user.is_superuser)
    )


def _get_redis_client():
    """Return a Redis client instance, or None if Redis is unavailable.

    Thin wrapper over ``django_waf.services.redis_client.get_redis_client``
    (#44), kept so existing call sites and test patches within this module
    (and ``django_waf.testing.fixtures.waf_redis_mock``) don't need to
    change. See that module for why this never falls back to a non-Redis
    cache object: a WAF that appears to keep evaluating requests using a
    fake Redis client fails several frames deeper with an unhandled
    AttributeError, which the middleware's outer handler then catches and
    fails the whole WAF open, silently. Returning None here instead makes
    every existing "if redis_client is None: fail open" call site in this
    module (BR-EVAL-007) trigger deterministically instead.
    """
    from django_waf.services.redis_client import get_redis_client

    return get_redis_client()


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
