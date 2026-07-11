"""
Views for django-waf.

Challenge flow (AllowAny, no auth required):
    GET  /waf/challenge/                   — ChallengeView
    POST /waf/verify/                      — VerifyView (CSRF-exempt)

Staff dashboard (staff/superuser only):
    GET  /waf/dashboard/                   — DashboardView
    GET  /waf/dashboard/stats/             — DashboardStatsPanel
    GET  /waf/dashboard/top-blocked/       — DashboardTopBlockedPanel
    GET  /waf/dashboard/anomalies/         — DashboardAnomalyPanel
    POST /waf/dashboard/anomalies/<id>/confirm/  — DashboardAnomalyConfirmView
    POST /waf/dashboard/anomalies/<id>/reject/   — DashboardAnomalyRejectView
"""

from __future__ import annotations

import json
import logging

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.translation import gettext as _
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import TemplateView

logger = logging.getLogger("django_waf.views")

# Applied to every WAF-served interstitial response (challenge and verify).
# These pages carry ?next= URLs that leak site structure, and a crawler
# indexing a "Security Check" page pollutes search results. Belt and braces
# with the <meta name="robots"> tag in challenge.html: some crawlers honour
# only the header, some only the meta tag.
_NOINDEX_ROBOTS_HEADER = "noindex, nofollow, noarchive"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class NoIndexResponseMixin:
    """Attach X-Robots-Tag: noindex, nofollow, noarchive to every response.

    Applies to any view whose responses must never be indexed or followed by
    crawlers: the WAF challenge and verify interstitials are the only
    consumers today. Covers every return path (render, redirect, JSON error)
    by wrapping ``dispatch`` rather than a single response constructor.
    """

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        response = super().dispatch(request, *args, **kwargs)  # type: ignore[misc]
        response["X-Robots-Tag"] = _NOINDEX_ROBOTS_HEADER
        return response


def _get_ip(request: HttpRequest) -> str:
    """Extract the client IP address from the request.

    Respects DJANGO_WAF_TRUST_X_FORWARDED_FOR — uses the first IP in the
    X-Forwarded-For chain when trusted, otherwise falls back to REMOTE_ADDR.
    Returns ``0.0.0.0`` as a last resort to avoid NULL constraint violations
    on ChallengeToken.ip_address.
    """
    from django_waf import conf

    if conf.DJANGO_WAF_TRUST_X_FORWARDED_FOR:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR", "") or "0.0.0.0"


def _get_redis_client():
    """
    Return a Redis client, preferring django-redis.
    Falls back to django.core.cache if django-redis is not installed.
    """
    try:
        from django_redis import get_redis_connection  # type: ignore[import]

        from django_waf import conf

        return get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except (ImportError, Exception):
        from django.core.cache import cache

        return cache


def _validate_next_url(request: HttpRequest, next_param: str | None) -> str:
    """Return a safe redirect target, defaulting to '/' if the URL is unsafe."""
    if not next_param:
        return "/"

    # Only allow relative URLs on the same host.
    safe = url_has_allowed_host_and_scheme(
        url=next_param,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    )
    if not safe:
        return "/"

    return next_param


def _is_staff(request: HttpRequest) -> bool:
    return request.user.is_authenticated and request.user.is_staff  # type: ignore[union-attr]


def _is_superuser(request: HttpRequest) -> bool:
    return request.user.is_authenticated and request.user.is_superuser  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Challenge flow
# ---------------------------------------------------------------------------


class ChallengeView(NoIndexResponseMixin, TemplateView):
    """
    GET /waf/challenge/?next=<path>

    Presents the JS proof-of-work challenge page.
    Access: AllowAny — middleware has already decided a challenge is needed.
    Every response carries X-Robots-Tag: noindex, nofollow, noarchive
    (NoIndexResponseMixin) — this page must never be indexed or have its
    ?next= URL followed by a crawler.
    """

    template_name = "django_waf/challenge.html"

    def get(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        from urllib.parse import urlencode

        from django_waf import conf
        from django_waf.services.challenge_service import issue_challenge

        ip = _get_ip(request)
        next_url = _validate_next_url(request, request.GET.get("next"))
        redis_client = _get_redis_client()
        user_agent = request.META.get("HTTP_USER_AGENT", "")

        challenge_token = issue_challenge(ip, redis_client, user_agent=user_agent)

        # Form-replay token: when the form-protection orchestrator
        # redirected here on a FLAGGED submission, the original POST
        # data is parked in the session and ``form_replay=<token>`` is
        # in the URL. Preserve it through to next_url so the
        # post-challenge landing page can resubmit.
        form_replay = request.GET.get("form_replay", "")
        if form_replay:
            separator = "&" if "?" in next_url else "?"
            next_url = f"{next_url}{separator}{urlencode({'form_replay': form_replay})}"

        # Resolve the verify URL the same way the middleware does
        # (django_waf.middleware._get_challenge_paths) — honour the operator
        # override first, fall back to reverse() per-request. Critical for
        # projects with per-request urlconf routing (django-hosts), where
        # reverse() inside this view runs against whichever host's urlconf
        # is active; if the django_waf URLs aren't mounted on that host, the
        # solver POSTs to the wrong path, never reaches VerifyView, and
        # tokens stay PENDING forever.
        verify_path = conf.DJANGO_WAF_VERIFY_URL or reverse("django_waf:verify")

        response = self.render_to_response(
            {
                "token": challenge_token.token,
                # Use the token's stored difficulty so the solver always
                # matches the verifier, even if conf changes mid-flight.
                "difficulty": challenge_token.difficulty,
                "next_url": next_url,
                "post_url": request.build_absolute_uri(verify_path),
            }
        )
        response["Cache-Control"] = "no-store"
        return response


challenge_view = ChallengeView.as_view()


@method_decorator(csrf_exempt, name="dispatch")
class VerifyView(NoIndexResponseMixin, View):
    """
    POST /waf/verify/

    Accepts a proof-of-work solution (JSON or form-encoded).
    CSRF-exempt because the challenge may be presented before a session exists.
    Access: AllowAny.
    Every response path (redirect on success, JSON 400 on failure) carries
    X-Robots-Tag: noindex, nofollow, noarchive (NoIndexResponseMixin).
    """

    def post(self, request: HttpRequest) -> HttpResponse:
        from django_waf.services.challenge_service import (
            ChallengeExpiredError,
            ChallengeInvalidError,
            ChallengeMismatchError,
            issue_challenge,
            issue_pass_cookie,
            verify_challenge_solution,
        )

        # --- Parse request body (JSON or form-encoded) ---
        token = nonce = next_param = None

        content_type = request.content_type or ""
        if "application/json" in content_type:
            try:
                data = json.loads(request.body)
                token = data.get("token")
                nonce = data.get("nonce")
                next_param = data.get("next")
            except (json.JSONDecodeError, ValueError):
                return JsonResponse({"error": _("Invalid JSON in request body.")}, status=400)
        else:
            token = request.POST.get("token")
            nonce = request.POST.get("nonce")
            next_param = request.POST.get("next")

        if not token or not nonce:
            return JsonResponse({"error": _("Missing token or nonce.")}, status=400)

        ip = _get_ip(request)
        next_url = _validate_next_url(request, next_param)
        redis_client = _get_redis_client()

        try:
            verify_challenge_solution(token, nonce, ip, redis_client)
        except (ChallengeExpiredError, ChallengeMismatchError, ChallengeInvalidError) as exc:
            reason = str(exc)
            try:
                user_agent = request.META.get("HTTP_USER_AGENT", "")
                new_token = issue_challenge(ip, redis_client, user_agent=user_agent)
                return JsonResponse({"error": reason, "new_token": new_token.token}, status=400)
            except Exception:
                logger.exception("django-waf: failed to issue replacement challenge token")
                return JsonResponse({"error": reason}, status=400)

        # Mark IP as solved in Redis so escalation counter resets
        try:
            solved_key = f"waf:solved:{ip}"
            redis_client.setex(solved_key, 86400, "1")  # 24-hour flag
            redis_client.delete(f"waf:challenged:{ip}")
        except Exception:
            pass

        # Register this browser's HTTP fingerprint as known-good
        try:
            from django_waf.services.fingerprint import compute_fingerprint, register_known_fingerprint

            fp_hash = compute_fingerprint(request.META)
            register_known_fingerprint(fp_hash, redis_client)
        except Exception:
            pass

        response = redirect(next_url)
        issue_pass_cookie(response, token, ip, secure=request.is_secure())
        return response


verify_view = VerifyView.as_view()


# ---------------------------------------------------------------------------
# Staff dashboard
# ---------------------------------------------------------------------------


class StaffRequiredMixin(LoginRequiredMixin):
    """Redirect to login if the user is not authenticated and is not staff."""

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not _is_staff(request):
            return self.handle_no_permission()
        return super(LoginRequiredMixin, self).dispatch(request, *args, **kwargs)  # type: ignore[misc]


class SuperuserRequiredMixin(LoginRequiredMixin):
    """Redirect to login if the user is not a superuser."""

    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        if not _is_superuser(request):
            return self.handle_no_permission()
        return super(LoginRequiredMixin, self).dispatch(request, *args, **kwargs)  # type: ignore[misc]


class DashboardView(StaffRequiredMixin, TemplateView):
    """
    GET /waf/dashboard/

    Dashboard shell — HTMX panels load asynchronously.
    Access: Staff only.
    """

    template_name = "django_waf/dashboard.html"

    def get_context_data(self, **kwargs) -> dict:
        ctx = super().get_context_data(**kwargs)
        ctx["stats_url"] = reverse("django_waf:dashboard-stats")
        ctx["top_blocked_url"] = reverse("django_waf:dashboard-top-blocked")
        ctx["anomalies_url"] = reverse("django_waf:dashboard-anomalies")
        return ctx


dashboard_view = DashboardView.as_view()


class DashboardStatsPanel(StaffRequiredMixin, TemplateView):
    """
    GET /waf/dashboard/stats/

    HTMX fragment: real-time counters from Redis or RequestLog fallback.
    Auto-refreshed every 30 s by the dashboard shell.
    Access: Staff only.
    """

    template_name = "django_waf/partials/stats_panel.html"

    def get_context_data(self, **kwargs) -> dict:
        ctx = super().get_context_data(**kwargs)
        ctx.update(self._fetch_stats())
        return ctx

    def _fetch_stats(self) -> dict:
        """Return today's counter dict, preferring Redis over DB aggregate."""
        try:
            redis_client = _get_redis_client()
            raw: dict = {}

            # django-redis returns a real Redis client; fall back to cache API.
            if hasattr(redis_client, "hgetall"):
                raw = redis_client.hgetall("waf:stats:today") or {}
                # Redis may return bytes
                raw = {
                    (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in raw.items()
                }
            else:
                # Using Django cache — key was stored as JSON dict.
                stored = redis_client.get("waf:stats:today") or {}
                if isinstance(stored, str):
                    import json as _json

                    stored = _json.loads(stored)
                raw = stored or {}

        except Exception:
            logger.warning("django-waf: could not fetch stats from Redis; falling back to DB")
            raw = self._db_stats_today()

        return {
            "total": int(raw.get("total", 0)),
            "blocked": int(raw.get("blocked", 0)),
            "challenged": int(raw.get("challenged", 0)),
            "throttled": int(raw.get("throttled", 0)),
            "allowed": int(raw.get("allowed", 0)),
            "passed": int(raw.get("passed", 0)),
        }

    @staticmethod
    def _db_stats_today() -> dict:
        from django.db.models import Count
        from django.utils import timezone

        from django_waf.enums import Verdict
        from django_waf.models import RequestLog

        today = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        rows = RequestLog.objects.filter(timestamp__gte=today).values("verdict").annotate(n=Count("id"))
        mapping = {row["verdict"]: row["n"] for row in rows}
        total = sum(mapping.values())
        return {
            "total": total,
            "blocked": mapping.get(Verdict.BLOCKED, 0),
            "challenged": mapping.get(Verdict.CHALLENGED, 0),
            "throttled": mapping.get(Verdict.THROTTLED, 0),
            "allowed": mapping.get(Verdict.ALLOWED, 0),
            "passed": mapping.get(Verdict.PASSED, 0),
        }


dashboard_stats_panel = DashboardStatsPanel.as_view()


class DashboardTopBlockedPanel(StaffRequiredMixin, TemplateView):
    """
    GET /waf/dashboard/top-blocked/

    HTMX fragment: top 10 IPs by blocked_requests from IPReputation.
    Access: Staff only.
    """

    template_name = "django_waf/partials/top_blocked_panel.html"

    def get_context_data(self, **kwargs) -> dict:
        ctx = super().get_context_data(**kwargs)
        try:
            from django_waf.models import IPReputation

            ctx["ips"] = IPReputation.objects.order_by("-blocked_requests")[:10]
        except Exception:
            logger.warning("django-waf: could not fetch top-blocked IPs; degrading to empty panel")
            ctx["ips"] = []
        return ctx


dashboard_top_blocked_panel = DashboardTopBlockedPanel.as_view()


class DashboardAnomalyPanel(StaffRequiredMixin, TemplateView):
    """
    GET /waf/dashboard/anomalies/

    HTMX fragment: auto-generated BlockRules from the last 48 hours.
    Access: Staff only.
    """

    template_name = "django_waf/partials/anomalies_panel.html"

    def get_context_data(self, **kwargs) -> dict:
        ctx = super().get_context_data(**kwargs)
        try:
            from datetime import timedelta

            from django.utils import timezone

            from django_waf.enums import RuleSource
            from django_waf.models import BlockRule

            cutoff = timezone.now() - timedelta(hours=48)
            ctx["rules"] = BlockRule.objects.filter(
                source=RuleSource.AUTO,
                created_at__gte=cutoff,
            ).order_by("-created_at")
        except Exception:
            logger.warning("django-waf: could not fetch anomaly rules; degrading to empty panel")
            ctx["rules"] = []
        return ctx


dashboard_anomalies_panel = DashboardAnomalyPanel.as_view()


class DashboardAnomalyConfirmView(SuperuserRequiredMixin, View):
    """
    POST /waf/dashboard/anomalies/<rule_id>/confirm/

    Promotes an auto-generated rule to a permanent admin rule.
    Returns HTMX partial for the updated row.
    Access: Superuser only.
    """

    def post(self, request: HttpRequest, rule_id) -> HttpResponse:
        from django.template.loader import render_to_string

        from django_waf.enums import RuleSource
        from django_waf.models import BlockRule

        rule = get_object_or_404(BlockRule, id=rule_id)
        rule.source = RuleSource.ADMIN
        rule.expires_at = None
        rule.save(update_fields=["source", "expires_at", "updated_at"])

        html = render_to_string(
            "django_waf/partials/anomaly_row_confirmed.html",
            {"rule": rule},
            request=request,
        )
        return HttpResponse(html)


anomaly_confirm_view = DashboardAnomalyConfirmView.as_view()


class DashboardAnomalyRejectView(SuperuserRequiredMixin, View):
    """
    POST /waf/dashboard/anomalies/<rule_id>/reject/

    Deactivates an auto-generated rule.
    Returns an empty 200 so HTMX deletes the row (hx-swap="delete").
    Access: Superuser only.
    """

    def post(self, request: HttpRequest, rule_id) -> HttpResponse:
        from django_waf.models import BlockRule

        rule = get_object_or_404(BlockRule, id=rule_id)
        rule.is_active = False
        rule.save(update_fields=["is_active", "updated_at"])

        return HttpResponse("")


anomaly_reject_view = DashboardAnomalyRejectView.as_view()
