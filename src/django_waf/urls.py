"""
URL configuration for django-waf.

Consuming projects include these routes in their root URL conf:

    path("waf/", include("django_waf.urls", namespace="django_waf"))

The namespace must be "django_waf" to match reverse() calls throughout the package.

The optional DRF API is mounted under waf/api/ only when
DJANGO_WAF_API_ENABLED is true. This is read once, at urlconf-import time,
which is the Django norm for urlpatterns: matches how ROOT_URLCONF itself
is only re-evaluated on process restart or explicit urlconf-cache clearing.
Django resolves a urlconf lazily, on first URL dispatch, not at
ROOT_URLCONF assignment, so this module's body can execute at an arbitrary
later point in a process (e.g. mid-test). Whatever DJANGO_WAF_API_ENABLED
resolves to at that one moment decides the mount for the rest of the
process; a later settings change does not remount the routes.

Importing this module with the API disabled never imports rest_framework,
keeping djangorestframework an optional dependency (the [api] extra).
"""

import logging

from django.urls import URLPattern, URLResolver, include, path

from django_waf import conf, views

app_name = "django_waf"

# Annotated explicitly rather than left to inference: the base list is all
# path() calls (URLPattern), but the optional API block below appends an
# include() result (URLResolver), so the list genuinely holds both types.
urlpatterns: list[URLPattern | URLResolver] = [
    # -----------------------------------------------------------------------
    # Challenge flow — AllowAny
    # -----------------------------------------------------------------------
    path("challenge/", views.challenge_view, name="challenge"),
    path("verify/", views.verify_view, name="verify"),
    # -----------------------------------------------------------------------
    # Site password gate — WafMiddleware intercepts POSTs to
    # DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH directly (see
    # WafMiddleware._handle_site_password_verify); this route exists as a
    # fallback so reverse() resolves and a direct hit still gets a
    # sane response.
    # -----------------------------------------------------------------------
    path("site-password/", views.site_password_verify_view, name="site-password-verify"),
    # -----------------------------------------------------------------------
    # Staff dashboard
    # -----------------------------------------------------------------------
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("dashboard/stats/", views.dashboard_stats_panel, name="dashboard-stats"),
    path("dashboard/top-blocked/", views.dashboard_top_blocked_panel, name="dashboard-top-blocked"),
    path("dashboard/anomalies/", views.dashboard_anomalies_panel, name="dashboard-anomalies"),
    path(
        "dashboard/rule-effectiveness/",
        views.dashboard_rule_effectiveness_panel,
        name="dashboard-rule-effectiveness",
    ),
    # Superuser-only anomaly actions
    path(
        "dashboard/anomalies/<uuid:rule_id>/confirm/",
        views.anomaly_confirm_view,
        name="anomaly-confirm",
    ),
    path(
        "dashboard/anomalies/<uuid:rule_id>/reject/",
        views.anomaly_reject_view,
        name="anomaly-reject",
    ),
]

# -----------------------------------------------------------------------
# Optional DRF API — off by default, requires django-waf[api]
# -----------------------------------------------------------------------
if conf.DJANGO_WAF_API_ENABLED:
    try:
        from django_waf.api import urls as api_urls

        urlpatterns += [
            path("api/", include((api_urls.urlpatterns, "django_waf_api"), namespace="api")),
        ]
    except ImportError:  # pragma: no cover - exercised only when djangorestframework is absent
        logging.getLogger("django_waf").warning(
            "DJANGO_WAF_API_ENABLED is True but djangorestframework is not installed; "
            "install django-waf[api]. The API routes are not mounted."
        )
