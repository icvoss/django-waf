"""
URL configuration for django-waf.

Consuming projects include these routes in their root URL conf:

    path("waf/", include("django_waf.urls", namespace="django_waf"))

The namespace must be "django_waf" to match reverse() calls throughout the package.

The optional DRF API is mounted under waf/api/ only when
DJANGO_WAF_API_ENABLED is true (see django_waf.conf). This is read once, at
urlconf-import time, which is the Django norm for urlpatterns — matches how
ROOT_URLCONF itself is only re-evaluated on process restart or explicit
urlconf-cache clearing. Importing this module with the API disabled never
imports rest_framework, keeping djangorestframework an optional dependency
(the [api] extra).
"""

import logging

from django.urls import include, path

from django_waf import conf, views

app_name = "django_waf"

urlpatterns = [
    # -----------------------------------------------------------------------
    # Challenge flow — AllowAny
    # -----------------------------------------------------------------------
    path("challenge/", views.challenge_view, name="challenge"),
    path("verify/", views.verify_view, name="verify"),
    # -----------------------------------------------------------------------
    # Staff dashboard
    # -----------------------------------------------------------------------
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("dashboard/stats/", views.dashboard_stats_panel, name="dashboard-stats"),
    path("dashboard/top-blocked/", views.dashboard_top_blocked_panel, name="dashboard-top-blocked"),
    path("dashboard/anomalies/", views.dashboard_anomalies_panel, name="dashboard-anomalies"),
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
    except ImportError:
        logging.getLogger("django_waf").warning(
            "DJANGO_WAF_API_ENABLED is True but djangorestframework is not installed; "
            "install django-waf[api]. The API routes are not mounted."
        )
