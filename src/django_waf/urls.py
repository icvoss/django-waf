"""
URL configuration for django-waf.

Consuming projects include these routes in their root URL conf:

    path("waf/", include("django_waf.urls", namespace="django_waf"))

The namespace must be "django_waf" to match reverse() calls throughout the package.

The optional DRF API is mounted under waf/api/ only when
DJANGO_WAF_API_ENABLED is true. This is read once, at urlconf-import time,
which is the Django norm for urlpatterns — matches how ROOT_URLCONF itself
is only re-evaluated on process restart or explicit urlconf-cache clearing.

The flag is read directly from django.conf.settings here rather than from
the cached django_waf.conf.DJANGO_WAF_API_ENABLED constant. Django resolves
a urlconf lazily, on first URL dispatch, not at ROOT_URLCONF assignment —
so this module's body can execute at an arbitrary later point in a process
(e.g. mid-test, inside another test's mock.patch of django_waf.conf). Reading
straight off settings here means the mount decision reflects the settings
that were active for the whole process, not whatever happened to be patched
onto django_waf.conf at the moment something first triggered a dispatch.

Importing this module with the API disabled never imports rest_framework,
keeping djangorestframework an optional dependency (the [api] extra).
"""

import logging

from django.conf import settings
from django.urls import include, path

from django_waf import views

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
if getattr(settings, "DJANGO_WAF_API_ENABLED", False):
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
