"""
URL configuration for django-waf.

Consuming projects include these routes in their root URL conf:

    path("waf/", include("django_waf.urls", namespace="django_waf"))

The namespace must be "django_waf" to match reverse() calls throughout the package.
"""

from django.urls import path

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
