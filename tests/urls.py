"""Test URL configuration for django-waf.

Wraps django_waf.urls in a namespace include so that reverse("django_waf:...")
resolves correctly in tests.  The tests/settings.py sets
ROOT_URLCONF = "django_waf.urls" (direct); this module is used by the view
tests which need the namespace to work.

Usage in tests:
    settings.ROOT_URLCONF = "tests.urls"    # or overridden via autouse fixture
"""

from django.urls import include, path

urlpatterns = [
    path("waf/", include("django_waf.urls", namespace="django_waf")),
]
