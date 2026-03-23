"""Test URL configuration for icv-waf.

Wraps icv_waf.urls in a namespace include so that reverse("icv_waf:...")
resolves correctly in tests.  The tests/settings.py sets
ROOT_URLCONF = "icv_waf.urls" (direct); this module is used by the view
tests which need the namespace to work.

Usage in tests:
    settings.ROOT_URLCONF = "tests.urls"    # or overridden via autouse fixture
"""

from django.urls import include, path

urlpatterns = [
    path("waf/", include("icv_waf.urls", namespace="icv_waf")),
]
