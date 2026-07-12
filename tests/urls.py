"""Test URL configuration for django-waf.

Wraps django_waf.urls in a namespace include so that reverse("django_waf:...")
resolves correctly in tests.  The tests/settings.py sets
ROOT_URLCONF = "django_waf.urls" (direct); this module is used by the view
tests which need the namespace to work.

Usage in tests:
    settings.ROOT_URLCONF = "tests.urls"    # or overridden via autouse fixture
"""

from django.http import HttpResponse
from django.urls import include, path


def noop_view(request):
    """A simple view that returns a 200 OK response."""
    return HttpResponse("OK")


urlpatterns = [
    path("", noop_view, name="root"),
    path("waf/", include("django_waf.urls", namespace="django_waf")),
]
