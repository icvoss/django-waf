"""A genuine URL configuration that does NOT route django_waf.urls.

This is the #102 deployment shape: a project installs ``django_waf``, adds
``WafMiddleware`` to ``MIDDLEWARE``, switches the WAF on, and never includes
``django_waf.urls`` anywhere. ``reverse("django_waf:challenge")`` then raises
``NoReverseMatch``, which before the fix escaped ``WafMiddleware.__call__``
and served a 500 to any visitor who tripped a detector.

It exists as a real module rather than as an inline approximation (an empty
``urlpatterns``, or a mocked ``reverse``) because that is the whole point:
a test that hand-builds the failure proves only that the mock was configured
as expected. Pointed at with ``override_settings(ROOT_URLCONF=...)``, this
module makes Django's real resolver do the failing on its own.

``tests/urls.py`` is the counterpart that DOES include the namespace, and is
the project default in ``tests/settings.py``.
"""

from django.http import HttpResponse
from django.urls import path


def noop_view(request):
    """A simple view that returns a 200 OK response."""
    return HttpResponse("OK")


urlpatterns = [
    path("", noop_view, name="root"),
    # Deliberately no path("waf/", include("django_waf.urls", ...)) here.
]
