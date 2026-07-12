"""Optional DRF API for django-waf.

Nothing in this package is imported by ``django_waf/__init__.py``,
``django_waf/apps.py``, or the top-level ``django_waf/urls.py`` import path.
It is only reached when a consuming project sets ``DJANGO_WAF_API_ENABLED =
True``, at which point ``django_waf/urls.py`` imports ``django_waf.api.urls``
inside a ``try``/``except ImportError`` block. This keeps
``djangorestframework`` an optional dependency (the ``[api]`` extra): the
package imports cleanly, and every existing test passes, whether or not DRF
is installed.
"""

from __future__ import annotations
