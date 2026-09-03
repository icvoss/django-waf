"""A block-response handler module whose own import fails, and not with an
ImportError.

Used by ``tests/test_block_response_hook.py`` to prove the middleware's
runtime import guard is broader than ``except ImportError``, and by
``tests/test_checks.py`` to prove the ``django_waf.E008`` boot check agrees
with it. A real consumer hits this shape when the handler module reads a
setting at import time (``ImproperlyConfigured``), touches the app
registry too early (``AppRegistryNotReady``), or ships a stale ``.pyc``.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

raise ImproperlyConfigured("this handler module cannot be imported")
