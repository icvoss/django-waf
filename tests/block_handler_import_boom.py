"""A block-response handler module whose own import fails, and not with an
ImportError.

Exists solely so ``tests/test_block_response_hook.py`` can prove the
middleware's import guard is broader than ``except ImportError``. A real
consumer hits this shape when the handler module reads a setting at import
time (``ImproperlyConfigured``), touches the app registry too early
(``AppRegistryNotReady``), or ships a stale ``.pyc``.

Nothing else may import this module.
"""

from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured

raise ImproperlyConfigured("this handler module cannot be imported")
