"""Deprecated compatibility shim for the old ``icv_waf`` import name.

The package was renamed ``icv_waf`` -> ``django_waf`` in 1.0.0. This shim keeps
``import icv_waf`` (and ``from icv_waf.<sub> import ...``) working with a
``DeprecationWarning``, by aliasing the ``icv_waf`` import namespace onto
``django_waf`` via a meta-path finder.

It covers **Python imports only**. It is NOT a Django app — do not put
``"icv_waf"`` in ``INSTALLED_APPS``; use ``"django_waf"``. The app label, model
tables, settings prefix (``DJANGO_WAF_*``) and management commands
(``django_waf_*``) all moved to the new name with no compatibility alias; see
the 1.0.0 CHANGELOG upgrade note.

This shim will be removed in a future major release.
"""

import importlib
import importlib.abc
import importlib.util
import sys
import warnings

_OLD = "icv_waf"
_NEW = "django_waf"

warnings.warn(
    "The 'icv_waf' import name is deprecated and will be removed in a future "
    "release. Import from 'django_waf' instead (e.g. 'from django_waf.forms "
    "import ...'). Note the app label, DB tables, settings prefix (now "
    "DJANGO_WAF_*) and management commands (now django_waf_*) also changed in "
    "1.0.0 — see the CHANGELOG upgrade note.",
    DeprecationWarning,
    stacklevel=2,
)


class _IcvWafAliasFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Resolve ``icv_waf`` and ``icv_waf.*`` to the ``django_waf`` equivalents."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname != _OLD and not fullname.startswith(_OLD + "."):
            return None
        new_name = _NEW + fullname[len(_OLD) :]
        # Import the real module, then expose it under the old name.
        real = importlib.import_module(new_name)
        sys.modules[fullname] = real
        return importlib.util.spec_from_loader(fullname, loader=self)

    def create_module(self, spec):
        # The real module is already in sys.modules; reuse it.
        return sys.modules[spec.name]

    def exec_module(self, module):
        # Nothing to execute — module is the already-imported django_waf one.
        return None


# Install the finder once, ahead of the default finders.
if not any(isinstance(f, _IcvWafAliasFinder) for f in sys.meta_path):
    sys.meta_path.insert(0, _IcvWafAliasFinder())

# Make `import icv_waf` itself resolve to django_waf's namespace.
_django_waf = importlib.import_module(_NEW)
sys.modules[_OLD] = _django_waf
