"""Coverage for the deprecated ``icv_waf`` import-name shim (#163).

The shim mutates process-global ``sys.modules`` and ``sys.meta_path`` on first
import, and a second import in the same process cannot re-exercise the
first-import warning path. Each case therefore runs in a fresh subprocess so
results do not depend on pytest's already-loaded ``django_waf`` or on sibling
cases leaving stale finder or module-cache state.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap


def _run_isolated(code: str) -> subprocess.CompletedProcess[str]:
    """Execute *code* in a clean interpreter with Django settings configured."""
    prologue = textwrap.dedent(
        """
        import os
        import warnings

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")
        warnings.filterwarnings("default", category=DeprecationWarning)
        import django

        django.setup()
        """
    )
    return subprocess.run(
        [sys.executable, "-c", prologue + "\n" + textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_import_icv_waf_aliases_django_waf():
    result = _run_isolated(
        """
        import django_waf
        import icv_waf

        assert icv_waf is django_waf, (icv_waf, django_waf)
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_import_emits_deprecation_warning_naming_replacement():
    result = _run_isolated(
        """
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", DeprecationWarning)
            import icv_waf  # noqa: F401

        matching = [
            w
            for w in caught
            if issubclass(w.category, DeprecationWarning)
            and "icv_waf" in str(w.message)
            and "django_waf" in str(w.message)
        ]
        assert matching, [str(w.message) for w in caught]
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_submodule_import_resolves_to_django_waf_equivalent():
    result = _run_isolated(
        """
        from django_waf.forms import ProtectedForm as DjangoProtectedForm
        from icv_waf.forms import ProtectedForm as IcvProtectedForm

        assert IcvProtectedForm is DjangoProtectedForm
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_second_import_does_not_double_install_finder():
    result = _run_isolated(
        """
        import sys

        import icv_waf  # noqa: F401

        finders_after_first = [f for f in sys.meta_path if type(f).__name__ == "_IcvWafAliasFinder"]
        assert len(finders_after_first) == 1

        import icv_waf  # noqa: F401
        from icv_waf.forms import ProtectedForm  # noqa: F401

        finders_after_second = [f for f in sys.meta_path if type(f).__name__ == "_IcvWafAliasFinder"]
        assert len(finders_after_second) == 1
        assert finders_after_second[0] is finders_after_first[0]
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout
