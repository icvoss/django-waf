    #!/usr/bin/env python
"""Generate migrations for the reusable icv_waf app.

This package ships no manage.py. ``tests/settings.py`` deliberately disables
migrations (``MIGRATION_MODULES = {"icv_waf": None, ...}``) so the test
database is built straight from the models for speed. That same setting
prevents ``makemigrations`` from writing files, so this script reuses the test
settings but re-enables real migration modules before invoking the command.

Usage:
    python make_migrations.py            # author/update migrations
    python make_migrations.py --check    # fail if migrations are missing
"""

from __future__ import annotations

import sys

import django
from django.conf import settings


def main(argv: list[str]) -> None:
    import tests.settings as test_settings

    config = {key: getattr(test_settings, key) for key in dir(test_settings) if key.isupper()}
    # Re-enable real migration modules so makemigrations writes files.
    config["MIGRATION_MODULES"] = {}

    settings.configure(**config)
    django.setup()

    from django.core.management import call_command

    call_command("makemigrations", "icv_waf", *argv)


if __name__ == "__main__":
    main(sys.argv[1:])
