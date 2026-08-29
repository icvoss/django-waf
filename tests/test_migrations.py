"""Tests that the django_waf app has no un-migrated model changes (#105).

BlockRule.detectors was declared without a ``default=`` kwarg while the
migration that added it recorded ``default=""``, so model state and
migration-graph state disagreed. A consumer running
``manage.py makemigrations --check --dry-run`` (a standard merge-blocking CI
gate) got a spurious AlterField diff for a field they do not own, with no
local fix available.

No test in this suite ran the migration autodetector at all, so nothing
caught it. tests/settings.py sets ``MIGRATION_MODULES`` to disable migrations
for the rest of the suite (fast, migration-free test databases), which means
this check must explicitly re-enable them for django_waf rather than relying
on the ambient setting, or it would either raise ("migrations have been
disabled") or silently compare against nothing.
"""

from __future__ import annotations

import django
from django.db import connections
from django.db.migrations.autodetector import MigrationAutodetector
from django.db.migrations.loader import MigrationLoader
from django.db.migrations.state import ProjectState
from django.test import override_settings


class TestNoPendingMigrations:
    def test_django_waf_has_no_pending_model_changes(self, db):
        """The django_waf app's models match its committed migrations.

        Builds a real MigrationLoader (with MIGRATION_MODULES temporarily
        cleared so django_waf's actual migration files are read, not the
        None sentinel tests/settings.py normally installs) and asks the
        MigrationAutodetector whether current model state diverges from
        what the migration graph records. A single un-migrated field
        default is enough to trip this: it is exactly the class of drift
        that a `makemigrations --check --dry-run` CI gate would catch for
        this app, and exactly what shipped un-caught in 2.2.0 (#105).
        """
        with override_settings(MIGRATION_MODULES={}):
            connection = connections["default"]
            loader = MigrationLoader(connection, ignore_no_migrations=True)
            autodetector = MigrationAutodetector(
                loader.project_state(),
                ProjectState.from_apps(django.apps.apps),
            )
            changes = autodetector.changes(graph=loader.graph)

        pending = changes.get("django_waf", [])
        descriptions = [f"{migration.name}: {[op.describe() for op in migration.operations]}" for migration in pending]
        assert not pending, (
            "django_waf has model changes with no matching migration. "
            "Run `makemigrations django_waf` and commit the result. "
            f"Detected operations: {descriptions}"
        )
