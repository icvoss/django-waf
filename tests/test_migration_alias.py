"""Regression test for icvoss/django-waf#164: every ORM call inside a
data migration's RunPython function must route through
schema_editor.connection.alias, not the implicit "default" alias.

Reproduces the reported failure mode directly: run each RunPython function
against the "other" alias (tests/settings.py's second, always-SQLite
alias) using the live app registry. The suite builds schema from models
(MIGRATION_MODULES disables migrations), so historical MigrationExecutor
state is not available here; the alias-routing contract does not depend on
historical field shape for these two functions.

If a RunPython function omits .using(alias), its writes land on "default"
instead of "other": this test asserts that divergence directly.
"""

from __future__ import annotations

import importlib
from datetime import timedelta

import pytest
from django.db import connections
from django.utils import timezone

from tests.conftest import AUTO_KEY_CONSTRAINT

# transactional=True: connections[alias].schema_editor() opens a schema
# editor purely to obtain a real .connection.alias-bearing object (no DDL
# runs through it here), but Django's SQLite backend still refuses to
# enter one while its own FK constraint checks are enabled, which the
# plain `db` fixture's open atomic block leaves them as.
pytestmark = pytest.mark.django_db(databases=["default", "other"], transaction=True)


def _run_data_migration(function, alias: str) -> None:
    """Run one RunPython function against `alias`, with a schema_editor
    whose .connection.alias is that alias, exactly as `migrate
    --database=<alias>` invokes it.
    """
    from django.apps import apps

    with connections[alias].schema_editor() as schema_editor:
        function(apps, schema_editor)


class TestSeedVerifiedCrawlersUsesConnectionAlias:
    """0003_seed_verified_crawlers.seed_verified_crawlers."""

    def test_seed_lands_on_the_migrating_alias_only(self, settings):
        from django.apps import apps

        settings.DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS = True
        module = importlib.import_module("django_waf.migrations.0003_seed_verified_crawlers")
        AllowRule = apps.get_model("django_waf", "AllowRule")

        _run_data_migration(module.seed_verified_crawlers, "other")

        assert AllowRule.objects.using("other").filter(pattern="Googlebot").exists()
        assert AllowRule.objects.using("other").filter(pattern="bingbot").exists()
        assert not AllowRule.objects.using("default").filter(pattern="Googlebot").exists()
        assert not AllowRule.objects.using("default").filter(pattern="bingbot").exists()


class TestDedupeAutoBlockRulesUsesConnectionAlias:
    """0008_dedupe_auto_block_rules.dedupe_auto_block_rules."""

    def test_dedupe_deletes_on_the_migrating_alias_only(self):
        from django.apps import apps
        from django_waf.models import BlockRule as LiveBlockRule

        module = importlib.import_module("django_waf.migrations.0008_dedupe_auto_block_rules")
        BlockRule = apps.get_model("django_waf", "BlockRule")

        # Drop the partial unique constraint on "other" so duplicate auto
        # rows can be seeded (the suite builds schema from models).
        constraint = next(c for c in LiveBlockRule._meta.constraints if c.name == AUTO_KEY_CONSTRAINT)
        other = connections["other"]
        with other.schema_editor() as schema_editor:
            schema_editor.remove_constraint(LiveBlockRule, constraint)

        try:
            now = timezone.now()
            older = now - timedelta(hours=2)
            newer = now - timedelta(hours=1)

            # Seed duplicate auto rows on "other" only. Without .using(alias)
            # the migration would look at "default" (empty) and leave both.
            older_row = BlockRule.objects.using("other").create(
                name="older",
                rule_type="ip",
                pattern="203.0.113.10",
                action="block",
                match_type="exact",
                source="auto",
                is_active=True,
            )
            keep = BlockRule.objects.using("other").create(
                name="newer",
                rule_type="ip",
                pattern="203.0.113.10",
                action="block",
                match_type="exact",
                source="auto",
                is_active=True,
            )
            # auto_now_add ignores create() kwargs; set ordering explicitly.
            BlockRule.objects.using("other").filter(pk=older_row.pk).update(created_at=older)
            BlockRule.objects.using("other").filter(pk=keep.pk).update(created_at=newer)

            _run_data_migration(module.dedupe_auto_block_rules, "other")

            remaining = list(BlockRule.objects.using("other").filter(pattern="203.0.113.10"))
            assert len(remaining) == 1
            assert remaining[0].pk == keep.pk
            assert not BlockRule.objects.using("default").filter(pattern="203.0.113.10").exists()
        finally:
            with other.cursor() as cursor:
                still_present = AUTO_KEY_CONSTRAINT in other.introspection.get_constraints(
                    cursor, LiveBlockRule._meta.db_table
                )
            if not still_present:
                BlockRule.objects.using("other").filter(source="auto").delete()
                with other.schema_editor() as schema_editor:
                    schema_editor.add_constraint(LiveBlockRule, constraint)
