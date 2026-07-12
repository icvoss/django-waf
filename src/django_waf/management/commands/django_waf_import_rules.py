"""
Management command: django_waf_import_rules

Loads BlockRule and AllowRule records from the JSON produced by
django_waf_export_rules. Imported rules are always tagged
source=admin — they are never re-tagged as feed/auto, regardless of
what the exporting site originally recorded.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Import WAF block and allow rules from JSON produced by django_waf_export_rules."

    def add_arguments(self, parser) -> None:
        parser.add_argument("file", help="Path to the JSON file to import.")
        parser.add_argument(
            "--merge",
            action="store_true",
            default=False,
            help="Skip rules that already exist (matched on rule_type, match_type, pattern). Default mode.",
        )
        parser.add_argument(
            "--replace",
            action="store_true",
            default=False,
            help="Delete existing source=admin rules before importing.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Report what would be created/skipped/replaced without writing any changes.",
        )

    def handle(self, *args, **options) -> None:
        import json

        from django.db import transaction
        from django.utils.dateparse import parse_datetime

        from django_waf.enums import RuleSource
        from django_waf.models import AllowRule, BlockRule

        file_path: str = options["file"]
        merge: bool = options["merge"]
        replace: bool = options["replace"]
        dry_run: bool = options["dry_run"]

        if merge and replace:
            raise CommandError("--merge and --replace are mutually exclusive.")

        # --merge is the default when neither flag is given.
        if not merge and not replace:
            merge = True

        try:
            with open(file_path) as fh:
                payload = json.load(fh)
        except OSError as exc:
            raise CommandError(f"Could not read {file_path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise CommandError(f"{file_path} is not valid JSON: {exc}") from exc

        block_rules = payload.get("block_rules", [])
        allow_rules = payload.get("allow_rules", [])

        created = 0
        skipped = 0
        replaced = 0

        with transaction.atomic():
            if replace:
                # AllowRule has no source field — "admin rules" for allow
                # rules means all of them, since every AllowRule is
                # hand-authored (there is no auto/feed source for allows).
                replaced_block_count = BlockRule.objects.filter(source=RuleSource.ADMIN).count()
                replaced_allow_count = AllowRule.objects.count()
                if not dry_run:
                    BlockRule.objects.filter(source=RuleSource.ADMIN).delete()
                    AllowRule.objects.all().delete()
                replaced = replaced_block_count + replaced_allow_count

            existing_block_keys = set()
            if merge:
                existing_block_keys = set(BlockRule.objects.values_list("rule_type", "match_type", "pattern"))
            existing_allow_keys = set()
            if merge:
                existing_allow_keys = set(AllowRule.objects.values_list("rule_type", "match_type", "pattern"))

            for entry in block_rules:
                key = (entry["rule_type"], entry["match_type"], entry["pattern"])
                if merge and key in existing_block_keys:
                    skipped += 1
                    continue
                if dry_run:
                    created += 1
                    continue
                expires_at = parse_datetime(entry["expires_at"]) if entry.get("expires_at") else None
                feed_first_seen = entry.get("feed_first_seen") or None
                BlockRule.objects.create(
                    name=entry["name"],
                    rule_type=entry["rule_type"],
                    match_type=entry["match_type"],
                    pattern=entry["pattern"],
                    action=entry["action"],
                    priority=entry.get("priority", 100),
                    is_active=entry.get("is_active", True),
                    source=RuleSource.ADMIN,
                    expires_at=expires_at,
                    confidence=entry.get("confidence", "1.00"),
                    feed_first_seen=feed_first_seen,
                    feed_reporters=entry.get("feed_reporters", 0),
                    notes=entry.get("notes", ""),
                )
                created += 1
                existing_block_keys.add(key)

            for entry in allow_rules:
                key = (entry["rule_type"], entry["match_type"], entry["pattern"])
                if merge and key in existing_allow_keys:
                    skipped += 1
                    continue
                if dry_run:
                    created += 1
                    continue
                AllowRule.objects.create(
                    name=entry["name"],
                    rule_type=entry["rule_type"],
                    match_type=entry["match_type"],
                    pattern=entry["pattern"],
                    verify_rdns=entry.get("verify_rdns", False),
                    rdns_pattern=entry.get("rdns_pattern", ""),
                    is_active=entry.get("is_active", True),
                    notes=entry.get("notes", ""),
                )
                created += 1
                existing_allow_keys.add(key)

            if dry_run:
                # Roll back — dry-run must not persist anything.
                transaction.set_rollback(True)

        prefix = "[dry-run] " if dry_run else ""
        self.stdout.write(self.style.SUCCESS(f"{prefix}Created: {created}"))
        self.stdout.write(self.style.WARNING(f"{prefix}Skipped (already exists): {skipped}"))
        if replace:
            self.stdout.write(self.style.WARNING(f"{prefix}Replaced (deleted admin rules): {replaced}"))
