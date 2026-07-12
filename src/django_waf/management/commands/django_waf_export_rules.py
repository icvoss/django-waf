"""
Management command: django_waf_export_rules

Serialises BlockRule and AllowRule records to JSON for backup or transfer
to another site. Pairs with django_waf_import_rules.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Export WAF block and allow rules to JSON."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output",
            default=None,
            help="File path to write the JSON to (default: stdout).",
        )
        parser.add_argument(
            "--source",
            choices=["admin", "auto", "feed", "all"],
            default="all",
            help="Only export rules from this source (default: all).",
        )
        parser.add_argument(
            "--rule-type",
            choices=["block", "allow", "all"],
            default="all",
            help="Only export block rules, allow rules, or both (default: all).",
        )

    def handle(self, *args, **options) -> None:
        import json

        from django.utils import timezone

        from django_waf.models import AllowRule, BlockRule

        source: str = options["source"]
        rule_type: str = options["rule_type"]
        output: str | None = options["output"]

        block_rules: list[dict] = []
        allow_rules: list[dict] = []

        if rule_type in ("block", "all"):
            qs = BlockRule.objects.all()
            if source != "all":
                qs = qs.filter(source=source)
            block_rules = [_serialise_block_rule(rule) for rule in qs]

        if rule_type in ("allow", "all"):
            qs = AllowRule.objects.all()
            allow_rules = [_serialise_allow_rule(rule) for rule in qs]

        payload = {
            "version": 1,
            "exported_at": timezone.now().isoformat(),
            "block_rules": block_rules,
            "allow_rules": allow_rules,
        }

        text = json.dumps(payload, indent=2)

        if output:
            try:
                with open(output, "w") as fh:
                    fh.write(text)
            except OSError as exc:
                raise CommandError(f"Could not write to {output}: {exc}") from exc
            self.stdout.write(
                self.style.SUCCESS(
                    f"Exported {len(block_rules)} block rule(s) and {len(allow_rules)} allow rule(s) to {output}."
                )
            )
            return

        self.stdout.write(text)


def _serialise_block_rule(rule) -> dict:
    """Return a JSON-serialisable dict of the meaningful BlockRule fields.

    Excludes id, created_at, and updated_at — those are regenerated on
    import.
    """
    return {
        "name": rule.name,
        "rule_type": rule.rule_type,
        "match_type": rule.match_type,
        "pattern": rule.pattern,
        "action": rule.action,
        "priority": rule.priority,
        "is_active": rule.is_active,
        "source": rule.source,
        "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
        "confidence": str(rule.confidence),
        "feed_first_seen": rule.feed_first_seen.isoformat() if rule.feed_first_seen else None,
        "feed_reporters": rule.feed_reporters,
        "notes": rule.notes,
    }


def _serialise_allow_rule(rule) -> dict:
    """Return a JSON-serialisable dict of the meaningful AllowRule fields.

    Excludes id, created_at, and updated_at — those are regenerated on
    import.
    """
    return {
        "name": rule.name,
        "rule_type": rule.rule_type,
        "match_type": rule.match_type,
        "pattern": rule.pattern,
        "verify_rdns": rule.verify_rdns,
        "rdns_pattern": rule.rdns_pattern,
        "is_active": rule.is_active,
        "notes": rule.notes,
    }
