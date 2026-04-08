"""
Management command: icv_waf_block

Manually block an IP address or CIDR range by creating a BlockRule.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Block an IP address or CIDR range."

    def add_arguments(self, parser) -> None:
        parser.add_argument("pattern", help="IP address or CIDR range to block (e.g. 203.0.113.42 or 10.0.0.0/24)")
        parser.add_argument("--reason", default="", help="Reason for blocking (stored in rule notes)")
        parser.add_argument(
            "--ttl",
            type=int,
            default=None,
            help="Hours until the rule expires (default: permanent)",
        )
        parser.add_argument(
            "--action",
            choices=["block", "challenge"],
            default="block",
            help="Action to take (default: block)",
        )

    def handle(self, *args, **options) -> None:
        from datetime import timedelta

        from django.utils import timezone

        from icv_waf.enums import RuleSource, RuleType
        from icv_waf.models import BlockRule

        pattern = options["pattern"].strip()
        action = options["action"]
        reason = options["reason"]
        ttl_hours = options["ttl"]

        # Determine rule type
        rule_type = RuleType.CIDR if "/" in pattern else RuleType.IP
        match_type = "cidr" if rule_type == RuleType.CIDR else "exact"

        expires_at = None
        if ttl_hours is not None:
            expires_at = timezone.now() + timedelta(hours=ttl_hours)

        try:
            rule, created = BlockRule.objects.update_or_create(
                rule_type=rule_type,
                pattern=pattern,
                source=RuleSource.ADMIN,
                action=action,
                defaults={
                    "name": f"Manual block: {pattern}",
                    "match_type": match_type,
                    "is_active": True,
                    "expires_at": expires_at,
                    "notes": reason,
                },
            )
        except Exception as exc:
            raise CommandError(f"Failed to create rule: {exc}") from exc

        if created:
            self.stdout.write(self.style.SUCCESS(f"Blocked {pattern} ({action})."))
        else:
            self.stdout.write(self.style.SUCCESS(f"Updated existing rule for {pattern}."))

        if expires_at:
            self.stdout.write(f"  Expires: {expires_at.isoformat()}")
        else:
            self.stdout.write("  Permanent (no expiry).")

        if reason:
            self.stdout.write(f"  Reason: {reason}")
