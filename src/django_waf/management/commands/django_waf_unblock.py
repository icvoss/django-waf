"""
Management command: django_waf_unblock

Remove block rules for an IP address or CIDR range.
"""

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Unblock an IP address or CIDR range by deactivating matching rules."

    def add_arguments(self, parser) -> None:
        parser.add_argument("pattern", help="IP address or CIDR range to unblock")
        parser.add_argument(
            "--delete",
            action="store_true",
            default=False,
            help="Delete the rules entirely instead of deactivating",
        )

    def handle(self, *args, **options) -> None:
        from django_waf.models import BlockRule

        pattern = options["pattern"].strip()
        delete = options["delete"]

        rules = BlockRule.objects.filter(pattern=pattern, is_active=True)
        count = rules.count()

        if count == 0:
            self.stdout.write(f"No active rules found for {pattern}.")
            return

        if delete:
            rules.delete()
            self.stdout.write(self.style.SUCCESS(f"Deleted {count} rule(s) for {pattern}."))
        else:
            rules.update(is_active=False)
            self.stdout.write(self.style.SUCCESS(f"Deactivated {count} rule(s) for {pattern}."))
