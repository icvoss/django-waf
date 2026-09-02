"""
Management command: django_waf_prune_rules

Hard-deletes expired, inactive, auto-generated BlockRule records older than
the configured retention period. Mirrors the behaviour of the
prune_stale_rules Celery task (tasks.py) for manual invocation.

Defaults to dry-run, unlike django_waf_prune_logs and
django_waf_prune_challenges, which default to executing and require an
explicit --dry-run to preview. This command inverts that convention on
purpose: a RequestLog row is a sampled, low-value record and a
ChallengeToken is ephemeral proof-of-work state, but a BlockRule is a
decision record, and this is the only prune path in the package that hard-
deletes one. The wave that added it (the wave 2 rule-provenance plan) treats this as the
package's one genuinely irreversible operator action, so the safe path
(report a count, delete nothing) has to be what an operator gets by typing
the command with no flags and no prior reading of --help. An explicit
--execute is required to actually delete; --dry-run is also accepted, as a
no-op synonym for the default, so a script written against the other prune
commands' --dry-run convention still behaves safely here rather than
deleting on the first unfamiliar flag.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Delete expired, inactive, auto-generated WAF block rules older than the retention "
        "period. Defaults to reporting the count without deleting; pass --execute to delete."
    )

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help=("Override retention period in days (default: DJANGO_WAF_RULE_RETENTION_DAYS, typically 90)."),
        )
        parser.add_argument(
            "--execute",
            action="store_true",
            default=False,
            help="Actually delete the matching rows. Without this flag the command only reports "
            "the count that would be deleted.",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Report the number of rules that would be deleted without deleting them "
            "(this is the default behaviour; the flag is accepted for symmetry with the "
            "other prune commands and has no additional effect).",
        )

    def handle(self, *args, **options) -> None:
        from django_waf import conf
        from django_waf.models import BlockRule

        days: int = options["days"] if options["days"] is not None else conf.DJANGO_WAF_RULE_RETENTION_DAYS
        execute: bool = options["execute"]

        if days < 1:
            raise CommandError("--days must be a positive integer.")

        stale_qs = BlockRule.objects.stale(days=days)

        if not execute:
            count = stale_qs.count()
            self.stdout.write(
                self.style.WARNING(
                    f"[dry-run] Would delete {count} block rule(s) older than {days} day(s). "
                    "Pass --execute to actually delete."
                )
            )
            return

        try:
            deleted_count, _ = stale_qs.delete()
        except Exception as exc:
            raise CommandError(f"Rule pruning failed: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} block rule(s) older than {days} day(s)."))
