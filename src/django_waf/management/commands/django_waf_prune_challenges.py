"""
Management command: django_waf_prune_challenges

Deletes pending or failed ChallengeToken records older than the given
age threshold. Mirrors the behaviour of the prune_challenge_tokens Celery
task for manual invocation.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Delete pending or failed WAF challenge token records older than N hours."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--hours",
            type=int,
            default=24,
            help="Age threshold in hours, measured against expires_at (default: 24).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Report the number of records that would be deleted without deleting them.",
        )

    def handle(self, *args, **options) -> None:
        from django.utils import timezone

        from django_waf.enums import ChallengeStatus
        from django_waf.models import ChallengeToken

        hours: int = options["hours"]
        dry_run: bool = options["dry_run"]

        if hours < 1:
            raise CommandError("--hours must be a positive integer.")

        cutoff = timezone.now() - timezone.timedelta(hours=hours)
        purgeable_qs = ChallengeToken.objects.filter(
            status__in=[ChallengeStatus.PENDING, ChallengeStatus.FAILED],
            expires_at__lt=cutoff,
        )

        if dry_run:
            count = purgeable_qs.count()
            self.stdout.write(
                self.style.WARNING(f"[dry-run] Would delete {count} challenge token(s) older than {hours} hour(s).")
            )
            return

        try:
            deleted_count, _ = purgeable_qs.delete()
        except Exception as exc:
            raise CommandError(f"Challenge token pruning failed: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} challenge token(s) older than {hours} hour(s)."))
