"""
Management command: django_waf_prune_logs

Deletes RequestLog records older than the configured retention period.
Mirrors the behaviour of the prune_request_logs Celery task for manual invocation.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Delete WAF request log records older than the retention period."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--days",
            type=int,
            default=None,
            help=("Override retention period in days (default: DJANGO_WAF_LOG_RETENTION_DAYS, typically 30)."),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Report the number of records that would be deleted without deleting them.",
        )

    def handle(self, *args, **options) -> None:
        from django_waf import conf
        from django_waf.models import RequestLog

        days: int = options["days"] if options["days"] is not None else conf.DJANGO_WAF_LOG_RETENTION_DAYS
        dry_run: bool = options["dry_run"]

        if days < 1:
            raise CommandError("--days must be a positive integer.")

        purgeable_qs = RequestLog.objects.purgeable(days=days)

        if dry_run:
            count = purgeable_qs.count()
            self.stdout.write(
                self.style.WARNING(f"[dry-run] Would delete {count} log record(s) older than {days} day(s).")
            )
            return

        try:
            deleted_count, _ = purgeable_qs.delete()
        except Exception as exc:
            raise CommandError(f"Log pruning failed: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Deleted {deleted_count} log record(s) older than {days} day(s)."))
