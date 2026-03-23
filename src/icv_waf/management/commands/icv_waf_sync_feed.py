"""
Management command: icv_waf_sync_feed

Synchronises WAF block rules from the central threat feed.
Mirrors the behaviour of the sync_threat_feed Celery task for manual invocation,
or for bootstrapping on first deploy.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Synchronise WAF block rules from the central threat feed."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--feed-url",
            type=str,
            default=None,
            help="Override the feed URL (default: ICV_WAF_FEED_URL).",
        )
        parser.add_argument(
            "--min-confidence",
            type=float,
            default=None,
            help=(
                "Override the minimum confidence score to import a rule "
                "(0.0–1.0; default: ICV_WAF_FEED_MIN_CONFIDENCE)."
            ),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help=("Show what would be created, updated, or expired without writing any changes to the database."),
        )

    def handle(self, *args, **options) -> None:
        from icv_waf import conf

        feed_url: str | None = options["feed_url"]
        min_confidence: float | None = options["min_confidence"]
        dry_run: bool = options["dry_run"]

        if not conf.ICV_WAF_FEED_ENABLED and not feed_url:
            self.stdout.write(
                self.style.WARNING("ICV_WAF_FEED_ENABLED is False and no --feed-url was supplied. Skipping sync.")
            )
            return

        if dry_run:
            self.stdout.write(self.style.WARNING("[dry-run] Fetching feed — no database changes will be made."))

        from icv_waf.services.threat_feed import sync_feed

        try:
            summary = sync_feed(
                feed_url=feed_url,
                min_confidence=min_confidence,
            )
        except Exception as exc:
            raise CommandError(f"Feed sync failed: {exc}") from exc

        created = summary.get("created", 0)
        updated = summary.get("updated", 0)
        expired = summary.get("expired", 0)
        skipped = summary.get("skipped", 0)

        self.stdout.write(
            self.style.SUCCESS(
                f"Feed sync complete: {created} created, {updated} updated, {expired} expired, {skipped} skipped."
            )
        )
