"""
Management command: django_waf_detect_anomalies

Runs all WAF anomaly detectors and auto-creates expiring BlockRules for any
patterns detected. Useful for manual invocation outside of the Celery schedule,
or during incident response.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Run WAF anomaly detectors and auto-create block rules."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--window-minutes",
            type=int,
            default=None,
            help=("Override the analysis window in minutes (default: 5 for UA rotation, 15 for burst detection)."),
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Report detected anomalies without creating BlockRules.",
        )

    def handle(self, *args, **options) -> None:
        from django_waf.services.anomaly_detector import run_all_detectors

        dry_run: bool = options["dry_run"]
        window_minutes: int | None = options["window_minutes"]

        if dry_run:
            self.stdout.write(self.style.WARNING("[dry-run] Analysing anomalies — no rules will be created."))

        try:
            results = run_all_detectors(window_minutes=window_minutes)
        except Exception as exc:
            raise CommandError(f"Anomaly detection failed: {exc}") from exc

        # run_all_detectors returns a dict keyed by detector name.
        total_created = 0
        for detector_name, rules_created in results.items():
            count = len(rules_created) if isinstance(rules_created, list) else int(rules_created)
            if count:
                label = "would create" if dry_run else "created"
                self.stdout.write(f"  {detector_name}: {label} {count} rule(s)")
            total_created += count

        if total_created:
            msg = (
                f"[dry-run] Would have created {total_created} rule(s)."
                if dry_run
                else f"Created {total_created} anomaly rule(s)."
            )
            self.stdout.write(self.style.SUCCESS(msg))
        else:
            self.stdout.write(self.style.SUCCESS("No anomalies detected."))
