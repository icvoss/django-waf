"""
Management command: django_waf_probe_detectors

Runs the detector liveness probe (BR-ANOM-012) against synthetic fixture
traffic and reports which anomaly detectors are alive. Useful for manual
invocation outside the Celery schedule, incident response, or a
readiness/liveness probe wired to an external monitor.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Run the WAF detector liveness probe against synthetic fixture traffic."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--exercise-writes",
            action="store_true",
            default=False,
            help=(
                "Report with real detector writes rather than each detector's own "
                "read-only dry-run mode (default: dry-run). No synthetic row is ever "
                "committed either way (the whole run is wrapped in a rolled-back "
                "transaction), but --exercise-writes DOES fire the anomaly_detected "
                "signal for real, for a synthetic event: any receiver a consuming "
                "project has wired to it (paging, a webhook, a metrics counter) "
                "fires on this synthetic data. Use only when you specifically need "
                "to exercise the write path (quarantine logic, the review_status "
                "guard, dedup-retry), which dry-run mode cannot reach."
            ),
        )

    def handle(self, *args, **options) -> None:
        from django_waf.services.detector_probe import run_detector_probe

        exercise_writes: bool = options["exercise_writes"]

        if exercise_writes:
            self.stdout.write(
                self.style.WARNING(
                    "[exercise-writes] Running detectors for real against synthetic fixture "
                    "traffic. anomaly_detected WILL fire for this synthetic event."
                )
            )

        try:
            result = run_detector_probe(dry_run=not exercise_writes)
        except Exception as exc:
            raise CommandError(f"Detector probe failed to run: {exc}") from exc

        for detector_name in sorted(result):
            if detector_name in ("all_alive", "silent_detectors", "dry_run"):
                continue
            status = result[detector_name]
            state = "alive" if status["alive"] else "SILENT"
            self.stdout.write(f"  {detector_name}: {state} (rules_reported={status['rules_reported']})")

        if result["all_alive"]:
            self.stdout.write(self.style.SUCCESS("All detectors alive."))
            return

        # Non-zero exit on a bad result, unlike most commands in this
        # package: this command is meant to be wired into a cron wrapper
        # or a k8s liveness/readiness probe that keys off exit status, so a
        # silent detector must fail the process, not just print a warning.
        silent = ", ".join(result["silent_detectors"])
        raise CommandError(f"Detectors silent: {silent}")
