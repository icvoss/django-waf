"""
Management command: django_waf_detector_outcomes

Reports the production outcome of every anomaly detector over a window
(default 30 days): rules created, rules ever hit, hit rate, total hits
attributed, and the most recent rule created, plus the BR-ANOM-010 review
outcome counts for the same period. Read-only: makes no BlockRule write, no
RequestLog write, and emits no signal.

The missing fourth link of the chain-of-command rule (wave 2 of the
provenance plan): identity, action and justification already existed for
every detector; production outcome did not, and getting it previously meant
ad-hoc ORM queries run directly against a live deployment.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Report each anomaly detector's production outcome (rules created, hit rate, review status)."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--days",
            type=int,
            default=30,
            help="Window in days to look back over BlockRule.created_at (default: 30).",
        )

    def handle(self, *args, **options) -> None:
        from django_waf.services.detector_outcomes import report_detector_outcomes

        days: int = options["days"]

        try:
            result = report_detector_outcomes(window_days=days)
        except ValueError as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(f"Detector outcomes, last {result['window_days']} day(s):")
        self.stdout.write("")

        for name, stats in result["detectors"].items():
            self._write_detector_row(name, stats)

        if result["unregistered_detectors"]:
            self.stdout.write("")
            self.stdout.write(
                self.style.WARNING("Names found in BlockRule.detectors outside anomaly_detector.DETECTOR_NAMES:")
            )
            for name, stats in result["unregistered_detectors"].items():
                self._write_detector_row(name, stats)

        outcomes = result["review_outcomes"]
        self.stdout.write("")
        self.stdout.write(
            "Review outcomes: pending={pending} confirmed={confirmed} rejected={rejected} "
            "expired_unreviewed={expired_unreviewed} not_applicable={not_applicable} total={total}".format(**outcomes)
        )

    def _write_detector_row(self, name: str, stats: dict) -> None:
        most_recent = stats["most_recent_rule_created"]
        most_recent_str = most_recent.isoformat() if most_recent is not None else "never"
        self.stdout.write(
            f"  {name}: created={stats['rules_created']} ever_hit={stats['rules_ever_hit']} "
            f"hit_rate={stats['hit_rate']:.2%} total_hits={stats['total_hits']} "
            f"most_recent={most_recent_str}"
        )
