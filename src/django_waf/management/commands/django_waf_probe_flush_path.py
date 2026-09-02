"""
Management command: django_waf_probe_flush_path

Runs the flush-path liveness probe (#100) against a real counter driven
through the real producer (``rule_engine._record_rule_hit``) and the real
consumer (``tasks.flush_rule_hit_counts``), and reports whether it
demonstrably reached the database. Useful for manual invocation outside
the Celery schedule, incident response, or a readiness/liveness probe
wired to an external monitor.
"""

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Run the WAF flush-path liveness probe against a real, synthetic hit counter."

    def handle(self, *args, **options) -> None:
        from django_waf.services.flush_probe import run_flush_probe

        try:
            result = run_flush_probe()
        except Exception as exc:
            raise CommandError(f"Flush probe failed to run: {exc}") from exc

        self.stdout.write(
            f"  flushed={result['flushed']} keys_seen={result['keys_seen']} errors={result['errors']} "
            f"hit_count_delta={result['hit_count_delta']} key_deleted={result['key_deleted']}"
        )

        if result["alive"]:
            self.stdout.write(self.style.SUCCESS("Flush path alive."))
            return

        # Non-zero exit on a bad result, unlike most commands in this
        # package: this command is meant to be wired into a cron wrapper
        # or a k8s liveness/readiness probe that keys off exit status, so
        # a broken flush path must fail the process, not just print a
        # warning.
        raise CommandError(f"Flush path DEAD: {result['failure_reason']}")
