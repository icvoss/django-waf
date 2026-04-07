"""
Management command: icv_waf_generate_blocklist

Generates the nginx IP/UA blocklist configuration file from active WAF rules.
Can be run manually during initial setup, testing, or after emergency rule changes.
"""

import contextlib

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Generate nginx blocklist configuration from active WAF rules."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--output-path",
            type=str,
            default=None,
            help="Override the output file path (default: ICV_WAF_NGINX_BLOCKLIST_PATH).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            default=False,
            help="Print the generated configuration to stdout without writing the file.",
        )

    def handle(self, *args, **options) -> None:
        output_path: str | None = options["output_path"]
        dry_run: bool = options["dry_run"]

        if dry_run:
            self._dry_run(output_path)
        else:
            self._write_and_reload(output_path)

    def _dry_run(self, output_path: str | None) -> None:
        """Print the blocklist to stdout without writing any file."""
        import os
        import tempfile

        # Write to a temp file, then read it back.
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".conf.tmp")
        try:
            os.close(tmp_fd)
            from icv_waf.services.blocklist_generator import generate_nginx_blocklist

            count = generate_nginx_blocklist(output_path=tmp_path)
            with open(tmp_path) as fh:
                self.stdout.write(fh.read())
            self.stdout.write(self.style.SUCCESS(f"[dry-run] Would write {count} rule(s). No file was created."))
        except Exception as exc:
            raise CommandError(f"Failed to generate blocklist: {exc}") from exc
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp_path)

    def _write_and_reload(self, output_path: str | None) -> None:
        """Write the blocklist file and signal nginx to reload."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist, reload_nginx

        try:
            count = generate_nginx_blocklist(output_path=output_path)
        except Exception as exc:
            raise CommandError(f"Failed to generate blocklist: {exc}") from exc

        self.stdout.write(self.style.SUCCESS(f"Wrote {count} rule(s) to blocklist file."))

        reloaded = reload_nginx()
        if reloaded:
            self.stdout.write(self.style.SUCCESS("nginx reloaded successfully."))
        else:
            self.stdout.write(
                self.style.WARNING(
                    "nginx reload failed or nginx is not available. "
                    "The blocklist file has been written; reload nginx manually."
                )
            )
