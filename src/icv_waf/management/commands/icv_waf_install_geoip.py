"""
Management command: icv_waf_install_geoip

Download and install the MaxMind GeoLite2-Country database for the WAF
middleware's country lookup. Requires a free MaxMind licence key.

Usage::

    # One-off install (licence key from ICV_WAF_MAXMIND_LICENSE_KEY):
    manage.py icv_waf_install_geoip

    # Pass the licence key explicitly:
    manage.py icv_waf_install_geoip --license-key=XXXXXXXXXXXXXXXX

    # Skip if existing file is younger than 7 days (cron-friendly):
    manage.py icv_waf_install_geoip --if-older-than=7 --quiet

    # Override output path:
    manage.py icv_waf_install_geoip --output-path=/etc/geoip/country.mmdb
"""

from __future__ import annotations

from datetime import UTC

from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = "Download and install the MaxMind GeoLite2-Country database."

    def add_arguments(self, parser) -> None:
        parser.add_argument(
            "--license-key",
            default=None,
            help="MaxMind licence key. Defaults to ICV_WAF_MAXMIND_LICENSE_KEY.",
        )
        parser.add_argument(
            "--output-path",
            default=None,
            help="Destination .mmdb path. Defaults to ICV_WAF_GEOIP_PATH.",
        )
        parser.add_argument(
            "--if-older-than",
            type=int,
            default=0,
            help="Skip the download if the existing file is younger than N days. 0 = always download.",
        )
        parser.add_argument(
            "--quiet",
            action="store_true",
            default=False,
            help="Suppress progress output (keeps errors).",
        )

    def handle(self, *args, **options) -> None:
        from icv_waf.services.geoip import (
            GeoIPDownloadError,
            GeoIPError,
            GeoIPLicenseMissingError,
            GeoIPNotInstalledError,
            install_geoip_database,
        )

        quiet = options["quiet"]

        try:
            result = install_geoip_database(
                license_key=options["license_key"],
                output_path=options["output_path"],
                if_older_than_days=options["if_older_than"],
            )
        except GeoIPNotInstalledError as exc:
            raise CommandError(str(exc)) from exc
        except GeoIPLicenseMissingError as exc:
            raise CommandError(str(exc)) from exc
        except GeoIPDownloadError as exc:
            raise CommandError(f"Download failed: {exc}") from exc
        except GeoIPError as exc:
            raise CommandError(str(exc)) from exc

        if quiet:
            return

        if result["skipped"]:
            self.stdout.write(self.style.SUCCESS(f"GeoIP database at {result['path']} is fresh — skipped download."))
            return

        size_mb = result["size_bytes"] / (1024 * 1024)
        self.stdout.write(self.style.SUCCESS(f"Installed {result['edition']} to {result['path']} ({size_mb:.1f} MB)."))
        if result["build_epoch"]:
            from datetime import datetime

            build_dt = datetime.fromtimestamp(result["build_epoch"], tz=UTC)
            self.stdout.write(f"  Database build: {build_dt.isoformat()}")
        self.stdout.write("  Note: running workers must be restarted to pick up the new file.")
