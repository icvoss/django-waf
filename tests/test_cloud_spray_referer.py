"""Regression tests for issue #24: detect_cloud_spray blind to spoofed bare-origin referers.

A botnet that stamps every request with a static bare-origin referer (e.g.
"https://vendably.shop", no trailing slash, no path) previously slipped past
detect_cloud_spray entirely: both the spray-UA aggregation query and the
per-IP counting query only matched empty or NULL referers. Genuine browser
navigation always serialises at least a trailing slash after the host, so a
path-less referer is impossible from real traffic and must be treated as
equivalent to a missing referer.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from django.utils import timezone

from django_waf.services.anomaly_detector import detect_cloud_spray
from django_waf.testing.factories import RequestLogFactory

pytestmark = pytest.mark.django_db


class TestDetectCloudSprayBareOriginReferer:
    def test_bare_origin_referer_counts_as_missing(self):
        """A shared bare-origin referer (no path) is treated as a missing referer.

        Production case (VendablyCSS, 2026-08-01): every request in the flood
        carried "Referer: https://vendably.shop" with no trailing slash, so
        the old missing-referer-only filter reported cloud_spray=0.
        """
        import django_waf.conf as conf_mod

        now = timezone.now()
        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        for i in range(min_ips):
            RequestLogFactory(
                ip_address=f"203.0.113.{i}",
                user_agent=shared_ua,
                referer="https://vendably.shop",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert len(created) == 1
        assert created[0].pattern == "203.0.113.0/24"

    def test_bare_origin_referer_with_rotated_uas_still_detected(self):
        """A small rotated UA pool with a shared bare-origin referer is still caught.

        Mirrors the production shape more closely than a single identical UA:
        each of the min_ips distinct IPs uses one of a handful of rotated UA
        strings, so no single UA alone clears the distinct-IP threshold. The
        detector must still flag the subnet once the bare-origin referer is
        counted as missing.
        """
        import django_waf.conf as conf_mod

        now = timezone.now()
        min_ips = 20
        ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/119.0.0.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/121.0.0.0",
        ]

        # Reduce the threshold so a UA pool split four ways can still clear
        # it per-UA, while proving no single UA repeats an IP.
        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 5),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            for i in range(min_ips):
                RequestLogFactory(
                    ip_address=f"198.51.100.{i}",
                    user_agent=ua_pool[i % len(ua_pool)],
                    referer="https://vendably.shop",
                    timestamp=now,
                )

            created = detect_cloud_spray(window_minutes=30)

        # Every rotated UA maps to the same subnet, and _get_or_create_auto_rule
        # is keyed on (rule_type, pattern, source, action): only the first UA's
        # pass creates the rule, later passes refresh the same row (created=False).
        assert len(created) == 1
        assert created[0].pattern == "198.51.100.0/24"

    def test_real_referer_with_path_excluded(self):
        """A referer with a real path is not treated as missing, alone.

        Real navigation from a specific page must not falsely trip the
        missing-referer bucket used for cloud-spray detection.
        """
        import django_waf.conf as conf_mod

        now = timezone.now()
        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        for i in range(min_ips):
            RequestLogFactory(
                ip_address=f"203.0.113.{i}",
                user_agent=shared_ua,
                referer="https://example.com/page",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert created == []

    def test_trailing_slash_origin_referer_excluded(self):
        """A referer that is the origin WITH a trailing slash is a real referer, not bare.

        "https://example.com/" is what Referrer-Policy: origin actually
        produces from genuine navigation; it must not be folded into the
        missing-referer bucket.
        """
        import django_waf.conf as conf_mod

        now = timezone.now()
        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        for i in range(min_ips):
            RequestLogFactory(
                ip_address=f"203.0.113.{i}",
                user_agent=shared_ua,
                referer="https://example.com/",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert created == []

    def test_empty_referer_still_detected(self):
        """Existing missing-referer detection (empty string) still works."""
        import django_waf.conf as conf_mod

        now = timezone.now()
        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        for i in range(min_ips):
            RequestLogFactory(
                ip_address=f"203.0.113.{i}",
                user_agent=shared_ua,
                referer="",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert len(created) == 1
        assert created[0].pattern == "203.0.113.0/24"
