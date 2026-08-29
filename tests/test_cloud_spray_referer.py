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

from django_waf.enums import RuleAction, RuleType
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


class TestDetectCloudSprayDiffuseUA:
    """Regression tests for issues #68/#69: diffuse residential-proxy spray.

    A botnet that puts one IP per /24 (issue #69's live reproduction: 217
    IPs across 216 distinct subnets) is invisible to the subnet path, whose
    ``count < 2`` membership floor drops any subnet with only one
    suspicious IP in it. The UA path (opt-in, DJANGO_WAF_CLOUD_SPRAY_UA_RULE)
    flags the shared UA itself once it alone clears MIN_IPS distinct
    suspicious IPs, independent of subnet distribution.
    """

    # 25 distinct /24s, one suspicious IP each: the shape issue #69 measured.
    # Deliberately > MIN_IPS (20) via an explicit literal, not derived from
    # the patched setting, so the fixture provably crosses the threshold.
    RESIDENTIAL_SPRAY_IP_COUNT = 25

    def _create_residential_spray_fixture(self, shared_ua: str) -> None:
        now = timezone.now()
        for i in range(self.RESIDENTIAL_SPRAY_IP_COUNT):
            RequestLogFactory(
                ip_address=f"203.0.{i}.7",
                user_agent=shared_ua,
                referer="",
                timestamp=now,
            )

    def test_residential_spray_creates_ua_rule_when_toggle_on(self):
        """One IP per /24 over MIN_IPS subnets creates a UA rule when opted in.

        This is the core regression test for #68/#69: it MUST fail against
        the unmodified detector, since the old code has no UA-creation path
        at all and the subnet path's count < 2 floor drops every one of
        these single-IP subnets.
        """
        import django_waf.conf as conf_mod

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20
        assert min_ips < self.RESIDENTIAL_SPRAY_IP_COUNT

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        assert len(ua_rules) == 1
        assert ua_rules[0].pattern == shared_ua

    def test_residential_spray_creates_no_ua_rule_when_toggle_off(self):
        """Same fixture, default toggle (off): no UA rule, no behaviour change on upgrade."""
        import django_waf.conf as conf_mod

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_cloud_spray(window_minutes=30)

        assert created == []

    def test_ua_rule_action_is_challenge_not_block(self):
        import django_waf.conf as conf_mod

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        assert len(ua_rules) == 1
        assert ua_rules[0].action == RuleAction.CHALLENGE

    def test_ua_rule_carries_detector_provenance(self):
        import django_waf.conf as conf_mod

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        assert len(ua_rules) == 1
        assert ua_rules[0].detectors == "detect_cloud_spray"

    def test_ua_rule_absent_from_for_nginx_export(self):
        """A CHALLENGE UA rule is middleware-only, never exported to nginx (BR-BL-005)."""
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        assert len(ua_rules) == 1
        assert not BlockRule.objects.for_nginx().filter(pk=ua_rules[0].pk).exists()

    def test_top_n_cap_is_configurable_not_hardcoded(self):
        """DJANGO_WAF_CLOUD_SPRAY_TOP_N replaces the old hardcoded [:5] cap.

        Six distinct spray UAs each individually clear MIN_IPS, each with a
        different distinct-IP count so Step 1's ``order_by("-distinct_ips")``
        ranking is unambiguous. With TOP_N patched to 2, only the top 2 UAs
        are considered at all, so with the UA path enabled at most 2 UA
        rules can be created even though six UAs qualify.
        """
        import django_waf.conf as conf_mod

        now = timezone.now()
        min_ips = 5
        num_uas = 6

        for ua_index in range(num_uas):
            # Distinct, strictly descending IP counts: ua 0 has the most
            # distinct IPs, ua 5 the fewest, so the top-N ranking is exact.
            ip_count_for_this_ua = min_ips + (num_uas - ua_index)
            for ip_index in range(ip_count_for_this_ua):
                RequestLogFactory(
                    ip_address=f"203.{ua_index}.{ip_index}.7",
                    user_agent=f"spray-agent-{ua_index}",
                    referer="",
                    timestamp=now,
                )

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 1),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_TOP_N", 2),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        flagged_uas = {rule.pattern for rule in ua_rules}
        assert flagged_uas == {"spray-agent-0", "spray-agent-1"}

    def test_dry_run_creates_no_rows(self):
        """dry_run=True (BR-ANOM-006) writes nothing; check _state.adding, not pk.

        BlockRule.id is a UUIDField with default=uuid.uuid4, so pk is
        always populated even on an unsaved instance; _state.adding is the
        only reliable signal that a row was never written.
        """
        import django_waf.conf as conf_mod
        from django_waf.models import BlockRule

        shared_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0"
        min_ips = 20

        self._create_residential_spray_fixture(shared_ua)

        with (
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", min_ips),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3),
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_CLOUD_SPRAY_UA_RULE", True),
        ):
            created = detect_cloud_spray(window_minutes=30, dry_run=True)

        ua_rules = [rule for rule in created if rule.rule_type == RuleType.UA]
        assert len(ua_rules) == 1
        assert ua_rules[0]._state.adding is True
        assert not BlockRule.objects.filter(rule_type=RuleType.UA, pattern=shared_ua).exists()
