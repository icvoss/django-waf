"""Tests for django_waf.conf default values.

Focused on settings whose defaults carry operational meaning (the threat-feed
URLs point at a real operated server; telemetry stays opt-in) rather than
exhaustively re-asserting every setting in the module.
"""

from __future__ import annotations

import django_waf.conf as conf_mod


class TestThreatFeedDefaults:
    """DJANGO_WAF_FEED_* defaults point at the operated feed server.

    Regression: pre-1.1.1 the defaults were ``threats.icv.dev``, a spec
    placeholder that never resolved to an operated service (docs/specs/
    django-waf/06-threat-feed-api.md, section 1). Repointed to the real
    server, threats.drystane.com, so a consuming site only needs to flip
    DJANGO_WAF_FEED_REPORT to start reporting.
    """

    def test_feed_url_default_points_at_drystane(self):
        assert conf_mod.DJANGO_WAF_FEED_URL == "https://threats.drystane.com/v1/feed.json"

    def test_feed_report_url_default_points_at_drystane(self):
        assert conf_mod.DJANGO_WAF_FEED_REPORT_URL == "https://threats.drystane.com/v1/report"

    def test_feed_url_default_is_not_the_retired_icv_dev_placeholder(self):
        assert "threats.icv.dev" not in conf_mod.DJANGO_WAF_FEED_URL

    def test_feed_report_url_default_is_not_the_retired_icv_dev_placeholder(self):
        assert "threats.icv.dev" not in conf_mod.DJANGO_WAF_FEED_REPORT_URL

    def test_feed_report_still_defaults_false(self):
        """Telemetry stays opt-in regardless of the URL repoint (ADR-021 point 4)."""
        assert conf_mod.DJANGO_WAF_FEED_REPORT is False
