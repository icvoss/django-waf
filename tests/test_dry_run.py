"""Tests for anomaly-detection dry-run non-mutation (#38).

Verified defect: ``django_waf_detect_anomalies --dry-run`` called
``run_all_detectors()`` unconditionally, which created and activated real
BlockRules despite the command output claiming "would create". These tests
cover the command, the service layer, and the underlying helper that used
to always write.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.utils import timezone

from django_waf.enums import RuleAction, RuleSource, RuleType
from django_waf.testing.factories import BlockRuleFactory, RequestLogFactory

# ---------------------------------------------------------------------------
# _get_or_create_auto_rule — the shared write path
# ---------------------------------------------------------------------------


class TestGetOrCreateAutoRuleDryRun:
    def test_dry_run_does_not_write_a_new_rule(self, db):
        """dry_run=True returns an unsaved rule and creates zero BlockRule rows."""
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import _get_or_create_auto_rule

        before = BlockRule.objects.count()

        rule, created = _get_or_create_auto_rule(
            name="Auto: dry-run test",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="198.51.100.7",
            action=RuleAction.CHALLENGE,
            expiry=timezone.now() + timezone.timedelta(hours=24),
            dry_run=True,
        )

        assert created is True
        # BlockRule.id is a UUIDField(default=uuid.uuid4): Django evaluates
        # that default at __init__, so an unsaved instance already carries a
        # generated pk. "Unsaved" is proven by _state.adding (True until the
        # first save()) and by the row count below, not by pk being None.
        assert rule._state.adding is True
        assert BlockRule.objects.count() == before

    def test_dry_run_reports_created_false_when_rule_already_exists(self, db):
        """dry_run=True reports created=False for a pattern that already has an active auto rule.

        Mirrors real-run update_or_create semantics: a matching rule already
        exists, so a real run would refresh it (created=False), not create a
        new one.
        """
        from django_waf.services.anomaly_detector import _get_or_create_auto_rule

        existing = BlockRuleFactory(
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="198.51.100.8",
            action=RuleAction.CHALLENGE,
            source=RuleSource.AUTO,
        )

        rule, created = _get_or_create_auto_rule(
            name="Auto: dry-run test",
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="198.51.100.8",
            action=RuleAction.CHALLENGE,
            expiry=timezone.now() + timezone.timedelta(hours=24),
            dry_run=True,
        )

        assert created is False
        assert rule.pk == existing.pk


# ---------------------------------------------------------------------------
# run_all_detectors — dry-run end to end
# ---------------------------------------------------------------------------


class TestRunAllDetectorsDryRun:
    def test_dry_run_creates_zero_block_rules(self, db):
        """run_all_detectors(dry_run=True) makes zero BlockRule writes end to end."""
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import run_all_detectors

        ip = "203.0.113.50"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        before = BlockRule.objects.count()

        result = run_all_detectors(window_minutes=10, dry_run=True)

        assert BlockRule.objects.count() == before
        assert result["ua_rotation_rules"] >= 1
        assert result["total_rules_created"] >= 1

    def test_normal_run_still_creates_rules(self, db):
        """Without dry_run, run_all_detectors creates rules exactly as before (#38 regression guard)."""
        from django_waf.models import BlockRule
        from django_waf.services.anomaly_detector import run_all_detectors

        ip = "203.0.113.51"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        before = BlockRule.objects.count()

        result = run_all_detectors(window_minutes=10, dry_run=False)

        assert BlockRule.objects.count() > before
        assert result["total_rules_created"] >= 1
        assert BlockRule.objects.filter(pattern=ip, is_active=True).exists()

    def test_dry_run_does_not_emit_anomaly_signal(self, db):
        """dry_run=True does not fire anomaly_detected (no persisting side effects)."""
        from django_waf.services.anomaly_detector import run_all_detectors

        ip = "203.0.113.52"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        with patch("django_waf.signals.anomaly_detected.send") as mock_send:
            run_all_detectors(window_minutes=10, dry_run=True)

        mock_send.assert_not_called()


# ---------------------------------------------------------------------------
# django_waf_detect_anomalies command — dry-run end to end (no mocking)
# ---------------------------------------------------------------------------


class TestDetectAnomaliesCommandDryRunEndToEnd:
    @pytest.mark.django_db
    def test_dry_run_creates_zero_rules_against_real_service(self):
        """--dry-run against the real (unmocked) service creates zero BlockRule rows."""
        from django_waf.models import BlockRule

        ip = "203.0.113.60"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        before = BlockRule.objects.count()

        out = StringIO()
        call_command("django_waf_detect_anomalies", "--dry-run", "--window-minutes=10", stdout=out)

        assert BlockRule.objects.count() == before
        assert "would create" in out.getvalue()

    @pytest.mark.django_db
    def test_without_dry_run_creates_rules_against_real_service(self):
        """Without --dry-run, the command still creates real BlockRule rows as before."""
        from django_waf.models import BlockRule

        ip = "203.0.113.61"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        before = BlockRule.objects.count()

        out = StringIO()
        call_command("django_waf_detect_anomalies", "--window-minutes=10", stdout=out)

        assert BlockRule.objects.count() > before
        assert BlockRule.objects.filter(pattern=ip, is_active=True).exists()
