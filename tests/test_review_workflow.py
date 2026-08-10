"""Tests for the approve-before-enforce review workflow (issues #45-#48).

Covers BR-ANOM-007 through BR-ANOM-010 and their acceptance criteria
(AC-ANOM-005 through AC-ANOM-013) in docs/specs/django-waf/05-verification.md:

  - AC-ANOM-005/006: quarantine on/off controls is_active/review_status at
    creation, and a quarantined rule does not enforce.
  - AC-ANOM-007/008: an operator's CONFIRMED/REJECTED decision survives a
    later re-detection of the same pattern.
  - AC-ANOM-009/010: DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS forces
    quarantine for a listed detector only, and composes with dry-run.
  - AC-ANOM-011/012: confidence and notes carry the detection evidence.
  - AC-ANOM-013: expire_rules marks a still-PENDING rule EXPIRED_UNREVIEWED
    regardless of is_active.

Redis is mocked in every evaluate_request call, matching the pattern in
test_services.py and test_rule_expiry.py.
"""

from __future__ import annotations

import time
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone

from django_waf.enums import ReviewStatus, RuleSource, RuleType, Verdict
from django_waf.models import BlockRule
from django_waf.services.rule_engine import evaluate_request
from django_waf.testing.factories import BlockRuleFactory, RequestLogFactory

User = get_user_model()

pytestmark = pytest.mark.django_db


def _make_redis() -> MagicMock:
    """Return a MagicMock configured as a minimal Redis client."""
    redis = MagicMock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 1
    redis.incr.return_value = 1
    redis.zcount.return_value = 0
    return redis


def _make_pipeline_mock(zcard_return: int) -> MagicMock:
    """Return a pipeline mock for [zadd, zremrangebyscore, zcard, zrange, expire]."""
    pipeline = MagicMock()
    now = time.time()
    pipeline.execute.return_value = [1, 0, zcard_return, [(str(now), now)], True]
    return pipeline


def _seed_rotating_ip(ip: str, count: int = 25) -> None:
    """Create enough distinct-UA RequestLogs from ``ip`` to trip detect_ua_rotation
    against the default threshold (20)."""
    now = timezone.now()
    for i in range(count):
        RequestLogFactory(ip_address=ip, user_agent=f"Agent-{ip}-{i}/1.0", timestamp=now)


def _make_superuser(username: str) -> User:
    return User.objects.create_user(
        username=username,
        email=f"{username}@example.com",
        password="pass",
        is_staff=True,
        is_superuser=True,
    )


# ---------------------------------------------------------------------------
# AC-ANOM-005 / AC-ANOM-006: quarantine on/off at creation
# ---------------------------------------------------------------------------


class TestQuarantineAutoRulesSetting:
    def test_quarantine_on_creates_inactive_pending_rule_that_does_not_enforce(self):
        """AC-ANOM-005: quarantine ON creates is_active=False/PENDING, and the
        rule engine does not challenge the offending IP while quarantined."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        ip = "203.0.113.10"
        _seed_rotating_ip(ip)

        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
        ):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert len(created) == 1
        rule = created[0]
        assert rule.is_active is False
        assert rule.review_status == ReviewStatus.PENDING

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5
        result = evaluate_request(
            ip_address=ip,
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        # The quarantined rule is not active, so BlockRuleManager.active()
        # excludes it: evaluation falls through to ALLOWED, never CHALLENGED.
        assert result.verdict != Verdict.CHALLENGED
        assert result.verdict == Verdict.ALLOWED

    def test_quarantine_off_default_matches_pre_change_behaviour(self):
        """AC-ANOM-006: quarantine OFF (default) creates is_active=True/NOT_APPLICABLE."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        ip = "203.0.113.11"
        _seed_rotating_ip(ip)

        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", False),
        ):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert len(created) == 1
        rule = created[0]
        assert rule.is_active is True
        assert rule.review_status == ReviewStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# AC-ANOM-007 / AC-ANOM-008: re-detection must not undo an operator decision
# ---------------------------------------------------------------------------


class TestReDetectionSurvivesReviewDecision:
    def test_confirmed_rule_stays_active_and_confirmed_on_redetection(self, client: Client, settings):
        """AC-ANOM-007: a rule confirmed via DashboardAnomalyConfirmView keeps
        is_active=True/CONFIRMED when the same pattern is re-detected; only
        expires_at may refresh.

        Reaches CONFIRMED via the real confirm view (not a hand-set factory
        field), then triggers a real detector re-run to prove the guard.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        settings.ROOT_URLCONF = "tests.urls"
        superuser = _make_superuser("confirmer")
        client.force_login(superuser)

        ip = "203.0.113.12"
        _seed_rotating_ip(ip)

        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
        ):
            created = detect_ua_rotation(window_minutes=10, threshold=20)
        assert len(created) == 1
        rule_id = created[0].pk

        response = client.post(f"/waf/dashboard/anomalies/{rule_id}/confirm/")
        assert response.status_code == 200

        rule = BlockRule.objects.get(pk=rule_id)
        assert rule.review_status == ReviewStatus.CONFIRMED
        assert rule.is_active is True
        original_expires_at = rule.expires_at

        # Confirming promotes source to ADMIN (existing pre-#47 behaviour),
        # so a real re-detection no longer matches this row via the
        # source=AUTO lookup key and instead creates a fresh AUTO rule for
        # the same IP. The guard under test is that the confirmed row
        # itself is left untouched by that re-run.
        _seed_rotating_ip(ip)
        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 48),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
        ):
            detect_ua_rotation(window_minutes=10, threshold=20)

        rule.refresh_from_db()
        assert rule.is_active is True
        assert rule.review_status == ReviewStatus.CONFIRMED
        assert rule.source == RuleSource.ADMIN
        assert rule.expires_at == original_expires_at

    def test_rejected_rule_stays_inactive_and_rejected_on_redetection(self, client: Client, settings):
        """AC-ANOM-008: a rule rejected via DashboardAnomalyRejectView keeps
        is_active=False/REJECTED when the same (rule_type, pattern, source=AUTO,
        action) is re-detected. Critical regression guard: a detector must
        never silently re-enable a rule an operator has already rejected.

        Reaches REJECTED via the real reject view, then triggers a real
        detector re-run against the same key fields to prove the guard.
        """
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        settings.ROOT_URLCONF = "tests.urls"
        superuser = _make_superuser("rejecter")
        client.force_login(superuser)

        ip = "203.0.113.13"
        _seed_rotating_ip(ip)

        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
        ):
            created = detect_ua_rotation(window_minutes=10, threshold=20)
        assert len(created) == 1
        rule_id = created[0].pk

        response = client.post(f"/waf/dashboard/anomalies/{rule_id}/reject/")
        assert response.status_code == 200

        rule = BlockRule.objects.get(pk=rule_id)
        assert rule.review_status == ReviewStatus.REJECTED
        assert rule.is_active is False
        # Rejection (unlike confirm) does not change source or pattern, so
        # this row remains the exact match key a re-detection would hit.
        assert rule.source == RuleSource.AUTO

        _seed_rotating_ip(ip)
        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 48),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", True),
        ):
            detect_ua_rotation(window_minutes=10, threshold=20)

        rule.refresh_from_db()
        assert rule.is_active is False
        assert rule.review_status == ReviewStatus.REJECTED

        # The detector must not silently re-enable the rejected rule via the
        # rule engine either.
        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5
        result = evaluate_request(
            ip_address=ip,
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )
        assert result.verdict != Verdict.CHALLENGED


# ---------------------------------------------------------------------------
# AC-ANOM-009 / AC-ANOM-010: observe-only detectors
# ---------------------------------------------------------------------------


class TestObserveOnlyDetectors:
    def test_observe_only_detector_is_quarantined_others_are_not(self):
        """AC-ANOM-009: DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS=["detect_cloud_spray"]
        with quarantine OFF quarantines a detect_cloud_spray rule, while a
        detect_ua_rotation rule created in the same run is not quarantined."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import run_all_detectors

        rotation_ip = "203.0.113.20"
        _seed_rotating_ip(rotation_ip)

        # Cloud-spray: one UA shared by >= min_ips distinct IPs, each making
        # few requests with no referer.
        now = timezone.now()
        ua = "SprayBot/1.0"
        min_ips = conf_mod.DJANGO_WAF_CLOUD_SPRAY_MIN_IPS
        for i in range(min_ips + 2):
            RequestLogFactory(
                ip_address=f"198.51.100.{i}",
                user_agent=ua,
                referer="",
                timestamp=now,
            )

        with (
            patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", False),
            patch.object(conf_mod, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", ["detect_cloud_spray"]),
        ):
            result = run_all_detectors(window_minutes=30)

        assert result["cloud_spray_rules"] >= 1
        assert result["ua_rotation_rules"] >= 1

        spray_rule = BlockRule.objects.filter(rule_type=RuleType.CIDR, source=RuleSource.AUTO).first()
        rotation_rule = BlockRule.objects.filter(pattern=rotation_ip, source=RuleSource.AUTO).first()

        assert spray_rule is not None
        assert spray_rule.is_active is False
        assert spray_rule.review_status == ReviewStatus.PENDING

        assert rotation_rule is not None
        assert rotation_rule.is_active is True
        assert rotation_rule.review_status == ReviewStatus.NOT_APPLICABLE

    def test_dry_run_wins_over_observe_only(self):
        """AC-ANOM-010: dry_run=True suppresses all writes even for a detector
        listed in DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import run_all_detectors

        now = timezone.now()
        ua = "SprayBotDryRun/1.0"
        min_ips = conf_mod.DJANGO_WAF_CLOUD_SPRAY_MIN_IPS
        for i in range(min_ips + 2):
            RequestLogFactory(
                ip_address=f"198.51.101.{i}",
                user_agent=ua,
                referer="",
                timestamp=now,
            )

        before = BlockRule.objects.count()

        with patch.object(conf_mod, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", ["detect_cloud_spray"]):
            run_all_detectors(window_minutes=30, dry_run=True)

        assert BlockRule.objects.count() == before


# ---------------------------------------------------------------------------
# AC-ANOM-011 / AC-ANOM-012: confidence and notes carry detection evidence
# ---------------------------------------------------------------------------


class TestConfidenceAndNotesEvidence:
    def test_confidence_between_half_and_one_and_notes_contain_evidence(self):
        """AC-ANOM-011: 21 distinct UAs against a threshold of 20 produces
        confidence in (0.5, 1.00) and notes containing the distinct UA count
        and the window in minutes."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        ip = "203.0.113.30"
        now = timezone.now()
        for i in range(21):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert len(created) == 1
        rule = created[0]
        assert rule.confidence > Decimal("0.5")
        assert rule.confidence < Decimal("1.00")
        assert "21" in rule.notes
        assert "10" in rule.notes

    def test_wider_margin_yields_strictly_greater_confidence_neither_reaches_99(self):
        """AC-ANOM-012: a wide-margin detection has strictly greater confidence
        than a barely-clears detection, and neither reaches 0.99."""
        import django_waf.conf as conf_mod
        from django_waf.services.anomaly_detector import detect_ua_rotation

        barely_ip = "203.0.113.31"
        wide_ip = "203.0.113.32"
        now = timezone.now()
        # Threshold is 20 (distinct_ua_count__gt=20): 21 barely clears it,
        # 60 clears it by a wide margin.
        for i in range(21):
            RequestLogFactory(ip_address=barely_ip, user_agent=f"Barely-{i}/1.0", timestamp=now)
        for i in range(60):
            RequestLogFactory(ip_address=wide_ip, user_agent=f"Wide-{i}/1.0", timestamp=now)

        with patch.object(conf_mod, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        by_ip = {rule.pattern: rule for rule in created}
        barely_rule = by_ip[barely_ip]
        wide_rule = by_ip[wide_ip]

        assert wide_rule.confidence > barely_rule.confidence
        assert barely_rule.confidence < Decimal("0.99")
        assert wide_rule.confidence < Decimal("0.99")


# ---------------------------------------------------------------------------
# AC-ANOM-013: expire_rules marks a still-PENDING rule EXPIRED_UNREVIEWED
# ---------------------------------------------------------------------------


class TestExpireRulesMarksUnreviewedRules:
    @pytest.mark.parametrize("initial_is_active", [True, False])
    def test_pending_rule_past_expiry_becomes_expired_unreviewed(self, initial_is_active):
        """AC-ANOM-013: a PENDING auto rule whose expires_at has passed
        becomes EXPIRED_UNREVIEWED when expire_rules runs, for both
        is_active starting states, and is counted in the expired_unreviewed
        aggregate bucket immediately afterwards."""
        from django_waf.services.anomaly_detector import auto_rule_review_outcomes

        rule = BlockRuleFactory(
            source=RuleSource.AUTO,
            review_status=ReviewStatus.PENDING,
            is_active=initial_is_active,
            expires_at=timezone.now() - timedelta(hours=1),
        )

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        rule.refresh_from_db()
        assert rule.review_status == ReviewStatus.EXPIRED_UNREVIEWED
        assert rule.is_active is False
        assert result["expired_unreviewed_count"] == 1

        outcomes = auto_rule_review_outcomes()
        assert outcomes["expired_unreviewed"] == 1
        assert outcomes["pending"] == 0


# ---------------------------------------------------------------------------
# auto_rule_review_outcomes: bucket shape
# ---------------------------------------------------------------------------


class TestAutoRuleReviewOutcomes:
    def test_all_buckets_present_and_zero_filled_when_no_rows(self):
        from django_waf.services.anomaly_detector import auto_rule_review_outcomes

        outcomes = auto_rule_review_outcomes()

        assert outcomes == {
            "pending": 0,
            "confirmed": 0,
            "rejected": 0,
            "expired_unreviewed": 0,
            "not_applicable": 0,
            "total": 0,
        }

    def test_not_applicable_is_its_own_bucket_not_counted_as_pending(self):
        """A NOT_APPLICABLE auto rule (quarantine off, never queued for review)
        must not be folded into the pending bucket."""
        from django_waf.services.anomaly_detector import auto_rule_review_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, review_status=ReviewStatus.NOT_APPLICABLE)
        BlockRuleFactory(source=RuleSource.AUTO, review_status=ReviewStatus.PENDING)

        outcomes = auto_rule_review_outcomes()

        assert outcomes["not_applicable"] == 1
        assert outcomes["pending"] == 1
        assert outcomes["total"] == 2

    def test_admin_source_rules_excluded_from_outcomes(self):
        """The outcome metric is scoped to source=AUTO rows only."""
        from django_waf.services.anomaly_detector import auto_rule_review_outcomes

        BlockRuleFactory(source=RuleSource.ADMIN, review_status=ReviewStatus.NOT_APPLICABLE)

        outcomes = auto_rule_review_outcomes()

        assert outcomes["total"] == 0
