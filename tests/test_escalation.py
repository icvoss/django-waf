"""Tests for challenge-escalation reachability (#27).

Prior to this fix, the auto-block-on-unsolved-challenges check sat at the
very end of evaluate_request, after every branch that can return a
CHALLENGED verdict (a rule-driven BlockRule challenge, the no-referer
challenge, and a score-driven challenge). Because each of those branches
returns early, the escalation check was unreachable dead code: a
repeatedly-challenged IP just kept getting challenged forever.

The fix routes every CHALLENGED verdict through a single
``_gate_challenge_or_escalate`` gate before it is returned. These tests
exercise that gate via both a rule-driven and a score-driven challenge
path, confirm a solve resets the counter, and confirm below-threshold
requests still challenge normally.

Redis is not available in the test environment; all Redis calls are mocked
using unittest.mock, matching the pattern in test_services.py.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from django.test import override_settings

from django_waf.enums import RuleAction, RuleSource, RuleType, Verdict
from django_waf.models import BlockRule
from django_waf.services.rule_engine import evaluate_request
from django_waf.testing.factories import BlockRuleFactory


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
    """Return a pipeline mock for [zadd, zremrangebyscore, zcard, zrange, expire].

    Matches the 5-command pipeline shape rate_limiter.py builds since #30
    (see tests/test_retry_after.py), zcard_return sits at index 2, and a
    single (member, score) zrange result sits at index 3.
    """
    pipeline = MagicMock()
    now = time.time()
    pipeline.execute.return_value = [1, 0, zcard_return, [(str(now), now)], True]
    return pipeline


@pytest.mark.django_db
class TestEscalationReachableFromRuleDrivenChallenge:
    """A BlockRule with action=CHALLENGE must escalate to BLOCKED once the
    unsolved-challenge threshold is reached, instead of challenging forever."""

    def test_below_threshold_still_challenges(self):
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="11.11.11.11",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()
        redis.get.side_effect = lambda key: b"9" if key == "waf:challenged:11.11.11.11" else None

        with override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10):
            result = evaluate_request(
                ip_address="11.11.11.11",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.CHALLENGED

    def test_at_threshold_escalates_to_blocked_with_one_auto_rule(self):
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="12.12.12.12",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()
        redis.get.side_effect = lambda key: b"10" if key == "waf:challenged:12.12.12.12" else None

        with override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10, DJANGO_WAF_ESCALATION_BLOCK_TTL=3600):
            result = evaluate_request(
                ip_address="12.12.12.12",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.BLOCKED
        assert result.action == RuleAction.BLOCK
        auto_rules = BlockRule.objects.filter(pattern="12.12.12.12", source=RuleSource.AUTO)
        assert auto_rules.count() == 1
        assert auto_rules.first().expires_at is not None


@pytest.mark.django_db
class TestEscalationReachableFromScoreDrivenChallenge:
    """A score-driven CHALLENGED verdict (no matching rule at all) must also
    escalate once the threshold is reached, the old dead-code placement
    only ever ran after this branch, so it could never fire from here."""

    def test_score_driven_challenge_escalates_at_threshold(self):
        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5

        def _get(key):
            if key.startswith("waf:challenged:"):
                return b"10"
            return None

        redis.get.side_effect = _get

        with (
            override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10),
            patch("django_waf.conf.DJANGO_WAF_CHALLENGE_NO_REFERER", True),
            patch("django_waf.conf.DJANGO_WAF_NO_REFERER_EXEMPT_PATHS", []),
        ):
            result = evaluate_request(
                ip_address="13.13.13.13",
                user_agent="Mozilla/5.0",
                path="/some-page/",
                method="GET",
                redis_client=redis,
                referer="",
            )

        assert result.verdict == Verdict.BLOCKED
        auto_rules = BlockRule.objects.filter(pattern="13.13.13.13", source=RuleSource.AUTO)
        assert auto_rules.count() == 1


@pytest.mark.django_db
class TestSolveResetsEscalationCounter:
    """Confirm the existing solve flow (VerifyView.post, not
    challenge_service.py) resets waf:challenged:{ip} so escalation does
    not fire on the next request after a successful solve.

    Follows the same patch targets, Client usage, and ROOT_URLCONF override
    as tests/test_views.py::TestVerifyView, since VerifyView imports
    verify_challenge_solution and issue_pass_cookie lazily from
    django_waf.services.challenge_service inside the method body.
    """

    @pytest.fixture(autouse=True)
    def waf_urls(self, settings):
        settings.ROOT_URLCONF = "tests.urls"

    def test_verify_view_deletes_challenged_counter_on_solve(self, settings):
        """VerifyView.post clears waf:challenged:{ip} after a successful
        proof-of-work verification (views.py, not challenge_service.py, the counter reset already lives in the views
        layer where the solve
        is processed, satisfying #27's second requirement without touching
        the sibling-owned challenge_service.py)."""
        from django.test import Client

        settings.DJANGO_WAF_ENABLED = True

        client = Client()
        redis = _make_redis()

        with (
            patch("django_waf.views._get_redis_client") as mock_redis_fn,
            patch("django_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("django_waf.services.challenge_service.issue_pass_cookie"),
        ):
            mock_redis_fn.return_value = redis
            mock_verify.return_value = True

            client.post(
                "/waf/verify/",
                data={"token": "sometoken", "nonce": "somenonce", "next": "/"},
            )

        redis.setex.assert_any_call("waf:solved:127.0.0.1", 86400, "1")
        redis.delete.assert_any_call("waf:challenged:127.0.0.1")


@pytest.mark.django_db
class TestBotFingerprintEscalatesDespiteSolvedChallenges:
    """Core regression for the fix: a bot-fingerprinted client that solves
    every challenge (waf:solved is set) must still reach the escalation
    threshold and get BLOCKED. Fails against the pre-fix code, where a
    solved challenge always cleared waf:challenged:{ip} to 0 regardless of
    fingerprint, so the threshold was never reached (the production
    incident: ~37,700 events, 3,044 CHALLENGED, zero BLOCKED)."""

    def test_bot_fingerprint_solved_challenges_still_escalate_to_blocked(self):
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="20.20.20.20",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()

        def _get(key):
            if key == "waf:challenged:20.20.20.20":
                return b"10"
            if key == "waf:solved:20.20.20.20":
                # Every challenge was solved, at negligible cost on a
                # datacentre CPU for a JS-executing botnet.
                return b"1"
            return None

        redis.get.side_effect = _get

        with (
            override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10, DJANGO_WAF_ESCALATION_BLOCK_TTL=3600),
            patch("django_waf.services.fingerprint.classify_fingerprint", return_value="bot"),
        ):
            result = evaluate_request(
                ip_address="20.20.20.20",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.BLOCKED
        assert result.action == RuleAction.BLOCK
        auto_rules = BlockRule.objects.filter(pattern="20.20.20.20", source=RuleSource.AUTO)
        assert auto_rules.count() == 1
        # The challenged-count key must never have been cleared for a bot
        # fingerprint (other unrelated keys, e.g. the rebuild lock, may
        # still legitimately be deleted elsewhere in the request path).
        deleted_keys = {call.args[0] for call in redis.delete.call_args_list}
        assert "waf:challenged:20.20.20.20" not in deleted_keys


@pytest.mark.django_db
class TestNonBotFingerprintSolveStillClearsCounter:
    """Proves the fix did not break the safety valve for real users: a
    non-bot fingerprint that solves a challenge still has its counter
    cleared and is not escalated, even at what would otherwise be the
    escalation threshold."""

    def test_browser_fingerprint_solved_challenge_is_not_escalated(self):
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="21.21.21.21",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()

        def _get(key):
            if key == "waf:challenged:21.21.21.21":
                return b"10"
            if key == "waf:solved:21.21.21.21":
                return b"1"
            return None

        redis.get.side_effect = _get

        with (
            override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10),
            patch("django_waf.services.fingerprint.classify_fingerprint", return_value="browser"),
        ):
            result = evaluate_request(
                ip_address="21.21.21.21",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.CHALLENGED
        redis.delete.assert_any_call("waf:challenged:21.21.21.21")
        assert not BlockRule.objects.filter(pattern="21.21.21.21", source=RuleSource.AUTO).exists()


@pytest.mark.django_db
class TestEscalationHonoursOperatorReviewDecision:
    """_create_escalation_rule must route through the same CONFIRMED/REJECTED
    review guard every other auto-rule path uses (BR-ANOM-007), not call
    BlockRule.objects.update_or_create directly. Before the fix, escalation
    bypassed the guard entirely and could silently resurrect a rejected rule
    as an active block."""

    def test_rejected_auto_rule_is_not_resurrected_by_escalation(self):
        """An operator-REJECTED rule (is_active=False) stays inactive after
        _create_escalation_rule fires for the same IP. Fails against the old
        direct update_or_create call, which had no review-status guard and
        would flip is_active back to True."""
        from django_waf.enums import ReviewStatus
        from django_waf.services.rule_engine import _create_escalation_rule

        rejected = BlockRuleFactory(
            is_active=False,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="22.22.22.22",
            action=RuleAction.BLOCK,
            source=RuleSource.AUTO,
            review_status=ReviewStatus.REJECTED,
        )

        _create_escalation_rule("22.22.22.22")

        rejected.refresh_from_db()
        assert rejected.is_active is False
        assert rejected.review_status == ReviewStatus.REJECTED
        assert BlockRule.objects.filter(pattern="22.22.22.22", source=RuleSource.AUTO).count() == 1

    def test_confirmed_auto_rule_keeps_review_state_through_escalation(self):
        """An operator-CONFIRMED rule keeps is_active=True/CONFIRMED when the
        same IP re-escalates; only expiry-bearing fields may refresh."""
        from django_waf.enums import ReviewStatus
        from django_waf.services.rule_engine import _create_escalation_rule

        confirmed = BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="23.23.23.23",
            action=RuleAction.BLOCK,
            source=RuleSource.AUTO,
            review_status=ReviewStatus.CONFIRMED,
        )
        original_expires_at = confirmed.expires_at

        _create_escalation_rule("23.23.23.23")

        confirmed.refresh_from_db()
        assert confirmed.is_active is True
        assert confirmed.review_status == ReviewStatus.CONFIRMED
        assert confirmed.expires_at != original_expires_at
        assert BlockRule.objects.filter(pattern="23.23.23.23", source=RuleSource.AUTO).count() == 1


@pytest.mark.django_db
class TestGateHonoursSolvedFlag:
    def test_gate_treats_solved_ip_as_below_threshold(self):
        """Once waf:solved:{ip} is set (by VerifyView on success), the gate's
        own count lookup, via _get_unsolved_challenge_count, returns 0
        even if a stale counter value is still present, so escalation does
        not fire for an IP that has just solved a challenge."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="15.15.15.15",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()

        def _get(key):
            if key == "waf:challenged:15.15.15.15":
                return b"10"
            if key == "waf:solved:15.15.15.15":
                return b"1"
            return None

        redis.get.side_effect = _get

        with override_settings(DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD=10):
            result = evaluate_request(
                ip_address="15.15.15.15",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.CHALLENGED
        redis.delete.assert_any_call("waf:challenged:15.15.15.15")
        assert not BlockRule.objects.filter(pattern="15.15.15.15", source=RuleSource.AUTO).exists()
