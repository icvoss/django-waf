"""Tests for rule expiry enforcement (#25).

Covers three layers:
  - Manager querysets (BlockRuleManager.active/expired, AllowRuleManager.active/expired)
    exclude/include passed expires_at correctly.
  - Rule-cache evaluation (_check_block_rules/_check_allow_rules) rejects an
    expired rule even when served from a cache built before the rule expired.
  - The expire_rules task deactivates both BlockRules and AllowRules and
    invalidates the rule cache.

Redis is not available in the test environment; all Redis calls are mocked
using unittest.mock, matching the pattern in test_services.py and test_tasks.py.
"""

from __future__ import annotations

import time
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from django_waf.enums import RuleAction, RuleType, Verdict
from django_waf.models import AllowRule, BlockRule
from django_waf.services.rule_engine import RuleCache, _check_allow_rules, _check_block_rules, evaluate_request
from django_waf.testing.factories import AllowRuleFactory, BlockRuleFactory


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
    (see tests/test_retry_after.py) — zcard_return sits at index 2, and a
    single (member, score) zrange result sits at index 3.
    """
    pipeline = MagicMock()
    now = time.time()
    pipeline.execute.return_value = [1, 0, zcard_return, [(str(now), now)], True]
    return pipeline


# ---------------------------------------------------------------------------
# BlockRuleManager.active() / .expired()
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestBlockRuleManagerExpiry:
    def test_active_excludes_expired_rule(self):
        """An active=True BlockRule with a passed expires_at is excluded from .active()."""
        BlockRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(hours=1))

        assert BlockRule.objects.active().count() == 0

    def test_active_includes_rule_with_no_expiry(self):
        """A BlockRule with expires_at=None is never excluded by expiry."""
        rule = BlockRuleFactory(is_active=True, expires_at=None)

        assert list(BlockRule.objects.active()) == [rule]

    def test_active_includes_rule_with_future_expiry(self):
        """A BlockRule whose expires_at is still in the future remains active."""
        rule = BlockRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))

        assert list(BlockRule.objects.active()) == [rule]

    def test_expired_returns_only_passed_expiry(self):
        """.expired() returns only active rules whose expires_at has passed."""
        expired = BlockRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(minutes=1))
        BlockRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))
        BlockRuleFactory(is_active=True, expires_at=None)

        assert list(BlockRule.objects.expired()) == [expired]


# ---------------------------------------------------------------------------
# AllowRuleManager.active() / .expired()
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAllowRuleManagerExpiry:
    def test_active_excludes_expired_rule(self):
        """An active=True AllowRule with a passed expires_at is excluded from .active()."""
        AllowRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(hours=1))

        assert AllowRule.objects.active().count() == 0

    def test_active_includes_rule_with_no_expiry(self):
        """An AllowRule with expires_at=None is never excluded by expiry."""
        rule = AllowRuleFactory(is_active=True, expires_at=None)

        assert list(AllowRule.objects.active()) == [rule]

    def test_active_includes_rule_with_future_expiry(self):
        """An AllowRule whose expires_at is still in the future remains active."""
        rule = AllowRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))

        assert list(AllowRule.objects.active()) == [rule]

    def test_expired_returns_only_passed_expiry(self):
        """.expired() returns only active AllowRules whose expires_at has passed."""
        expired = AllowRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(minutes=1))
        AllowRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))
        AllowRuleFactory(is_active=True, expires_at=None)

        assert list(AllowRule.objects.expired()) == [expired]

    def test_inactive_expired_rule_not_returned(self):
        """.expired() only returns rules that are still is_active=True."""
        AllowRuleFactory(is_active=False, expires_at=timezone.now() - timedelta(hours=1))

        assert AllowRule.objects.expired().count() == 0


# ---------------------------------------------------------------------------
# Cache-level enforcement — a rule that expired after the cache was built
# must never match, even without a cache rebuild (#25).
# ---------------------------------------------------------------------------


class TestExpiredRuleRejectedAtCacheEvaluation:
    def test_expired_block_rule_in_stale_cache_does_not_match(self):
        """A BlockRule cached before it expired is rejected at match time."""
        expired_dict = {
            "id": "00000000-0000-0000-0000-000000000010",
            "rule_type": RuleType.IP,
            "match_type": "exact",
            "pattern": "9.9.9.9",
            "action": RuleAction.BLOCK,
            "priority": 100,
            "expires_at": (timezone.now() - timedelta(minutes=5)).isoformat(),
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[expired_dict], ua_regex_set=[])

        result = _check_block_rules("9.9.9.9", "Mozilla/5.0", cache)

        assert result is None

    def test_non_expired_block_rule_in_cache_still_matches(self):
        """A BlockRule with a future expires_at still matches normally."""
        future_dict = {
            "id": "00000000-0000-0000-0000-000000000011",
            "rule_type": RuleType.IP,
            "match_type": "exact",
            "pattern": "9.9.9.8",
            "action": RuleAction.BLOCK,
            "priority": 100,
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[future_dict], ua_regex_set=[])

        result = _check_block_rules("9.9.9.8", "Mozilla/5.0", cache)

        assert result is not None
        assert result[0] == future_dict["id"]

    def test_block_rule_without_expires_at_key_still_matches(self):
        """A cached rule dict with no expires_at key (old cache payload) is never treated as expired."""
        no_expiry_dict = {
            "id": "00000000-0000-0000-0000-000000000012",
            "rule_type": RuleType.IP,
            "match_type": "exact",
            "pattern": "9.9.9.7",
            "action": RuleAction.BLOCK,
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[no_expiry_dict], ua_regex_set=[])

        result = _check_block_rules("9.9.9.7", "Mozilla/5.0", cache)

        assert result is not None

    def test_expired_allow_rule_in_stale_cache_does_not_match(self):
        """An AllowRule cached before it expired is rejected at match time."""
        expired_dict = {
            "id": "00000000-0000-0000-0000-000000000020",
            "rule_type": RuleType.IP,
            "match_type": "exact",
            "pattern": "8.8.8.8",
            "verify_rdns": False,
            "rdns_pattern": "",
            "expires_at": (timezone.now() - timedelta(minutes=5)).isoformat(),
        }
        cache = RuleCache(version=1, allow_rules=[expired_dict], block_rules=[], ua_regex_set=[])
        redis = _make_redis()

        result = _check_allow_rules("8.8.8.8", "Mozilla/5.0", cache, redis)

        assert result is None

    def test_non_expired_allow_rule_in_cache_still_matches(self):
        """An AllowRule with a future expires_at still matches normally."""
        future_dict = {
            "id": "00000000-0000-0000-0000-000000000021",
            "rule_type": RuleType.IP,
            "match_type": "exact",
            "pattern": "8.8.8.7",
            "verify_rdns": False,
            "rdns_pattern": "",
            "expires_at": (timezone.now() + timedelta(hours=1)).isoformat(),
        }
        cache = RuleCache(version=1, allow_rules=[future_dict], block_rules=[], ua_regex_set=[])
        redis = _make_redis()

        result = _check_allow_rules("8.8.8.7", "Mozilla/5.0", cache, redis)

        assert result is not None
        assert result[0] == future_dict["id"]


# ---------------------------------------------------------------------------
# End-to-end via evaluate_request — an expired crawler AllowRule must not
# bypass evaluation, and an expired BlockRule must not be enforced.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEvaluateRequestExpiryEndToEnd:
    def test_expired_allow_rule_does_not_bypass_evaluation(self):
        """An expired AllowRule is excluded from the rebuilt cache, so the
        request falls through to normal (allowed) evaluation rather than
        an automatic PASSED verdict."""
        AllowRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="7.7.7.7",
            expires_at=timezone.now() - timedelta(hours=1),
        )

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5

        result = evaluate_request(
            ip_address="7.7.7.7",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict != Verdict.PASSED

    def test_expired_block_rule_does_not_block(self):
        """An expired BlockRule is excluded from the rebuilt cache, so the
        request is not blocked by it."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="6.6.6.6",
            action=RuleAction.BLOCK,
            expires_at=timezone.now() - timedelta(hours=1),
        )

        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5

        result = evaluate_request(
            ip_address="6.6.6.6",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict != Verdict.BLOCKED


# ---------------------------------------------------------------------------
# expire_rules task — deactivates both models, invalidates the cache.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestExpireRulesDeactivatesBothModels:
    def test_deactivates_expired_block_and_allow_rules(self):
        """expire_rules deactivates expired rows in both BlockRule and AllowRule."""
        expired_block = BlockRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(hours=1))
        expired_allow = AllowRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(hours=1))
        active_block = BlockRuleFactory(is_active=True, expires_at=timezone.now() + timedelta(days=1))
        active_allow = AllowRuleFactory(is_active=True, expires_at=None)

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            result = expire_rules()

        expired_block.refresh_from_db()
        expired_allow.refresh_from_db()
        active_block.refresh_from_db()
        active_allow.refresh_from_db()

        assert expired_block.is_active is False
        assert expired_allow.is_active is False
        assert active_block.is_active is True
        assert active_allow.is_active is True
        assert result["expired_block_count"] == 1
        assert result["expired_allow_count"] == 1
        assert result["expired_count"] == 2

    def test_invalidates_cache_when_only_allow_rule_expires(self):
        """Cache invalidation fires even when only an AllowRule (no BlockRule) expired."""
        AllowRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(minutes=1))

        with patch("django_waf.tasks._invalidate_rule_cache_redis") as mock_inval:
            from django_waf.tasks import expire_rules

            expire_rules()

        mock_inval.assert_called_once()

    def test_no_invalidation_when_nothing_expired(self):
        """Cache invalidation is skipped when neither model has an expired row."""
        BlockRuleFactory(is_active=True, expires_at=None)
        AllowRuleFactory(is_active=True, expires_at=None)

        with patch("django_waf.tasks._invalidate_rule_cache_redis") as mock_inval:
            from django_waf.tasks import expire_rules

            result = expire_rules()

        mock_inval.assert_not_called()
        assert result["expired_count"] == 0

    def test_non_expiring_rules_unaffected(self):
        """Rules with expires_at=None are never touched by expire_rules."""
        block = BlockRuleFactory(is_active=True, expires_at=None)
        allow = AllowRuleFactory(is_active=True, expires_at=None)

        with patch("django_waf.tasks._invalidate_rule_cache_redis"):
            from django_waf.tasks import expire_rules

            expire_rules()

        block.refresh_from_db()
        allow.refresh_from_db()
        assert block.is_active is True
        assert allow.is_active is True
