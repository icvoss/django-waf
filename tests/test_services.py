"""Tests for icv-waf service functions.

Redis is not available in the test environment; all Redis calls are mocked
using unittest.mock.
"""

from __future__ import annotations

import hashlib
import json
import time
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from icv_waf.enums import (
    ChallengeStatus,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)
from icv_waf.services.challenge_service import (
    ChallengeExpiredError,
    ChallengeInvalidError,
    ChallengeMismatchError,
    issue_challenge,
    issue_pass_cookie,
    validate_pass_cookie,
    verify_challenge_solution,
)
from icv_waf.services.rate_limiter import check_rate_limit
from icv_waf.services.rule_engine import (
    RuleCache,
    evaluate_request,
    load_rule_cache,
)
from icv_waf.services.ua_analyser import classify_ua, score_user_agent
from icv_waf.testing.factories import (
    AllowRuleFactory,
    BlockRuleFactory,
    ChallengeTokenFactory,
    IPReputationFactory,
    RequestLogFactory,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    """Return a pipeline mock whose execute() result has zcard_return at index 2."""
    pipeline = MagicMock()
    pipeline.execute.return_value = [1, 0, zcard_return, True]
    return pipeline


# ---------------------------------------------------------------------------
# score_user_agent
# ---------------------------------------------------------------------------


class TestScoreUserAgent:
    def test_empty_ua_returns_1(self):
        """Empty UA string returns a score of 1.0."""
        assert score_user_agent("") == 1.0

    def test_normal_browser_ua_scores_low(self):
        """A typical browser UA should score 0.0."""
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        assert score_user_agent(ua) == 0.0

    def test_python_requests_scores_high(self):
        """python-requests UA triggers scraper-library weight."""
        score = score_user_agent("python-requests/2.28.1")
        # Scraper lib (2.5) + missing impossible combo, but short (1.0) = at least 2.5
        assert score >= 2.5

    def test_curl_scores_as_scraper(self):
        """curl UA triggers scraper-library weight."""
        score = score_user_agent("curl/7.68.0")
        assert score >= 2.5

    def test_wget_scores_as_scraper(self):
        """Wget UA triggers scraper-library weight."""
        score = score_user_agent("Wget/1.20.3 (linux-gnu)")
        assert score >= 2.5

    def test_ancient_msie_scores_high(self):
        """MSIE 6 browser UA triggers ancient-browser weight."""
        ua = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
        score = score_user_agent(ua)
        assert score >= 2.0

    def test_ancient_firefox_scores_high(self):
        """Firefox/2.x UA triggers ancient-browser weight."""
        ua = "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.9) Gecko/20100101 Firefox/2.0"
        score = score_user_agent(ua)
        assert score >= 2.0

    def test_impossible_ios_windows_combo(self):
        """iPhone + Windows NT is an impossible combination — scores 3.0+."""
        ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) Windows NT 10.0"
        score = score_user_agent(ua)
        assert score >= 3.0

    def test_impossible_android_ios_combo(self):
        """Android + iPhone combination is impossible — scores 3.0+."""
        ua = "Mozilla/5.0 (Android 12; iPhone; U; en-US)"
        score = score_user_agent(ua)
        assert score >= 3.0

    def test_very_short_ua_adds_weight(self):
        """UAs under 15 characters add 1.0 to score."""
        ua = "ShortUA/1"  # 9 chars, no version token → 1.5 (no token) + 1.0 (short)
        score = score_user_agent(ua)
        assert score >= 1.0

    def test_ua_without_version_token_adds_weight(self):
        """UA lacking any 'Word/version' token adds 1.5 to score."""
        ua = "UnknownBrowserWithNoVersionToken"
        score = score_user_agent(ua)
        assert score >= 1.5

    def test_score_capped_at_ten(self):
        """Score is capped at 10.0 regardless of accumulation."""
        # Impossible combo (3) + scraper (2.5) + ancient (2.0) + no token (1.5) + short (1.0) = 10
        ua = "MSIE 6.0 python-requests iPhone Windows NT"
        score = score_user_agent(ua)
        assert score <= 10.0

    def test_googlebot_scores_zero(self):
        """Googlebot's legitimate UA scores 0.0 (no suspicious signals)."""
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        score = score_user_agent(ua)
        assert score == 0.0


# ---------------------------------------------------------------------------
# classify_ua
# ---------------------------------------------------------------------------


class TestClassifyUa:
    def test_empty_ua_is_unknown(self):
        assert classify_ua("") == "unknown"

    def test_googlebot_is_crawler(self):
        ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        assert classify_ua(ua) == "crawler"

    def test_bingbot_is_crawler(self):
        ua = "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        assert classify_ua(ua) == "crawler"

    def test_python_requests_is_library(self):
        assert classify_ua("python-requests/2.28.1") == "library"

    def test_aiohttp_is_library(self):
        assert classify_ua("Python/3.10 aiohttp/3.8.1") == "library"

    def test_curl_is_library(self):
        assert classify_ua("curl/7.68.0") == "library"

    def test_generic_bot_self_identifier(self):
        """UA containing standalone 'bot' keyword is classified as 'bot'."""
        # _RE_BOT uses \bbot\b — requires 'bot' as a standalone word token.
        assert classify_ua("My Custom bot/1.0") == "bot"

    def test_spider_self_identifier(self):
        """UA containing standalone 'spider' keyword is classified as 'bot'."""
        assert classify_ua("Generic spider/2.0") == "bot"

    def test_normal_chrome_is_browser(self):
        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        assert classify_ua(ua) == "browser"

    def test_firefox_is_browser(self):
        ua = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/109.0"
        assert classify_ua(ua) == "browser"

    def test_unknown_ua_returns_unknown(self):
        assert classify_ua("SomethingCompletelyUnrecognised/9.9") == "unknown"


# ---------------------------------------------------------------------------
# check_rate_limit
# ---------------------------------------------------------------------------


class TestCheckRateLimit:
    """Tests for check_rate_limit.

    icv_waf.conf caches settings values at import time, so the pytest
    ``settings`` fixture alone will not affect thresholds read from
    ``conf.ICV_WAF_RATE_LIMIT_*``.  We patch conf module attributes directly.
    """

    def _pipeline_returning(self, zcard_value: int) -> MagicMock:
        pipeline = MagicMock()
        pipeline.execute.return_value = [1, 0, zcard_value, True]
        return pipeline

    def test_within_limits_returns_not_exceeded(self):
        """When all windows are within limits, exceeded is False."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = self._pipeline_returning(1)  # 1 request in every window

        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is False
        assert result.window is None
        assert result.retry_after is None

    def test_burst_exceeded(self):
        """When the 1s burst window is exceeded, result reflects that."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        # First pipeline call (1s window) returns count > burst limit
        redis.pipeline.return_value = self._pipeline_returning(6)

        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "1s"
        assert result.retry_after is not None
        assert result.retry_after >= 1

    def test_per_minute_exceeded(self):
        """When only the 1m window is exceeded, result names that window."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()

        call_count = 0

        def pipeline_side_effect():
            nonlocal call_count
            call_count += 1
            # Return within-limit for 1s, over-limit for 1m
            if call_count == 1:
                return self._pipeline_returning(2)  # 1s — OK
            return self._pipeline_returning(101)  # 1m — exceeded

        redis.pipeline.side_effect = pipeline_side_effect

        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 100),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = check_rate_limit("1.2.3.4", redis)

        assert result.exceeded is True
        assert result.window == "1m"

    def test_pipeline_called_once_per_window_at_most(self):
        """Pipeline is called for each window until one is exceeded."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        redis.pipeline.return_value = self._pipeline_returning(6)  # exceeds burst immediately

        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 5),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            check_rate_limit("1.2.3.4", redis)

        # Only one pipeline should be needed (burst exceeded on first iteration)
        assert redis.pipeline.call_count == 1

    def test_uses_correct_redis_key_per_window(self):
        """Rate limit keys follow the 'waf:rate:{ip}:{window}' format."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        pipeline = MagicMock()
        pipeline.execute.return_value = [1, 0, 1, True]
        redis.pipeline.return_value = pipeline

        ip = "5.5.5.5"
        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 10),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            check_rate_limit(ip, redis)

        # Check that zadd was called with correct keys for all 3 windows
        zadd_calls = pipeline.zadd.call_args_list
        used_keys = {c.args[0] for c in zadd_calls}
        assert f"waf:rate:{ip}:1s" in used_keys
        assert f"waf:rate:{ip}:1m" in used_keys
        assert f"waf:rate:{ip}:5m" in used_keys


# ---------------------------------------------------------------------------
# load_rule_cache
# ---------------------------------------------------------------------------


class TestLoadRuleCache:
    def test_cache_miss_rebuilds_from_db(self, db):
        """When Redis has no cached data, rules are loaded from the database."""
        BlockRuleFactory(is_active=True, rule_type=RuleType.IP)
        AllowRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.return_value = None  # No version, no cached data

        cache = load_rule_cache(redis)

        assert isinstance(cache, RuleCache)
        assert len(cache.block_rules) == 1
        assert len(cache.allow_rules) == 1

    def test_cache_hit_returns_without_db_query(self, db):
        """When Redis has valid cached data, it is used directly (no DB query)."""
        cached_data = json.dumps(
            {
                "allow_rules": [
                    {
                        "id": "00000000-0000-0000-0000-000000000001",
                        "rule_type": "ip",
                        "match_type": "exact",
                        "pattern": "192.168.1.1",
                        "verify_rdns": False,
                        "rdns_pattern": "",
                    },
                ],
                "block_rules": [],
            }
        )

        redis = _make_redis()
        # Return version=5, then cached payload
        redis.get.side_effect = ["5", cached_data.encode()]

        cache = load_rule_cache(redis)

        assert cache.version == 5
        assert len(cache.allow_rules) == 1
        assert cache.allow_rules[0]["pattern"] == "192.168.1.1"
        assert len(cache.block_rules) == 0

    def test_returns_rule_cache_namedtuple(self, db):
        """load_rule_cache always returns a RuleCache namedtuple."""
        redis = _make_redis()

        cache = load_rule_cache(redis)

        assert hasattr(cache, "version")
        assert hasattr(cache, "allow_rules")
        assert hasattr(cache, "block_rules")
        assert hasattr(cache, "ua_regex_set")

    def test_ua_regex_patterns_are_precompiled(self, db):
        """UA-type block rules are compiled into ua_regex_set."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.UA,
            match_type="regex",
            pattern=r"BadBot/\d+",
        )

        redis = _make_redis()
        cache = load_rule_cache(redis)

        assert len(cache.ua_regex_set) == 1
        compiled_re, rule_dict = cache.ua_regex_set[0]
        # Compiled pattern should match a known bad bot string
        assert compiled_re.search("BadBot/2.0")

    def test_inactive_rules_excluded(self, db):
        """Inactive rules are not included in the rebuilt cache."""
        BlockRuleFactory(is_active=True)
        BlockRuleFactory(is_active=False)

        redis = _make_redis()
        cache = load_rule_cache(redis)

        assert len(cache.block_rules) == 1

    def test_corrupt_cache_falls_back_to_db(self, db):
        """Corrupt cached JSON causes a rebuild from the database."""
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.side_effect = ["5", b"not valid json"]  # version=5, then corrupt

        cache = load_rule_cache(redis)

        # Still returns valid cache rebuilt from DB
        assert len(cache.block_rules) == 1


# ---------------------------------------------------------------------------
# evaluate_request
# ---------------------------------------------------------------------------


class TestEvaluateRequest:
    """Tests for evaluate_request via mocked Redis + DB-backed rules."""

    def _make_rule_cache(
        self,
        allow_rules=None,
        block_rules=None,
    ) -> RuleCache:
        return RuleCache(
            version=1,
            allow_rules=allow_rules or [],
            block_rules=block_rules or [],
            ua_regex_set=[],
        )

    def test_allowed_when_no_rules_and_within_rate_limit(self, db):
        """Clean request with no matching rules returns ALLOWED verdict."""
        redis = _make_redis()
        redis.pipeline.return_value = _make_pipeline_mock(1)  # 1 request — within limits
        redis.zcount.return_value = 5  # <10 recent requests — no UA scoring

        result = evaluate_request(
            ip_address="10.0.0.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            path="/page/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.ALLOWED
        assert result.action is None

    def test_allow_rule_match_returns_passed(self, db):
        """A matching AllowRule bypasses block rules and returns PASSED."""
        AllowRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="1.1.1.1",
        )

        redis = _make_redis()

        result = evaluate_request(
            ip_address="1.1.1.1",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.PASSED
        assert result.matched_rule_id is not None
        assert result.matched_rule_type == "allow"

    def test_block_rule_match_returns_blocked(self, db):
        """A matching BlockRule with BLOCK action returns BLOCKED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="2.2.2.2",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None  # No cached blocked IP entry

        result = evaluate_request(
            ip_address="2.2.2.2",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id is not None
        assert result.matched_rule_type == "block"

    def test_challenge_rule_returns_challenged(self, db):
        """A matching BlockRule with CHALLENGE action returns CHALLENGED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="3.3.3.3",
            action=RuleAction.CHALLENGE,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="3.3.3.3",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.CHALLENGED
        assert result.action == RuleAction.CHALLENGE

    def test_throttle_rule_returns_throttled(self, db):
        """A matching BlockRule with THROTTLE action returns THROTTLED verdict."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="4.4.4.4",
            action=RuleAction.THROTTLE,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="4.4.4.4",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.THROTTLED

    def test_redis_blocked_ip_fast_path(self, db):
        """An IP in the Redis blocked-IP cache is rejected immediately."""
        redis = _make_redis()
        # Simulate a blocked IP cache hit
        redis.get.side_effect = lambda key: b"1" if "blocked" in key else None

        result = evaluate_request(
            ip_address="5.5.5.5",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED
        assert result.matched_rule_id is None  # Fast-path block has no rule ID

    def test_rate_limit_exceeded_returns_throttled(self, db):
        """When rate limit is exceeded, result is THROTTLED."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        redis.get.return_value = None
        # Pipeline returns count > burst limit of 1
        redis.pipeline.return_value = _make_pipeline_mock(zcard_return=2)

        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 1),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600),
        ):
            result = evaluate_request(
                ip_address="6.6.6.6",
                user_agent="Mozilla/5.0",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict == Verdict.THROTTLED
        assert result.action == RuleAction.THROTTLE

    def test_ua_anomaly_score_triggers_challenge(self, db):
        """High-anomaly UA with >10 recent requests triggers CHALLENGED verdict."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        redis.get.return_value = None
        # Within rate limits
        redis.pipeline.return_value = _make_pipeline_mock(1)
        # >10 recent requests so UA scoring kicks in
        redis.zcount.return_value = 15

        # 'urllib' scores 5.0 (scraper 2.5 + no version token 1.5 + short 1.0)
        # which maps to CHALLENGED per _score_to_verdict.
        with (
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_BURST", 120),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 1200),
            patch.object(conf_mod, "ICV_WAF_RATE_LIMIT_PER_5MIN", 6000),
        ):
            result = evaluate_request(
                ip_address="7.7.7.7",
                user_agent="urllib",
                path="/",
                method="GET",
                redis_client=redis,
            )

        assert result.verdict in (Verdict.CHALLENGED, Verdict.BLOCKED)
        assert result.anomaly_score is not None

    def test_ua_anomaly_scoring_skipped_under_10_requests(self, db):
        """UA scoring is skipped when the IP has 10 or fewer recent requests."""
        redis = _make_redis()
        redis.get.return_value = None
        redis.pipeline.return_value = _make_pipeline_mock(1)
        redis.zcount.return_value = 5  # <=10 — no UA scoring

        result = evaluate_request(
            ip_address="8.8.8.8",
            user_agent="python-requests/2.28.1",
            path="/",
            method="GET",
            redis_client=redis,
        )

        # Without UA scoring even a scraper UA is ALLOWED
        assert result.verdict == Verdict.ALLOWED
        assert result.anomaly_score is None

    def test_allow_rule_takes_precedence_over_block_rule(self, db):
        """Allow rules are evaluated before block rules (BR-EVAL-003)."""
        AllowRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="9.9.9.9",
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern="9.9.9.9",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()

        result = evaluate_request(
            ip_address="9.9.9.9",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.PASSED

    def test_cidr_block_rule_matches_ip_in_range(self, db):
        """CIDR block rule matches an IP within the specified network."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.CIDR,
            match_type="cidr",
            pattern="192.168.100.0/24",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="192.168.100.42",
            user_agent="Mozilla/5.0",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED

    def test_ua_block_rule_matches_contains_pattern(self, db):
        """UA block rule with CONTAINS match_type matches a substring."""
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.UA,
            match_type="contains",
            pattern="SuspiciousTool",
            action=RuleAction.BLOCK,
        )

        redis = _make_redis()
        redis.get.return_value = None

        result = evaluate_request(
            ip_address="10.0.0.1",
            user_agent="SuspiciousTool/2.0 (python)",
            path="/",
            method="GET",
            redis_client=redis,
        )

        assert result.verdict == Verdict.BLOCKED


# ---------------------------------------------------------------------------
# issue_challenge
# ---------------------------------------------------------------------------


class TestIssueChallenge:
    def test_creates_challenge_token_in_db(self, db):
        """issue_challenge creates and persists a ChallengeToken record."""
        import icv_waf.conf as conf_mod
        from icv_waf.models import ChallengeToken

        redis = _make_redis()

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            token_obj = issue_challenge("10.0.0.1", redis)

        assert token_obj.pk is not None
        assert ChallengeToken.objects.filter(pk=token_obj.pk).exists()
        assert token_obj.ip_address == "10.0.0.1"
        assert token_obj.status == ChallengeStatus.PENDING
        assert token_obj.difficulty == 4

    def test_token_stored_in_redis(self, db):
        """issue_challenge stores the challenge payload in Redis."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            issue_challenge("10.0.0.2", redis)

        # setex should have been called once for the challenge key
        assert redis.setex.called
        setex_call = redis.setex.call_args
        key = setex_call.args[0]
        assert key.startswith("waf:challenge:")

        # The payload should be valid JSON with ip and difficulty
        payload = json.loads(setex_call.args[2])
        assert payload["ip"] == "10.0.0.2"
        assert payload["difficulty"] == 4

    def test_token_uses_configured_difficulty(self, db):
        """Difficulty on created token reflects ICV_WAF_CHALLENGE_DIFFICULTY setting."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 6),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600),
        ):
            token_obj = issue_challenge("10.0.0.3", redis)

        assert token_obj.difficulty == 6

    def test_expiry_is_set_based_on_cookie_ttl(self, db):
        """expires_at is approximately now + ICV_WAF_CHALLENGE_COOKIE_TTL seconds."""
        import icv_waf.conf as conf_mod

        redis = _make_redis()
        before = timezone.now()

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 4),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 7200),
        ):  # 2 hours
            token_obj = issue_challenge("10.0.0.4", redis)

        after = timezone.now()
        expected_min = before + timezone.timedelta(seconds=7199)
        expected_max = after + timezone.timedelta(seconds=7201)

        assert token_obj.expires_at >= expected_min
        assert token_obj.expires_at <= expected_max

    def test_emits_challenge_issued_signal(self, db):
        """issue_challenge emits the challenge_issued signal."""
        import icv_waf.conf as conf_mod
        from icv_waf.signals import challenge_issued

        received = []

        def handler(sender, token, ip_address, **kwargs):
            received.append((token, ip_address))

        challenge_issued.connect(handler, dispatch_uid="test_issue_challenge_signal")
        try:
            redis = _make_redis()
            with (
                patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 4),
                patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600),
            ):
                issue_challenge("10.0.0.5", redis)
        finally:
            challenge_issued.disconnect(dispatch_uid="test_issue_challenge_signal")

        assert len(received) == 1
        _, ip = received[0]
        assert ip == "10.0.0.5"


# ---------------------------------------------------------------------------
# verify_challenge_solution
# ---------------------------------------------------------------------------


class TestVerifyChallengeService:
    def _valid_nonce(self, token: str, difficulty: int) -> str:
        """Brute-force a nonce that satisfies the proof-of-work for the given token."""
        for n in range(1_000_000):
            nonce = str(n)
            digest = hashlib.sha256(f"{token}{nonce}".encode()).digest()
            if all(b == 0 for b in digest[:difficulty]):
                return nonce
        raise RuntimeError("Could not find a valid nonce within 1,000,000 iterations")

    def test_valid_solution_returns_true(self, db):
        """A correct nonce marks the token SOLVED and returns True."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )
        nonce = self._valid_nonce(token_obj.token, 1)

        redis = _make_redis()
        redis.get.return_value = None  # Force DB lookup

        result = verify_challenge_solution(
            token=token_obj.token,
            nonce=nonce,
            ip_address="1.2.3.4",
            redis_client=redis,
        )

        assert result is True
        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.SOLVED
        assert token_obj.nonce == nonce
        assert token_obj.solved_at is not None

    def test_expired_token_raises(self, db):
        """A token past its expiry raises ChallengeExpiredError."""
        past = timezone.now() - timezone.timedelta(hours=1)
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            status=ChallengeStatus.PENDING,
            expires_at=past,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.EXPIRED

    def test_already_solved_token_raises(self, db):
        """A token that was already solved raises ChallengeExpiredError."""
        token_obj = ChallengeTokenFactory(status=ChallengeStatus.SOLVED)

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address=token_obj.ip_address,
                redis_client=redis,
            )

    def test_already_failed_token_raises(self, db):
        """A token that was already failed raises ChallengeExpiredError."""
        token_obj = ChallengeTokenFactory(status=ChallengeStatus.FAILED)

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeExpiredError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="any_nonce",
                ip_address=token_obj.ip_address,
                redis_client=redis,
            )

    def test_ip_mismatch_raises(self, db):
        """Submitting a solution from a different IP raises ChallengeMismatchError."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeMismatchError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="some_nonce",
                ip_address="5.5.5.5",  # Wrong IP
                redis_client=redis,
            )

    def test_invalid_nonce_raises(self, db):
        """A nonce that fails proof-of-work raises ChallengeInvalidError."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=4,  # Difficult enough that "wrong_nonce" won't pass
            status=ChallengeStatus.PENDING,
        )

        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeInvalidError):
            verify_challenge_solution(
                token=token_obj.token,
                nonce="wrong_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

        token_obj.refresh_from_db()
        assert token_obj.status == ChallengeStatus.FAILED

    def test_nonexistent_token_raises(self, db):
        """A token that does not exist raises ChallengeInvalidError."""
        redis = _make_redis()
        redis.get.return_value = None

        with pytest.raises(ChallengeInvalidError, match="not found"):
            verify_challenge_solution(
                token="no-such-token",
                nonce="any_nonce",
                ip_address="1.2.3.4",
                redis_client=redis,
            )

    def test_redis_cache_used_when_available(self, db):
        """verify_challenge_solution uses Redis data when available (avoids DB lookup)."""
        token_obj = ChallengeTokenFactory(
            ip_address="1.2.3.4",
            difficulty=1,
            status=ChallengeStatus.PENDING,
        )
        nonce = self._valid_nonce(token_obj.token, 1)

        redis_payload = json.dumps(
            {
                "ip": "1.2.3.4",
                "difficulty": 1,
                "expires": token_obj.expires_at.isoformat(),
            }
        ).encode()
        redis = _make_redis()
        redis.get.return_value = redis_payload

        result = verify_challenge_solution(
            token=token_obj.token,
            nonce=nonce,
            ip_address="1.2.3.4",
            redis_client=redis,
        )

        assert result is True


# ---------------------------------------------------------------------------
# validate_pass_cookie / issue_pass_cookie
# ---------------------------------------------------------------------------


class TestPassCookie:
    def test_round_trip_valid(self):
        """A cookie issued by issue_pass_cookie passes validate_pass_cookie."""
        import icv_waf.conf as conf_mod

        ip = "10.0.0.1"
        token = "abc123def456abc123def456abc123"

        response = MagicMock()
        cookie_value_captured = {}

        def capture_cookie(name, value, **kwargs):
            cookie_value_captured["value"] = value

        response.set_cookie.side_effect = capture_cookie

        with patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600):
            issue_pass_cookie(response, token, ip, secure=False)

        assert cookie_value_captured["value"] is not None
        assert validate_pass_cookie(cookie_value_captured["value"], ip) is True

    def test_wrong_ip_returns_false(self):
        """Cookie issued for one IP does not validate for a different IP."""
        import icv_waf.conf as conf_mod

        ip = "10.0.0.1"
        other_ip = "10.0.0.2"
        token = "some-token-value"

        response = MagicMock()
        cookie_value_captured = {}

        def capture_cookie(name, value, **kwargs):
            cookie_value_captured["value"] = value

        response.set_cookie.side_effect = capture_cookie

        with patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 3600):
            issue_pass_cookie(response, token, ip, secure=False)

        assert validate_pass_cookie(cookie_value_captured["value"], other_ip) is False

    def test_tampered_signature_returns_false(self):
        """A cookie with a modified signature is rejected."""
        future_ts = int(time.time()) + 3600
        # Construct a cookie value with a bogus signature
        bad_cookie = f"some-token:10.0.0.1:{future_ts}:invalidsignature"

        assert validate_pass_cookie(bad_cookie, "10.0.0.1") is False

    def test_expired_cookie_returns_false(self):
        """A cookie with a past expiry timestamp is rejected."""
        from icv_waf.services.challenge_service import _hmac_sign

        ip = "10.0.0.1"
        token = "some-token"
        expired_ts = int(time.time()) - 1  # Already in the past

        value_prefix = f"{token}:{ip}:{expired_ts}"
        sig = _hmac_sign(value_prefix)
        bad_cookie = f"{value_prefix}:{sig}"

        assert validate_pass_cookie(bad_cookie, ip) is False

    def test_malformed_cookie_returns_false(self):
        """A cookie with wrong format is gracefully rejected."""
        assert validate_pass_cookie("", "1.2.3.4") is False
        assert validate_pass_cookie("notacookie", "1.2.3.4") is False
        assert validate_pass_cookie("a:b", "1.2.3.4") is False

    def test_issue_pass_cookie_sets_cookie_on_response(self):
        """issue_pass_cookie calls response.set_cookie with correct parameters."""
        import icv_waf.conf as conf_mod

        response = MagicMock()

        with patch.object(conf_mod, "ICV_WAF_CHALLENGE_COOKIE_TTL", 86400):
            issue_pass_cookie(response, "my-token", "10.0.0.1", secure=True)

        response.set_cookie.assert_called_once()
        call_kwargs = response.set_cookie.call_args
        assert call_kwargs.args[0] == "waf_pass"
        assert call_kwargs.kwargs.get("httponly") is True
        assert call_kwargs.kwargs.get("samesite") == "Lax"
        assert call_kwargs.kwargs.get("secure") is True


# ---------------------------------------------------------------------------
# detect_ua_rotation
# ---------------------------------------------------------------------------


class TestDetectUaRotation:
    def test_creates_block_rule_for_rotating_ip(self, db):
        """detect_ua_rotation creates a CHALLENGE block rule for offending IPs."""
        import icv_waf.conf as conf_mod
        from icv_waf.models import BlockRule
        from icv_waf.services.anomaly_detector import detect_ua_rotation

        ip = "11.11.11.11"
        now = timezone.now()
        # Create distinct UAs from the same IP
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"Agent-{i}/1.0", timestamp=now)

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert len(created) == 1
        rule = created[0]
        assert rule.pattern == ip
        assert rule.action == RuleAction.CHALLENGE
        assert rule.source == RuleSource.AUTO
        assert rule.rule_type == RuleType.IP
        assert BlockRule.objects.filter(pk=rule.pk).exists()

    def test_returns_empty_when_no_offenders(self, db):
        """detect_ua_rotation returns empty list when no IP exceeds the threshold."""
        from icv_waf.services.anomaly_detector import detect_ua_rotation

        result = detect_ua_rotation(window_minutes=5, threshold=20)

        assert result == []

    def test_does_not_duplicate_existing_active_rule(self, db):
        """BR-ANOM-004: skip if an active rule already exists for the IP."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import detect_ua_rotation

        ip = "12.12.12.12"
        now = timezone.now()
        for i in range(25):
            RequestLogFactory(ip_address=ip, user_agent=f"UA-{i}/1.0", timestamp=now)

        # Pre-existing active rule
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
        )

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_ua_rotation(window_minutes=10, threshold=20)

        assert created == []


# ---------------------------------------------------------------------------
# detect_subnet_burst
# ---------------------------------------------------------------------------


class TestDetectSubnetBurst:
    def test_creates_cidr_rule_for_bursting_subnet(self, db):
        """detect_subnet_burst creates a CIDR block rule for a bursting /24 subnet."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # 100 requests from a single /24 subnet, 1 each from 9 other subnets.
        # Mean = (100 + 9) / 10 = 10.9. 3× = 32.7.
        # The 20.20.20.0/24 subnet (100 requests) exceeds 3× mean.
        for i in range(100):
            RequestLogFactory(ip_address=f"20.20.20.{i % 255}", timestamp=now)
        for j in range(9):
            RequestLogFactory(ip_address=f"30.30.{j}.1", timestamp=now)

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_subnet_burst(window_minutes=60)

        # The 20.20.20.0/24 subnet should be flagged
        assert len(created) >= 1
        rule_patterns = [r.pattern for r in created]
        assert "20.20.20.0/24" in rule_patterns

    def test_returns_empty_when_no_burst(self, db):
        """detect_subnet_burst returns empty list when no subnet exceeds 3× mean."""
        from icv_waf.services.anomaly_detector import detect_subnet_burst

        result = detect_subnet_burst(window_minutes=15)

        assert result == []


# ---------------------------------------------------------------------------
# detect_challenge_farms
# ---------------------------------------------------------------------------


class TestDetectChallengeFarms:
    def test_creates_block_rule_for_farm_ip(self, db):
        """detect_challenge_farms creates a BLOCK rule for IPs with high failure rates."""
        import icv_waf.conf as conf_mod
        from icv_waf.models import BlockRule
        from icv_waf.services.anomaly_detector import detect_challenge_farms

        IPReputationFactory(
            ip_address="99.99.99.99",
            challenge_failures=15,
            challenge_passes=0,
            last_seen_at=timezone.now(),
        )

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_challenge_farms(window_hours=24)

        assert len(created) == 1
        rule = created[0]
        assert rule.pattern == "99.99.99.99"
        assert rule.action == RuleAction.BLOCK
        assert rule.source == RuleSource.AUTO
        assert BlockRule.objects.filter(pk=rule.pk).exists()

    def test_returns_empty_when_no_suspects(self, db):
        """detect_challenge_farms returns empty list when no IPs meet the criteria."""
        from icv_waf.services.anomaly_detector import detect_challenge_farms

        # IP with low failure count — should not be flagged
        IPReputationFactory(
            challenge_failures=2,
            challenge_passes=5,
            last_seen_at=timezone.now(),
        )

        result = detect_challenge_farms(window_hours=24)

        assert result == []

    def test_does_not_duplicate_existing_block_rule(self, db):
        """BR-ANOM-004: skip if an active BLOCK rule already exists for the IP."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import detect_challenge_farms

        ip = "88.88.88.88"
        IPReputationFactory(
            ip_address=ip,
            challenge_failures=20,
            challenge_passes=0,
            last_seen_at=timezone.now(),
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            match_type="exact",
            pattern=ip,
            action=RuleAction.BLOCK,
        )

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_challenge_farms(window_hours=24)

        assert created == []


# ---------------------------------------------------------------------------
# run_all_detectors
# ---------------------------------------------------------------------------


class TestRunAllDetectors:
    def test_returns_summary_dict_with_correct_keys(self, db):
        """run_all_detectors returns a dict with the expected summary keys."""
        from icv_waf.services.anomaly_detector import run_all_detectors

        result = run_all_detectors()

        assert set(result.keys()) == {
            "ua_rotation_rules",
            "subnet_burst_rules",
            "challenge_farm_rules",
            "total_rules_created",
        }

    def test_returns_zero_counts_when_no_anomalies(self, db):
        """When no anomalies exist, all counts are zero."""
        from icv_waf.services.anomaly_detector import run_all_detectors

        result = run_all_detectors()

        assert result["ua_rotation_rules"] == 0
        assert result["subnet_burst_rules"] == 0
        assert result["challenge_farm_rules"] == 0
        assert result["total_rules_created"] == 0

    def test_total_rules_created_sums_all_detectors(self, db):
        """total_rules_created is the sum across all three detectors."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import run_all_detectors

        now = timezone.now()
        # Trigger UA rotation detector: one IP with many distinct UAs
        for i in range(25):
            RequestLogFactory(ip_address="55.55.55.55", user_agent=f"UA-{i}/1.0", timestamp=now)

        with (
            patch.object(conf_mod, "ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 20),
            patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            result = run_all_detectors()

        assert result["ua_rotation_rules"] == 1
        expected = result["ua_rotation_rules"] + result["subnet_burst_rules"] + result["challenge_farm_rules"]
        assert result["total_rules_created"] == expected


# ---------------------------------------------------------------------------
# _emit_anomaly_signal exception path
# ---------------------------------------------------------------------------


class TestEmitAnomalySignalExceptionPath:
    def test_exception_during_signal_send_is_swallowed(self, db):
        """_emit_anomaly_signal swallows exceptions raised inside the signal send."""
        from icv_waf.enums import AnomalyType
        from icv_waf.services.anomaly_detector import _emit_anomaly_signal

        rule = BlockRuleFactory(is_active=True, rule_type=RuleType.IP)

        with patch("icv_waf.signals.anomaly_detected.send", side_effect=Exception("signal error")):
            # Should not raise — exceptions from signal send are caught
            _emit_anomaly_signal(
                rule=rule,
                anomaly_type=AnomalyType.UA_ROTATION,
                details={"distinct_ua_count": 5},
            )


# ---------------------------------------------------------------------------
# detect_subnet_burst — branch coverage for non-burst path
# ---------------------------------------------------------------------------


class TestDetectSubnetBurstBranches:
    def test_subnet_below_burst_threshold_not_flagged(self, db):
        """Subnets at or below 3× mean are not flagged."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # Uniform distribution: 10 requests per /24 subnet — no burst
        for j in range(10):
            RequestLogFactory(ip_address=f"40.40.{j}.1", timestamp=now)

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            created = detect_subnet_burst(window_minutes=60)

        assert created == []

    def test_invalid_ip_in_logs_is_skipped(self, db):
        """RequestLog entries with invalid IP addresses are silently skipped."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.anomaly_detector import detect_subnet_burst

        now = timezone.now()
        # Create a log entry with a value that cannot be parsed as an IP
        RequestLogFactory(ip_address="999.999.999.999", timestamp=now)

        with patch.object(conf_mod, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24):
            # Should not raise
            result = detect_subnet_burst(window_minutes=60)

        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# sync_feed
# ---------------------------------------------------------------------------


class TestSyncFeed:
    def test_creates_new_rules_from_feed(self, db):
        """sync_feed creates BlockRule records for new feed entries."""
        from icv_waf.models import BlockRule
        from icv_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "1.2.3.4",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
                "reporters": 5,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        assert result["updated"] == 0
        assert result["skipped"] == 0
        assert BlockRule.objects.filter(source="feed", pattern="1.2.3.4").exists()

    def test_updates_existing_feed_rule(self, db):
        """sync_feed updates an existing feed rule matched on (source, rule_type, pattern)."""
        from icv_waf.enums import RuleSource
        from icv_waf.services.threat_feed import sync_feed

        BlockRuleFactory(
            source=RuleSource.FEED,
            rule_type="ip",
            match_type="exact",
            pattern="5.6.7.8",
            action="block",
            confidence="0.7",
            is_active=True,
        )

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "5.6.7.8",
                "action": "challenge",
                "match_type": "exact",
                "confidence": 0.95,
                "reporters": 10,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["updated"] == 1
        assert result["created"] == 0

    def test_skips_entries_below_confidence_threshold(self, db):
        """Entries with confidence below the threshold are counted as skipped."""
        from icv_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "9.9.9.9",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.1,  # below threshold
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.8)

        assert result["skipped"] == 1
        assert result["created"] == 0

    def test_skips_entries_missing_rule_type_or_pattern(self, db):
        """Entries without rule_type or pattern are counted as skipped."""
        from icv_waf.services.threat_feed import sync_feed

        feed_payload = [
            {"confidence": 0.9, "action": "block"},  # missing rule_type and pattern
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1

    def test_deactivates_feed_rules_absent_from_feed(self, db):
        """Feed rules no longer in the feed response are deactivated (BR-FEED-005)."""
        from icv_waf.enums import RuleSource
        from icv_waf.services.threat_feed import sync_feed

        stale_rule = BlockRuleFactory(
            source=RuleSource.FEED,
            rule_type="ip",
            match_type="exact",
            pattern="10.20.30.40",
            action="block",
            is_active=True,
        )

        # Feed returns an empty list — stale_rule is not present
        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = []
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["expired"] == 1
        stale_rule.refresh_from_db()
        assert stale_rule.is_active is False

    def test_network_error_returns_error_dict(self, db):
        """When the HTTP request fails, sync_feed returns an error dict without raising."""
        from icv_waf.services.threat_feed import sync_feed

        with patch("httpx.get", side_effect=Exception("connection refused")):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert "error" in result
        assert result["created"] == 0

    def test_accepts_wrapped_rules_dict(self, db):
        """sync_feed handles a feed payload wrapped in {'rules': [...]} format."""
        from icv_waf.services.threat_feed import sync_feed

        feed_payload = {
            "rules": [
                {
                    "rule_type": "ip",
                    "pattern": "11.22.33.44",
                    "action": "block",
                    "match_type": "exact",
                    "confidence": 0.9,
                }
            ]
        }

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1

    def test_entry_with_expires_field_uses_parsed_datetime(self, db):
        """A feed entry with an 'expires' field sets expires_at from that value."""
        from icv_waf.models import BlockRule
        from icv_waf.services.threat_feed import sync_feed

        future_ts = "2099-12-31T00:00:00+00:00"
        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "66.77.88.99",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
                "expires": future_ts,
            }
        ]

        with patch("httpx.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.json.return_value = feed_payload
            mock_resp.raise_for_status.return_value = None
            mock_get.return_value = mock_resp

            sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        rule = BlockRule.objects.get(pattern="66.77.88.99")
        assert rule.expires_at.year == 2099

    def test_emits_feed_synced_signal(self, db):
        """sync_feed emits the feed_synced signal on completion."""
        from icv_waf.services.threat_feed import sync_feed
        from icv_waf.signals import feed_synced

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        feed_synced.connect(handler, dispatch_uid="test_sync_feed_signal")
        try:
            with patch("httpx.get") as mock_get:
                mock_resp = MagicMock()
                mock_resp.json.return_value = []
                mock_resp.raise_for_status.return_value = None
                mock_get.return_value = mock_resp

                sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)
        finally:
            feed_synced.disconnect(dispatch_uid="test_sync_feed_signal")

        assert len(received) == 1
        assert "created" in received[0]


# ---------------------------------------------------------------------------
# build_telemetry_payload
# ---------------------------------------------------------------------------


class TestBuildTelemetryPayload:
    def test_returns_payload_with_expected_keys(self, db):
        """build_telemetry_payload returns a dict with all required top-level keys."""
        from icv_waf.services.threat_feed import build_telemetry_payload

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="test-install-id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert set(payload.keys()) == {"install_id", "period", "ua_hashes", "subnets", "anomalies", "summary"}

    def test_install_id_in_payload(self, db):
        """The install_id from get_or_create_install_id is included in the payload."""
        from icv_waf.services.threat_feed import build_telemetry_payload

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="my-stable-id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert payload["install_id"] == "my-stable-id"

    def test_summary_counts_requests_in_period(self, db):
        """summary.total_requests reflects the count of RequestLog entries in the period."""
        from icv_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory.create_batch(3, timestamp=now - timezone.timedelta(minutes=30))

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        assert payload["summary"]["total_requests"] == 3

    def test_ua_hashes_are_sha256_of_ua_rules(self, db):
        """UA block rules are hashed with SHA-256 — raw patterns are not included."""
        import hashlib

        from icv_waf.enums import RuleSource
        from icv_waf.services.threat_feed import build_telemetry_payload

        raw_pattern = "EvilBot/1.0"
        BlockRuleFactory(
            source=RuleSource.ADMIN,
            rule_type="ua",
            match_type="exact",
            pattern=raw_pattern,
            is_active=True,
        )

        period_start = timezone.now() - timezone.timedelta(hours=1)
        period_end = timezone.now()

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        ua_hashes = payload["ua_hashes"]
        assert len(ua_hashes) == 1
        expected_hash = hashlib.sha256(raw_pattern.encode()).hexdigest()
        assert ua_hashes[0]["sha256"] == expected_hash
        # Raw pattern must not appear anywhere in the payload
        assert raw_pattern not in str(payload)

    def test_subnets_are_truncated_to_slash24(self, db):
        """IP addresses in logs are truncated to /24 subnets in the payload."""
        from icv_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory(ip_address="192.0.2.100", timestamp=now - timezone.timedelta(minutes=5))

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            payload = build_telemetry_payload(period_start, period_end)

        subnet_cidrs = [s["cidr"] for s in payload["subnets"]]
        assert "192.0.2.0/24" in subnet_cidrs

    def test_invalid_ip_in_logs_is_skipped(self, db):
        """RequestLog entries with invalid IPs are skipped during subnet aggregation."""
        from icv_waf.services.threat_feed import build_telemetry_payload

        now = timezone.now()
        period_start = now - timezone.timedelta(hours=1)
        period_end = now

        RequestLogFactory(ip_address="999.999.999.999", timestamp=now - timezone.timedelta(minutes=5))

        with patch("icv_waf.services.threat_feed.get_or_create_install_id", return_value="id"):
            # Should not raise
            payload = build_telemetry_payload(period_start, period_end)

        assert isinstance(payload["subnets"], list)


# ---------------------------------------------------------------------------
# submit_telemetry
# ---------------------------------------------------------------------------


class TestSubmitTelemetry:
    def test_returns_true_on_successful_post(self):
        """submit_telemetry returns True when the server responds with 2xx."""
        from icv_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is True

    def test_returns_false_on_non_2xx_response(self):
        """submit_telemetry returns False when the server responds with a non-2xx status."""
        from icv_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.is_success = False
            mock_resp.status_code = 503
            mock_post.return_value = mock_resp

            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is False

    def test_returns_false_on_network_error(self):
        """submit_telemetry returns False when a network error occurs (BR-TEL-004)."""
        from icv_waf.services.threat_feed import submit_telemetry

        with patch("httpx.post", side_effect=Exception("timeout")):
            result = submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        assert result is False

    def test_includes_bearer_token_when_api_key_set(self):
        """An API key from conf is sent as a Bearer token in the Authorization header."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.threat_feed import submit_telemetry

        with (
            patch.object(conf_mod, "ICV_WAF_FEED_API_KEY", "secret-key-123"),
            patch("httpx.post") as mock_post,
        ):
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        _, call_kwargs = mock_post.call_args
        headers = call_kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer secret-key-123"

    def test_omits_auth_header_when_no_api_key(self):
        """When ICV_WAF_FEED_API_KEY is empty, no Authorization header is sent."""
        import icv_waf.conf as conf_mod
        from icv_waf.services.threat_feed import submit_telemetry

        with (
            patch.object(conf_mod, "ICV_WAF_FEED_API_KEY", ""),
            patch("httpx.post") as mock_post,
        ):
            mock_resp = MagicMock()
            mock_resp.is_success = True
            mock_post.return_value = mock_resp

            submit_telemetry({"install_id": "x"}, report_url="https://report.example.com")

        _, call_kwargs = mock_post.call_args
        headers = call_kwargs.get("headers", {})
        assert "Authorization" not in headers


# ---------------------------------------------------------------------------
# get_or_create_install_id
# ---------------------------------------------------------------------------


class TestGetOrCreateInstallId:
    def test_returns_cached_value_without_file_io(self):
        """Returns the install_id from Django cache without touching the filesystem."""
        from icv_waf.services.threat_feed import get_or_create_install_id

        with patch("django.core.cache.cache") as mock_cache:
            mock_cache.get.return_value = "cached-install-id"

            result = get_or_create_install_id()

        assert result == "cached-install-id"

    def test_reads_id_from_file_when_cache_empty(self, tmp_path):
        """When the cache is empty, reads install_id from the filesystem file."""
        from unittest.mock import mock_open

        from icv_waf.services.threat_feed import get_or_create_install_id

        with (
            patch("django.core.cache.cache") as mock_cache,
            patch("os.path.isfile", return_value=True),
            patch("builtins.open", mock_open(read_data="file-install-id")),
        ):
            mock_cache.get.return_value = None

            result = get_or_create_install_id()

        assert result == "file-install-id"

    def test_generates_new_uuid_when_no_file_exists(self, tmp_path):
        """When the cache is empty and no file exists, generates and persists a new UUID."""
        import uuid as uuid_mod

        from icv_waf.services.threat_feed import get_or_create_install_id

        with (
            patch("django.core.cache.cache") as mock_cache,
            patch("os.path.isfile", return_value=False),
            patch("uuid.uuid4", return_value=uuid_mod.UUID("12345678-1234-5678-1234-567812345678")),
            patch("builtins.open", side_effect=OSError("no write")),
        ):
            mock_cache.get.return_value = None

            result = get_or_create_install_id()

        assert result == "12345678-1234-5678-1234-567812345678"
        mock_cache.set.assert_called_once()

    def test_persists_new_id_to_cache(self, tmp_path):
        """A freshly generated install_id is stored in the Django cache."""
        from icv_waf.services.threat_feed import get_or_create_install_id

        with (
            patch("django.core.cache.cache") as mock_cache,
            patch("os.path.isfile", return_value=False),
            patch("builtins.open", side_effect=OSError("no write")),
        ):
            mock_cache.get.return_value = None

            get_or_create_install_id()

        assert mock_cache.set.called


# ---------------------------------------------------------------------------
# generate_nginx_blocklist
# ---------------------------------------------------------------------------


class TestGenerateNginxBlocklist:
    def test_writes_file_with_ip_and_ua_rules(self, db, tmp_path):
        """generate_nginx_blocklist writes both IP/CIDR and UA rules to the output file."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        BlockRuleFactory(
            is_active=True,
            rule_type="ip",
            match_type="exact",
            pattern="10.0.0.1",
            action="block",
        )
        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="EvilBot/1.0",
            action="block",
        )

        count = generate_nginx_blocklist(output_path=output_file)

        assert count == 2
        with open(output_file) as fh:
            content = fh.read()
        assert "10.0.0.1" in content
        assert '"EvilBot/1.0"' in content
        assert "map $http_user_agent $waf_block_ua" in content
        assert "geo $waf_block_ip" in content

    def test_returns_count_of_rules_written(self, db, tmp_path):
        """generate_nginx_blocklist returns the number of rules written."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory.create_batch(3, is_active=True, rule_type="ip", match_type="exact", action="block")
        output_file = str(tmp_path / "blocklist.conf")

        count = generate_nginx_blocklist(output_path=output_file)

        assert count == 3

    def test_write_is_atomic_via_rename(self, db, tmp_path):
        """The output file is written via temp file + rename (BR-BL-002)."""
        import os

        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        output_file = str(tmp_path / "blocklist.conf")

        rename_calls = []
        real_rename = os.rename

        def tracking_rename(src, dst):
            rename_calls.append((src, dst))
            real_rename(src, dst)

        with patch("icv_waf.services.blocklist_generator.os.rename", side_effect=tracking_rename):
            generate_nginx_blocklist(output_path=output_file)

        assert len(rename_calls) == 1
        _, dst = rename_calls[0]
        assert dst == output_file

    def test_ua_contains_pattern_escaped_as_regex(self, db, tmp_path):
        """UA rules with match_type='contains' are written as case-insensitive nginx regexes."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="contains",
            pattern="badbot",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        # Contains pattern should use ~* prefix
        assert "~*" in content

    def test_ua_regex_pattern_written_with_prefix(self, db, tmp_path):
        """UA rules with match_type='regex' are written with ~* nginx prefix."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="regex",
            pattern=r"EvilBot/\d+",
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        assert "~*" in content

    def test_empty_ua_pattern_is_omitted(self, db, tmp_path):
        """UA rules with an empty pattern are not written to the output file."""
        from icv_waf.services.blocklist_generator import generate_nginx_blocklist

        BlockRuleFactory(
            is_active=True,
            rule_type="ua",
            match_type="exact",
            pattern="",  # empty — should be skipped
            action="block",
        )
        output_file = str(tmp_path / "blocklist.conf")
        generate_nginx_blocklist(output_path=output_file)

        with open(output_file) as fh:
            content = fh.read()
        # An empty-pattern rule should produce no entry line beyond 'default 0;'
        ua_section = content.split("map $http_user_agent")[1].split("}")[0]
        lines_with_entries = [
            line
            for line in ua_section.splitlines()
            if line.strip() and "default 0" not in line and "{" not in line
        ]
        assert lines_with_entries == []


# ---------------------------------------------------------------------------
# reload_nginx
# ---------------------------------------------------------------------------


class TestReloadNginx:
    def test_returns_true_on_successful_reload(self):
        """reload_nginx returns True when nginx exits with code 0."""
        from icv_waf.services.blocklist_generator import reload_nginx

        with patch("icv_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")

            result = reload_nginx()

        assert result is True

    def test_returns_false_on_nonzero_exit_code(self):
        """reload_nginx returns False when nginx exits with a non-zero code."""
        from icv_waf.services.blocklist_generator import reload_nginx

        with patch("icv_waf.services.blocklist_generator.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="configuration file error")

            result = reload_nginx()

        assert result is False

    def test_returns_false_when_nginx_not_found(self):
        """reload_nginx returns False when nginx is not on the PATH."""
        from icv_waf.services.blocklist_generator import reload_nginx

        with patch(
            "icv_waf.services.blocklist_generator.subprocess.run",
            side_effect=FileNotFoundError,
        ):
            result = reload_nginx()

        assert result is False

    def test_returns_false_on_timeout(self):
        """reload_nginx returns False when the subprocess times out."""
        import subprocess

        from icv_waf.services.blocklist_generator import reload_nginx

        with patch(
            "icv_waf.services.blocklist_generator.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="nginx", timeout=10),
        ):
            result = reload_nginx()

        assert result is False

    def test_returns_false_on_os_error(self):
        """reload_nginx returns False on a generic OSError."""
        from icv_waf.services.blocklist_generator import reload_nginx

        with patch(
            "icv_waf.services.blocklist_generator.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            result = reload_nginx()

        assert result is False


# ---------------------------------------------------------------------------
# rule_engine — _verify_rdns
# ---------------------------------------------------------------------------


class TestVerifyRdns:
    def test_returns_true_when_hostname_matches_pattern(self):
        """_verify_rdns returns True when the resolved hostname matches the pattern."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None  # No cached value

        with patch("icv_waf.services.rule_engine.socket.gethostbyaddr", return_value=("crawl.googlebot.com", [], [])):
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        assert result is True

    def test_returns_false_when_hostname_does_not_match(self):
        """_verify_rdns returns False when the hostname does not match the pattern."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with patch("icv_waf.services.rule_engine.socket.gethostbyaddr", return_value=("evil.example.com", [], [])):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False

    def test_returns_false_on_dns_failure(self):
        """_verify_rdns returns False when DNS lookup fails."""
        import socket

        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with patch("icv_waf.services.rule_engine.socket.gethostbyaddr", side_effect=socket.herror):
            result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False

    def test_uses_cached_hostname_from_redis(self):
        """_verify_rdns uses the cached hostname from Redis without a DNS lookup."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = b"crawl.googlebot.com"

        with patch("icv_waf.services.rule_engine.socket.gethostbyaddr") as mock_dns:
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        mock_dns.assert_not_called()
        assert result is True

    def test_stores_resolved_hostname_in_redis(self):
        """_verify_rdns caches the resolved hostname in Redis with a 24-hour TTL."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = None

        with patch("icv_waf.services.rule_engine.socket.gethostbyaddr", return_value=("host.example.com", [], [])):
            _verify_rdns("1.2.3.4", r"example\.com$", redis)

        assert redis.setex.called
        call_args = redis.setex.call_args
        assert call_args.args[1] == 86400  # 24-hour TTL
        assert call_args.args[2] == "host.example.com"

    def test_returns_false_for_empty_cached_hostname(self):
        """_verify_rdns returns False when the cached hostname is an empty string."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = b""  # Cached empty hostname (prior DNS failure)

        result = _verify_rdns("1.2.3.4", r"\.googlebot\.com$", redis)

        assert result is False

    def test_returns_false_for_invalid_rdns_regex(self):
        """_verify_rdns returns False gracefully when rdns_pattern is an invalid regex."""
        from icv_waf.services.rule_engine import _verify_rdns

        redis = _make_redis()
        redis.get.return_value = b"host.example.com"

        result = _verify_rdns("1.2.3.4", "[invalid(regex", redis)

        assert result is False


# ---------------------------------------------------------------------------
# rule_engine — _check_block_rules CIDR and regex paths
# ---------------------------------------------------------------------------


class TestCheckBlockRulesPaths:
    def test_cidr_rule_matches_ip_in_range(self, db):
        """_check_block_rules matches a CIDR-type rule for an IP within the network."""
        from icv_waf.services.rule_engine import RuleCache, _check_block_rules

        cidr_rule = {
            "id": "00000000-0000-0000-0000-000000000001",
            "rule_type": "cidr",
            "match_type": "cidr",
            "pattern": "10.10.0.0/16",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[cidr_rule], ua_regex_set=[])

        result = _check_block_rules("10.10.5.1", "Mozilla/5.0", cache)

        assert result is not None
        matched_id, rule = result
        assert matched_id == cidr_rule["id"]

    def test_cidr_rule_does_not_match_ip_outside_range(self, db):
        """_check_block_rules does not match a CIDR rule for an IP outside the network."""
        from icv_waf.services.rule_engine import RuleCache, _check_block_rules

        cidr_rule = {
            "id": "00000000-0000-0000-0000-000000000002",
            "rule_type": "cidr",
            "match_type": "cidr",
            "pattern": "10.10.0.0/16",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[cidr_rule], ua_regex_set=[])

        result = _check_block_rules("192.168.1.1", "Mozilla/5.0", cache)

        assert result is None

    def test_ua_regex_rule_matches(self, db):
        """_check_block_rules matches a UA rule with regex match_type."""
        from icv_waf.services.rule_engine import RuleCache, _check_block_rules

        ua_rule = {
            "id": "00000000-0000-0000-0000-000000000003",
            "rule_type": "ua",
            "match_type": "regex",
            "pattern": r"EvilBot/\d+",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[ua_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "EvilBot/3", cache)

        assert result is not None

    def test_ua_contains_rule_matches(self, db):
        """_check_block_rules matches a UA rule with contains match_type."""
        from icv_waf.services.rule_engine import RuleCache, _check_block_rules

        ua_rule = {
            "id": "00000000-0000-0000-0000-000000000004",
            "rule_type": "ua",
            "match_type": "contains",
            "pattern": "SuspiciousTool",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[ua_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "Some SuspiciousTool/2.0", cache)

        assert result is not None

    def test_unknown_rule_type_returns_none(self, db):
        """_check_block_rules returns None for an unrecognised rule_type."""
        from icv_waf.services.rule_engine import RuleCache, _check_block_rules

        unknown_rule = {
            "id": "00000000-0000-0000-0000-000000000005",
            "rule_type": "unknown_type",
            "match_type": "exact",
            "pattern": "1.2.3.4",
            "action": "block",
            "priority": 100,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[unknown_rule], ua_regex_set=[])

        result = _check_block_rules("1.2.3.4", "Mozilla/5.0", cache)

        assert result is None


# ---------------------------------------------------------------------------
# rule_engine — _compile_ua_patterns invalid regex
# ---------------------------------------------------------------------------


class TestCompileUaPatterns:
    def test_invalid_regex_pattern_is_skipped_with_warning(self):
        """_compile_ua_patterns skips rules with invalid regex patterns."""
        from icv_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000001",
                "rule_type": "ua",
                "match_type": "regex",
                "pattern": "[invalid(regex",  # deliberately invalid
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        # Invalid pattern should be silently dropped
        assert result == []

    def test_valid_regex_pattern_is_compiled(self):
        """_compile_ua_patterns compiles a valid regex pattern."""
        from icv_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000002",
                "rule_type": "ua",
                "match_type": "regex",
                "pattern": r"BadBot/\d+",
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        assert len(result) == 1
        compiled_re, rule_dict = result[0]
        assert compiled_re.search("BadBot/99")

    def test_non_ua_rules_are_excluded(self):
        """_compile_ua_patterns only processes ua-type rules."""
        from icv_waf.services.rule_engine import _compile_ua_patterns

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000003",
                "rule_type": "ip",
                "match_type": "exact",
                "pattern": "1.2.3.4",
                "action": "block",
                "priority": 100,
            }
        ]

        result = _compile_ua_patterns(rules)

        assert result == []


# ---------------------------------------------------------------------------
# rule_engine — load_rule_cache DB fallback path
# ---------------------------------------------------------------------------


class TestLoadRuleCacheDbFallback:
    def test_corrupt_json_triggers_db_rebuild(self, db):
        """A corrupt Redis cache value causes a DB rebuild."""
        BlockRuleFactory(is_active=True, rule_type=RuleType.IP)
        AllowRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.side_effect = ["3", b"{not: valid json}"]

        cache = load_rule_cache(redis)

        assert len(cache.block_rules) == 1
        assert len(cache.allow_rules) == 1

    def test_db_rebuild_stores_result_in_redis(self, db):
        """After a DB rebuild, the result is stored in Redis via setex."""
        BlockRuleFactory(is_active=True)

        redis = _make_redis()
        redis.get.return_value = None

        load_rule_cache(redis)

        assert redis.setex.called


# ---------------------------------------------------------------------------
# rule_engine — record_block_verdict
# ---------------------------------------------------------------------------


class TestRecordBlockVerdict:
    def test_sets_blocked_ip_key_in_redis(self):
        """record_block_verdict writes the blocked-IP key to Redis with the given TTL."""
        from icv_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("1.2.3.4", redis, ttl=300)

        redis.setex.assert_called_once_with("waf:blocked:1.2.3.4", 300, "1")

    def test_increments_daily_stats_counter(self):
        """record_block_verdict increments the daily stats blocked counter."""
        from icv_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("1.2.3.4", redis, ttl=300)

        redis.hincrby.assert_called_once_with("waf:stats:today", "blocked", 1)

    def test_custom_ttl_is_respected(self):
        """record_block_verdict uses the custom TTL argument."""
        from icv_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("5.6.7.8", redis, ttl=600)

        call_args = redis.setex.call_args.args
        assert call_args[1] == 600

    def test_default_ttl_is_300(self):
        """record_block_verdict defaults to a 300-second TTL."""
        from icv_waf.services.rule_engine import record_block_verdict

        redis = _make_redis()
        record_block_verdict("9.8.7.6", redis)

        call_args = redis.setex.call_args.args
        assert call_args[1] == 300
