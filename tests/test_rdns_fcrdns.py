"""Tests for forward-confirmed reverse DNS (FCrDNS) verified crawler allows (#34).

Prior to this fix, ``_verify_rdns`` did a bare PTR (reverse-DNS) lookup and
matched the resolved hostname against ``rdns_pattern`` — no forward lookup
anywhere. An attacker who controls the PTR record of their own IP (any cloud
VM with settable rDNS) could set a PTR record like
``fake-crawler.googlebot.com`` and pass the check without being Google at
all, since nothing confirmed that Google's DNS zone (the *forward* record)
actually points back at that IP.

The fix forward-resolves the PTR hostname after a pattern match and requires
the original IP to appear among the forward-resolved addresses (both IPv4
and IPv6 families via ``socket.getaddrinfo``). Any DNS error — reverse or
forward — fails closed. The final verified verdict is cached per (ip,
rdns_pattern): 24 hours for a positive verification, a short
DJANGO_WAF_RDNS_FAILURE_CACHE_TTL (default 300s) for a negative one, so a
transient resolver outage does not suppress a legitimate crawler's
AllowRule match for a full day per IP.

This file focuses on end-to-end/integration-flavoured scenarios (spoofed
PTR denial, genuine FCrDNS allow via evaluate_request, IPv4 and IPv6
address families, and the differentiated cache TTLs). Function-level unit
coverage of ``_verify_rdns`` and ``_resolve_and_confirm_rdns`` lives in
tests/test_services.py::TestVerifyRdns (mocking pattern matches what the
pre-existing _verify_rdns tests there used).
"""

from __future__ import annotations

import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from django_waf.enums import RuleType, Verdict
from django_waf.services.rule_engine import _fcrdns_cache_key, _resolve_and_confirm_rdns, _verify_rdns, evaluate_request
from django_waf.testing.factories import AllowRuleFactory


def _make_redis() -> MagicMock:
    redis = MagicMock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 1
    redis.incr.return_value = 1
    redis.zcount.return_value = 0
    # Configure the rate-limiter pipeline shape (see test_retry_after.py)
    # so an AllowRule miss that falls through to check_rate_limit doesn't
    # hit a bare, unconfigured MagicMock at `count > threshold`.
    now = time.time()
    pipeline = MagicMock()
    pipeline.execute.return_value = [1, 0, 1, [(str(now), now)], True]
    redis.pipeline.return_value = pipeline
    return redis


# ---------------------------------------------------------------------------
# Spoofed PTR denial vs genuine FCrDNS allow
# ---------------------------------------------------------------------------


class TestSpoofedVsGenuineFCrDNS:
    def test_spoofed_ptr_suffix_matches_but_forward_resolves_elsewhere_is_denied(self):
        """An attacker-controlled PTR record that happens to match the
        pattern suffix is denied when the hostname's forward resolution
        does not include the attacker's own IP — they control the PTR of
        their IP, but not example.com's DNS zone."""
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("attacker-owned.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                # Forward resolution of the spoofed hostname points at
                # Google's real infrastructure, not the attacker's IP.
                return_value=[(socket.AF_INET, 1, 6, "", ("66.249.66.1", 0))],
            ),
        ):
            result = _verify_rdns("198.51.100.7", r"\.googlebot\.com$", redis)

        assert result is False

    def test_genuine_fcrdns_forward_set_contains_the_ip_is_allowed(self):
        """A real crawler IP: PTR matches the pattern AND the hostname's
        forward resolution includes that same IP among (possibly several)
        addresses."""
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl-66-249-66-1.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET, 1, 6, "", ("66.249.66.2", 0)),
                    (socket.AF_INET, 1, 6, "", ("66.249.66.1", 0)),  # the original IP, among others
                ],
            ),
        ):
            result = _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        assert result is True


# ---------------------------------------------------------------------------
# IPv4 and IPv6
# ---------------------------------------------------------------------------


class TestAddressFamilies:
    def test_ipv4_forward_confirmation(self):
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET, 1, 6, "", ("66.249.66.1", 0))],
            ),
        ):
            assert _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis) is True

    def test_ipv6_forward_confirmation(self):
        """getaddrinfo's IPv6 sockaddr tuple is (address, port, flowinfo,
        scope_id) — address is still element 0 of the sockaddr, which is
        info[4][0], same as IPv4."""
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET6, 1, 6, "", ("2001:4860:4801:10::64", 0, 0, 0))],
            ),
        ):
            assert _verify_rdns("2001:4860:4801:10::64", r"\.googlebot\.com$", redis) is True

    def test_ipv6_forward_mismatch_is_denied(self):
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("spoofed.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET6, 1, 6, "", ("2001:4860:4801:10::99", 0, 0, 0))],
            ),
        ):
            assert _verify_rdns("2001:4860:4801:10::64", r"\.googlebot\.com$", redis) is False

    def test_mixed_ipv4_and_ipv6_forward_results_confirms_ipv4_target(self):
        """A hostname that forward-resolves to both address families
        confirms correctly against an IPv4 target IP."""
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[
                    (socket.AF_INET6, 1, 6, "", ("2001:4860:4801:10::64", 0, 0, 0)),
                    (socket.AF_INET, 1, 6, "", ("66.249.66.1", 0)),
                ],
            ),
        ):
            assert _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis) is True


# ---------------------------------------------------------------------------
# Both failure modes fail closed
# ---------------------------------------------------------------------------


class TestFailsClosedOnEitherDnsFailure:
    def test_reverse_dns_failure_fails_closed(self):
        redis = _make_redis()

        with patch(
            "django_waf.services.rule_engine.socket.gethostbyaddr",
            side_effect=socket.herror("no PTR record"),
        ):
            assert _verify_rdns("203.0.113.5", r"\.googlebot\.com$", redis) is False

    def test_forward_dns_failure_fails_closed_even_after_ptr_match(self):
        """The PTR hostname matches the pattern, but the forward lookup
        itself raises — must still deny, not fall back to trusting the PTR."""
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                side_effect=socket.gaierror("resolver timeout"),
            ),
        ):
            assert _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis) is False

    def test_resolve_and_confirm_helper_fails_closed_on_generic_os_error(self):
        """Non-DNS-specific OSError subclasses on the reverse lookup also fail closed."""
        with patch(
            "django_waf.services.rule_engine.socket.gethostbyaddr",
            side_effect=OSError("network unreachable"),
        ):
            assert _resolve_and_confirm_rdns("203.0.113.5", r"\.googlebot\.com$") is False


# ---------------------------------------------------------------------------
# Cache TTL differentiation: 24h positive, short negative
# ---------------------------------------------------------------------------


class TestCacheTtlDifferentiation:
    def test_positive_result_cached_for_24_hours(self):
        redis = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET, 1, 6, "", ("66.249.66.1", 0))],
            ),
        ):
            _verify_rdns("66.249.66.1", r"\.googlebot\.com$", redis)

        redis.setex.assert_called_once()
        cache_key, ttl, value = redis.setex.call_args.args
        assert ttl == 86400
        assert value == "1"
        assert cache_key == _fcrdns_cache_key("66.249.66.1", r"\.googlebot\.com$")

    def test_negative_result_cached_with_configured_failure_ttl(self):
        redis = _make_redis()

        with (
            patch("django_waf.conf.DJANGO_WAF_RDNS_FAILURE_CACHE_TTL", 120),
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("attacker.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET, 1, 6, "", ("9.9.9.9", 0))],
            ),
        ):
            _verify_rdns("198.51.100.7", r"\.googlebot\.com$", redis)

        redis.setex.assert_called_once()
        _cache_key, ttl, value = redis.setex.call_args.args
        assert ttl == 120
        assert value == "0"

    def test_dns_failure_result_also_cached_with_short_ttl_not_24h(self):
        """A DNS error (not just a pattern/forward mismatch) is a negative
        verdict too, and must not get the 24-hour positive TTL — otherwise
        a transient resolver outage would suppress a legitimate crawler's
        AllowRule match for a full day per IP."""
        redis = _make_redis()

        with (
            patch("django_waf.conf.DJANGO_WAF_RDNS_FAILURE_CACHE_TTL", 300),
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                side_effect=socket.herror("resolver down"),
            ),
        ):
            _verify_rdns("203.0.113.5", r"\.googlebot\.com$", redis)

        redis.setex.assert_called_once()
        _cache_key, ttl, value = redis.setex.call_args.args
        assert ttl == 300
        assert value == "0"

    def test_different_patterns_for_same_ip_cache_independently(self):
        """The cache key includes the pattern, so checking the same IP
        against two different AllowRule patterns doesn't collide."""
        key_a = _fcrdns_cache_key("1.2.3.4", r"\.googlebot\.com$")
        key_b = _fcrdns_cache_key("1.2.3.4", r"\.search\.msn\.com$")

        assert key_a != key_b


# ---------------------------------------------------------------------------
# End-to-end via evaluate_request
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestEvaluateRequestFCrDNSEndToEnd:
    def test_spoofed_crawler_ua_with_non_confirming_ptr_does_not_bypass(self):
        """A spoofed Googlebot UA from an IP whose PTR happens to match the
        suffix, but whose forward resolution does not confirm the IP, must
        not be granted the AllowRule's PASSED verdict."""
        AllowRuleFactory(
            rule_type=RuleType.UA,
            match_type="regex",
            pattern="Googlebot",
            verify_rdns=True,
            rdns_pattern=r"\.googlebot\.com$|\.google\.com$",
            is_active=True,
        )

        redis_client = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("attacker-controlled.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET, 1, 6, "", ("8.8.8.8", 0))],  # not the attacker's IP
            ),
        ):
            result = evaluate_request(
                ip_address="198.51.100.7",
                user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
                path="/",
                method="GET",
                redis_client=redis_client,
            )

        assert result.verdict != Verdict.PASSED

    def test_genuine_crawler_with_confirming_ptr_bypasses_via_allow_rule(self):
        """A genuine Googlebot request whose PTR both matches the pattern
        and forward-confirms is granted PASSED via the AllowRule."""
        AllowRuleFactory(
            rule_type=RuleType.UA,
            match_type="regex",
            pattern="Googlebot",
            verify_rdns=True,
            rdns_pattern=r"\.googlebot\.com$|\.google\.com$",
            is_active=True,
        )

        redis_client = _make_redis()

        with (
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                return_value=("crawl-66-249-66-1.googlebot.com", [], []),
            ),
            patch(
                "django_waf.services.rule_engine.socket.getaddrinfo",
                return_value=[(socket.AF_INET, 1, 6, "", ("66.249.66.1", 0))],
            ),
        ):
            result = evaluate_request(
                ip_address="66.249.66.1",
                user_agent="Googlebot/2.1 (+http://www.google.com/bot.html)",
                path="/",
                method="GET",
                redis_client=redis_client,
            )

        assert result.verdict == Verdict.PASSED
        assert result.matched_rule_type == "allow"
