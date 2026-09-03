"""Tests for detect_scraper_404_ratio (BR-ANOM-014).

Production case: VendablyCSS, shopping.vendably.com, django-waf 2.1.0,
three-day window. A residential-proxy scraping botnet (10,874 distinct IPs
across roughly 9,700 distinct /24 subnets, 15,426 distinct User-Agent
strings) defeated every other detector: it never concentrated enough
volume in any one subnet, never shared a UA, and every request scored
exactly 3.50 (below DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE), so verdict was
"logged" throughout. The 404 ratio is the one signal that separates a
scraper working from a stale link graph from real traffic.

House discipline: every threshold test is sized from a fixed literal, never
derived from the setting under test, so raising the threshold alone can
falsify the fixture rather than the fixture silently tracking the raise.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest
from django.utils import timezone

from django_waf.enums import MatchType, RequestLogSource, RuleAction, RuleSource, RuleType, Verdict
from django_waf.services.anomaly_detector import detect_scraper_404_ratio
from django_waf.testing.factories import AllowRuleFactory, RequestLogFactory

pytestmark = pytest.mark.django_db


def _make_requests(
    ip: str,
    *,
    total: int,
    count_404: int,
    verdict: str = Verdict.ALLOWED,
    response_code_non_404: int = 200,
    timestamp=None,
    source: str = RequestLogSource.MIDDLEWARE,
    user_agent: str | None = None,
) -> None:
    """Create ``total`` RequestLog rows for ``ip``, ``count_404`` of them 404."""
    now = timestamp or timezone.now()
    kwargs = {}
    if user_agent is not None:
        kwargs["user_agent"] = user_agent
    for i in range(total):
        RequestLogFactory(
            ip_address=ip,
            path=f"/stale-path-{i}/",
            verdict=verdict,
            response_code=404 if i < count_404 else response_code_non_404,
            timestamp=now,
            source=source,
            **kwargs,
        )


def _make_redis() -> MagicMock:
    """Mirrors tests/test_rdns_fcrdns.py's _make_redis: a working Redis
    double with the rule-cache and rate-limiter pipeline shapes configured
    so a call into rule_engine machinery doesn't hit an unconfigured
    MagicMock partway through."""
    redis = MagicMock()
    redis.get.return_value = None
    redis.set.return_value = True
    redis.setex.return_value = True
    redis.delete.return_value = 1
    redis.incr.return_value = 1
    redis.zcount.return_value = 0
    now = time.time()
    pipeline = MagicMock()
    pipeline.execute.return_value = [1, 0, 1, [(str(now), now)], True]
    redis.pipeline.return_value = pipeline
    return redis


@pytest.fixture(autouse=True)
def _redis_client_available():
    """Autouse: every test in this module runs detect_scraper_404_ratio for
    real, and the AllowRule re-resolution step (#140, #135) needs
    get_redis_client() to return a working client to load the rule cache.
    Without this, every pre-existing test in this module that expects a
    rule to be created would instead fail closed for a reason unrelated to
    what it is actually checking.

    Tests in TestDetectScraper404RatioNginxAllowRuleExclusion that need a
    different Redis behaviour (in particular, the unavailable-client case)
    nest their own ``patch(...get_redis_client...)`` inside this one, which
    overrides it for their duration and is restored on exit, so this
    fixture does not interfere with them.
    """
    with patch(
        "django_waf.services.redis_client.get_redis_client",
        return_value=_make_redis(),
    ):
        yield


class TestDetectScraper404RatioCreatesRule:
    def test_ip_at_100_percent_404_over_min_requests_creates_rule(self):
        """An IP at 100% 404 over >= MIN_REQUESTS creates a rule."""
        ip = "31.58.20.59"
        _make_requests(ip, total=32, count_404=32)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        rule = created[0]
        assert rule.pattern == ip
        assert rule.rule_type == RuleType.IP
        assert rule.source == RuleSource.AUTO
        assert rule.action == RuleAction.CHALLENGE

    def test_evidence_dict_carries_counts_and_ratio(self):
        """notes/evidence records total_requests, count_404, ratio, window_minutes."""
        ip = "88.167.25.244"
        _make_requests(ip, total=75, count_404=73)  # 97.3%, matches the production trace

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        notes = created[0].notes
        assert "total_requests: 75" in notes
        assert "count_404: 73" in notes
        assert "window_minutes: 180" in notes
        assert "ratio:" in notes


class TestDetectScraper404RatioThresholdTeeth:
    def test_below_min_requests_creates_no_rule_even_at_100_percent(self):
        """An IP below MIN_REQUESTS does NOT create a rule even at 100% 404.

        Fixed at 19 requests (one below the pinned floor of 20): if the
        min-requests gate were ever dropped this would still create a rule
        at 100% ratio, so this is a genuine test of the floor, not a
        vacuous one.
        """
        ip = "10.10.10.10"
        _make_requests(ip, total=19, count_404=19)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []

    def test_above_min_requests_but_below_ratio_creates_no_rule(self):
        """An IP above MIN_REQUESTS but below RATIO does NOT create a rule.

        30 requests (above the 20-request floor), 20 of them 404
        (66.7%, below the pinned 85% floor).
        """
        ip = "10.10.10.20"
        _make_requests(ip, total=30, count_404=20)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []

    def test_min_requests_threshold_has_teeth_against_reversion(self):
        """Raising MIN_REQUESTS past a fixed fixture size defeats the query for real.

        The fixture is pinned to 25 requests (a literal, not derived from
        the setting under test); raising the setting to 9999 must make the
        real query return nothing, proving the floor is read live rather
        than baked into a fixture that would pass regardless.
        """
        ip = "10.10.10.30"
        _make_requests(ip, total=25, count_404=25)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 9999),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []


class TestDetectScraper404RatioVerdictScoping:
    def test_verified_crawler_passed_verdict_with_huge_404_count_creates_no_rule(self):
        """A verified-crawler IP (verdict=PASSED) with a huge 404 count creates NO rule.

        Regression test for the most dangerous failure mode this detector
        could introduce: auto-challenging (or, with
        DJANGO_WAF_SCRAPER_404_ACTION_BLOCK=True, auto-blocking) a verified
        search crawler. Production evidence (measured over an identical
        180-minute window at the default 20-request/85%-ratio gate):
        excluding verdict=passed traffic flagged zero IPs; including it
        flagged 10, every single one a verified Bingbot IP, e.g.
        40.77.167.132 (34 requests, 100% 404) and 207.46.13.156 (25
        requests, 100% 404), re-crawling roughly 14,897 dead URLs still
        present in its own historical index (a stale-sitemap/HTTP 410 gap
        on the site's side, not malicious behaviour).

        This fixture is pinned at 100% 404 (the actual worst-case shape
        measured live for Bingbot, not a softened one), well clear of the
        ratio floor, specifically so this is a genuine falsifiability
        check: a detector that forgot to exclude Verdict.PASSED would
        create a rule here, not merely one that happened to fall on the
        safe side of some other gate.
        """
        ip = "40.77.167.132"
        _make_requests(ip, total=34, count_404=34, verdict=Verdict.PASSED)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []

    def test_spoofed_crawler_ua_that_fails_allowrule_is_still_caught(self):
        """An impostor sending a genuine crawler UA, but that never matches
        the AllowRule (fails FCrDNS, so verdict is never PASSED), is not
        given the same protection as the real crawler.

        Production trace: 45.45.237.69 sent the exact Googlebot User-Agent
        string but sits outside Google's published ranges, so it fails the
        seeded AllowRule's forward-confirmed reverse-DNS check and never
        gets verdict=passed; it was flagged (27 requests, 89% 404). Real
        Googlebot IPs (66.249.x) in the same trace matched the AllowRule,
        got verdict=passed, and were excluded (see the previous test's
        sibling case). This is the property that makes verdict-scoping
        (rather than a UA or IP/CIDR rule) able to distinguish an impostor
        presenting an identical UA string from the real crawler: this test
        represents the impostor's outcome (verdict=allowed, since it did
        not match the AllowRule) and asserts it IS flagged.
        """
        ip = "45.45.237.69"
        _make_requests(
            ip,
            total=27,
            count_404=24,  # ~89%, matching the production trace
            verdict=Verdict.ALLOWED,
        )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].pattern == ip

    def test_empty_user_agent_scraper_is_caught(self):
        """A scraper sending no User-Agent at all is still caught.

        Production trace: 4.205.62.107 sent an empty User-Agent header and
        was flagged (446 requests, 100% 404, requesting randomly-named PHP
        paths such as /agg.php, /cp2.php). This detector has no UA-derived
        signal at all, unlike detect_ua_rotation and detect_cloud_spray's
        UA path, both of which are structurally blind to an empty or
        absent User-Agent.
        """
        ip = "4.205.62.107"
        for i in range(30):
            RequestLogFactory(
                ip_address=ip,
                user_agent="",
                path=f"/random-{i}.php",
                verdict=Verdict.ALLOWED,
                response_code=404,
                timestamp=timezone.now(),
            )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].pattern == ip

    def test_blocked_challenged_throttled_rows_do_not_dilute_denominator(self):
        """WAF-produced verdicts (blocked/challenged/throttled) never enter the ratio.

        An IP with 15 real, application-reaching 404s (below MIN_REQUESTS
        of 20 alone) plus 10 BLOCKED-verdict rows that, if wrongly counted,
        would push it over the 20-request floor. If the detector counted
        those rows, this IP would qualify (25 total >= 20); because it must
        exclude them, only 15 real requests remain, below the floor, so no
        rule is created. This is the genuine falsifiability check for the
        verdict-scoping filter: a detector that forgot the filter would
        create a rule here.
        """
        ip = "10.10.10.40"
        _make_requests(ip, total=15, count_404=15)
        # WAF-produced verdicts: never reached the view, response_code is
        # what the WAF itself returned (403 for blocked), not a genuine
        # application 404.
        for i in range(10):
            RequestLogFactory(
                ip_address=ip,
                path=f"/blocked-path-{i}/",
                verdict=Verdict.BLOCKED,
                response_code=403,
                timestamp=timezone.now(),
            )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []

    def test_challenged_and_throttled_rows_also_excluded(self):
        """CHALLENGED and THROTTLED rows are excluded from the denominator too.

        Mirrors the BLOCKED case: 15 real 404s plus 10 CHALLENGED and 10
        THROTTLED rows. If any of those entered the count, this IP (35
        total) would clear the 20-request floor; correctly excluded, only
        15 real requests remain and no rule is created.
        """
        ip = "10.10.10.50"
        _make_requests(ip, total=15, count_404=15)
        for i in range(10):
            RequestLogFactory(
                ip_address=ip,
                path=f"/challenged-path-{i}/",
                verdict=Verdict.CHALLENGED,
                response_code=302,
                timestamp=timezone.now(),
            )
        for i in range(10):
            RequestLogFactory(
                ip_address=ip,
                path=f"/throttled-path-{i}/",
                verdict=Verdict.THROTTLED,
                response_code=429,
                timestamp=timezone.now(),
            )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []


class TestDetectScraper404RatioDryRun:
    def test_dry_run_creates_nothing(self):
        """dry_run=True (BR-ANOM-006) writes nothing; check _state.adding, not pk.

        BlockRule.id is a UUIDField with default=uuid.uuid4, so pk is
        always populated even on an unsaved instance; _state.adding is the
        only reliable signal that a row was never written.
        """
        from django_waf.models import BlockRule

        ip = "10.10.10.60"
        _make_requests(ip, total=25, count_404=25)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio(window_minutes=180, dry_run=True)

        assert len(created) == 1
        assert created[0]._state.adding is True
        assert not BlockRule.objects.filter(rule_type=RuleType.IP, pattern=ip).exists()


class TestDetectScraper404RatioActionStaging:
    def test_default_action_is_challenge(self):
        """Default DJANGO_WAF_SCRAPER_404_ACTION_BLOCK=False stages at CHALLENGE."""
        ip = "10.10.10.70"
        _make_requests(ip, total=25, count_404=25)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_ACTION_BLOCK", False),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].action == RuleAction.CHALLENGE

    def test_action_block_true_produces_block_rule(self):
        """DJANGO_WAF_SCRAPER_404_ACTION_BLOCK=True produces a BLOCK rule."""
        ip = "10.10.10.80"
        _make_requests(ip, total=25, count_404=25)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_ACTION_BLOCK", True),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].action == RuleAction.BLOCK


class TestDetectScraper404RatioWindow:
    def test_window_minutes_default_reads_from_setting(self):
        """window_minutes=None falls back to DJANGO_WAF_SCRAPER_404_WINDOW_MINUTES."""
        ip = "10.10.10.90"
        _make_requests(ip, total=25, count_404=25)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_WINDOW_MINUTES", 180),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
        ):
            created = detect_scraper_404_ratio()

        assert len(created) == 1

    def test_requests_outside_window_are_excluded(self):
        """A request timestamped before the cutoff is not counted."""
        from datetime import timedelta

        ip = "10.10.10.100"
        old = timezone.now() - timedelta(hours=6)
        _make_requests(ip, total=25, count_404=25, timestamp=old)

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []


class TestDetectScraper404RatioNginxAllowRuleExclusion:
    """Regression coverage for #140/#135: the production incident this
    detector's verdict-scoping filter could not catch on its own, because a
    nginx-sourced row's verdict is inferred from the status code and can
    never be Verdict.PASSED. These tests would fail if the AllowRule
    exclusion at the counting stage were removed, proving it is load-bearing
    rather than redundant with the existing reached_app filter."""

    def test_verified_crawler_nginx_sourced_allowed_verdict_with_allow_rule_is_excluded(self):
        """The exact #140 shape: source=nginx_log, verdict=allowed (never
        passed, since nginx verdicts are inferred, not observed), 100% 404,
        WITH a matching active AllowRule. Must NOT be flagged.

        Without the fix this creates a rule, because reached_app's
        Verdict.PASSED exclusion never applies to a nginx-sourced row in
        the first place: the row is verdict=allowed, one of the two
        verdicts the base filter counts.
        """
        ip = "40.77.167.132"  # a real Bingbot address from the traced incident
        AllowRuleFactory(
            rule_type=RuleType.IP,
            match_type=MatchType.EXACT,
            pattern=ip,
            verify_rdns=False,
            is_active=True,
        )
        _make_requests(
            ip,
            total=34,
            count_404=34,
            verdict=Verdict.ALLOWED,
            source=RequestLogSource.NGINX_LOG,
        )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch(
                "django_waf.services.redis_client.get_redis_client",
                return_value=_make_redis(),
            ),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []

    def test_impostor_same_user_agent_but_no_allow_rule_match_is_still_flagged(self):
        """An impostor IP presents the identical User-Agent a seeded
        UA+rDNS AllowRule requires, but its PTR record does not
        forward-confirm (FCrDNS fails), so it never matches the AllowRule.
        Must still be flagged.

        Proves the fix preserves BR-ANOM-014's discrimination property
        (a real crawler is excluded, an impostor presenting the same UA is
        not) rather than switching the detector off for anyone claiming to
        be a crawler.
        """
        import socket

        crawler_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        AllowRuleFactory(
            rule_type=RuleType.UA,
            match_type=MatchType.CONTAINS,
            pattern="Googlebot",
            verify_rdns=True,
            rdns_pattern=r"\.googlebot\.com$|\.google\.com$",
            is_active=True,
        )

        impostor_ip = "45.45.237.69"
        _make_requests(
            impostor_ip,
            total=27,
            count_404=24,
            verdict=Verdict.ALLOWED,
            source=RequestLogSource.NGINX_LOG,
            user_agent=crawler_ua,
        )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch(
                "django_waf.services.redis_client.get_redis_client",
                return_value=_make_redis(),
            ),
            patch(
                "django_waf.services.rule_engine.socket.gethostbyaddr",
                side_effect=socket.herror("no PTR record"),
            ),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].pattern == impostor_ip

    def test_malicious_nginx_sourced_ip_with_no_allow_rule_at_all_is_still_flagged(self):
        """A malicious scraper, nginx-sourced, no AllowRule anywhere in the
        system. Must still be flagged: proves nginx rows remain counted and
        the detector was not quietly disabled by adding the AllowRule
        check."""
        ip = "4.205.62.107"
        _make_requests(
            ip,
            total=25,
            count_404=25,
            verdict=Verdict.ALLOWED,
            source=RequestLogSource.NGINX_LOG,
        )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch(
                "django_waf.services.redis_client.get_redis_client",
                return_value=_make_redis(),
            ),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert len(created) == 1
        assert created[0].pattern == ip

    def test_allow_rule_check_unavailable_fails_closed_and_does_not_flag(self):
        """When the AllowRule check cannot be evaluated at all (no Redis
        client obtainable), a qualifying IP is NOT flagged, even with no
        AllowRule in the system and a 100% 404 ratio that would otherwise
        create a rule.

        This is the fail-closed guarantee: an unverifiable check must never
        let a flag through, exactly as an unverifiable check must never let
        a request through elsewhere in this package (BR-EVAL-007).
        """
        ip = "10.10.10.200"
        _make_requests(
            ip,
            total=25,
            count_404=25,
            verdict=Verdict.ALLOWED,
            source=RequestLogSource.NGINX_LOG,
        )

        with (
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20),
            patch("django_waf.conf.DJANGO_WAF_SCRAPER_404_RATIO", 0.85),
            patch("django_waf.conf.DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24),
            patch(
                "django_waf.services.redis_client.get_redis_client",
                return_value=None,
            ),
        ):
            created = detect_scraper_404_ratio(window_minutes=180)

        assert created == []
