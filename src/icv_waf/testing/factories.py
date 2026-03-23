"""factory-boy factories for icv-waf models."""

from __future__ import annotations

import uuid
from decimal import Decimal

import factory
import factory.django
from django.utils import timezone

from icv_waf.enums import (
    ChallengeStatus,
    MatchType,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)


class BlockRuleFactory(factory.django.DjangoModelFactory):
    """Factory for BlockRule.

    Produces active, admin-created IP-exact block rules by default.
    Override fields as needed for specific test scenarios.
    """

    name = factory.Sequence(lambda n: f"block-rule-{n}")
    rule_type = RuleType.IP
    match_type = MatchType.EXACT
    pattern = factory.Sequence(lambda n: f"10.0.{n // 256}.{n % 256}")
    action = RuleAction.BLOCK
    priority = factory.Sequence(lambda n: 100 + n)
    is_active = True
    source = RuleSource.ADMIN
    expires_at = None
    hit_count = 0
    last_hit_at = None
    confidence = Decimal("1.00")
    feed_first_seen = None
    feed_reporters = 0
    notes = ""

    class Meta:
        model = "icv_waf.BlockRule"


class AllowRuleFactory(factory.django.DjangoModelFactory):
    """Factory for AllowRule.

    Produces active, admin-created IP-exact allow rules by default.
    """

    name = factory.Sequence(lambda n: f"allow-rule-{n}")
    rule_type = RuleType.IP
    match_type = MatchType.EXACT
    pattern = factory.Sequence(lambda n: f"192.168.{n // 256}.{n % 256}")
    verify_rdns = False
    rdns_pattern = ""
    is_active = True
    notes = ""

    class Meta:
        model = "icv_waf.AllowRule"


class RequestLogFactory(factory.django.DjangoModelFactory):
    """Factory for RequestLog.

    Produces log entries with an ALLOWED verdict for the current time by default.
    """

    timestamp = factory.LazyFunction(timezone.now)
    ip_address = factory.Sequence(lambda n: f"10.1.{n // 256}.{n % 256}")
    user_agent = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    path = factory.Sequence(lambda n: f"/page/{n}/")
    method = "GET"
    verdict = Verdict.ALLOWED
    matched_rule_id = None
    matched_rule_type = ""
    anomaly_score = None
    response_code = 200
    country_code = ""

    class Meta:
        model = "icv_waf.RequestLog"


class IPReputationFactory(factory.django.DjangoModelFactory):
    """Factory for IPReputation.

    Produces a clean (zero-threat-score) reputation record by default.
    """

    ip_address = factory.Sequence(lambda n: f"172.16.{n // 256}.{n % 256}")
    total_requests = 0
    blocked_requests = 0
    challenged_requests = 0
    challenge_passes = 0
    challenge_failures = 0
    distinct_ua_count = 1
    threat_score = Decimal("0.00")
    last_seen_at = factory.LazyFunction(timezone.now)
    window_start = None
    window_end = None

    class Meta:
        model = "icv_waf.IPReputation"


class ChallengeTokenFactory(factory.django.DjangoModelFactory):
    """Factory for ChallengeToken.

    Produces a PENDING challenge valid for 24 hours by default.
    """

    token = factory.LazyFunction(lambda: uuid.uuid4().hex + uuid.uuid4().hex)
    ip_address = factory.Sequence(lambda n: f"10.2.{n // 256}.{n % 256}")
    difficulty = 4
    nonce = ""
    status = ChallengeStatus.PENDING
    expires_at = factory.LazyFunction(lambda: timezone.now() + timezone.timedelta(hours=24))
    solved_at = None

    class Meta:
        model = "icv_waf.ChallengeToken"
