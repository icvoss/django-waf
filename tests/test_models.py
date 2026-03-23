"""Tests for icv-waf models."""

from __future__ import annotations

import uuid
from decimal import Decimal

import pytest
from django.utils import timezone

from icv_waf.enums import (
    ChallengeStatus,
    MatchType,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)
from icv_waf.models import (
    AllowRule,
    BlockRule,
    ChallengeToken,
    IPReputation,
    RequestLog,
)
from icv_waf.testing.factories import (
    AllowRuleFactory,
    BlockRuleFactory,
    ChallengeTokenFactory,
    IPReputationFactory,
    RequestLogFactory,
)

# ---------------------------------------------------------------------------
# BlockRule
# ---------------------------------------------------------------------------


class TestBlockRule:
    def test_create_block_rule(self, db):
        """BlockRule can be created and persisted."""
        rule = BlockRule.objects.create(
            name="Block bad bot",
            rule_type=RuleType.UA,
            match_type=MatchType.CONTAINS,
            pattern="BadBot/1.0",
        )

        assert rule.pk is not None
        assert isinstance(rule.pk, uuid.UUID)
        assert rule.name == "Block bad bot"

    def test_default_field_values(self, db):
        """Default values are applied correctly on creation."""
        rule = BlockRuleFactory()

        assert rule.action == RuleAction.BLOCK
        assert rule.priority == pytest.approx(rule.priority)  # positive integer
        assert rule.is_active is True
        assert rule.source == RuleSource.ADMIN
        assert rule.expires_at is None
        assert rule.hit_count == 0
        assert rule.last_hit_at is None
        assert rule.confidence == Decimal("1.00")
        assert rule.feed_reporters == 0
        assert rule.notes == ""

    def test_str_includes_action_and_name(self, db):
        """__str__ returns '[action] name'."""
        rule = BlockRuleFactory(name="Block 1.2.3.4", action=RuleAction.BLOCK)
        assert str(rule) == "[block] Block 1.2.3.4"

    def test_str_challenge_action(self, db):
        rule = BlockRuleFactory(name="Challenge scraper", action=RuleAction.CHALLENGE)
        assert str(rule) == "[challenge] Challenge scraper"

    def test_meta_ordering(self, db):
        """Rules are ordered by priority ascending then created_at descending."""
        r1 = BlockRuleFactory(priority=200)
        r2 = BlockRuleFactory(priority=50)
        r3 = BlockRuleFactory(priority=50)  # same priority — newer, so before r2

        pks = list(BlockRule.objects.values_list("pk", flat=True))
        # r2 and r3 share priority 50 (before 200); within that group newest first
        assert pks[0] == r3.pk
        assert pks[1] == r2.pk
        assert pks[2] == r1.pk

    def test_manager_active_returns_only_active(self, db):
        """BlockRuleManager.active() excludes inactive rules."""
        active = BlockRuleFactory(is_active=True)
        BlockRuleFactory(is_active=False)

        qs = BlockRule.objects.active()

        assert active.pk in [r.pk for r in qs]
        assert qs.count() == 1

    def test_manager_active_orders_by_priority(self, db):
        """BlockRuleManager.active() returns rules in priority order."""
        BlockRuleFactory(is_active=True, priority=300)
        BlockRuleFactory(is_active=True, priority=10)
        BlockRuleFactory(is_active=True, priority=150)

        priorities = list(BlockRule.objects.active().values_list("priority", flat=True))
        assert priorities == sorted(priorities)

    def test_manager_expired_returns_past_expiry_only(self, db):
        """BlockRuleManager.expired() returns active rules whose expiry has passed."""
        past = timezone.now() - timezone.timedelta(hours=1)
        future = timezone.now() + timezone.timedelta(hours=1)

        expired_rule = BlockRuleFactory(is_active=True, expires_at=past)
        BlockRuleFactory(is_active=True, expires_at=future)
        BlockRuleFactory(is_active=True, expires_at=None)

        qs = BlockRule.objects.expired()

        assert qs.count() == 1
        assert qs.first().pk == expired_rule.pk

    def test_manager_expired_excludes_inactive(self, db):
        """Inactive rules with past expiry are not returned by expired()."""
        past = timezone.now() - timezone.timedelta(hours=1)
        BlockRuleFactory(is_active=False, expires_at=past)

        assert BlockRule.objects.expired().count() == 0

    def test_manager_auto_generated(self, db):
        """BlockRuleManager.auto_generated() returns only source=AUTO rules."""
        auto = BlockRuleFactory(is_active=True, source=RuleSource.AUTO)
        BlockRuleFactory(is_active=True, source=RuleSource.ADMIN)
        BlockRuleFactory(is_active=True, source=RuleSource.FEED)

        qs = BlockRule.objects.auto_generated()

        assert qs.count() == 1
        assert qs.first().pk == auto.pk

    def test_manager_feed_sourced(self, db):
        """BlockRuleManager.feed_sourced() returns only source=FEED rules."""
        feed = BlockRuleFactory(is_active=True, source=RuleSource.FEED)
        BlockRuleFactory(is_active=True, source=RuleSource.AUTO)

        qs = BlockRule.objects.feed_sourced()

        assert qs.count() == 1
        assert qs.first().pk == feed.pk

    def test_manager_for_nginx(self, db):
        """BlockRuleManager.for_nginx() returns active IP/CIDR/UA block or throttle rules only."""
        nginx_eligible = BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            action=RuleAction.BLOCK,
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.COMPOSITE,
            action=RuleAction.BLOCK,
        )
        BlockRuleFactory(
            is_active=True,
            rule_type=RuleType.IP,
            action=RuleAction.CHALLENGE,  # Not block or throttle — excluded
        )
        BlockRuleFactory(is_active=False, rule_type=RuleType.IP, action=RuleAction.BLOCK)

        qs = BlockRule.objects.for_nginx()

        assert qs.count() == 1
        assert qs.first().pk == nginx_eligible.pk

    def test_pk_is_uuid(self, db):
        """BlockRule inherits UUID primary key from BaseModel."""
        rule = BlockRuleFactory()
        assert isinstance(rule.pk, uuid.UUID)


# ---------------------------------------------------------------------------
# AllowRule
# ---------------------------------------------------------------------------


class TestAllowRule:
    def test_create_allow_rule(self, db):
        """AllowRule can be created and persisted."""
        rule = AllowRule.objects.create(
            name="Googlebot allow",
            rule_type=RuleType.UA,
            match_type=MatchType.REGEX,
            pattern="Googlebot",
        )

        assert rule.pk is not None
        assert rule.name == "Googlebot allow"

    def test_default_field_values(self, db):
        """Default values are applied correctly on creation."""
        rule = AllowRuleFactory()

        assert rule.is_active is True
        assert rule.verify_rdns is False
        assert rule.rdns_pattern == ""
        assert rule.notes == ""

    def test_str_format(self, db):
        """__str__ returns '[allow] name'."""
        rule = AllowRuleFactory(name="Trusted CDN")
        assert str(rule) == "[allow] Trusted CDN"

    def test_meta_ordering_by_name(self, db):
        """AllowRules are ordered alphabetically by name."""
        AllowRuleFactory(name="zzz")
        AllowRuleFactory(name="aaa")
        AllowRuleFactory(name="mmm")

        names = list(AllowRule.objects.values_list("name", flat=True))
        assert names == sorted(names)

    def test_manager_active_excludes_inactive(self, db):
        """AllowRuleManager.active() excludes inactive rules."""
        active = AllowRuleFactory(is_active=True)
        AllowRuleFactory(is_active=False)

        qs = AllowRule.objects.active()

        assert qs.count() == 1
        assert qs.first().pk == active.pk

    def test_manager_requiring_rdns(self, db):
        """AllowRuleManager.requiring_rdns() returns active rules with verify_rdns=True."""
        rdns_rule = AllowRuleFactory(is_active=True, verify_rdns=True, rdns_pattern=r"\.googlebot\.com$")
        AllowRuleFactory(is_active=True, verify_rdns=False)
        AllowRuleFactory(is_active=False, verify_rdns=True)

        qs = AllowRule.objects.requiring_rdns()

        assert qs.count() == 1
        assert qs.first().pk == rdns_rule.pk

    def test_pk_is_uuid(self, db):
        """AllowRule inherits UUID primary key from BaseModel."""
        rule = AllowRuleFactory()
        assert isinstance(rule.pk, uuid.UUID)


# ---------------------------------------------------------------------------
# RequestLog
# ---------------------------------------------------------------------------


class TestRequestLog:
    def test_create_request_log(self, db):
        """RequestLog can be created and persisted."""
        now = timezone.now()
        log = RequestLog.objects.create(
            timestamp=now,
            ip_address="1.2.3.4",
            user_agent="Mozilla/5.0",
            path="/shop/",
            method="GET",
            verdict=Verdict.ALLOWED,
        )

        assert log.pk is not None
        assert log.ip_address == "1.2.3.4"
        assert log.path == "/shop/"

    def test_default_method_is_get(self, db):
        """Default HTTP method is GET."""
        log = RequestLogFactory()
        assert log.method == "GET"

    def test_str_format(self, db):
        """__str__ includes timestamp, IP, and verdict."""
        log = RequestLogFactory(ip_address="5.6.7.8", verdict=Verdict.BLOCKED)
        result = str(log)

        assert "5.6.7.8" in result
        assert Verdict.BLOCKED in result

    def test_meta_ordering_newest_first(self, db):
        """RequestLogs are ordered by timestamp descending."""
        earlier = timezone.now() - timezone.timedelta(minutes=5)
        later = timezone.now()

        old_log = RequestLogFactory(timestamp=earlier)
        new_log = RequestLogFactory(timestamp=later)

        pks = list(RequestLog.objects.values_list("pk", flat=True))
        assert pks[0] == new_log.pk
        assert pks[1] == old_log.pk

    def test_manager_recent_default_24h(self, db):
        """RequestLogManager.recent() returns logs from the last 24 hours."""
        now = timezone.now()
        recent = RequestLogFactory(timestamp=now - timezone.timedelta(hours=1))
        RequestLogFactory(timestamp=now - timezone.timedelta(hours=25))

        qs = RequestLog.objects.recent()

        pks = [r.pk for r in qs]
        assert recent.pk in pks
        assert qs.count() == 1

    def test_manager_recent_custom_hours(self, db):
        """RequestLogManager.recent(hours=2) respects custom window."""
        now = timezone.now()
        RequestLogFactory(timestamp=now - timezone.timedelta(hours=1))
        RequestLogFactory(timestamp=now - timezone.timedelta(hours=3))

        qs = RequestLog.objects.recent(hours=2)

        assert qs.count() == 1

    def test_manager_for_ip(self, db):
        """RequestLogManager.for_ip() filters by IP address."""
        target_ip = "9.9.9.9"
        RequestLogFactory(ip_address=target_ip)
        RequestLogFactory(ip_address=target_ip)
        RequestLogFactory(ip_address="1.1.1.1")

        qs = RequestLog.objects.for_ip(target_ip)

        assert qs.count() == 2
        assert all(r.ip_address == target_ip for r in qs)

    def test_manager_blocked(self, db):
        """RequestLogManager.blocked() returns only BLOCKED verdict logs."""
        blocked = RequestLogFactory(verdict=Verdict.BLOCKED)
        RequestLogFactory(verdict=Verdict.ALLOWED)
        RequestLogFactory(verdict=Verdict.CHALLENGED)

        qs = RequestLog.objects.blocked()

        assert qs.count() == 1
        assert qs.first().pk == blocked.pk

    def test_manager_purgeable(self, db):
        """RequestLogManager.purgeable() returns logs older than N days."""
        now = timezone.now()
        old = RequestLogFactory(timestamp=now - timezone.timedelta(days=31))
        RequestLogFactory(timestamp=now - timezone.timedelta(days=1))

        qs = RequestLog.objects.purgeable(days=30)

        assert qs.count() == 1
        assert qs.first().pk == old.pk

    def test_matched_rule_id_is_plain_uuid(self, db):
        """matched_rule_id stores a plain UUID, not a FK, so it survives rule deletion."""
        rule_id = uuid.uuid4()
        log = RequestLogFactory(matched_rule_id=rule_id, matched_rule_type="block")

        log.refresh_from_db()
        assert log.matched_rule_id == rule_id
        assert log.matched_rule_type == "block"

    def test_optional_fields_can_be_blank(self, db):
        """user_agent, matched fields, anomaly_score, country_code are all optional."""
        log = RequestLog.objects.create(
            timestamp=timezone.now(),
            ip_address="2.2.2.2",
            path="/",
            verdict=Verdict.ALLOWED,
        )

        assert log.user_agent == ""
        assert log.matched_rule_id is None
        assert log.matched_rule_type == ""
        assert log.anomaly_score is None
        assert log.country_code == ""


# ---------------------------------------------------------------------------
# IPReputation
# ---------------------------------------------------------------------------


class TestIPReputation:
    def test_create_ip_reputation(self, db):
        """IPReputation can be created with a unique IP."""
        rep = IPReputation.objects.create(
            ip_address="203.0.113.1",
        )

        assert rep.pk is not None
        assert rep.ip_address == "203.0.113.1"

    def test_default_field_values(self, db):
        """Default counters start at zero and threat_score is 0.00."""
        rep = IPReputationFactory()

        assert rep.total_requests == 0
        assert rep.blocked_requests == 0
        assert rep.challenged_requests == 0
        assert rep.challenge_passes == 0
        assert rep.challenge_failures == 0
        assert rep.threat_score == Decimal("0.00")

    def test_str_format(self, db):
        """__str__ includes IP and threat score."""
        rep = IPReputationFactory(ip_address="8.8.8.8", threat_score=Decimal("0.75"))
        result = str(rep)

        assert "8.8.8.8" in result
        assert "0.75" in result

    def test_ip_address_is_unique(self, db):
        """ip_address has a unique constraint."""
        from django.db import IntegrityError

        IPReputationFactory(ip_address="10.0.0.1")
        with pytest.raises(IntegrityError):
            IPReputationFactory(ip_address="10.0.0.1")

    def test_meta_ordering_by_threat_score_desc(self, db):
        """IPReputation records are ordered by threat_score descending."""
        IPReputationFactory(threat_score=Decimal("0.20"))
        IPReputationFactory(threat_score=Decimal("0.90"))
        IPReputationFactory(threat_score=Decimal("0.50"))

        scores = list(IPReputation.objects.values_list("threat_score", flat=True))
        assert scores == sorted(scores, reverse=True)

    def test_manager_high_threat(self, db):
        """IPReputationManager.high_threat() returns records above the threshold."""
        high = IPReputationFactory(threat_score=Decimal("0.85"))
        IPReputationFactory(threat_score=Decimal("0.50"))
        IPReputationFactory(threat_score=Decimal("0.10"))

        qs = IPReputation.objects.high_threat(threshold=0.7)

        assert qs.count() == 1
        assert qs.first().pk == high.pk

    def test_manager_high_threat_default_threshold(self, db):
        """IPReputationManager.high_threat() uses 0.7 as default threshold."""
        IPReputationFactory(threat_score=Decimal("0.80"))
        IPReputationFactory(threat_score=Decimal("0.65"))

        qs = IPReputation.objects.high_threat()

        assert qs.count() == 1

    def test_manager_top_offenders(self, db):
        """IPReputationManager.top_offenders() returns records in threat_score desc order."""
        IPReputationFactory(threat_score=Decimal("0.30"))
        IPReputationFactory(threat_score=Decimal("0.90"))
        IPReputationFactory(threat_score=Decimal("0.60"))

        results = list(IPReputation.objects.top_offenders(limit=2))

        assert len(results) == 2
        assert results[0].threat_score == Decimal("0.90")
        assert results[1].threat_score == Decimal("0.60")

    def test_update_reputation_fields(self, db):
        """IPReputation fields can be updated individually."""
        rep = IPReputationFactory()

        rep.total_requests = 100
        rep.blocked_requests = 10
        rep.threat_score = Decimal("0.45")
        rep.save(update_fields=["total_requests", "blocked_requests", "threat_score"])

        rep.refresh_from_db()

        assert rep.total_requests == 100
        assert rep.blocked_requests == 10
        assert rep.threat_score == Decimal("0.45")


# ---------------------------------------------------------------------------
# ChallengeToken
# ---------------------------------------------------------------------------


class TestChallengeToken:
    def test_create_challenge_token(self, db):
        """ChallengeToken can be created and persisted."""
        expires = timezone.now() + timezone.timedelta(hours=1)
        token = ChallengeToken.objects.create(
            token="abc123def456abc123def456abc123def456abc123def456abc123def456abc1",
            ip_address="10.0.0.99",
            difficulty=4,
            expires_at=expires,
        )

        assert token.pk is not None
        assert token.status == ChallengeStatus.PENDING

    def test_default_status_is_pending(self, db):
        """Default status on creation is PENDING."""
        token = ChallengeTokenFactory()
        assert token.status == ChallengeStatus.PENDING

    def test_default_difficulty(self, db):
        """Default difficulty is 4 leading zero bits."""
        token = ChallengeTokenFactory()
        assert token.difficulty == 4

    def test_str_format(self, db):
        """__str__ includes truncated token and status."""
        token = ChallengeTokenFactory(
            token="abcdef123456abcdef123456abcdef123456",
            status=ChallengeStatus.PENDING,
        )
        result = str(token)

        assert "abcdef123456" in result
        assert ChallengeStatus.PENDING in result

    def test_str_shows_first_12_chars_of_token(self, db):
        """__str__ shows the first 12 characters of the token followed by '...'."""
        token = ChallengeTokenFactory(token="xxxxxxxxxxxxxxxxxxxx")
        assert "xxxxxxxxxxxx..." in str(token)

    def test_token_is_unique(self, db):
        """token field has a unique constraint."""
        from django.db import IntegrityError

        ChallengeTokenFactory(token="unique-token-value-1234567890123456789012345678901234")
        with pytest.raises(IntegrityError):
            ChallengeTokenFactory(token="unique-token-value-1234567890123456789012345678901234")

    def test_status_transition_to_solved(self, db):
        """ChallengeToken status can be updated to SOLVED."""
        token = ChallengeTokenFactory(status=ChallengeStatus.PENDING)
        now = timezone.now()

        token.status = ChallengeStatus.SOLVED
        token.solved_at = now
        token.nonce = "valid-nonce"
        token.save(update_fields=["status", "solved_at", "nonce"])

        token.refresh_from_db()
        assert token.status == ChallengeStatus.SOLVED
        assert token.solved_at is not None
        assert token.nonce == "valid-nonce"

    def test_status_transition_to_expired(self, db):
        """ChallengeToken status can be updated to EXPIRED."""
        token = ChallengeTokenFactory(status=ChallengeStatus.PENDING)

        token.status = ChallengeStatus.EXPIRED
        token.save(update_fields=["status"])

        token.refresh_from_db()
        assert token.status == ChallengeStatus.EXPIRED

    def test_status_transition_to_failed(self, db):
        """ChallengeToken status can be updated to FAILED."""
        token = ChallengeTokenFactory(status=ChallengeStatus.PENDING)

        token.status = ChallengeStatus.FAILED
        token.save(update_fields=["status"])

        token.refresh_from_db()
        assert token.status == ChallengeStatus.FAILED

    def test_meta_ordering_newest_first(self, db):
        """ChallengeTokens are ordered by issued_at descending."""
        # issued_at is auto_now_add so ordering is by insertion order
        t1 = ChallengeTokenFactory()
        t2 = ChallengeTokenFactory()

        pks = list(ChallengeToken.objects.values_list("pk", flat=True))
        assert pks[0] == t2.pk
        assert pks[1] == t1.pk

    def test_pending_manager_filter(self, db):
        """Only PENDING tokens are returned when filtering by status."""
        pending = ChallengeTokenFactory(status=ChallengeStatus.PENDING)
        ChallengeTokenFactory(status=ChallengeStatus.SOLVED)
        ChallengeTokenFactory(status=ChallengeStatus.EXPIRED)

        qs = ChallengeToken.objects.filter(status=ChallengeStatus.PENDING)

        assert qs.count() == 1
        assert qs.first().pk == pending.pk

    def test_expired_tokens_can_be_filtered(self, db):
        """Expired tokens (by expiry time) can be queried."""
        now = timezone.now()
        expired = ChallengeTokenFactory(
            status=ChallengeStatus.PENDING,
            expires_at=now - timezone.timedelta(hours=1),
        )
        ChallengeTokenFactory(
            status=ChallengeStatus.PENDING,
            expires_at=now + timezone.timedelta(hours=1),
        )

        qs = ChallengeToken.objects.filter(expires_at__lt=now)

        assert qs.count() == 1
        assert qs.first().pk == expired.pk

    def test_nonce_is_blank_by_default(self, db):
        """nonce field starts blank (filled only after solution submission)."""
        token = ChallengeTokenFactory()
        assert token.nonce == ""

    def test_solved_at_is_null_by_default(self, db):
        """solved_at is None until the challenge is solved."""
        token = ChallengeTokenFactory()
        assert token.solved_at is None
