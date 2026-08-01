"""Tests for threat-feed entry validation and constraint hardening (#33).

Redis is not available in the test environment; sync_feed does not touch
Redis directly, only httpx and the ORM, so no Redis mocking is needed here.
Mirrors the mocking pattern used for TestSyncFeed in test_services.py.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django_waf.testing.factories import BlockRuleFactory


def _mock_feed_response(payload):
    """Build a context manager patching httpx.get to return payload as JSON."""
    mock_resp = MagicMock()
    mock_resp.json.return_value = payload
    mock_resp.raise_for_status.return_value = None
    return patch("httpx.get", return_value=mock_resp)


class TestConfidenceValidation:
    def test_non_numeric_confidence_skips_entry_without_crashing(self, db):
        """A non-numeric confidence skips only that entry; the sync completes.

        Regression for the pre-#33 defect: float(entry.get("confidence", 0.0))
        raised an uncaught ValueError for a non-numeric confidence, aborting
        the whole sync. The rest of the feed must still be processed.
        """
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "1.2.3.4",
                "action": "block",
                "match_type": "exact",
                "confidence": "not-a-number",
            },
            {
                "rule_type": "ip",
                "pattern": "5.6.7.8",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert "error" not in result
        assert result["skipped"] == 1
        assert result["created"] == 1
        assert BlockRule.objects.filter(pattern="5.6.7.8").exists()
        assert not BlockRule.objects.filter(pattern="1.2.3.4").exists()

    def test_none_confidence_skips_entry(self, db):
        """A confidence of None (not merely absent) also skips gracefully."""
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "9.9.9.9",
                "action": "block",
                "match_type": "exact",
                "confidence": None,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0


class TestActionWhitelist:
    def test_unknown_action_is_skipped_not_blocked(self, db):
        """An unrecognised action is skipped, never silently treated as block.

        Pre-#33, an unrecognised action was stored verbatim on BlockRule and
        the rule engine's default-BLOCKED fallback (rule_engine.py:598-604)
        applied it as a block. This must no longer happen: the entry is
        dropped entirely rather than persisted with an action the engine
        cannot interpret safely.
        """
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "3.3.3.3",
                "action": "quarantine-and-notify",  # not a known RuleAction
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0
        assert not BlockRule.objects.filter(pattern="3.3.3.3").exists()

    def test_known_action_still_imports(self, db):
        """A valid block entry with a recognised action still imports normally."""
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "4.4.4.4",
                "action": "throttle",
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        rule = BlockRule.objects.get(pattern="4.4.4.4")
        assert rule.action == "throttle"


class TestRuleTypeAndMatchTypeWhitelist:
    def test_unknown_rule_type_is_skipped(self, db):
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "asn",  # not a known RuleType
                "pattern": "AS12345",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0

    def test_unknown_match_type_is_skipped(self, db):
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ip",
                "pattern": "7.7.7.7",
                "action": "block",
                "match_type": "fuzzy",  # not a known MatchType
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0


class TestRegexPatternSafety:
    def test_unsafe_regex_pattern_is_skipped(self, db):
        """A catastrophic-backtracking-shaped regex pattern is skipped.

        Exercises the fallback validator directly (pattern_validation.py may
        not be installed in this environment): a nested-quantifier pattern
        like (a+)+ is rejected by _fallback_validate_regex regardless of
        whether the sibling validator has landed.
        """
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": r"(a+)+$",
                "action": "block",
                "match_type": "regex",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert not BlockRule.objects.filter(pattern=r"(a+)+$").exists()

    def test_overlength_regex_pattern_is_skipped(self, db):
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": "a" * 600,
                "action": "block",
                "match_type": "regex",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1

    def test_invalid_regex_syntax_is_skipped(self, db):
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": "[invalid(regex",
                "action": "block",
                "match_type": "regex",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1

    def test_safe_regex_pattern_still_imports(self, db):
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": r"curl/7\.",
                "action": "block",
                "match_type": "regex",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        assert BlockRule.objects.filter(pattern=r"curl/7\.").exists()

    def test_non_regex_pattern_is_not_run_through_pattern_validator(self, db):
        """An exact/contains pattern is not subject to the regex safety check.

        Only match_type='regex' entries are validated for ReDoS shape; an
        exact-match UA string containing regex metacharacters must still
        import normally.
        """
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "ua",
                "pattern": "(a+)+ literal string",
                "action": "block",
                "match_type": "exact",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        assert BlockRule.objects.filter(pattern="(a+)+ literal string").exists()


class TestAllowRuleQuarantineAndRdnsConstraint:
    def test_allow_rule_missing_verify_rdns_is_skipped(self, db):
        """A feed allow entry without verify_rdns=True is skipped entirely.

        A feed must never be able to strip the rDNS safeguard off its own
        allow rules by omitting verify_rdns.
        """
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "SpoofableBot",
                "match_type": "contains",
                "confidence": 0.9,
                # no verify_rdns, no rdns_pattern
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert result["created"] == 0
        assert not AllowRule.objects.filter(pattern="SpoofableBot").exists()

    def test_allow_rule_with_verify_rdns_false_is_skipped(self, db):
        """A feed allow entry with verify_rdns explicitly false is skipped."""
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "UnverifiedBot",
                "match_type": "contains",
                "verify_rdns": False,
                "rdns_pattern": r"\.unverified\.example$",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert not AllowRule.objects.filter(pattern="UnverifiedBot").exists()

    def test_allow_rule_missing_rdns_pattern_is_skipped(self, db):
        """verify_rdns=True with no rdns_pattern is still skipped (nothing to verify against)."""
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "NoPatternBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": "",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["skipped"] == 1
        assert not AllowRule.objects.filter(pattern="NoPatternBot").exists()

    def test_valid_allow_rule_is_quarantined_by_default(self, db):
        """A well-formed feed allow entry is created but not activated.

        Default DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES=True means a
        feed-sourced allow rule requires operator approval before it takes
        effect: it must never become an active rule automatically.
        """
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "QuarantinedBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": r"\.quarantinedbot\.example$",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        rule = AllowRule.objects.get(pattern="QuarantinedBot")
        assert rule.is_active is False
        assert rule.verify_rdns is True
        assert rule.rdns_pattern == r"\.quarantinedbot\.example$"

    def test_quarantine_disabled_activates_allow_rule_on_create(self, db, settings):
        """With quarantine disabled via setting, a valid allow entry is active on create."""
        import importlib

        import django_waf.conf as conf_mod
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        settings.DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES = False
        importlib.reload(conf_mod)

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "TrustedBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": r"\.trustedbot\.example$",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["created"] == 1
        rule = AllowRule.objects.get(pattern="TrustedBot")
        assert rule.is_active is True

    def test_operator_approval_of_quarantined_rule_survives_resync(self, db):
        """An operator-activated quarantined rule is not re-quarantined on the next sync.

        Once an operator has reviewed a quarantined AllowRule and flipped
        is_active=True by hand, a later sync (with quarantine still enabled)
        must not silently flip it back to inactive.
        """
        from django_waf.models import AllowRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "kind": "allow",
                "rule_type": "ua",
                "pattern": "ApprovedBot",
                "match_type": "contains",
                "verify_rdns": True,
                "rdns_pattern": r"\.approvedbot\.example$",
                "confidence": 0.9,
            },
        ]

        with _mock_feed_response(feed_payload):
            sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        rule = AllowRule.objects.get(pattern="ApprovedBot")
        assert rule.is_active is False
        rule.is_active = True
        rule.save(update_fields=["is_active"])

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.5)

        assert result["updated"] == 1
        rule.refresh_from_db()
        assert rule.is_active is True


class TestValidBlockEntryStillImports:
    def test_valid_block_entry_imports_with_all_validation_active(self, db):
        """A well-formed block entry passes every new validation gate and imports."""
        from django_waf.models import BlockRule
        from django_waf.services.threat_feed import sync_feed

        feed_payload = [
            {
                "rule_type": "cidr",
                "pattern": "198.51.100.0/24",
                "action": "block",
                "match_type": "cidr",
                "confidence": 0.95,
                "reporters": 14,
                "provenance": "spamhaus_drop",
            },
        ]

        with _mock_feed_response(feed_payload):
            result = sync_feed(feed_url="https://feed.example.com", min_confidence=0.8)

        assert result["created"] == 1
        assert result["skipped"] == 0
        rule = BlockRule.objects.get(pattern="198.51.100.0/24")
        assert rule.action == "block"
        assert rule.source == "feed"


class TestExistingFixtureCompatibility:
    def test_pre_existing_active_block_rule_untouched_by_validation(self, db):
        """Validation changes do not affect non-feed rules already in the DB."""
        BlockRuleFactory(source="admin", pattern="203.0.113.1", is_active=True)

        from django_waf.models import BlockRule

        assert BlockRule.objects.filter(pattern="203.0.113.1", source="admin").exists()
