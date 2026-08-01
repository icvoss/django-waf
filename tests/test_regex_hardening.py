"""Tests for UA regex hardening (#28).

Covers two things:

1. django_waf.services.pattern_validation.validate_ua_regex_pattern —
   write-time rejection of catastrophic-backtracking patterns and
   over-length patterns, and acceptance of a legitimate pattern. Exercised
   directly and via the BlockRuleAdminForm/AllowRuleAdminForm clean_pattern
   hook in django_waf.admin.
2. django_waf.services.rule_engine — UA regex matching consults the
   compiled-pattern cache instead of recompiling the raw pattern on every
   call.
"""

from __future__ import annotations

import re
from unittest.mock import MagicMock, patch

import pytest

from django_waf.admin import AllowRuleAdminForm, BlockRuleAdminForm
from django_waf.services.pattern_validation import (
    MAX_PATTERN_LENGTH,
    PatternValidationError,
    validate_ua_regex_pattern,
)
from django_waf.testing.factories import BlockRuleFactory

# ---------------------------------------------------------------------------
# validate_ua_regex_pattern — direct unit tests
# ---------------------------------------------------------------------------


class TestValidateUaRegexPattern:
    @pytest.mark.parametrize(
        "pattern",
        [
            r"(a+)+",
            r"(a*)*",
            r"(.*)*",
            r"(.+)+",
            r"(?:a+)+",
            r"(a|ab)+",
            r"(a|a)*",
        ],
    )
    def test_catastrophic_pattern_is_rejected(self, pattern):
        """A pattern with a nested quantifier or quantified alternation is rejected."""
        with pytest.raises(PatternValidationError):
            validate_ua_regex_pattern(pattern)

    @pytest.mark.parametrize(
        "pattern",
        [
            r"BadBot/\d+",
            r"python-requests",
            r"Mozilla.*Chrome/\d+",
            r"(Googlebot|Bingbot)",
            r"(GPTBot|CCBot|ClaudeBot)/\d+\.\d+",
        ],
    )
    def test_valid_pattern_is_accepted(self, pattern):
        """A well-formed, non-catastrophic pattern passes validation."""
        validate_ua_regex_pattern(pattern)  # does not raise

    def test_over_length_pattern_is_rejected(self):
        with pytest.raises(PatternValidationError, match="exceeds the maximum length"):
            validate_ua_regex_pattern("a" * (MAX_PATTERN_LENGTH + 1))

    def test_pattern_at_max_length_is_accepted(self):
        """A pattern exactly at the boundary is accepted (not off-by-one)."""
        pattern = "a" * MAX_PATTERN_LENGTH
        validate_ua_regex_pattern(pattern)  # does not raise

    def test_empty_pattern_is_rejected(self):
        with pytest.raises(PatternValidationError, match="must not be empty"):
            validate_ua_regex_pattern("")

    def test_invalid_regex_syntax_is_rejected(self):
        with pytest.raises(PatternValidationError, match="not a valid regular expression"):
            validate_ua_regex_pattern("[unclosed")

    def test_unquantified_alternation_is_accepted(self):
        """A plain alternation group with no trailing quantifier is not
        flagged — the risk is specifically a *quantified* alternation."""
        validate_ua_regex_pattern(r"(Googlebot|Bingbot|DuckDuckBot)")  # does not raise


# ---------------------------------------------------------------------------
# Admin form validation (BlockRuleAdminForm / AllowRuleAdminForm)
# ---------------------------------------------------------------------------


class TestBlockRuleAdminFormPatternValidation:
    def _form_data(self, **overrides) -> dict:
        data = {
            "name": "test-rule",
            "rule_type": "ua",
            "match_type": "regex",
            "pattern": r"BadBot/\d+",
            "action": "block",
            "priority": "100",
            "is_active": "on",
            "source": "admin",
            "confidence": "1.00",
            "feed_reporters": "0",
            "notes": "",
        }
        data.update(overrides)
        return data

    @pytest.mark.django_db
    def test_catastrophic_pattern_is_rejected_at_form_validation(self):
        form = BlockRuleAdminForm(data=self._form_data(pattern=r"(a+)+"))

        assert form.is_valid() is False
        assert "pattern" in form.errors

    @pytest.mark.django_db
    def test_valid_pattern_is_accepted_at_form_validation(self):
        form = BlockRuleAdminForm(data=self._form_data(pattern=r"BadBot/\d+"))

        assert form.is_valid() is True

    @pytest.mark.django_db
    def test_over_length_pattern_is_rejected_at_form_validation(self):
        form = BlockRuleAdminForm(data=self._form_data(pattern="a" * (MAX_PATTERN_LENGTH + 1)))

        assert form.is_valid() is False
        assert "pattern" in form.errors

    @pytest.mark.django_db
    def test_non_ua_rule_type_skips_regex_validation(self):
        """An IP/CIDR rule's pattern is never a regex — the catastrophic-pattern
        check only applies to rule_type='ua' + match_type='regex'."""
        form = BlockRuleAdminForm(
            self._form_data(
                rule_type="ip",
                match_type="exact",
                pattern="(a+)+",  # would be catastrophic as a UA regex; irrelevant here
            )
        )

        assert form.is_valid() is True


class TestAllowRuleAdminFormPatternValidation:
    def _form_data(self, **overrides) -> dict:
        data = {
            "name": "test-allow-rule",
            "rule_type": "ua",
            "match_type": "regex",
            "pattern": r"Googlebot/\d+",
            "verify_rdns": "",
            "rdns_pattern": "",
            "is_active": "on",
            "source": "admin",
            "confidence": "1.00",
            "feed_reporters": "0",
            "notes": "",
        }
        data.update(overrides)
        return data

    @pytest.mark.django_db
    def test_catastrophic_pattern_is_rejected_at_form_validation(self):
        form = AllowRuleAdminForm(data=self._form_data(pattern=r"(.*)*"))

        assert form.is_valid() is False
        assert "pattern" in form.errors

    @pytest.mark.django_db
    def test_valid_pattern_is_accepted_at_form_validation(self):
        form = AllowRuleAdminForm(data=self._form_data(pattern=r"Googlebot/\d+"))

        assert form.is_valid() is True


# ---------------------------------------------------------------------------
# rule_engine — matching uses the compiled cache instead of recompiling
# ---------------------------------------------------------------------------


class TestMatchingUsesCompiledCache:
    def setup_method(self):
        """Reset the module-level compiled-pattern cache before each test.

        The cache is content-addressed (keyed on the pattern string) and
        persists for the life of the process by design (#28) — it is not
        reset by the shared autouse rule-cache fixture in conftest.py,
        which only resets the in-process RuleCache (_process_cache), a
        different cache. Tests that assert on compile *counts* need a
        clean slate so a pattern reused by an earlier test doesn't produce
        a spurious cache hit.
        """
        import django_waf.services.rule_engine as rule_engine_mod

        rule_engine_mod._ua_pattern_cache.clear()

    def teardown_method(self):
        import django_waf.services.rule_engine as rule_engine_mod

        rule_engine_mod._ua_pattern_cache.clear()

    def test_match_ua_compiles_pattern_once_across_repeated_calls(self):
        """Calling _match_ua repeatedly with the same regex pattern compiles
        it once, not once per call."""
        from django_waf.services.rule_engine import _match_ua

        pattern = r"EvilBot/\d+"
        with patch("django_waf.services.rule_engine.re.compile", wraps=re.compile) as mock_compile:
            assert _match_ua("EvilBot/1", pattern, "regex") is True
            assert _match_ua("EvilBot/2", pattern, "regex") is True
            assert _match_ua("SomethingElse", pattern, "regex") is False

        mock_compile.assert_called_once()

    def test_ua_regex_set_entry_is_consulted_not_recompiled(self):
        """A pattern pre-compiled into RuleCache.ua_regex_set by
        _compile_ua_patterns (as happens on a rule-cache rebuild) is found
        by _match_ua's cache lookup rather than being recompiled."""
        from django_waf.services.rule_engine import _compile_ua_patterns, _match_ua

        rules = [
            {
                "id": "00000000-0000-0000-0000-000000000099",
                "rule_type": "ua",
                "match_type": "regex",
                "pattern": r"NastyCrawler/\d+",
                "action": "block",
                "priority": 100,
            }
        ]

        ua_regex_set = _compile_ua_patterns(rules)
        assert len(ua_regex_set) == 1

        with patch("django_waf.services.rule_engine.re.compile", wraps=re.compile) as mock_compile:
            result = _match_ua("NastyCrawler/3", r"NastyCrawler/\d+", "regex")

        assert result is True
        # The pattern was already memoised by _compile_ua_patterns above;
        # _match_ua's lookup must not trigger a second compile.
        mock_compile.assert_not_called()

    def test_invalid_pattern_is_memoised_as_non_match_not_recompiled(self):
        """An invalid regex pattern compiles (and fails) once, then every
        subsequent call is a cache hit returning False without retrying
        compilation."""
        from django_waf.services.rule_engine import _match_ua

        pattern = "[unclosed"
        with patch("django_waf.services.rule_engine.re.compile", wraps=re.compile) as mock_compile:
            assert _match_ua("anything", pattern, "regex") is False
            assert _match_ua("anything else", pattern, "regex") is False

        mock_compile.assert_called_once()

    @pytest.mark.django_db
    def test_load_rule_cache_populates_pattern_cache_from_db_rule(self):
        """A UA regex BlockRule loaded via load_rule_cache populates the
        compiled-pattern cache, and a subsequent _match_ua call for the
        same pattern is a cache hit."""
        import django_waf.services.rule_engine as rule_engine_mod
        from django_waf.enums import MatchType, RuleType
        from django_waf.services.rule_engine import _match_ua, load_rule_cache

        pattern = r"KnownBad/\d+"
        BlockRuleFactory(is_active=True, rule_type=RuleType.UA, match_type=MatchType.REGEX, pattern=pattern)

        redis = MagicMock()
        redis.get.return_value = None

        cache = load_rule_cache(redis)
        assert len(cache.ua_regex_set) == 1
        assert (pattern, "regex") in rule_engine_mod._ua_pattern_cache

        with patch("django_waf.services.rule_engine.re.compile", wraps=re.compile) as mock_compile:
            assert _match_ua("KnownBad/7", pattern, "regex") is True

        mock_compile.assert_not_called()
