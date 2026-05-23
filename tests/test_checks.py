"""Tests for the icv_waf Django system checks.

These exist because v0.10.4 shipped with a units mismatch
(``ICV_WAF_CHALLENGE_DIFFICULTY`` was counted in bytes while documented in
bits) that made the default unsolvable in a browser and locked legitimate
users out. The check refuses settings that would reproduce that lockout.
"""

from __future__ import annotations

from unittest.mock import patch


def _run_checks():
    from icv_waf.checks import check_challenge_difficulty

    return check_challenge_difficulty(app_configs=None)


class TestChallengeDifficultyCheck:
    def test_recommended_defaults_produce_no_messages(self):
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            assert _run_checks() == []

    def test_difficulty_over_28_errors(self):
        """The v0.10.4 lockout class — refuse to start with this config."""
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 32),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "icv_waf.E002" for m in messages)

    def test_difficulty_over_24_warns(self):
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 26),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "icv_waf.W001" for m in messages)

    def test_difficulty_under_8_warns(self):
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 4),
        ):
            messages = _run_checks()

        assert any(m.id == "icv_waf.W002" for m in messages)

    def test_none_allowed_for_device_keys(self):
        """Desktop/mobile = None means 'use the fallback' and must not warn."""
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", 20),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", None),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", None),
        ):
            assert _run_checks() == []

    def test_negative_is_error(self):
        import icv_waf.conf as conf_mod

        with (
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY", -1),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22),
            patch.object(conf_mod, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18),
        ):
            messages = _run_checks()

        assert any(m.id == "icv_waf.E001" for m in messages)
