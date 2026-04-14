"""Tests for icv-waf signal handlers.

Handlers are connected via @receiver decorators in icv_waf.handlers, which
is imported by IcvWafConfig.ready(). All tests that need the DB are marked
with @pytest.mark.django_db.

Redis/cache interactions are replaced with Django's LocMemCache (configured
in tests/settings.py CACHES) — no real Redis is required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_cache_incr_path() -> str:
    """Importable patch target for _get_cache inside handlers."""
    return "icv_waf.handlers._get_cache"


# ---------------------------------------------------------------------------
# BlockRule save → cache invalidation
# ---------------------------------------------------------------------------


class TestBlockRuleSaveInvalidatesCache:
    """on_block_rule_save increments the rules version key in the cache."""

    @pytest.mark.django_db
    def test_save_new_block_rule_invalidates_cache(self):
        from icv_waf.testing.factories import BlockRuleFactory

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            BlockRuleFactory()  # triggers post_save → on_block_rule_save

        mock_conn.incr.assert_called()

    @pytest.mark.django_db
    def test_update_block_rule_invalidates_cache(self):
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory()

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            rule.notes = "updated"
            rule.save(update_fields=["notes"])

        mock_conn.incr.assert_called()

    @pytest.mark.django_db
    def test_cache_version_key_is_correct(self):
        """The handler must use waf:rules:version as the cache key."""
        from icv_waf.handlers import _RULES_VERSION_KEY

        assert _RULES_VERSION_KEY == "waf:rules:version"


# ---------------------------------------------------------------------------
# BlockRule delete → cache invalidation
# ---------------------------------------------------------------------------


class TestBlockRuleDeleteInvalidatesCache:
    """on_block_rule_delete increments the rules version key after deletion."""

    @pytest.mark.django_db
    def test_delete_block_rule_invalidates_cache(self):
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory()

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            rule.delete()

        mock_conn.incr.assert_called()


# ---------------------------------------------------------------------------
# AllowRule save → cache invalidation
# ---------------------------------------------------------------------------


class TestAllowRuleSaveInvalidatesCache:
    """on_allow_rule_save increments the rules version key."""

    @pytest.mark.django_db
    def test_save_new_allow_rule_invalidates_cache(self):
        from icv_waf.testing.factories import AllowRuleFactory

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            AllowRuleFactory()

        mock_conn.incr.assert_called()

    @pytest.mark.django_db
    def test_update_allow_rule_invalidates_cache(self):
        from icv_waf.testing.factories import AllowRuleFactory

        rule = AllowRuleFactory()

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            rule.notes = "changed"
            rule.save(update_fields=["notes"])

        mock_conn.incr.assert_called()


# ---------------------------------------------------------------------------
# AllowRule delete → cache invalidation
# ---------------------------------------------------------------------------


class TestAllowRuleDeleteInvalidatesCache:
    """on_allow_rule_delete increments the rules version key after deletion."""

    @pytest.mark.django_db
    def test_delete_allow_rule_invalidates_cache(self):
        from icv_waf.testing.factories import AllowRuleFactory

        rule = AllowRuleFactory()

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            rule.delete()

        mock_conn.incr.assert_called()


# ---------------------------------------------------------------------------
# Cache fallback: else branch (conn has no incr attribute)
# ---------------------------------------------------------------------------


class TestCacheFallback:
    """The else branch is taken when conn has no 'incr' attribute.
    It tries conn.incr(); on ValueError it calls conn.set(key, 1).
    """

    def test_else_branch_set_called_on_value_error(self):
        """When conn has no incr attr but exposes incr as a method that raises
        ValueError, the else branch should call conn.set(key, 1)."""
        from icv_waf.handlers import _invalidate_rule_cache

        class FallbackCache:
            """Simulates a Django cache backend that signals a cache miss via ValueError."""

            def __init__(self):
                self.set_calls: list = []

            def incr(self, key):
                raise ValueError("Key not found — cache miss")

            def set(self, key, value, **kwargs):
                self.set_calls.append((key, value))

        cache = FallbackCache()

        # Make hasattr(cache, 'incr') return False so the else branch runs.
        import builtins

        original_hasattr = builtins.hasattr

        def patched_hasattr(obj, name):
            if obj is cache and name == "incr":
                return False
            return original_hasattr(obj, name)

        with (
            patch(_get_cache_incr_path(), return_value=cache),
            patch("builtins.hasattr", side_effect=patched_hasattr),
        ):
            _invalidate_rule_cache()

        assert ("waf:rules:version", 1) in cache.set_calls


# ---------------------------------------------------------------------------
# Cache failure is swallowed — handler never raises
# ---------------------------------------------------------------------------


class TestCacheErrorHandling:
    """Failures in _invalidate_rule_cache must not propagate to callers."""

    @pytest.mark.django_db
    def test_cache_connection_error_does_not_raise(self):
        from icv_waf.testing.factories import BlockRuleFactory

        mock_conn = MagicMock()
        mock_conn.incr.side_effect = ConnectionError("Redis unreachable")

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            # Saving the rule must not raise even when Redis is down
            try:
                BlockRuleFactory()
            except Exception as exc:  # noqa: BLE001
                pytest.fail(f"Handler raised unexpectedly: {exc}")

    @pytest.mark.django_db
    def test_cache_get_failure_does_not_raise(self):
        from icv_waf.testing.factories import AllowRuleFactory

        with patch(_get_cache_incr_path(), side_effect=RuntimeError("unexpected")):
            try:
                AllowRuleFactory()
            except Exception as exc:  # noqa: BLE001
                pytest.fail(f"Handler raised unexpectedly: {exc}")


# ---------------------------------------------------------------------------
# request_blocked signal → structured log entry
# ---------------------------------------------------------------------------


class TestRequestBlockedHandler:
    """on_request_blocked emits a structured log entry when a request is blocked."""

    def test_on_request_blocked_logs_event(self):
        """The handler writes a structured log record with waf_event key."""

        from icv_waf.signals import request_blocked

        with patch("icv_waf.handlers.logger") as mock_logger:
            request_blocked.send(
                sender=None,
                ip_address="1.2.3.4",
                user_agent="TestBot/1.0",
                path="/admin/",
                rule=None,
                verdict="blocked",
            )

        mock_logger.info.assert_called_once()
        _args, kwargs = mock_logger.info.call_args
        extra = kwargs.get("extra", {})
        assert extra.get("waf_event") == "request_blocked"
        assert extra.get("ip_address") == "1.2.3.4"
        assert extra.get("path") == "/admin/"

    def test_on_request_blocked_handles_rule_with_none(self):
        """Passing rule=None must not raise — rule_id and rule_name default to None."""
        from icv_waf.signals import request_blocked

        with patch("icv_waf.handlers.logger") as mock_logger:
            request_blocked.send(
                sender=None,
                ip_address="5.6.7.8",
                user_agent="",
                path="/login/",
                rule=None,
                verdict="blocked",
            )

        _args, kwargs = mock_logger.info.call_args
        extra = kwargs.get("extra", {})
        assert extra.get("rule_id") is None
        assert extra.get("rule_name") is None

    @pytest.mark.django_db
    def test_on_request_blocked_includes_rule_id_when_rule_present(self):
        """When a BlockRule instance is passed, its id and str are logged."""
        from icv_waf.signals import request_blocked
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory()

        with patch("icv_waf.handlers.logger") as mock_logger:
            request_blocked.send(
                sender=None,
                ip_address="9.10.11.12",
                user_agent="",
                path="/blocked/",
                rule=rule,
                verdict="blocked",
            )

        _args, kwargs = mock_logger.info.call_args
        extra = kwargs.get("extra", {})
        assert extra.get("rule_id") == str(rule.id)
        assert extra.get("rule_name") == str(rule)

    def test_on_request_blocked_includes_user_agent(self):
        """user_agent from the signal is included in the structured log record."""
        from icv_waf.signals import request_blocked

        with patch("icv_waf.handlers.logger") as mock_logger:
            request_blocked.send(
                sender=None,
                ip_address="1.2.3.4",
                user_agent="SuspiciousBot/2.0",
                path="/probe/",
                rule=None,
                verdict="blocked",
            )

        _args, kwargs = mock_logger.info.call_args
        extra = kwargs.get("extra", {})
        assert extra.get("user_agent") == "SuspiciousBot/2.0"

    def test_on_request_blocked_defaults_verdict_when_missing(self):
        """If verdict is not passed in the signal (external caller), the handler
        defaults to empty string rather than crashing.

        Regression: the receiver declared ``verdict: str`` as a required
        parameter without a default. If any external code fired the signal
        without verdict, the receiver would raise TypeError.
        """
        from icv_waf.signals import request_blocked

        with patch("icv_waf.handlers.logger") as mock_logger:
            # Deliberately omit verdict
            request_blocked.send(
                sender=None,
                ip_address="1.2.3.4",
                path="/",
                rule=None,
            )

        mock_logger.info.assert_called_once()
        _args, kwargs = mock_logger.info.call_args
        extra = kwargs.get("extra", {})
        assert extra.get("verdict") == ""


# ---------------------------------------------------------------------------
# _invalidate_rule_cache — unit tests for the helper directly
# ---------------------------------------------------------------------------


class TestInvalidateRuleCacheHelper:
    """Direct unit tests of _invalidate_rule_cache (not via signals)."""

    def test_calls_incr_on_connection(self):
        from icv_waf.handlers import _invalidate_rule_cache

        mock_conn = MagicMock()
        mock_conn.incr = MagicMock()

        with patch(_get_cache_incr_path(), return_value=mock_conn):
            _invalidate_rule_cache()

        mock_conn.incr.assert_called_once_with("waf:rules:version")

    def test_else_branch_calls_set_when_incr_raises_value_error(self):
        """Else branch (conn has no incr attr): tries conn.incr, catches ValueError,
        falls back to conn.set(key, 1)."""
        import builtins

        from icv_waf.handlers import _invalidate_rule_cache

        class FallbackCache:
            def __init__(self):
                self.data: dict = {}

            def incr(self, key):
                raise ValueError("Key not found")

            def set(self, key, value, **kwargs):
                self.data[key] = value

        cache = FallbackCache()
        original_hasattr = builtins.hasattr

        def patched_hasattr(obj, name):
            if obj is cache and name == "incr":
                return False
            return original_hasattr(obj, name)

        with (
            patch(_get_cache_incr_path(), return_value=cache),
            patch("builtins.hasattr", side_effect=patched_hasattr),
        ):
            _invalidate_rule_cache()

        assert cache.data.get("waf:rules:version") == 1
