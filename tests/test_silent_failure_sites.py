"""Failure-path tests for the reliability release's four silent-failure
sites (#78): every bare ``except Exception`` on a Redis call that a WAF
operator has no way to observe, because the request/task still returned
success-shaped output.

The contract under test throughout is the same: fails open AND logs.
Fail-open (BR-EVAL-007) is correct and unchanged: a Redis outage must never
turn into a blocked request or a crashed task. What #78 fixes is the "AND
logs" half: before this release, three of these four sites had no log line
at all, so an operator watching Redis come back up after an outage had no
way to see that a chunk of hit counters, or a whole rule-cache
invalidation, was silently dropped during the gap.

Three of the four sites live inside ``flush_rule_hit_counts`` (tasks.py);
the per-key GET/DELETE failure and the DB-update failure are covered
directly in ``test_flush_rule_hit_counts.py`` alongside the crux tests for
that function. This file covers the two sites not covered there:

1. ``flush_rule_hit_counts`` failing to obtain a Redis connection at all
   (the top-level ``get_redis_connection`` call).
2. ``flush_rule_hit_counts`` failing to list ``waf:rule_hits:*`` keys
   (``redis_client.keys()`` raising).
3. ``_invalidate_rule_cache_redis`` (called from ``expire_rules``) falling
   back to the Django cache with no log at all. Per the task brief: if the
   logging is not there yet, the test is still written to drive the
   requirement rather than skipped.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest


def mock_redis_connection_raises(exc: Exception):
    """Patch ``django_redis.get_redis_connection`` to raise, simulating a
    Redis outage at the point every one of these tasks first tries to
    obtain a client."""
    return patch("django_redis.get_redis_connection", side_effect=exc)


# ---------------------------------------------------------------------------
# flush_rule_hit_counts: Redis connection unavailable
# ---------------------------------------------------------------------------


class TestFlushRuleHitCountsRedisUnavailable:
    def test_fails_open_with_a_zeroed_result(self):
        from django_waf.tasks import flush_rule_hit_counts

        with mock_redis_connection_raises(RuntimeError("connection refused")):
            result = flush_rule_hit_counts()

        assert result == {"flushed": 0, "keys_seen": 0, "errors": 0}

    def test_logs_the_outage(self, caplog):
        from django_waf.tasks import flush_rule_hit_counts

        with (
            caplog.at_level(logging.WARNING, logger="django_waf.tasks"),
            mock_redis_connection_raises(RuntimeError("connection refused")),
        ):
            flush_rule_hit_counts()

        assert any("Redis unavailable" in message for message in caplog.messages)

    def test_does_not_raise(self):
        """The task itself must never propagate a Redis outage (BR-EVAL-007
        applied to a background task: a failed flush waits for the next
        scheduled run rather than crashing the worker)."""
        from django_waf.tasks import flush_rule_hit_counts

        with mock_redis_connection_raises(ConnectionError("refused")):
            flush_rule_hit_counts()  # must not raise


# ---------------------------------------------------------------------------
# flush_rule_hit_counts: Redis reachable but KEYS fails
# ---------------------------------------------------------------------------


class TestFlushRuleHitCountsKeysListingFails:
    def _broken_keys_client(self):
        from unittest.mock import MagicMock

        client = MagicMock()
        client.keys.side_effect = RuntimeError("redis timeout")
        return client

    def test_fails_open_with_one_error_counted(self):
        from django_waf.tasks import flush_rule_hit_counts

        client = self._broken_keys_client()
        with patch("django_redis.get_redis_connection", return_value=client):
            result = flush_rule_hit_counts()

        assert result == {"flushed": 0, "keys_seen": 0, "errors": 1}

    def test_logs_the_failure(self, caplog):
        from django_waf.tasks import flush_rule_hit_counts

        client = self._broken_keys_client()
        with (
            caplog.at_level(logging.ERROR, logger="django_waf.tasks"),
            patch("django_redis.get_redis_connection", return_value=client),
        ):
            flush_rule_hit_counts()

        assert any("failed to list Redis hit count keys" in message for message in caplog.messages)

    def test_does_not_raise(self):
        from django_waf.tasks import flush_rule_hit_counts

        client = self._broken_keys_client()
        with patch("django_redis.get_redis_connection", return_value=client):
            flush_rule_hit_counts()  # must not raise


# ---------------------------------------------------------------------------
# _invalidate_rule_cache_redis: falls back to the Django cache
# ---------------------------------------------------------------------------


class TestInvalidateRuleCacheRedisFailure:
    """The fourth silent-failure site. Unlike the three inside
    flush_rule_hit_counts, this one had no log line on its except branch as
    of the start of this reliability release: it falls back to the Django
    cache and returns, indistinguishable from the Redis path having
    succeeded. This test is written to the target contract (fails open AND
    logs) regardless of whether the logging has landed yet; if it has not,
    this test's failure is the signal that the source-side half of #78 is
    still outstanding for this site.
    """

    def test_falls_back_to_django_cache_without_raising(self):
        from django.core.cache import cache

        from django_waf.tasks import _invalidate_rule_cache_redis

        cache.delete("waf:rules:version")

        with mock_redis_connection_raises(RuntimeError("redis down")):
            _invalidate_rule_cache_redis()  # must not raise

        # Fail-open still does its job: the version key moved via the
        # Django cache fallback even though Redis was unavailable.
        assert cache.get("waf:rules:version") == 1

    def test_logs_the_fallback(self, caplog):
        from django_waf.tasks import _invalidate_rule_cache_redis

        with (
            caplog.at_level(logging.WARNING, logger="django_waf.tasks"),
            mock_redis_connection_raises(RuntimeError("redis down")),
        ):
            _invalidate_rule_cache_redis()

        assert any("rule cache" in message.lower() or "invalidat" in message.lower() for message in caplog.messages), (
            "expected a log line when _invalidate_rule_cache_redis falls back to the "
            "Django cache; before #78 this except branch was silent"
        )

    def test_fallback_routes_through_icv_caches_alias(self):
        """The Django cache fallback routes through ICV_CACHES_ALIAS (#149,
        ADR-037), proven against two real, distinct LocMemCache aliases so a
        regression that keeps writing to "default" cannot pass unnoticed.
        """
        from django.core.cache import caches
        from django.test import override_settings

        from django_waf.tasks import _invalidate_rule_cache_redis

        with override_settings(
            CACHES={
                "default": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "icv-caches-alias-default",
                },
                "icv": {
                    "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                    "LOCATION": "icv-caches-alias-icv",
                },
            },
            ICV_CACHES_ALIAS="icv",
        ):
            caches["default"].delete("waf:rules:version")
            caches["icv"].delete("waf:rules:version")

            with mock_redis_connection_raises(RuntimeError("redis down")):
                _invalidate_rule_cache_redis()

            assert caches["icv"].get("waf:rules:version") == 1
            assert caches["default"].get("waf:rules:version") is None


# ---------------------------------------------------------------------------
# expire_rules: the caller, proving the fail-open contract end to end
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestExpireRulesSurvivesRedisOutage:
    def test_expire_rules_completes_when_cache_invalidation_fails(self):
        """expire_rules already swallows _invalidate_rule_cache_redis
        exceptions (see tests/test_tasks.py::TestExpireRules), but that
        coverage mocks the helper itself out entirely. This test drives the
        real helper through a real Redis outage, proving the two layers
        compose: a Redis outage during cache invalidation must not stop
        expire_rules from returning its rule-expiry counts."""
        from datetime import timedelta

        from django.utils import timezone

        from django_waf.tasks import expire_rules
        from django_waf.testing.factories import BlockRuleFactory

        BlockRuleFactory(is_active=True, expires_at=timezone.now() - timedelta(minutes=1))

        with mock_redis_connection_raises(RuntimeError("redis down")):
            result = expire_rules()

        assert result["expired_block_count"] >= 1
