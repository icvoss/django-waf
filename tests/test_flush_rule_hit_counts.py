"""Tests for ``flush_rule_hit_counts`` and its Redis hit-counter producer,
``_record_rule_hit`` (#78).

``flush_rule_hit_counts`` was the only task in ``tasks.py`` with no test
class at all: a production defect (``GETDEL`` requires Redis 6.2+, silently
failing on Redis 6.0.16 for 40,936 task runs) went undetected because
nothing exercised the flush path against Redis at all, real or fake. The
old implementation called ``redis_client.getdel(key)`` directly; on a
server below 6.2 that raises inside the per-key ``try/except Exception``,
which silently ``continue``s to the next key with the counter never
cleared and never applied to the row. The fix (already landed by the time
this file was written) replaced the single ``getdel`` with a
``GET``+``DELETE`` pipeline, which works on the package's declared Redis
6.0 floor.

This file uses ``waf_redis_mock`` (fakeredis) throughout: it drives the
full producer (``_record_rule_hit``) then flush (``flush_rule_hit_counts``)
path against a real, Redis-shaped client and asserts on the actual
observable effects (the ``BlockRule.hit_count`` row and the Redis key),
never merely that a mock method was called. fakeredis's pipeline supports
``GET``/``DELETE`` identically to a real server, so this file proves the
pipeline-based implementation is correct in general; it cannot, by itself,
prove the old ``getdel`` implementation is broken, because fakeredis
accepts ``GETDEL`` regardless of Redis floor (see
``tests/test_flush_rule_hit_counts_redis_integration.py``, which runs
against a real Redis 6.0 server and is the actual regression test for this
defect: falsifiability requires a check that fails against the old code
for the original reason, and fakeredis cannot provide that here).
"""

from __future__ import annotations

import logging

import pytest

from django_waf.testing.factories import BlockRuleFactory
from django_waf.testing.fixtures import waf_redis_mock  # noqa: F401 (used as a pytest fixture)

# ---------------------------------------------------------------------------
# _record_rule_hit: the producer side actually writes waf:rule_hits:*
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestRecordRuleHitWritesRedis:
    """``_record_rule_hit`` is exercised incidentally by other tests, via
    ``MagicMock`` call assertions in test_services.py, but nothing asserts
    the actual Redis-side effect: that the key exists afterwards with the
    right value and TTL. The audit flagged this as "covered but not
    tested"."""

    def test_increments_a_real_redis_key(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit

        _record_rule_hit("rule-abc", waf_redis_mock)

        assert waf_redis_mock.get("waf:rule_hits:rule-abc") == b"1"

    def test_repeated_hits_accumulate_on_the_same_key(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit

        for _ in range(3):
            _record_rule_hit("rule-abc", waf_redis_mock)

        assert waf_redis_mock.get("waf:rule_hits:rule-abc") == b"3"

    def test_sets_a_two_day_ttl_on_the_key(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit

        _record_rule_hit("rule-abc", waf_redis_mock)

        ttl = waf_redis_mock.ttl("waf:rule_hits:rule-abc")
        assert 0 < ttl <= 86400 * 2

    def test_failure_logs_a_warning_naming_the_rule(self, caplog):
        """This is the producer half of the counter flush_rule_hit_counts
        reads: a silent failure here means every subsequent read of this
        rule's hit count reads as zero forever, indistinguishable from the
        rule never matching."""
        from unittest.mock import MagicMock

        from django_waf.services.rule_engine import _record_rule_hit

        broken_client = MagicMock()
        broken_client.incr.side_effect = RuntimeError("redis down")

        with caplog.at_level(logging.WARNING, logger="django_waf.rule_engine"):
            _record_rule_hit("rule-abc", broken_client)

        assert any("rule-abc" in message for message in caplog.messages)

    def test_check_block_rules_calls_the_producer_for_a_matched_rule(self, waf_redis_mock):
        """End-to-end from the evaluation entry point actually used in
        production: a matched BlockRule's hit lands in Redis, not just in
        a mock's call log."""
        from django_waf.services.rule_engine import RuleCache, _check_block_rules

        rule = {
            "id": "rule-xyz",
            "rule_type": "ip",
            "match_type": "exact",
            "pattern": "10.10.10.10",
            "priority": 1,
            "expires_at": None,
        }
        cache = RuleCache(version=1, allow_rules=[], block_rules=[rule], ua_regex_set=[])

        result = _check_block_rules("10.10.10.10", "Mozilla/5.0", cache, redis_client=waf_redis_mock)

        assert result is not None
        assert waf_redis_mock.get("waf:rule_hits:rule-xyz") == b"1"


# ---------------------------------------------------------------------------
# flush_rule_hit_counts: the full producer, flush, DB path
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestFlushRuleHitCounts:
    """The crux tests: increment via the real producer path, run the flush,
    assert hit_count actually moved on the BlockRule row AND the Redis key
    was removed. This is the test class that did not exist before #78; its
    absence is exactly how the getdel defect went unnoticed for 40,936 task
    runs."""

    def test_flush_applies_accumulated_hits_to_the_block_rule_row(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=0)

        for _ in range(5):
            _record_rule_hit(str(rule.id), waf_redis_mock)

        with mock_redis_connection(waf_redis_mock):
            flush_rule_hit_counts()

        rule.refresh_from_db()
        assert rule.hit_count == 5
        assert rule.last_hit_at is not None

    def test_flush_removes_the_redis_key_after_applying(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=0)
        _record_rule_hit(str(rule.id), waf_redis_mock)

        assert waf_redis_mock.exists(f"waf:rule_hits:{rule.id}")

        with mock_redis_connection(waf_redis_mock):
            flush_rule_hit_counts()

        assert not waf_redis_mock.exists(f"waf:rule_hits:{rule.id}")

    def test_flush_accumulates_onto_an_existing_hit_count(self, waf_redis_mock):
        """hit_count is incremented (F() expression), not overwritten."""
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=10)
        for _ in range(4):
            _record_rule_hit(str(rule.id), waf_redis_mock)

        with mock_redis_connection(waf_redis_mock):
            flush_rule_hit_counts()

        rule.refresh_from_db()
        assert rule.hit_count == 14

    def test_flush_leaves_unrelated_rules_untouched(self, waf_redis_mock):
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        hit_rule = BlockRuleFactory(hit_count=0)
        untouched_rule = BlockRuleFactory(hit_count=0)
        _record_rule_hit(str(hit_rule.id), waf_redis_mock)

        with mock_redis_connection(waf_redis_mock):
            flush_rule_hit_counts()

        hit_rule.refresh_from_db()
        untouched_rule.refresh_from_db()
        assert hit_rule.hit_count == 1
        assert untouched_rule.hit_count == 0

    def test_flush_with_no_keys_is_a_clean_no_op(self, waf_redis_mock):
        from django_waf.tasks import flush_rule_hit_counts

        with mock_redis_connection(waf_redis_mock):
            result = flush_rule_hit_counts()

        assert result == {"flushed": 0, "keys_seen": 0, "errors": 0}

    def test_flush_skips_a_rule_id_that_no_longer_exists(self, waf_redis_mock):
        """A stale key for a deleted rule does not raise; the key is still
        cleared (update() against a non-matching id affects zero rows,
        which is a legitimate zero, not an error)."""
        from django_waf.tasks import flush_rule_hit_counts

        waf_redis_mock.incr("waf:rule_hits:00000000-0000-0000-0000-000000000000")

        with mock_redis_connection(waf_redis_mock):
            result = flush_rule_hit_counts()

        assert result["flushed"] == 0
        assert result["errors"] == 0
        assert not waf_redis_mock.exists("waf:rule_hits:00000000-0000-0000-0000-000000000000")

    def test_flush_counts_a_db_update_failure_as_an_error_not_a_silent_skip(self, waf_redis_mock, caplog):
        """A BlockRule.objects.filter(...).update() failure used to be caught
        by the same bare `except Exception: continue` as a Redis read
        failure, with no log at all and no way to tell the two apart. It
        must now increment `errors` and log at ERROR."""
        from unittest.mock import patch

        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=0)
        _record_rule_hit(str(rule.id), waf_redis_mock)

        with (
            caplog.at_level(logging.ERROR, logger="django_waf.tasks"),
            mock_redis_connection(waf_redis_mock),
            patch("django.db.models.F", side_effect=RuntimeError("db down")),
        ):
            result = flush_rule_hit_counts()

        assert result["errors"] == 1
        assert result["flushed"] == 0
        assert any(str(rule.id) in message for message in caplog.messages)

    def test_flush_logs_a_summary_line_on_success(self, waf_redis_mock, caplog):
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=0)
        _record_rule_hit(str(rule.id), waf_redis_mock)

        with caplog.at_level(logging.INFO, logger="django_waf.tasks"), mock_redis_connection(waf_redis_mock):
            flush_rule_hit_counts()

        assert any("flushed hit counts for 1 rules" in message for message in caplog.messages)


def mock_redis_connection(fake_client):
    """Patch ``django_redis.get_redis_connection`` (as imported inside
    ``tasks.flush_rule_hit_counts``) to return the given fakeredis client.

    ``flush_rule_hit_counts`` resolves its own client via
    ``django_redis.get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)``, a
    different resolution path than the middleware/views/forms accessors
    ``waf_redis_mock`` patches directly, so the fixture's shared client is
    wired in here rather than via monkeypatching a django_waf attribute.
    """
    from unittest.mock import patch

    return patch("django_redis.get_redis_connection", return_value=fake_client)
