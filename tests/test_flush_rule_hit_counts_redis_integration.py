"""Regression test for #78 against a REAL Redis server.

This file only runs on ``settings_redis`` (pytest-django's ``--ds`` flag),
selected by the dedicated ``test-redis-integration`` CI leg, which starts a
real ``redis:6.0-alpine`` service container. It is skipped everywhere else,
including the default fast unit run, because ``pytest.mark.redis_integration``
is not selected there and because ``settings.CACHES`` (LocMemCache) makes
``get_redis_client``/``get_redis_connection`` unable to reach a real server
under the default settings module in the first place.

Falsifiability is the whole point of this file. Before the fix,
``flush_rule_hit_counts`` called ``redis_client.getdel(key)`` directly.
``GETDEL`` was added in Redis 6.2; on the package's declared floor (6.0) it
does not exist, so the call raises ``redis.exceptions.ResponseError`` inside
a bare ``try/except Exception: continue``, silently skipping the key with
the counter never cleared and never applied to the BlockRule row (the
production incident this reliability release exists to fix: 40,936 task
runs against Redis 6.0.16). ``TestOldGetdelImplementationFailsOnRedis60``
below reproduces the old call pattern directly against the real server and
asserts it actually raises: this is the check that would have caught the
defect, and it is impossible to write against fakeredis, because fakeredis
accepts GETDEL unconditionally regardless of the requested ``version=``
(confirmed empirically against fakeredis 2.37.1's
``commands_mixins/string_mixin.py``, which registers ``getdel`` with no
version gate at all).

``TestFlushRuleHitCountsAgainstRealRedis`` then proves the CURRENT
(pipeline-based) implementation actually works end to end against the same
real server: the fast-suite equivalent in
``tests/test_flush_rule_hit_counts.py`` proves this against fakeredis, which
is necessary but not sufficient (fakeredis and real Redis agree on
GET/DELETE pipeline behaviour, so that half was never the risk).
"""

from __future__ import annotations

import uuid

import pytest
from django.conf import settings

from django_waf.testing.factories import BlockRuleFactory

pytestmark = pytest.mark.redis_integration


def _skip_unless_real_redis_configured() -> None:
    """Guard so this file fails loudly, not with a connection traceback,
    when accidentally collected under the default (LocMemCache) settings
    module rather than ``--ds=settings_redis``."""
    backend = settings.CACHES.get("default", {}).get("BACKEND", "")
    if not backend.startswith("django_redis.cache."):
        pytest.skip(
            "requires --ds=settings_redis (a real django-redis backend); "
            f"current CACHES['default']['BACKEND']={backend!r}"
        )


@pytest.fixture
def real_redis_client():
    """A real Redis client via the same resolution path production uses."""
    _skip_unless_real_redis_configured()

    from django_redis import get_redis_connection

    from django_waf import conf

    client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    client.flushdb()
    yield client
    client.flushdb()


class TestOldGetdelImplementationFailsOnRedis60:
    """Reproduces the exact call the old code made. This test's failure
    (before the fix) IS the production defect; its pass (after the fix,
    because the fix no longer calls getdel at all) proves the regression
    is closed at the command level, independent of the task's own
    try/except swallowing the same error."""

    def test_getdel_raises_on_a_pre_62_redis_server(self, real_redis_client):
        import redis

        key = f"waf:rule_hits:{uuid.uuid4()}"
        real_redis_client.set(key, 5)

        with pytest.raises(redis.exceptions.ResponseError, match="(?i)unknown command"):
            real_redis_client.getdel(key)

    def test_get_then_delete_pipeline_works_on_the_same_server(self, real_redis_client):
        """The replacement implementation's actual commands, confirmed
        against the same server the getdel call above just failed on."""
        key = f"waf:rule_hits:{uuid.uuid4()}"
        real_redis_client.set(key, 7)

        pipe = real_redis_client.pipeline()
        pipe.get(key)
        pipe.delete(key)
        get_result, delete_result = pipe.execute()

        assert get_result == b"7"
        assert delete_result == 1
        assert real_redis_client.get(key) is None


@pytest.mark.django_db
class TestFlushRuleHitCountsAgainstRealRedis:
    """The full task, against a real Redis 6.0 server. This is the test
    that proves the fix, not merely the absence of the old crash: a task
    that caught the getdel error and silently returned {"flushed": 0}
    would also "pass" a test that only checks for no exception."""

    def test_flush_moves_the_counter_to_the_block_rule_row(self, real_redis_client):
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        rule = BlockRuleFactory(hit_count=0)
        for _ in range(6):
            _record_rule_hit(str(rule.id), real_redis_client)

        result = flush_rule_hit_counts()

        rule.refresh_from_db()
        assert rule.hit_count == 6
        assert result == {"flushed": 1, "keys_seen": 1, "errors": 0}
        assert real_redis_client.get(f"waf:rule_hits:{rule.id}") is None


class TestRedisVersionCheckAgainstRealRedis:
    """get_redis_server_version (redis_client.py) reads via INFO, a command
    fakeredis does not implement at all (confirmed against the pinned
    fakeredis version: FakeRedis(version=(6, 0)).info() raises
    ResponseError: unknown command 'info'). Only a real server proves this
    path works; see tests/test_redis_fallback.py's
    TestGetRedisServerVersion for the MagicMock-based parsing tests."""

    def test_reads_the_real_server_version_at_or_above_the_floor(self):
        _skip_unless_real_redis_configured()

        from django_waf.services.redis_client import MIN_REDIS_VERSION, get_redis_server_version

        version = get_redis_server_version()

        assert version is not None
        assert version >= MIN_REDIS_VERSION  # the CI service container is redis:6.0-alpine

    def test_check_redis_version_is_silent_against_the_ci_container(self):
        """The CI service container (redis:6.0-alpine) sits exactly at the
        package's declared floor, so django_waf.E005 must not fire against
        it."""
        _skip_unless_real_redis_configured()

        from django_waf.checks import check_redis_version

        assert check_redis_version(app_configs=None) == []
