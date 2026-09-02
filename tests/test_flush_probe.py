"""Tests for the flush-path liveness probe (#100).

Covers ``services.flush_probe.run_flush_probe`` and the
``django_waf_probe_flush_path`` management command.

House discipline, mirroring ``tests/test_detector_probe.py``: the crux
test in this file is the one that proves the probe has teeth, not merely
that it runs. A probe that patches itself, or that only asserts a
hand-written zero is reported as zero, proves nothing about whether it
would have caught the real production defect. The real defect (#78) was
Redis ``GETDEL`` raising on a pre-6.2 server inside a bare
``except Exception: continue``, so ``flush_rule_hit_counts`` returned a
success-shaped ``{"flushed": 0, ...}`` while doing nothing. The current
implementation no longer calls ``GETDEL`` (it uses a GET+DELETE pipeline
instead, see ``tests/test_flush_rule_hit_counts_redis_integration.py``),
so that exact call can no longer be reproduced against fakeredis or a
Redis 6.0 server: it would simply succeed. What is reproduced here
instead is the SHAPE of the defect that made it invisible: the read that
feeds the flush raising inside the same ``except Exception: continue``
the old ``GETDEL`` call raised inside, so the flush again returns
success-shaped output while applying nothing. This is the closest
faithful reproduction available against the current (fixed) source: the
teeth test below runs the REAL ``run_flush_probe``, the REAL
``_record_rule_hit`` producer, and the REAL ``flush_rule_hit_counts``
consumer end to end, with only the pipeline's ``execute()`` call broken
to fail the way a rejected Redis command fails, and asserts the probe
goes RED with a ``failure_reason`` naming the real problem (the counter
never reaching the row), not merely that some assertion fails somewhere.
"""

from __future__ import annotations

import pytest

from django_waf.models import BlockRule
from django_waf.testing.fixtures import waf_redis_mock  # noqa: F401 (used as a pytest fixture)

from .test_flush_rule_hit_counts import mock_redis_connection


@pytest.mark.django_db
class TestRunFlushProbeFalsifiability:
    def test_probe_reports_alive_against_the_real_producer_and_consumer(self, waf_redis_mock):
        """Baseline green: unmocked, the probe reports alive with a
        positive hit_count_delta. Layer under test: the full real path,
        _record_rule_hit and flush_rule_hit_counts both execute for real
        against the real fakeredis client and the real database.
        """
        from django_waf.services.flush_probe import run_flush_probe

        with mock_redis_connection(waf_redis_mock):
            result = run_flush_probe()

        assert result["alive"] is True
        assert result["hit_count_delta"] == 1
        assert result["key_deleted"] is True
        assert result["flushed"] >= 1
        assert result["failure_reason"] is None

    def test_probe_goes_red_when_the_flush_silently_no_ops(self, waf_redis_mock, monkeypatch):
        """Teeth: reproduce the historical defect's SHAPE against the real
        (fixed) flush path and assert the probe fails for the right reason.

        The original #78 defect was ``GETDEL`` raising on a pre-6.2 Redis
        server inside ``flush_rule_hit_counts``'s per-key
        ``try/except Exception: continue``, so the task returned
        ``{"flushed": 0, "keys_seen": N, "errors": N}`` while the counter
        stayed in Redis, never applied to the row. The current
        implementation replaced the single GETDEL with a pipelined
        GET+DELETE, so that literal call can no longer be reproduced
        against fakeredis (which accepts GETDEL unconditionally regardless
        of version, per waf_redis_mock's own docstring, and the current
        code does not call it anyway). What is reproduced here is the same
        failure shape one level down: the pipeline's own ``execute()``
        raising, exactly as a rejected Redis command would raise, landing
        in the SAME ``except Exception: continue`` the old GETDEL call
        raised inside. This is not a stub of run_flush_probe or of
        flush_rule_hit_counts: both run for real, with only the Redis
        client's pipeline execute() call broken.
        """
        from django_waf.services.flush_probe import run_flush_probe

        class _RaisingPipeline:
            def __init__(self, real_pipeline):
                self._real_pipeline = real_pipeline

            def get(self, key):
                self._real_pipeline.get(key)
                return self

            def delete(self, key):
                self._real_pipeline.delete(key)
                return self

            def execute(self):
                # Reproduces the historical failure shape: the read that
                # feeds the flush raises, exactly as a real pre-6.2 server
                # raised on GETDEL, landing in flush_rule_hit_counts's own
                # `except Exception: continue` around this same call.
                raise Exception("ERR unknown command 'GETDEL', reproduced for #100 teeth test")

        class _BrokenPipelineClient:
            """Wraps the real fakeredis client so every command except
            pipeline() passes straight through unmodified (keys(), get(),
            incr(), expire(), delete() all still work for real), and only
            the pipelined GET+DELETE the flush relies on is broken. A
            MagicMock standing in for the whole client would not exercise
            the real keys()/incr()/expire() calls _record_rule_hit and the
            flush both depend on before reaching the broken step.
            """

            def __init__(self, real_client):
                self._real_client = real_client

            def pipeline(self):
                return _RaisingPipeline(self._real_client.pipeline())

            def __getattr__(self, name):
                return getattr(self._real_client, name)

        broken_client = _BrokenPipelineClient(waf_redis_mock)

        blockrule_count_before = BlockRule.objects.count()

        with mock_redis_connection(broken_client):
            result = run_flush_probe()

        assert result["alive"] is False
        assert result["hit_count_delta"] == 0
        assert result["failure_reason"] is not None
        assert "hit_count" in result["failure_reason"]
        # The flush's own per-key error counter must reflect the broken
        # read, not report a clean success-shaped zero: this is exactly
        # the distinction the original bug erased.
        assert result["errors"] >= 1

        # No synthetic BlockRule survives a failed run either: the
        # rollback covers this regardless of the probe's own verdict.
        assert BlockRule.objects.count() == blockrule_count_before

    def test_probe_cleans_up_its_own_key_and_row_on_success(self, waf_redis_mock):
        from django_waf.services.flush_probe import run_flush_probe

        blockrule_count_before = BlockRule.objects.count()

        with mock_redis_connection(waf_redis_mock):
            run_flush_probe()

        assert BlockRule.objects.count() == blockrule_count_before
        assert waf_redis_mock.keys("waf:rule_hits:*") == []

    def test_probe_cleans_up_on_the_failure_path_too(self, waf_redis_mock):
        from django_waf.services.flush_probe import run_flush_probe

        class _AlwaysRaisingClient:
            def __getattr__(self, name):
                def _raise(*args, **kwargs):
                    raise RuntimeError("redis unreachable")

                return _raise

        blockrule_count_before = BlockRule.objects.count()

        with mock_redis_connection(_AlwaysRaisingClient()):
            result = run_flush_probe()

        assert result["alive"] is False
        assert BlockRule.objects.count() == blockrule_count_before

    def test_probe_does_not_corrupt_a_real_rule_s_hit_count(self, waf_redis_mock):
        """The reconciliation hazard (docstring in flush_probe.py): the
        real flush sweeps up every waf:rule_hits:* key it finds, not just
        the probe's own, so a real counter present when the probe runs
        must not be lost by the probe's rolled-back transaction.

        The probe restores such a counter to Redis rather than to the
        row, so immediately after a probe run the row is unchanged and
        the count is still pending, which is exactly the state an
        unflushed counter is normally in. Nothing is lost: the companion
        test below runs the next flush and proves the count lands, once.
        """
        from django_waf.services.flush_probe import run_flush_probe
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.testing.factories import BlockRuleFactory

        real_rule = BlockRuleFactory(hit_count=10)
        for _ in range(3):
            _record_rule_hit(str(real_rule.id), waf_redis_mock)

        with mock_redis_connection(waf_redis_mock):
            result = run_flush_probe()

        assert result["alive"] is True

        real_rule.refresh_from_db()
        assert real_rule.hit_count == 10

        # The count is not lost, it is pending: still in Redis, under the
        # real producer's own key, for the next scheduled flush to apply.
        assert waf_redis_mock.get(f"waf:rule_hits:{real_rule.id}") == b"3"

    def test_probe_does_not_double_count_a_real_rule_on_the_next_flush(self, waf_redis_mock):
        """Regression test. Asserting the hit count immediately after the
        probe is not sufficient, and an earlier revision passed that check
        while still corrupting the data.

        The probe's reconciliation puts each real counter back into Redis
        so the next scheduled flush can apply it. If it ALSO re-applied
        the count to the BlockRule row, the count would land twice: once
        from the reconciliation, once more when the next real flush reads
        the key the reconciliation just restored. Measured against that
        earlier revision, a real counter of 5 reached hit_count=10 after
        one probe run followed by one flush.

        So this test runs the next real flush too, which is what the
        5-minute beat does in production, and asserts the total is still
        5. The window between the probe and that flush is exactly where
        the defect lived.
        """
        from django_waf.models import BlockRule
        from django_waf.services.flush_probe import run_flush_probe
        from django_waf.services.rule_engine import _record_rule_hit
        from django_waf.tasks import flush_rule_hit_counts

        real_rule = BlockRule.objects.create(
            name="real rule",
            rule_type="ip",
            match_type="exact",
            pattern="198.18.0.9",
            action="block",
            is_active=True,
            source="admin",
            hit_count=0,
        )
        for _ in range(5):
            _record_rule_hit(str(real_rule.id), waf_redis_mock)

        with mock_redis_connection(waf_redis_mock):
            assert run_flush_probe()["alive"] is True

            # The probe left the count pending in Redis, exactly where an
            # unflushed counter normally sits. The next scheduled flush is
            # what applies it, and it must apply it exactly once.
            flush_rule_hit_counts()

        real_rule.refresh_from_db()
        assert real_rule.hit_count == 5

    def test_probe_behaves_identically_regardless_of_debug(self, waf_redis_mock, settings):
        """No environment guard of any kind: DEBUG on or off must not
        change the probe's verdict or shape."""
        from django_waf.services.flush_probe import run_flush_probe

        settings.DEBUG = True
        with mock_redis_connection(waf_redis_mock):
            result_debug_on = run_flush_probe()

        settings.DEBUG = False
        with mock_redis_connection(waf_redis_mock):
            result_debug_off = run_flush_probe()

        assert result_debug_on["alive"] is True
        assert result_debug_off["alive"] is True
        assert set(result_debug_on) == set(result_debug_off)


@pytest.mark.django_db
class TestProbeFlushPathTask:
    def test_task_returns_the_probe_result_on_success(self, waf_redis_mock):
        from django_waf.tasks import probe_flush_path

        with mock_redis_connection(waf_redis_mock):
            result = probe_flush_path()

        assert result["alive"] is True

    def test_task_never_raises_and_reports_failure_shaped_output(self, monkeypatch):
        """probe_flush_path imports run_flush_probe lazily inside its own
        body (`from django_waf.services.flush_probe import
        run_flush_probe`), so it must be patched on the module it is
        imported FROM, not on `django_waf.tasks`, where no such name is
        ever bound."""
        from django_waf.services import flush_probe as flush_probe_module
        from django_waf.tasks import probe_flush_path

        def _boom() -> dict:
            raise RuntimeError("kaboom")

        monkeypatch.setattr(flush_probe_module, "run_flush_probe", _boom)

        result = probe_flush_path()

        assert result["alive"] is False
        assert "probe_flush_path raised" in result["failure_reason"]


@pytest.mark.django_db
class TestProbeFlushPathCommand:
    def test_command_exits_zero_when_alive(self, waf_redis_mock):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        with mock_redis_connection(waf_redis_mock):
            call_command("django_waf_probe_flush_path", stdout=out)

        assert "Flush path alive" in out.getvalue()

    def test_command_raises_command_error_when_dead(self, waf_redis_mock):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        class _AlwaysRaisingClient:
            def __getattr__(self, name):
                def _raise(*args, **kwargs):
                    raise RuntimeError("redis unreachable")

                return _raise

        with mock_redis_connection(_AlwaysRaisingClient()), pytest.raises(CommandError):
            call_command("django_waf_probe_flush_path")
