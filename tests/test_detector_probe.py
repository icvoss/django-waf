"""Tests for the detector liveness probe (BR-ANOM-012).

Covers ``services.detector_probe.run_detector_probe``, the ``probe_detectors``
Celery task, and the ``django_waf_probe_detectors`` management command.

House discipline: mocked-service tests plus an explicit end-to-end test
against the real (unmocked) anomaly detectors, mirroring
``test_window_minutes_end_to_end_against_real_service`` and
``TestDetectAnomaliesCommandDryRunEndToEnd``.

The five most important tests in this file are the
``test_probe_goes_red_when_<detector>_cannot_match_its_fixture`` tests, one
per detector in ``DETECTOR_NAMES``: each gives its detector a fixture
pinned independently of the setting (or, for detect_challenge_farms, the
hardcoded literal) its own query compares against, so the REAL query
genuinely finds nothing, with ``run_all_detectors`` and all five detector
functions executing for real. An earlier revision of this file raised only
the setting and left the fixture's size deriving from that SAME setting,
which self-adjusts to stay just above whatever the threshold is raised to
and therefore cannot be defeated; every test below pins the fixture size to
a fixed literal via each builder's explicit size parameter instead. This is
deliberately distinct from the mapping-logic tests further down (renamed
from an earlier revision that patched ``run_all_detectors`` itself, which
bypasses every detector and therefore cannot distinguish a working detector
from a broken one): a probe that cannot be shown to fail against its OWN
real query path, for every detector it names, is worth nothing.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError

from django_waf.services.anomaly_detector import DETECTOR_NAMES
from django_waf.services.detector_probe import run_detector_probe

# ---------------------------------------------------------------------------
# run_detector_probe: falsifiability against the REAL detection path
# ---------------------------------------------------------------------------
#
# These tests let run_all_detectors, and every real detector function, run
# for real. Nothing here mocks run_all_detectors itself: doing so bypasses
# the actual queries, which is exactly the layer 2.0.0's subnet regression
# broke at, and a test built that way cannot tell a working detector from a
# broken one, it can only tell you your own hand-written return_value from
# itself.


class TestRunDetectorProbeFalsifiability:
    def test_probe_reports_all_alive_against_the_real_service(self, db):
        """Baseline green: every detector reports alive against real fixture traffic.

        Unmocked end-to-end run: proves the fixtures this module builds
        really do cross every detector's own configured threshold, not just
        that the reporting/mapping logic is self-consistent. Layer under
        test: the full real path, run_all_detectors and all five detector
        functions execute for real against the real fixture rows.
        """
        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is True
        assert result["silent_detectors"] == []
        for detector_name in DETECTOR_NAMES:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_ua_rotation_cannot_match_its_fixture(self, db, monkeypatch):
        """detect_ua_rotation: the real query legitimately finds nothing.

        Layer under test: the full real path, exactly as in the green
        baseline above. run_all_detectors is NOT patched, and
        detect_ua_rotation is NOT patched: the real query runs against real
        RequestLog rows and genuinely finds nothing.

        Raising conf.DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS alone cannot
        produce this: _build_ua_rotation_fixture's default row count derives
        from the SAME live conf value (threshold + 1), so it self-adjusts to
        stay just above whatever the threshold is regardless of how high it
        is raised. What actually decouples them, the way a real regression
        does (the fixture represents real traffic and stays fixed; the
        query's own matching logic is what breaks), is pinning the
        fixture's size independently of the setting the query reads: this
        test wraps _build_ua_rotation_fixture with its explicit
        distinct_ua_count=25 (the builder's own decoupling parameter, added
        for exactly this purpose) while raising the threshold to 9999, so
        the fixture no longer tracks the query's own threshold. The real
        query then runs, real RequestLog rows exist, and it genuinely finds
        no IP clearing 9999 distinct UAs. This is the closest analogue to
        the production failure the probe exists to catch (2.0.0's subnet
        query silently stopped matching real rows): a real query, real
        rows, a real empty result.

        25 is deliberately above the query's REAL, un-raised default
        threshold of 20 (``distinct_ua_count__gt=20``), not merely "some
        number below 9999": pinning at exactly 20 would fail the query's
        strict ``__gt`` comparison even with the raise removed (20 is not
        greater than 20), which would make this test pass whether or not
        conf.DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS was ever monkeypatched,
        the same class of vacuity this test exists to rule out. 25 clears
        the real default (25 > 20, so with the raise removed the query
        WOULD match and the test would correctly fail), so the raise to
        9999 is the only thing that makes the query miss.

        The other four detectors are untouched (their own _build_*_fixture
        helpers still run for real, at their own conf-derived defaults) and
        must still report alive.
        """
        from django_waf import conf
        from django_waf.services import detector_probe as detector_probe_mod

        monkeypatch.setattr(conf, "DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 9999)

        real_builder = detector_probe_mod._build_ua_rotation_fixture
        monkeypatch.setattr(
            detector_probe_mod,
            "_build_ua_rotation_fixture",
            lambda *, now, conf: real_builder(now=now, conf=conf, distinct_ua_count=25),
        )

        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_ua_rotation"]
        assert result["detect_ua_rotation"]["alive"] is False
        assert result["detect_ua_rotation"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_ua_rotation"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_a_real_detector_function_is_replaced(self, db):
        """A second, cheaper falsifiability route: patch detect_ua_rotation
        itself (not run_all_detectors) so run_all_detectors, and the other
        four real detector functions, still execute for real; only the one
        named function is swapped for a stub returning [].

        Layer under test: run_all_detectors' own dispatch and aggregation
        logic runs for real; only detect_ua_rotation's internals are
        replaced. This is weaker evidence than the threshold test above
        (it does not prove the real query can fail, only that a genuinely
        empty detector result flows correctly through run_all_detectors and
        into the probe's report), but it is cheaper to reason about and
        pins run_all_detectors' own aggregation independently of any one
        detector's query shape.
        """
        with patch("django_waf.services.anomaly_detector.detect_ua_rotation", return_value=[]):
            result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_ua_rotation"]
        assert result["detect_ua_rotation"]["alive"] is False
        assert result["detect_ua_rotation"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_ua_rotation"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_subnet_burst_cannot_match_its_fixture(self, db, monkeypatch):
        """detect_subnet_burst: the real query legitimately finds nothing.

        Layer under test: the full real path. run_all_detectors is NOT
        patched, and detect_subnet_burst is NOT patched.

        detect_subnet_burst has two independent gates
        (``count < min_count and count <= burst_threshold: continue``), an
        absolute floor (DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT)
        and a 3x-median ratio, either of which is sufficient to trigger a
        match (issue #80). Pinning the fixture's request count to a fixed 31
        (via the builder's total_requests parameter) while raising the
        floor to 9999 defeats the first gate; the second gate (median
        ratio) is also checked here rather than assumed: with the other
        four detectors' fixtures present in the same window, the median
        across all subnets stays low enough (the pinned subnet's own count
        of 31 does not exceed 3x that median either), so neither gate fires
        and the real query genuinely returns [].

        31, not a smaller number such as 5, is deliberately chosen to be one
        ABOVE the real, un-raised default floor of 30
        (DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT's default):
        with the floor at its real default, this fixture's count of 31
        clears ``count < min_count`` (31 is not less than 30) and so WOULD
        create a rule, and the test would correctly fail, if the raise to
        9999 were ever removed or not actually reaching the query. A
        fixture pinned below the real default (e.g. 5) fails the floor gate
        whether or not the setting is raised at all, which would make this
        assertion pass regardless of whether the monkeypatched conf value
        is real, live conf read by the query.
        """
        from django_waf import conf
        from django_waf.services import detector_probe as detector_probe_mod

        monkeypatch.setattr(conf, "DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT", 9999)

        real_builder = detector_probe_mod._build_subnet_burst_fixture
        monkeypatch.setattr(
            detector_probe_mod,
            "_build_subnet_burst_fixture",
            lambda *, now, conf: real_builder(now=now, conf=conf, total_requests=31),
        )

        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_subnet_burst"]
        assert result["detect_subnet_burst"]["alive"] is False
        assert result["detect_subnet_burst"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_subnet_burst"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_unsolved_challenges_cannot_match_its_fixture(self, db, monkeypatch):
        """detect_unsolved_challenges (per-IP path): the real query finds nothing.

        Layer under test: the full real path. run_all_detectors is NOT
        patched, and detect_unsolved_challenges is NOT patched.

        Pins the fixture to a fixed 5 challenged rows (via the builder's
        challenged_count parameter) while raising
        DJANGO_WAF_UNSOLVED_MIN_CHALLENGED to 9999, so the per-IP
        candidates = [row for row in challenged_by_ip if
        row["challenged_count"] >= min_challenged] gate genuinely excludes
        the fixture IP, and the real query returns [] for the per-IP path.

        5, not a smaller number such as 2, is deliberately chosen to be
        ABOVE the real, un-raised default of 3
        (DJANGO_WAF_UNSOLVED_MIN_CHALLENGED's default): with the setting at
        its real default, this fixture's count of 5 clears
        ``challenged_count >= min_challenged`` (5 >= 3) and so WOULD create
        a rule, and the test would correctly fail, if the raise to 9999
        were ever removed or not actually reaching the query. A fixture
        pinned below the real default (e.g. 2, which fails 2 >= 3 on its
        own) fails the gate whether or not the setting is raised at all,
        which would make this assertion pass regardless of whether the
        monkeypatched conf value is real, live conf read by the query.

        This targets the per-IP path specifically, not the subnet path
        (which uses different settings, DJANGO_WAF_UNSOLVED_SUBNET_MIN_
        CHALLENGED / DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS, and is already
        unreachable by this fixture's single contributing IP regardless of
        DJANGO_WAF_UNSOLVED_MIN_CHALLENGED, since it never reaches the
        subnet path's distinct-IP floor of 10): raising the per-IP setting
        cannot accidentally trip the subnet path into creating a rule that
        would mask the per-IP path's failure.
        """
        from django_waf import conf
        from django_waf.services import detector_probe as detector_probe_mod

        monkeypatch.setattr(conf, "DJANGO_WAF_UNSOLVED_MIN_CHALLENGED", 9999)

        real_builder = detector_probe_mod._build_unsolved_challenge_fixture
        monkeypatch.setattr(
            detector_probe_mod,
            "_build_unsolved_challenge_fixture",
            lambda *, now, conf: real_builder(now=now, conf=conf, challenged_count=5),
        )

        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_unsolved_challenges"]
        assert result["detect_unsolved_challenges"]["alive"] is False
        assert result["detect_unsolved_challenges"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_unsolved_challenges"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_cloud_spray_cannot_match_its_fixture(self, db, monkeypatch):
        """detect_cloud_spray: the real query legitimately finds nothing.

        Layer under test: the full real path. run_all_detectors is NOT
        patched, and detect_cloud_spray is NOT patched.

        DJANGO_WAF_CLOUD_SPRAY_MIN_IPS gates the detector twice: the
        UA-level distinct-IP aggregation (``.filter(distinct_ips__gte=
        min_ips)``) and the subsequent per-IP recheck (``len(suspicious_ips)
        < min_ips: continue``). Pinning the fixture to a fixed 21 distinct
        IPs (via the builder's distinct_ip_count parameter) while raising
        the setting to 9999 defeats both gates in one move, since both read
        the same setting: the UA never even reaches the results returned by
        the first query, so the real query genuinely returns [].

        21, not a smaller number such as 5, is deliberately chosen to be
        ABOVE the real, un-raised default of 20
        (DJANGO_WAF_CLOUD_SPRAY_MIN_IPS's default): with the setting at its
        real default, this fixture's 21 distinct IPs clears
        ``distinct_ips__gte=min_ips`` (21 >= 20) and so WOULD create a rule,
        and the test would correctly fail, if the raise to 9999 were ever
        removed or not actually reaching the query. A fixture pinned below
        the real default (e.g. 5, which fails 5 >= 20 on its own) fails the
        gate whether or not the setting is raised at all, which would make
        this assertion pass regardless of whether the monkeypatched conf
        value is real, live conf read by the query. All 21 IPs still share
        one /24 (the fixture's own contiguous range), so the subsequent
        per-subnet ``count < 2: continue`` gate remains trivially cleared.
        """
        from django_waf import conf
        from django_waf.services import detector_probe as detector_probe_mod

        monkeypatch.setattr(conf, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 9999)

        real_builder = detector_probe_mod._build_cloud_spray_fixture
        monkeypatch.setattr(
            detector_probe_mod,
            "_build_cloud_spray_fixture",
            lambda *, now, conf: real_builder(now=now, conf=conf, distinct_ip_count=21),
        )

        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_cloud_spray"]
        assert result["detect_cloud_spray"]["alive"] is False
        assert result["detect_cloud_spray"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_cloud_spray"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0

    def test_probe_goes_red_when_challenge_farms_cannot_match_its_fixture(self, db, monkeypatch):
        """detect_challenge_farms: the real query legitimately finds nothing.

        Layer under test: the full real path. run_all_detectors is NOT
        patched, and detect_challenge_farms is NOT patched.

        Unlike the other four detectors, BR-ANOM-003's thresholds
        (``challenge_failures__gt=10, challenge_passes__lt=2``) are
        hardcoded in the detector itself, not settings-driven, so there is
        no conf setting to raise: the coupling trap the other four had does
        not exist here. Instead, the fixture is built with
        challenge_failures=10 (via the builder's own parameter), which
        fails the detector's hardcoded ``__gt=10`` comparison (10 is not
        greater than 10), so the real query genuinely returns [].
        """
        from django_waf.services import detector_probe as detector_probe_mod

        real_builder = detector_probe_mod._build_challenge_farm_fixture
        monkeypatch.setattr(
            detector_probe_mod,
            "_build_challenge_farm_fixture",
            lambda *, now, conf: real_builder(now=now, conf=conf, challenge_failures=10, challenge_passes=0),
        )

        result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_challenge_farms"]
        assert result["detect_challenge_farms"]["alive"] is False
        assert result["detect_challenge_farms"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_challenge_farms"}:
            assert result[detector_name]["alive"] is True
            assert result[detector_name]["rules_reported"] > 0


class TestRunDetectorProbeReportingLogic:
    """Mapping/reporting-logic tests: a hand-written run_all_detectors result
    dict becomes the correct alive/silent report. These do NOT exercise any
    real detector or query; they exist to pin the reporting layer
    (DETECTOR_NAME_TO_RESULT_KEY lookup, all_alive/silent_detectors
    derivation) independently of detection logic, which the tests above
    already cover. Renamed from an earlier revision that called these
    "falsifiability" tests, which they are not: run_all_detectors never
    runs here, so they cannot distinguish a working detector from a broken
    one, only prove that a zero in a dict you wrote by hand is reported as
    silent.
    """

    def test_zero_count_in_result_dict_is_reported_as_silent(self, db):
        broken_result = {
            "ua_rotation_rules": 0,
            "subnet_burst_rules": 1,
            "challenge_farm_rules": 1,
            "unsolved_challenge_rules": 1,
            "cloud_spray_rules": 1,
            "total_rules_created": 4,
        }

        with patch(
            "django_waf.services.anomaly_detector.run_all_detectors",
            return_value=broken_result,
        ):
            result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_ua_rotation"]
        assert result["detect_ua_rotation"]["alive"] is False
        assert result["detect_ua_rotation"]["rules_reported"] == 0
        for detector_name in DETECTOR_NAMES - {"detect_ua_rotation"}:
            assert result[detector_name]["alive"] is True

    def test_multiple_zero_counts_are_all_reported_as_silent(self, db):
        """Two zeroed keys in a hand-written result dict are both named, not just the first."""
        broken_result = {
            "ua_rotation_rules": 0,
            "subnet_burst_rules": 0,
            "challenge_farm_rules": 1,
            "unsolved_challenge_rules": 1,
            "cloud_spray_rules": 1,
            "total_rules_created": 3,
        }

        with patch(
            "django_waf.services.anomaly_detector.run_all_detectors",
            return_value=broken_result,
        ):
            result = run_detector_probe(dry_run=True)

        assert result["all_alive"] is False
        assert result["silent_detectors"] == ["detect_subnet_burst", "detect_ua_rotation"]


# ---------------------------------------------------------------------------
# run_detector_probe: no side effects
# ---------------------------------------------------------------------------


class TestRunDetectorProbeLeavesNoRowsBehind:
    def test_probe_leaves_no_rows_behind(self, db):
        """Direct analogue of test_dry_run_creates_zero_block_rules: after a
        probe run, RequestLog, IPReputation, and BlockRule row counts are
        all unchanged. This is the rollback guarantee: no synthetic row may
        ever survive, regardless of dry_run.
        """
        from django_waf.models import BlockRule, IPReputation, RequestLog

        before_logs = RequestLog.objects.count()
        before_reputation = IPReputation.objects.count()
        before_rules = BlockRule.objects.count()

        run_detector_probe(dry_run=True)

        assert RequestLog.objects.count() == before_logs
        assert IPReputation.objects.count() == before_reputation
        assert BlockRule.objects.count() == before_rules

    def test_probe_leaves_no_rows_behind_with_exercise_writes(self, db):
        """The rollback guarantee holds even with dry_run=False (exercise-writes),
        which makes the detectors perform real writes inside the transaction:
        the surrounding rollback must still discard everything.
        """
        from django_waf.models import BlockRule, IPReputation, RequestLog

        before_logs = RequestLog.objects.count()
        before_reputation = IPReputation.objects.count()
        before_rules = BlockRule.objects.count()

        run_detector_probe(dry_run=False)

        assert RequestLog.objects.count() == before_logs
        assert IPReputation.objects.count() == before_reputation
        assert BlockRule.objects.count() == before_rules

    def test_probe_leaves_no_rows_behind_when_fixture_construction_raises(self, db):
        """The rollback is unconditional: even if something inside the
        transaction raises, no synthetic row survives.
        """
        from django_waf.models import BlockRule, IPReputation, RequestLog

        before_logs = RequestLog.objects.count()
        before_reputation = IPReputation.objects.count()
        before_rules = BlockRule.objects.count()

        with (
            patch(
                "django_waf.services.detector_probe._build_challenge_farm_fixture",
                side_effect=ValueError("simulated fixture-construction failure"),
            ),
            pytest.raises(ValueError, match="simulated fixture-construction failure"),
        ):
            run_detector_probe(dry_run=True)

        assert RequestLog.objects.count() == before_logs
        assert IPReputation.objects.count() == before_reputation
        assert BlockRule.objects.count() == before_rules


# ---------------------------------------------------------------------------
# run_detector_probe: dry_run forwarding and DETECTOR_NAMES mapping
# ---------------------------------------------------------------------------


class TestRunDetectorProbeDryRunForwarding:
    def test_dry_run_true_is_forwarded_to_run_all_detectors(self, db):
        from django_waf.services.anomaly_detector import DETECTOR_NAME_TO_RESULT_KEY

        with patch(
            "django_waf.services.anomaly_detector.run_all_detectors",
            return_value=dict.fromkeys(DETECTOR_NAME_TO_RESULT_KEY.values(), 1),
        ) as mock_run:
            run_detector_probe(dry_run=True)

        mock_run.assert_called_once_with(dry_run=True)

    def test_dry_run_false_exercise_writes_is_forwarded(self, db):
        from django_waf.services.anomaly_detector import DETECTOR_NAME_TO_RESULT_KEY

        with patch(
            "django_waf.services.anomaly_detector.run_all_detectors",
            return_value=dict.fromkeys(DETECTOR_NAME_TO_RESULT_KEY.values(), 1),
        ) as mock_run:
            run_detector_probe(dry_run=False)

        mock_run.assert_called_once_with(dry_run=False)

    def test_result_dry_run_key_echoes_argument(self, db):
        result_true = run_detector_probe(dry_run=True)
        assert result_true["dry_run"] is True

    def test_report_is_keyed_on_detector_names_not_result_dict_keys(self, db):
        """The report dict's keys are DETECTOR_NAMES entries (function names),
        never run_all_detectors' own result-dict keys (e.g. "ua_rotation_rules"),
        which is the whole point of the DETECTOR_NAME_TO_RESULT_KEY mapping.
        """
        result = run_detector_probe(dry_run=True)

        for detector_name in DETECTOR_NAMES:
            assert detector_name in result
        assert "ua_rotation_rules" not in result
        assert "total_rules_created" not in result


# ---------------------------------------------------------------------------
# probe_detectors task
# ---------------------------------------------------------------------------


class TestProbeDetectorsTask:
    def test_calls_run_detector_probe_and_returns_result(self, db):
        from django_waf.tasks import probe_detectors

        expected = {
            "all_alive": True,
            "silent_detectors": [],
            "dry_run": True,
            **{name: {"alive": True, "rules_reported": 1} for name in DETECTOR_NAMES},
        }

        with patch(
            "django_waf.services.detector_probe.run_detector_probe",
            return_value=expected,
        ) as mock_probe:
            result = probe_detectors()

        mock_probe.assert_called_once_with(dry_run=True)
        assert result == expected

    def test_task_never_raises_and_reports_failure_as_a_result(self, db):
        """The task's whole point is unattended liveness reporting: an
        exception from the service layer must be caught, logged, and turned
        into a failure-shaped result, never propagated.
        """
        from django_waf.tasks import probe_detectors

        with patch(
            "django_waf.services.detector_probe.run_detector_probe",
            side_effect=RuntimeError("simulated probe crash"),
        ):
            result = probe_detectors()

        assert result["all_alive"] is False
        assert set(result["silent_detectors"]) == set(DETECTOR_NAMES)
        assert "error" in result

    def test_task_default_dry_run_is_true(self, db):
        """The scheduled task always runs in dry-run mode: it never exposes
        exercise-writes, since a signal wired to paging firing on a schedule
        from synthetic data would be a self-inflicted incident.
        """
        from django_waf.tasks import probe_detectors

        with patch(
            "django_waf.services.detector_probe.run_detector_probe",
            return_value={"all_alive": True, "silent_detectors": [], "dry_run": True},
        ) as mock_probe:
            probe_detectors()

        mock_probe.assert_called_once_with(dry_run=True)


# ---------------------------------------------------------------------------
# django_waf_probe_detectors command
# ---------------------------------------------------------------------------


class TestProbeDetectorsCommand:
    @pytest.mark.django_db
    def test_all_alive_reports_success(self):
        """Real (unmocked) end-to-end run: the command completes cleanly
        and reports every detector alive, mirroring
        TestDetectAnomaliesCommandDryRunEndToEnd's real-service pattern.
        """
        out = StringIO()
        call_command("django_waf_probe_detectors", stdout=out)

        output = out.getvalue()
        assert "All detectors alive." in output
        for detector_name in DETECTOR_NAMES:
            assert f"{detector_name}: alive" in output

    @pytest.mark.django_db
    def test_silent_detector_raises_command_error_with_exit_status(self):
        """A silent detector must raise CommandError so a cron wrapper or
        k8s probe can key off exit status 1, per this command's deliberate
        departure from most django-waf commands.
        """
        broken_result = {
            "ua_rotation_rules": 0,
            "subnet_burst_rules": 1,
            "challenge_farm_rules": 1,
            "unsolved_challenge_rules": 1,
            "cloud_spray_rules": 1,
            "total_rules_created": 4,
        }

        with patch(
            "django_waf.services.anomaly_detector.run_all_detectors",
            return_value=broken_result,
        ):
            out = StringIO()
            with pytest.raises(CommandError, match="detect_ua_rotation"):
                call_command("django_waf_probe_detectors", stdout=out)

    @pytest.mark.django_db
    def test_exercise_writes_flag_forwarded_as_dry_run_false(self):
        with patch("django_waf.services.detector_probe.run_detector_probe") as mock_probe:
            mock_probe.return_value = {
                "all_alive": True,
                "silent_detectors": [],
                "dry_run": False,
                **{name: {"alive": True, "rules_reported": 1} for name in DETECTOR_NAMES},
            }
            out = StringIO()
            call_command("django_waf_probe_detectors", "--exercise-writes", stdout=out)

        mock_probe.assert_called_once_with(dry_run=False)
        assert "exercise-writes" in out.getvalue()

    @pytest.mark.django_db
    def test_default_invocation_uses_dry_run(self):
        with patch("django_waf.services.detector_probe.run_detector_probe") as mock_probe:
            mock_probe.return_value = {
                "all_alive": True,
                "silent_detectors": [],
                "dry_run": True,
                **{name: {"alive": True, "rules_reported": 1} for name in DETECTOR_NAMES},
            }
            out = StringIO()
            call_command("django_waf_probe_detectors", stdout=out)

        mock_probe.assert_called_once_with(dry_run=True)

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        with patch(
            "django_waf.services.detector_probe.run_detector_probe",
            side_effect=RuntimeError("boom"),
        ):
            out = StringIO()
            with pytest.raises(CommandError, match="Detector probe failed to run"):
                call_command("django_waf_probe_detectors", stdout=out)
