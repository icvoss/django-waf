"""Tests for the detector production-outcome report (wave 2, BR-ANOM-015).

Covers ``services.detector_outcomes.report_detector_outcomes`` and the
``django_waf_detector_outcomes`` management command.

House discipline, mirroring ``tests/test_review_workflow.py``'s
``TestAutoRuleReviewOutcomes`` and ``tests/test_flush_probe.py``: every
assertion here must be provably falsifiable. A zero-filled row is only
evidence of zero-filling if the same test also proves a non-zero row is
reachable; a "name outside the registry" assertion is only evidence if a
registered name is also proven NOT to leak into that section; a window
boundary assertion is only evidence when both a just-inside and a
just-outside row are present in the same test.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.utils import timezone

from django_waf.enums import RuleSource
from django_waf.services.anomaly_detector import DETECTOR_NAMES
from django_waf.testing.factories import BlockRuleFactory

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Zero-filling
# ---------------------------------------------------------------------------


class TestZeroFilling:
    def test_every_registered_detector_appears_even_with_no_rules_at_all(self):
        """No BlockRule rows exist anywhere: every DETECTOR_NAMES entry must
        still appear as an explicit zero row, never be omitted. Proves the
        zero-fill happens independent of any row in the table."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        result = report_detector_outcomes()

        assert set(result["detectors"]) == DETECTOR_NAMES
        for stats in result["detectors"].values():
            assert stats == {
                "rules_created": 0,
                "rules_ever_hit": 0,
                "hit_rate": 0.0,
                "total_hits": 0,
                "most_recent_rule_created": None,
            }

    def test_a_silent_detector_is_zero_filled_alongside_a_productive_one(self):
        """The case this whole report exists for: one detector produces
        real rules, a sibling detector produces nothing. The silent one
        must still appear as an explicit zero row rather than being absent,
        proven here by asserting BOTH outcomes in the same result rather
        than a report built from an all-empty table (which the previous
        test already covers and cannot distinguish "correctly zero" from
        "the whole mechanism is a no-op")."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray", hit_count=5)

        result = report_detector_outcomes()

        assert result["detectors"]["detect_cloud_spray"]["rules_created"] == 1
        # detect_subnet_burst produced nothing: must still be present, zeroed.
        assert result["detectors"]["detect_subnet_burst"] == {
            "rules_created": 0,
            "rules_ever_hit": 0,
            "hit_rate": 0.0,
            "total_hits": 0,
            "most_recent_rule_created": None,
        }


# ---------------------------------------------------------------------------
# Hit rate arithmetic
# ---------------------------------------------------------------------------


class TestHitRateArithmetic:
    def test_mixed_hit_and_never_hit_rules_compute_the_correct_rate_and_total(self):
        """Three rules attributed to one detector: two ever hit (hit_count
        > 0), one never hit (hit_count == 0). Asserts rules_created,
        rules_ever_hit, hit_rate and total_hits are all independently
        correct, not just that hit_rate is "truthy"."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_subnet_burst", hit_count=10)
        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_subnet_burst", hit_count=7)
        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_subnet_burst", hit_count=0)

        result = report_detector_outcomes()
        stats = result["detectors"]["detect_subnet_burst"]

        assert stats["rules_created"] == 3
        assert stats["rules_ever_hit"] == 2
        # hit_rate is rounded to 4 decimal places by the service (its own
        # documented contract), so the tolerance here is half a unit in the
        # last reported place rather than pytest.approx's relative default:
        # tight enough that a genuinely wrong rate (1/3, 2/2) still fails.
        assert stats["hit_rate"] == pytest.approx(2 / 3, abs=5e-5)
        assert stats["total_hits"] == 17

    def test_zero_created_never_raises_zero_division(self):
        """A detector with rules_created == 0 must report hit_rate == 0.0,
        never raise ZeroDivisionError. Already implied by the zero-fill
        tests above but pinned explicitly since this is the exact failure
        mode a naive rules_ever_hit / rules_created would hit."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        result = report_detector_outcomes()

        assert result["detectors"]["detect_challenge_farms"]["hit_rate"] == 0.0


# ---------------------------------------------------------------------------
# Names outside DETECTOR_NAMES
# ---------------------------------------------------------------------------


class TestUnregisteredDetectorNames:
    def test_challenge_escalation_appears_in_its_own_section_not_dropped_not_merged(self):
        """challenge_escalation is written to BlockRule.detectors by
        rule_engine._create_escalation_rule but is not a DETECTOR_NAMES
        member (tests/test_services.py:4064-4082). It must appear in
        unregistered_detectors, with correct stats, and must NOT appear
        inside the registered `detectors` section (which would misrepresent
        it as a seventh detector) and must NOT be silently absent from the
        whole report (which would discard real provenance data)."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="challenge_escalation", hit_count=3)

        result = report_detector_outcomes()

        assert "challenge_escalation" not in DETECTOR_NAMES  # sanity: the premise still holds
        assert "challenge_escalation" not in result["detectors"]
        assert result["unregistered_detectors"]["challenge_escalation"] == {
            "rules_created": 1,
            "rules_ever_hit": 1,
            "hit_rate": 1.0,
            "total_hits": 3,
            "most_recent_rule_created": result["unregistered_detectors"]["challenge_escalation"][
                "most_recent_rule_created"
            ],
        }
        assert result["unregistered_detectors"]["challenge_escalation"]["most_recent_rule_created"] is not None

    def test_no_unregistered_section_entries_when_only_registered_names_are_present(self):
        """Negative control for the test above: a table containing only
        registered DETECTOR_NAMES rows must leave unregistered_detectors
        empty, proving the section is not populated unconditionally."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray")

        result = report_detector_outcomes()

        assert result["unregistered_detectors"] == {}

    def test_a_rule_stamped_by_both_a_registered_and_an_unregistered_detector_counts_in_both(self):
        """detectors is additive (#97): a single row can carry both a
        registered and an unregistered name at once, e.g. a rule
        detect_subnet_burst created that rule_engine later escalated.
        Both sides must count it independently."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(
            source=RuleSource.AUTO,
            detectors="challenge_escalation,detect_subnet_burst",
            hit_count=4,
        )

        result = report_detector_outcomes()

        assert result["detectors"]["detect_subnet_burst"]["rules_created"] == 1
        assert result["unregistered_detectors"]["challenge_escalation"]["rules_created"] == 1


# ---------------------------------------------------------------------------
# Window boundary
# ---------------------------------------------------------------------------


class TestWindowBoundary:
    def test_a_rule_just_inside_the_window_counts_a_rule_just_outside_does_not(self):
        """window_days=30: one rule created 29 days ago (inside) and one
        created 31 days ago (outside), both attributed to the same
        detector. Only the inside rule may be counted, proven by asserting
        the exact count is 1, not merely "> 0"."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        now = timezone.now()
        inside = BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_ua_rotation", hit_count=1)
        outside = BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_ua_rotation", hit_count=1)

        # created_at has auto_now_add=True: back-date via a direct update,
        # matching the idiom used elsewhere in this suite for testing
        # window boundaries against an auto_now_add field.
        from django_waf.models import BlockRule

        BlockRule.objects.filter(pk=inside.pk).update(created_at=now - timedelta(days=29))
        BlockRule.objects.filter(pk=outside.pk).update(created_at=now - timedelta(days=31))

        result = report_detector_outcomes(window_days=30)
        stats = result["detectors"]["detect_ua_rotation"]

        assert stats["rules_created"] == 1
        assert stats["total_hits"] == 1

    def test_most_recent_rule_created_reflects_the_latest_row_in_window(self):
        from django_waf.models import BlockRule
        from django_waf.services.detector_outcomes import report_detector_outcomes

        now = timezone.now()
        older = BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_scraper_404_ratio")
        newer = BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_scraper_404_ratio")

        BlockRule.objects.filter(pk=older.pk).update(created_at=now - timedelta(days=20))
        BlockRule.objects.filter(pk=newer.pk).update(created_at=now - timedelta(days=1))

        result = report_detector_outcomes(window_days=30)
        stats = result["detectors"]["detect_scraper_404_ratio"]

        newer.refresh_from_db()
        assert stats["most_recent_rule_created"] == newer.created_at

    def test_window_days_must_be_positive(self):
        from django_waf.services.detector_outcomes import report_detector_outcomes

        with pytest.raises(ValueError):
            report_detector_outcomes(window_days=0)


# ---------------------------------------------------------------------------
# Comma-separated parsing: no prefix collision
# ---------------------------------------------------------------------------


class TestCommaSeparatedParsingNoPrefixCollision:
    def test_a_hypothetical_v2_suffixed_name_does_not_match_its_prefix(self):
        """detectors is comma-separated, not a blob to substring-match. A
        row stamped only "detect_cloud_spray_v2" must not be counted
        against detect_cloud_spray: proves parsing is exact-membership on
        the split set, not `in` on the raw string. (detect_cloud_spray_v2
        does not exist as a real detector; it stands in for any future name
        sharing a prefix with a registered one, exactly the trap __contains
        would fall into.)"""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray_v2", hit_count=9)

        result = report_detector_outcomes()

        assert result["detectors"]["detect_cloud_spray"]["rules_created"] == 0
        assert result["detectors"]["detect_cloud_spray"]["total_hits"] == 0
        # The unrecognised prefix-colliding name must still surface somewhere
        # rather than vanish: it lands in unregistered_detectors, exactly
        # like any other name outside DETECTOR_NAMES.
        assert result["unregistered_detectors"]["detect_cloud_spray_v2"]["rules_created"] == 1

    def test_the_real_name_still_counts_when_a_colliding_name_is_also_present(self):
        """Positive control for the test above: with both
        detect_cloud_spray and detect_cloud_spray_v2 present on different
        rows, detect_cloud_spray's own count must be exactly the rows that
        genuinely carry it, proving the collision test isn't passing only
        because detect_cloud_spray was never reachable at all."""
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray", hit_count=2)
        BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray_v2", hit_count=9)

        result = report_detector_outcomes()

        assert result["detectors"]["detect_cloud_spray"]["rules_created"] == 1
        assert result["detectors"]["detect_cloud_spray"]["total_hits"] == 2


# ---------------------------------------------------------------------------
# Review outcomes reuse
# ---------------------------------------------------------------------------


class TestReviewOutcomesReuse:
    def test_review_outcomes_key_reflects_real_rule_state(self):
        """Not a stub: report_detector_outcomes must call the real
        auto_rule_review_outcomes and surface its real counts, proven by
        creating a PENDING auto rule and asserting it is reflected."""
        from django_waf.enums import ReviewStatus
        from django_waf.services.detector_outcomes import report_detector_outcomes

        BlockRuleFactory(
            source=RuleSource.AUTO,
            review_status=ReviewStatus.PENDING,
            detectors="detect_unsolved_challenges",
        )

        result = report_detector_outcomes()

        assert result["review_outcomes"]["pending"] == 1
        assert result["review_outcomes"]["total"] == 1


# ---------------------------------------------------------------------------
# Read-only
# ---------------------------------------------------------------------------


class TestReadOnly:
    def test_running_the_report_creates_no_rows_and_changes_no_existing_row(self):
        from django_waf.models import BlockRule
        from django_waf.services.detector_outcomes import report_detector_outcomes

        rule = BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray", hit_count=5)
        before_count = BlockRule.objects.count()
        before_hit_count = rule.hit_count

        report_detector_outcomes()
        report_detector_outcomes(window_days=1)

        rule.refresh_from_db()
        assert BlockRule.objects.count() == before_count
        assert rule.hit_count == before_hit_count


# ---------------------------------------------------------------------------
# Management command
# ---------------------------------------------------------------------------


class TestDetectorOutcomesCommand:
    def test_command_reports_every_registered_detector_by_name(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("django_waf_detector_outcomes", stdout=out)
        output = out.getvalue()

        for name in DETECTOR_NAMES:
            assert name in output

    def test_command_surfaces_unregistered_names_in_their_own_section(self):
        from io import StringIO

        from django.core.management import call_command

        BlockRuleFactory(source=RuleSource.AUTO, detectors="challenge_escalation")

        out = StringIO()
        call_command("django_waf_detector_outcomes", stdout=out)
        output = out.getvalue()

        assert "challenge_escalation" in output
        assert "outside anomaly_detector.DETECTOR_NAMES" in output

    def test_command_accepts_a_days_argument(self):
        from io import StringIO

        from django.core.management import call_command

        out = StringIO()
        call_command("django_waf_detector_outcomes", "--days", "7", stdout=out)

        assert "last 7 day(s)" in out.getvalue()

    def test_command_rejects_a_non_positive_days_argument(self):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        with pytest.raises(CommandError):
            call_command("django_waf_detector_outcomes", "--days", "0")


class TestQueryCost:
    """Pins the report's query count so the module docstring's cost claim
    cannot silently rot into an N+1.

    The docstring states two queries: one scan for the per-detector
    aggregate, plus the single GROUP BY ``auto_rule_review_outcomes``
    (BR-ANOM-010) issues for the review-outcome section. That claim was
    measured with ``CaptureQueriesContext``, not asserted, and this test is
    what keeps it measured. A future refactor that moved the per-detector
    aggregate back to one LIKE-filtered query per registry entry would
    take the count to eight and fail here, which is the whole point: the
    plan flagged per-detector query cost as a real risk against a
    production table of roughly 54,000 rows.
    """

    @pytest.mark.django_db
    def test_report_issues_a_constant_number_of_queries(self):
        """The query count must not scale with the number of rules."""
        from django.db import connection
        from django.test.utils import CaptureQueriesContext

        from django_waf.services.detector_outcomes import report_detector_outcomes

        for index in range(3):
            BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_subnet_burst", hit_count=index)

        with CaptureQueriesContext(connection) as few_rows:
            report_detector_outcomes()

        for index in range(30):
            BlockRuleFactory(source=RuleSource.AUTO, detectors="detect_cloud_spray", hit_count=index)

        with CaptureQueriesContext(connection) as many_rows:
            result = report_detector_outcomes()

        # Non-vacuous: the second run really did see the extra rows, so a
        # constant query count is evidence of constant cost rather than
        # evidence that neither run read anything.
        assert result["detectors"]["detect_cloud_spray"]["rules_created"] == 30
        assert len(few_rows) == 2
        assert len(many_rows) == 2
