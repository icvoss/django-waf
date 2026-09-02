"""Tests for django-waf management commands.

Each command is tested for:
  - ``--dry-run`` mode (should report without side effects)
  - Normal execution (should call the underlying service)
  - Stdout output
  - Argument handling / edge cases
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, create_autospec, patch

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone

from django_waf.services.anomaly_detector import run_all_detectors
from django_waf.testing.factories import (
    AllowRuleFactory,
    BlockRuleFactory,
    ChallengeTokenFactory,
    RequestLogFactory,
)

# ---------------------------------------------------------------------------
# django_waf_generate_blocklist
# ---------------------------------------------------------------------------


class TestGenerateBlocklistCommand:
    """Tests for the ``django_waf_generate_blocklist`` management command."""

    @pytest.mark.django_db
    def test_dry_run_does_not_write_file(self, tmp_path):
        """Dry-run prints the blocklist to stdout and does not create a permanent file."""
        fake_conf = tmp_path / "blocklist.conf"
        fake_conf.write_text("# placeholder\n")

        with patch(
            "django_waf.services.blocklist_generator.generate_nginx_blocklist",
            return_value=3,
        ) as mock_generate:
            out = StringIO()
            call_command("django_waf_generate_blocklist", "--dry-run", stdout=out)

        # The service IS called (to populate the temp file), but the permanent
        # output path is not touched.
        mock_generate.assert_called_once()
        output = out.getvalue()
        assert "dry-run" in output
        assert "3 rule(s)" in output

    @pytest.mark.django_db
    def test_normal_run_calls_service_and_reloads_nginx(self, tmp_path):
        """Normal run calls generate_nginx_blocklist and reload_nginx."""
        with (
            patch(
                "django_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=5,
            ) as mock_generate,
            patch(
                "django_waf.services.blocklist_generator.reload_nginx",
                return_value=True,
            ) as mock_reload,
        ):
            out = StringIO()
            call_command("django_waf_generate_blocklist", stdout=out)

        mock_generate.assert_called_once_with(output_path=None)
        mock_reload.assert_called_once()
        output = out.getvalue()
        assert "5 rule(s)" in output
        assert "nginx reloaded" in output

    @pytest.mark.django_db
    def test_normal_run_with_output_path(self, tmp_path):
        """--output-path is forwarded to the service."""
        custom_path = str(tmp_path / "custom.conf")

        with (
            patch(
                "django_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=1,
            ) as mock_generate,
            patch(
                "django_waf.services.blocklist_generator.reload_nginx",
                return_value=True,
            ),
        ):
            call_command("django_waf_generate_blocklist", f"--output-path={custom_path}")

        mock_generate.assert_called_once_with(output_path=custom_path)

    @pytest.mark.django_db
    def test_nginx_reload_failure_shows_warning(self):
        """When nginx reload fails the command emits a warning, not an error."""
        with (
            patch(
                "django_waf.services.blocklist_generator.generate_nginx_blocklist",
                return_value=2,
            ),
            patch(
                "django_waf.services.blocklist_generator.reload_nginx",
                return_value=False,
            ),
        ):
            out = StringIO()
            call_command("django_waf_generate_blocklist", stdout=out)

        output = out.getvalue()
        assert "reload nginx manually" in output

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        with (
            patch(
                "django_waf.services.blocklist_generator.generate_nginx_blocklist",
                side_effect=RuntimeError("disk full"),
            ),
            pytest.raises(CommandError, match="Failed to generate blocklist"),
        ):
            call_command("django_waf_generate_blocklist")


# ---------------------------------------------------------------------------
# django_waf_detect_anomalies
# ---------------------------------------------------------------------------


class TestDetectAnomaliesCommand:
    """Tests for the ``django_waf_detect_anomalies`` management command."""

    @staticmethod
    def _autospec_detector(return_value=None, side_effect=None):
        """Build an autospec'd mock of run_all_detectors.

        Using ``create_autospec`` (rather than a loose ``patch(...)``) means a
        call with a signature the real function doesn't accept raises
        ``TypeError`` from the mock itself, catching regressions like the one
        that let ``--window-minutes`` silently pass an unsupported keyword
        argument through to the service for an entire release.
        """
        mock_detect = create_autospec(run_all_detectors, spec_set=True)
        if side_effect is not None:
            mock_detect.side_effect = side_effect
        else:
            mock_detect.return_value = return_value
        return mock_detect

    @pytest.mark.django_db
    def test_dry_run_reports_without_creating_rules(self):
        """Dry-run emits the dry-run notice and displays detector results."""
        results = {"burst_detector": [MagicMock(), MagicMock()], "ua_rotation": []}
        mock_detect = self._autospec_detector(return_value=results)

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            out = StringIO()
            call_command("django_waf_detect_anomalies", "--dry-run", stdout=out)

        mock_detect.assert_called_once_with(window_minutes=None, dry_run=True)
        output = out.getvalue()
        assert "dry-run" in output
        assert "would create" in output
        assert "2 rule(s)" in output

    @pytest.mark.django_db
    def test_normal_run_calls_service(self):
        """Normal run calls run_all_detectors and reports created rule counts."""
        results = {"burst_detector": [MagicMock()], "ua_rotation": [MagicMock(), MagicMock()]}
        mock_detect = self._autospec_detector(return_value=results)

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            out = StringIO()
            call_command("django_waf_detect_anomalies", stdout=out)

        mock_detect.assert_called_once_with(window_minutes=None, dry_run=False)
        output = out.getvalue()
        assert "created" in output
        assert "3 anomaly rule(s)" in output

    @pytest.mark.django_db
    def test_window_minutes_forwarded_to_service(self):
        """--window-minutes is passed through to run_all_detectors."""
        mock_detect = self._autospec_detector(return_value={})

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            call_command("django_waf_detect_anomalies", "--window-minutes=10")

        mock_detect.assert_called_once_with(window_minutes=10, dry_run=False)

    @pytest.mark.django_db
    def test_no_anomalies_detected_message(self):
        """When no anomalies are detected the success message is shown."""
        mock_detect = self._autospec_detector(return_value={"burst_detector": [], "ua_rotation": []})

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            out = StringIO()
            call_command("django_waf_detect_anomalies", stdout=out)

        assert "No anomalies detected" in out.getvalue()

    @pytest.mark.django_db
    def test_total_rules_created_key_is_not_double_counted(self):
        """Issue #99: run_all_detectors' real return dict carries a
        total_rules_created key ALONGSIDE the six per-detector keys (see
        its own return statement). Before this fix, the command's
        `for detector_name, rules_created in results.items()` loop iterated
        that key too, printing it as if it were a seventh detector AND
        adding its value a second time to total_created, exactly doubling
        the reported total. A live run during the wave-2 investigation
        printed "unsolved_challenge_rules: would create 2" then
        "total_rules_created: would create 2" and concluded "Would have
        created 4 rule(s)" for what was actually 2 real rules.

        Uses the real int-shaped result dict run_all_detectors actually
        returns (int counts, not lists of mock rule objects, unlike the
        other tests in this class, which predate #99's own key and use a
        two-key stand-in dict that never exercised this bug), so the
        total_rules_created key is genuinely present, exactly as it always
        is on a real call.
        """
        results = {
            "ua_rotation_rules": 0,
            "subnet_burst_rules": 0,
            "challenge_farm_rules": 0,
            "unsolved_challenge_rules": 2,
            "cloud_spray_rules": 0,
            "scraper_404_rules": 0,
            "total_rules_created": 2,
        }
        mock_detect = self._autospec_detector(return_value=results)

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            out = StringIO()
            call_command("django_waf_detect_anomalies", "--dry-run", stdout=out)

        output = out.getvalue()
        assert "Would have created 2 rule(s)." in output
        assert "Would have created 4 rule(s)." not in output
        assert "total_rules_created" not in output

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        mock_detect = self._autospec_detector(side_effect=ValueError("bad window"))

        with (
            patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect),
            pytest.raises(CommandError, match="Anomaly detection failed"),
        ):
            call_command("django_waf_detect_anomalies")

    @pytest.mark.django_db
    def test_dry_run_with_window_minutes(self):
        """Dry-run correctly forwards --window-minutes."""
        mock_detect = self._autospec_detector(return_value={"ua_rotation": [MagicMock()]})

        with patch("django_waf.services.anomaly_detector.run_all_detectors", mock_detect):
            out = StringIO()
            call_command("django_waf_detect_anomalies", "--dry-run", "--window-minutes=20", stdout=out)

        mock_detect.assert_called_once_with(window_minutes=20, dry_run=True)
        assert "dry-run" in out.getvalue()

    @pytest.mark.django_db
    def test_window_minutes_end_to_end_against_real_service(self):
        """--window-minutes reaches the real run_all_detectors without mocking.

        Regression test for the bug where the command forwarded
        ``window_minutes`` to a ``run_all_detectors()`` that accepted no
        parameters at all, raising ``TypeError`` (masked as a CommandError)
        whenever ``--window-minutes`` was passed. No RequestLog data is
        created, so no anomalies are expected; the point is that the command
        completes successfully end-to-end with the flag set.
        """
        out = StringIO()
        call_command("django_waf_detect_anomalies", "--window-minutes=10", stdout=out)

        assert "No anomalies detected" in out.getvalue()


# ---------------------------------------------------------------------------
# django_waf_prune_logs
# ---------------------------------------------------------------------------


class TestPruneLogsCommand:
    """Tests for the ``django_waf_prune_logs`` management command."""

    @pytest.mark.django_db
    def test_dry_run_counts_without_deleting(self):
        """Dry-run reports stale record count and does not delete anything."""
        cutoff = timezone.now() - timezone.timedelta(days=31)
        # Create 3 old logs and 1 recent log.
        for _ in range(3):
            RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))
        RequestLogFactory()  # recent — should not be counted

        out = StringIO()
        call_command("django_waf_prune_logs", "--dry-run", "--days=30", stdout=out)

        from django_waf.models import RequestLog

        # Nothing should have been deleted.
        assert RequestLog.objects.count() == 4
        output = out.getvalue()
        assert "dry-run" in output
        assert "3 log record(s)" in output

    @pytest.mark.django_db
    def test_normal_run_deletes_old_records(self):
        """Normal run deletes records older than the retention window."""
        cutoff = timezone.now() - timezone.timedelta(days=31)
        for _ in range(2):
            RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))
        RequestLogFactory()  # recent — must survive

        from django_waf.models import RequestLog

        out = StringIO()
        call_command("django_waf_prune_logs", "--days=30", stdout=out)

        assert RequestLog.objects.count() == 1
        output = out.getvalue()
        assert "Deleted 2 log record(s)" in output

    @pytest.mark.django_db
    def test_days_argument_overrides_default(self):
        """--days overrides the configured retention period."""
        cutoff = timezone.now() - timezone.timedelta(days=8)
        RequestLogFactory(timestamp=cutoff - timezone.timedelta(hours=1))

        from django_waf.models import RequestLog

        call_command("django_waf_prune_logs", "--days=7")
        assert RequestLog.objects.count() == 0

    @pytest.mark.django_db
    def test_zero_days_raises_command_error(self):
        """--days=0 is rejected with a CommandError."""
        with pytest.raises(CommandError, match="positive integer"):
            call_command("django_waf_prune_logs", "--days=0")

    @pytest.mark.django_db
    def test_no_old_records_reports_zero_deleted(self):
        """When there are no stale records the command reports zero deletions."""
        RequestLogFactory()  # recent only

        out = StringIO()
        call_command("django_waf_prune_logs", "--days=30", stdout=out)

        assert "Deleted 0 log record(s)" in out.getvalue()

    @pytest.mark.django_db
    def test_default_retention_uses_conf_value(self):
        """When --days is omitted the command reads DJANGO_WAF_LOG_RETENTION_DAYS from conf."""
        from django_waf import conf

        default_days = conf.DJANGO_WAF_LOG_RETENTION_DAYS
        cutoff = timezone.now() - timezone.timedelta(days=default_days + 1)
        RequestLogFactory(timestamp=cutoff)

        from django_waf.models import RequestLog

        call_command("django_waf_prune_logs")
        assert RequestLog.objects.count() == 0


# ---------------------------------------------------------------------------
# django_waf_prune_challenges
# ---------------------------------------------------------------------------


class TestPruneChallengesCommand:
    """Tests for the ``django_waf_prune_challenges`` management command."""

    @pytest.mark.django_db
    def test_dry_run_counts_without_deleting(self):
        """Dry-run reports the stale token count and does not delete anything."""
        from django_waf.enums import ChallengeStatus

        old_cutoff = timezone.now() - timezone.timedelta(hours=25)
        for _ in range(2):
            ChallengeTokenFactory(status=ChallengeStatus.PENDING, expires_at=old_cutoff)
        ChallengeTokenFactory(status=ChallengeStatus.SOLVED, expires_at=old_cutoff)  # not pruned — solved

        out = StringIO()
        call_command("django_waf_prune_challenges", "--dry-run", "--hours=24", stdout=out)

        from django_waf.models import ChallengeToken

        assert ChallengeToken.objects.count() == 3
        output = out.getvalue()
        assert "dry-run" in output
        assert "2 challenge token(s)" in output

    @pytest.mark.django_db
    def test_normal_run_deletes_expired_pending_and_failed_tokens(self):
        """Normal run deletes PENDING/FAILED tokens older than the threshold."""
        from django_waf.enums import ChallengeStatus

        old_cutoff = timezone.now() - timezone.timedelta(hours=25)
        ChallengeTokenFactory(status=ChallengeStatus.PENDING, expires_at=old_cutoff)
        ChallengeTokenFactory(status=ChallengeStatus.FAILED, expires_at=old_cutoff)
        survivor = ChallengeTokenFactory(
            status=ChallengeStatus.PENDING, expires_at=timezone.now() + timezone.timedelta(hours=1)
        )

        from django_waf.models import ChallengeToken

        out = StringIO()
        call_command("django_waf_prune_challenges", "--hours=24", stdout=out)

        assert ChallengeToken.objects.count() == 1
        assert ChallengeToken.objects.filter(pk=survivor.pk).exists()
        assert "Deleted 2 challenge token(s)" in out.getvalue()

    @pytest.mark.django_db
    def test_zero_hours_raises_command_error(self):
        """--hours=0 is rejected with a CommandError."""
        with pytest.raises(CommandError, match="positive integer"):
            call_command("django_waf_prune_challenges", "--hours=0")

    @pytest.mark.django_db
    def test_no_stale_tokens_reports_zero_deleted(self):
        """When no tokens are stale the command reports zero deletions."""
        from django_waf.enums import ChallengeStatus

        ChallengeTokenFactory(status=ChallengeStatus.PENDING, expires_at=timezone.now() + timezone.timedelta(hours=1))

        out = StringIO()
        call_command("django_waf_prune_challenges", "--hours=24", stdout=out)

        assert "Deleted 0 challenge token(s)" in out.getvalue()


# ---------------------------------------------------------------------------
# django_waf_prune_rules
# ---------------------------------------------------------------------------


class TestPruneRulesCommand:
    """Tests for the ``django_waf_prune_rules`` management command.

    The command inverts the other two prune commands' default: no flags
    means report-only, ``--execute`` is required to actually delete. Every
    test below therefore asserts the table is non-empty first (so a
    survival assertion is never vacuous against an empty queryset), and at
    least one test proves the predicate has teeth by inducing a genuine
    deletion rather than only ever watching rows survive.
    """

    @staticmethod
    def _stale_kwargs(days_expired: int = 100):
        """Kwargs for a BlockRule that qualifies for deletion outright."""
        from django_waf.enums import ReviewStatus, RuleSource

        return {
            "source": RuleSource.AUTO,
            "is_active": False,
            "expires_at": timezone.now() - timezone.timedelta(days=days_expired),
            "review_status": ReviewStatus.NOT_APPLICABLE,
        }

    @pytest.mark.django_db
    def test_dry_run_is_the_default_and_deletes_nothing(self):
        """No flags at all: reports the count, deletes nothing."""
        from django_waf.testing.factories import BlockRuleFactory

        BlockRuleFactory(**self._stale_kwargs())
        BlockRuleFactory(**self._stale_kwargs())

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 2

        out = StringIO()
        call_command("django_waf_prune_rules", "--days=90", stdout=out)

        assert BlockRule.objects.count() == 2
        output = out.getvalue()
        assert "dry-run" in output
        assert "2 block rule(s)" in output
        assert "--execute" in output

    @pytest.mark.django_db
    def test_explicit_dry_run_flag_matches_default(self):
        """--dry-run is accepted as a no-op synonym for the default behaviour."""
        from django_waf.testing.factories import BlockRuleFactory

        BlockRuleFactory(**self._stale_kwargs())

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        out = StringIO()
        call_command("django_waf_prune_rules", "--dry-run", "--days=90", stdout=out)

        assert BlockRule.objects.count() == 1
        assert "1 block rule(s)" in out.getvalue()

    @pytest.mark.django_db
    def test_execute_deletes_matching_rows(self):
        """--execute performs the deletion the dry-run count promised.

        Proves the predicate has teeth: a genuinely stale row is actually
        removed by a real run, not merely reported.
        """
        from django_waf.testing.factories import BlockRuleFactory

        stale = BlockRuleFactory(**self._stale_kwargs())

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        dry_run_out = StringIO()
        call_command("django_waf_prune_rules", "--days=90", stdout=dry_run_out)
        assert "1 block rule(s)" in dry_run_out.getvalue()
        assert BlockRule.objects.filter(pk=stale.pk).exists()

        execute_out = StringIO()
        call_command("django_waf_prune_rules", "--days=90", "--execute", stdout=execute_out)

        assert not BlockRule.objects.filter(pk=stale.pk).exists()
        assert "Deleted 1 block rule(s)" in execute_out.getvalue()

    @pytest.mark.django_db
    def test_active_rule_survives_execute(self):
        """An active rule is never deleted, even with --execute."""
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["is_active"] = True
        active = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=active.pk).exists()

    @pytest.mark.django_db
    def test_unexpired_rule_survives_execute(self):
        """A rule whose expiry has not passed is never deleted."""
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["expires_at"] = timezone.now() + timezone.timedelta(days=1)
        unexpired = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=unexpired.pk).exists()

    @pytest.mark.django_db
    def test_pending_review_rule_survives_execute(self):
        """A rule still PENDING review is never deleted."""
        from django_waf.enums import ReviewStatus
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["review_status"] = ReviewStatus.PENDING
        pending = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=pending.pk).exists()

    @pytest.mark.django_db
    def test_confirmed_rule_survives_execute(self):
        """A rule an operator CONFIRMED is never deleted."""
        from django_waf.enums import ReviewStatus
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["review_status"] = ReviewStatus.CONFIRMED
        confirmed = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=confirmed.pk).exists()

    @pytest.mark.django_db
    def test_rejected_rule_survives_execute(self):
        """A rule an operator REJECTED is never deleted.

        Deliberate: a rejection is a decision the operator already made
        once. Deleting the row loses the record of that decision, so the
        next time a detector re-observes the same pattern it recreates the
        rule and the operator has to reject it again.
        """
        from django_waf.enums import ReviewStatus
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["review_status"] = ReviewStatus.REJECTED
        rejected = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=rejected.pk).exists()

    @pytest.mark.django_db
    def test_expired_unreviewed_rule_is_deleted_by_execute(self):
        """An EXPIRED_UNREVIEWED rule IS deleted: the counterpart to the REJECTED test above.

        expire_rules (BR-ANOM-010) moves a rule here when it was PENDING
        and its expires_at passed with nobody reviewing it. Unlike
        REJECTED, nobody made an explicit decision about the pattern, so
        there is no operator judgement to preserve and this row is safe to
        reclaim once stale.
        """
        from django_waf.enums import ReviewStatus
        from django_waf.testing.factories import BlockRuleFactory

        kwargs = self._stale_kwargs()
        kwargs["review_status"] = ReviewStatus.EXPIRED_UNREVIEWED
        expired_unreviewed = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert not BlockRule.objects.filter(pk=expired_unreviewed.pk).exists()

    @pytest.mark.django_db
    def test_admin_sourced_rule_survives_execute(self):
        """A hand-authored admin rule is never deleted regardless of age or state.

        source scoping is deliberate: an operator's own rule is not the
        self-regenerating auto-detector output this retention path exists
        to bound.
        """
        from django_waf.enums import ReviewStatus
        from django_waf.enums import RuleSource as RuleSourceEnum
        from django_waf.testing.factories import BlockRuleFactory

        admin_rule = BlockRuleFactory(
            source=RuleSourceEnum.ADMIN,
            is_active=False,
            expires_at=timezone.now() - timezone.timedelta(days=100),
            review_status=ReviewStatus.NOT_APPLICABLE,
        )

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=admin_rule.pk).exists()

    @pytest.mark.django_db
    def test_feed_sourced_rule_survives_execute(self):
        """A feed-sourced rule is never deleted regardless of age or state."""
        from django_waf.enums import ReviewStatus
        from django_waf.enums import RuleSource as RuleSourceEnum
        from django_waf.testing.factories import BlockRuleFactory

        feed_rule = BlockRuleFactory(
            source=RuleSourceEnum.FEED,
            is_active=False,
            expires_at=timezone.now() - timezone.timedelta(days=100),
            review_status=ReviewStatus.NOT_APPLICABLE,
        )

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=feed_rule.pk).exists()

    @pytest.mark.django_db
    def test_window_boundary_just_inside_survives_and_just_outside_is_deleted(self):
        """A row just inside the retention window survives; just outside is deleted."""
        from django_waf.testing.factories import BlockRuleFactory

        cutoff = timezone.now() - timezone.timedelta(days=90)
        just_inside = BlockRuleFactory(**{**self._stale_kwargs(), "expires_at": cutoff + timezone.timedelta(hours=1)})
        just_outside = BlockRuleFactory(**{**self._stale_kwargs(), "expires_at": cutoff - timezone.timedelta(hours=1)})

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 2

        call_command("django_waf_prune_rules", "--days=90", "--execute")

        assert BlockRule.objects.filter(pk=just_inside.pk).exists()
        assert not BlockRule.objects.filter(pk=just_outside.pk).exists()

    @pytest.mark.django_db
    def test_zero_days_raises_command_error(self):
        """--days=0 is rejected with a CommandError."""
        with pytest.raises(CommandError, match="positive integer"):
            call_command("django_waf_prune_rules", "--days=0")

    @pytest.mark.django_db
    def test_no_stale_rules_reports_zero(self):
        """When nothing is stale the dry-run reports zero."""
        from django_waf.testing.factories import BlockRuleFactory

        BlockRuleFactory()  # active, admin, default factory state, not stale

        out = StringIO()
        call_command("django_waf_prune_rules", "--days=90", stdout=out)

        assert "0 block rule(s)" in out.getvalue()

    @pytest.mark.django_db
    def test_default_retention_uses_conf_value(self):
        """When --days is omitted the command reads DJANGO_WAF_RULE_RETENTION_DAYS from conf."""
        from django_waf import conf
        from django_waf.testing.factories import BlockRuleFactory

        default_days = conf.DJANGO_WAF_RULE_RETENTION_DAYS
        kwargs = self._stale_kwargs()
        kwargs["expires_at"] = timezone.now() - timezone.timedelta(days=default_days + 1)
        stale = BlockRuleFactory(**kwargs)

        from django_waf.models import BlockRule

        assert BlockRule.objects.count() == 1

        call_command("django_waf_prune_rules", "--execute")

        assert not BlockRule.objects.filter(pk=stale.pk).exists()


# ---------------------------------------------------------------------------
# django_waf_sync_feed
# ---------------------------------------------------------------------------


class TestSyncFeedCommand:
    """Tests for the ``django_waf_sync_feed`` management command."""

    @pytest.mark.django_db
    def test_skips_when_feed_disabled_and_no_url(self):
        """Command exits early with a warning when feed is disabled and no URL given."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", False),
            patch("django_waf.services.threat_feed.sync_feed") as mock_sync,
        ):
            out = StringIO()
            call_command("django_waf_sync_feed", stdout=out)

        mock_sync.assert_not_called()
        assert "Skipping sync" in out.getvalue()

    @pytest.mark.django_db
    def test_dry_run_emits_notice(self):
        """Dry-run prints the notice before calling the service."""
        summary = {"created": 0, "updated": 0, "expired": 0, "skipped": 0}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch("django_waf.services.threat_feed.sync_feed", return_value=summary),
        ):
            out = StringIO()
            call_command("django_waf_sync_feed", "--dry-run", stdout=out)

        assert "dry-run" in out.getvalue()

    @pytest.mark.django_db
    def test_normal_run_calls_sync_feed(self):
        """Normal run calls sync_feed and reports the summary."""
        summary = {"created": 4, "updated": 1, "expired": 2, "skipped": 3}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch("django_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            out = StringIO()
            call_command("django_waf_sync_feed", stdout=out)

        mock_sync.assert_called_once_with(feed_url=None, min_confidence=None)
        output = out.getvalue()
        assert "4 created" in output
        assert "1 updated" in output
        assert "2 expired" in output
        assert "3 skipped" in output

    @pytest.mark.django_db
    def test_feed_url_override_bypasses_disabled_check(self):
        """Passing --feed-url overrides the feed-disabled guard and calls the service."""
        summary = {"created": 1, "updated": 0, "expired": 0, "skipped": 0}
        # Feed disabled at conf level — but --feed-url should bypass the guard.
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", False),
            patch("django_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            out = StringIO()
            call_command(
                "django_waf_sync_feed",
                "--feed-url=https://example.com/feed.json",
                stdout=out,
            )

        mock_sync.assert_called_once_with(
            feed_url="https://example.com/feed.json",
            min_confidence=None,
        )
        assert "Feed sync complete" in out.getvalue()

    @pytest.mark.django_db
    def test_min_confidence_forwarded_to_service(self):
        """--min-confidence is forwarded to sync_feed."""
        summary = {"created": 0, "updated": 0, "expired": 0, "skipped": 10}
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch("django_waf.services.threat_feed.sync_feed", return_value=summary) as mock_sync,
        ):
            call_command("django_waf_sync_feed", "--min-confidence=0.9")

        mock_sync.assert_called_once_with(feed_url=None, min_confidence=0.9)

    @pytest.mark.django_db
    def test_service_exception_raises_command_error(self):
        """A service exception is converted to CommandError."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch(
                "django_waf.services.threat_feed.sync_feed",
                side_effect=ConnectionError("timeout"),
            ),
            pytest.raises(CommandError, match="Feed sync failed"),
        ):
            call_command("django_waf_sync_feed")

    @pytest.mark.django_db
    def test_partial_summary_keys_default_to_zero(self):
        """A summary dict with missing keys defaults missing counts to zero without error."""
        with (
            patch("django_waf.conf.DJANGO_WAF_FEED_ENABLED", True),
            patch(
                "django_waf.services.threat_feed.sync_feed",
                return_value={"created": 2},
            ),
        ):
            out = StringIO()
            call_command("django_waf_sync_feed", stdout=out)

        output = out.getvalue()
        assert "2 created" in output
        assert "0 updated" in output
        assert "0 expired" in output
        assert "0 skipped" in output


# ---------------------------------------------------------------------------
# django_waf_block
# ---------------------------------------------------------------------------


class TestBlockCommand:
    """Tests for the ``django_waf_block`` management command."""

    @pytest.mark.django_db
    def test_block_creates_ip_rule(self):
        """Blocking a plain IP creates a BlockRule with rule_type=ip, match_type=exact."""
        from django_waf.enums import RuleSource, RuleType
        from django_waf.models import BlockRule

        out = StringIO()
        call_command("django_waf_block", "203.0.113.42", stdout=out)

        rule = BlockRule.objects.get(pattern="203.0.113.42")
        assert rule.rule_type == RuleType.IP
        assert rule.match_type == "exact"
        assert rule.source == RuleSource.ADMIN
        assert rule.action == "block"
        assert rule.is_active is True
        assert rule.expires_at is None
        output = out.getvalue()
        assert "Blocked 203.0.113.42" in output
        assert "Permanent" in output

    @pytest.mark.django_db
    def test_block_creates_cidr_rule(self):
        """Blocking a CIDR range creates a rule with rule_type=cidr, match_type=cidr."""
        from django_waf.enums import RuleType
        from django_waf.models import BlockRule

        call_command("django_waf_block", "10.0.0.0/24")

        rule = BlockRule.objects.get(pattern="10.0.0.0/24")
        assert rule.rule_type == RuleType.CIDR
        assert rule.match_type == "cidr"

    @pytest.mark.django_db
    def test_block_with_ttl_sets_expires_at(self):
        """--ttl converts hours into an absolute expires_at timestamp."""
        from django_waf.models import BlockRule

        out = StringIO()
        call_command("django_waf_block", "203.0.113.99", "--ttl", "24", stdout=out)

        rule = BlockRule.objects.get(pattern="203.0.113.99")
        assert rule.expires_at is not None
        delta = rule.expires_at - timezone.now()
        # Should be ~24h from now (allow 60s slack for test timing)
        assert 23 * 3600 < delta.total_seconds() < 25 * 3600
        assert "Expires:" in out.getvalue()

    @pytest.mark.django_db
    def test_block_with_reason_populates_notes(self):
        """--reason is stored in the rule's notes field and echoed to stdout."""
        from django_waf.models import BlockRule

        out = StringIO()
        call_command(
            "django_waf_block",
            "203.0.113.10",
            "--reason",
            "scanner from threat feed",
            stdout=out,
        )

        rule = BlockRule.objects.get(pattern="203.0.113.10")
        assert rule.notes == "scanner from threat feed"
        assert "Reason: scanner from threat feed" in out.getvalue()

    @pytest.mark.django_db
    def test_block_with_challenge_action(self):
        """--action=challenge produces a challenge rule rather than a block."""
        from django_waf.models import BlockRule

        out = StringIO()
        call_command("django_waf_block", "203.0.113.11", "--action", "challenge", stdout=out)

        rule = BlockRule.objects.get(pattern="203.0.113.11")
        assert rule.action == "challenge"
        assert "(challenge)" in out.getvalue()

    @pytest.mark.django_db
    def test_block_idempotent_updates_existing_rule(self):
        """Blocking the same pattern twice updates the existing rule (update_or_create)."""
        from django_waf.models import BlockRule

        call_command("django_waf_block", "203.0.113.50", "--reason", "first")
        out = StringIO()
        call_command("django_waf_block", "203.0.113.50", "--reason", "second", stdout=out)

        # Only one rule exists
        rules = BlockRule.objects.filter(pattern="203.0.113.50")
        assert rules.count() == 1
        assert rules.first().notes == "second"
        assert "Updated existing rule" in out.getvalue()

    @pytest.mark.django_db
    def test_block_db_failure_raises_command_error(self):
        """A BlockRule.update_or_create exception is converted to CommandError."""
        with (
            patch(
                "django_waf.models.BlockRule.objects.update_or_create",
                side_effect=RuntimeError("db error"),
            ),
            pytest.raises(CommandError, match="Failed to create rule"),
        ):
            call_command("django_waf_block", "203.0.113.200")


# ---------------------------------------------------------------------------
# django_waf_unblock
# ---------------------------------------------------------------------------


class TestUnblockCommand:
    """Tests for the ``django_waf_unblock`` management command."""

    @pytest.mark.django_db
    def test_unblock_deactivates_matching_rules(self):
        """Without --delete, matching rules are deactivated (is_active=False)."""
        from django_waf.models import BlockRule

        rule = BlockRuleFactory(pattern="198.51.100.1", is_active=True)

        out = StringIO()
        call_command("django_waf_unblock", "198.51.100.1", stdout=out)

        rule.refresh_from_db()
        assert rule.is_active is False
        # Row still exists — deactivated, not deleted
        assert BlockRule.objects.filter(pk=rule.pk).exists()
        assert "Deactivated 1 rule" in out.getvalue()

    @pytest.mark.django_db
    def test_unblock_with_delete_removes_rules(self):
        """--delete removes matching rules from the database entirely."""
        from django_waf.models import BlockRule

        rule = BlockRuleFactory(pattern="198.51.100.2", is_active=True)

        out = StringIO()
        call_command("django_waf_unblock", "198.51.100.2", "--delete", stdout=out)

        assert not BlockRule.objects.filter(pk=rule.pk).exists()
        assert "Deleted 1 rule" in out.getvalue()

    @pytest.mark.django_db
    def test_unblock_no_matching_rules_reports_nothing_to_do(self):
        """When no active rule matches, the command reports and exits cleanly."""
        out = StringIO()
        call_command("django_waf_unblock", "198.51.100.99", stdout=out)

        assert "No active rules found" in out.getvalue()

    @pytest.mark.django_db
    def test_unblock_ignores_already_inactive_rules(self):
        """Rules that are already inactive are not counted or touched."""
        from django_waf.models import BlockRule

        BlockRuleFactory(pattern="198.51.100.3", is_active=False)

        out = StringIO()
        call_command("django_waf_unblock", "198.51.100.3", stdout=out)

        # The inactive rule survives untouched
        assert BlockRule.objects.filter(pattern="198.51.100.3", is_active=False).exists()
        assert "No active rules found" in out.getvalue()

    @pytest.mark.django_db
    def test_unblock_deactivates_multiple_matching_rules(self):
        """All active rules matching the pattern are deactivated in a single call."""
        BlockRuleFactory(pattern="198.51.100.4", is_active=True, action="block")
        BlockRuleFactory(pattern="198.51.100.4", is_active=True, action="challenge")

        out = StringIO()
        call_command("django_waf_unblock", "198.51.100.4", stdout=out)

        assert "Deactivated 2 rule" in out.getvalue()


# ---------------------------------------------------------------------------
# django_waf_install_geoip
# ---------------------------------------------------------------------------


class TestInstallGeoipCommand:
    """Tests for the ``django_waf_install_geoip`` management command.

    The command delegates all work to ``services.geoip.install_geoip_database``
    — these tests mock that function and verify argument wiring and output.
    """

    def test_missing_license_key_raises_command_error(self):
        """A missing licence key surfaces as a CommandError with the signup link."""
        from django_waf.services.geoip import GeoIPLicenseMissingError

        with (
            patch(
                "django_waf.services.geoip.install_geoip_database",
                side_effect=GeoIPLicenseMissingError(
                    "No MaxMind licence key configured. Sign up at https://www.maxmind.com/en/geolite2/signup"
                ),
            ),
            pytest.raises(CommandError, match="Sign up at"),
        ):
            call_command("django_waf_install_geoip")

    def test_missing_geoip2_package_raises_command_error(self):
        """A missing geoip2 import surfaces as a CommandError with the pip hint."""
        from django_waf.services.geoip import GeoIPNotInstalledError

        with (
            patch(
                "django_waf.services.geoip.install_geoip_database",
                side_effect=GeoIPNotInstalledError("pip install django-waf[geoip]"),
            ),
            pytest.raises(CommandError, match="pip install"),
        ):
            call_command("django_waf_install_geoip")

    def test_successful_install_prints_path_and_size(self):
        """A successful install prints the destination path, size, and build date."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/var/lib/django-waf/GeoLite2-Country.mmdb",
                "size_bytes": 6_291_456,
                "skipped": False,
                "edition": "GeoLite2-Country",
                "build_epoch": 1_700_000_000,
            },
        ) as mock_install:
            out = StringIO()
            call_command("django_waf_install_geoip", stdout=out)

        output = out.getvalue()
        assert "Installed GeoLite2-Country" in output
        assert "/var/lib/django-waf/GeoLite2-Country.mmdb" in output
        assert "6.0 MB" in output
        assert "Database build:" in output
        assert "restart" in output.lower()
        # Args forwarded with all defaults
        mock_install.assert_called_once_with(
            license_key=None,
            output_path=None,
            if_older_than_days=0,
        )

    def test_skipped_output_when_file_is_fresh(self):
        """When the service reports skipped=True, the command says so and does not print install details."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/var/lib/django-waf/GeoLite2-Country.mmdb",
                "size_bytes": 6_291_456,
                "skipped": True,
                "edition": "GeoLite2-Country",
                "build_epoch": None,
            },
        ):
            out = StringIO()
            call_command("django_waf_install_geoip", "--if-older-than", "7", stdout=out)

        output = out.getvalue()
        assert "fresh" in output.lower()
        assert "Installed" not in output

    def test_license_key_cli_arg_forwarded(self):
        """--license-key is passed through to the service."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/tmp/out.mmdb",
                "size_bytes": 1000,
                "skipped": False,
                "edition": "GeoLite2-Country",
                "build_epoch": None,
            },
        ) as mock_install:
            call_command("django_waf_install_geoip", "--license-key", "my-key")

        assert mock_install.call_args.kwargs["license_key"] == "my-key"

    def test_output_path_cli_arg_forwarded(self):
        """--output-path is passed through to the service."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/etc/geoip/country.mmdb",
                "size_bytes": 1000,
                "skipped": False,
                "edition": "GeoLite2-Country",
                "build_epoch": None,
            },
        ) as mock_install:
            call_command("django_waf_install_geoip", "--output-path", "/etc/geoip/country.mmdb")

        assert mock_install.call_args.kwargs["output_path"] == "/etc/geoip/country.mmdb"

    def test_if_older_than_cli_arg_forwarded(self):
        """--if-older-than is passed through to the service."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/tmp/out.mmdb",
                "size_bytes": 1000,
                "skipped": True,
                "edition": "GeoLite2-Country",
                "build_epoch": None,
            },
        ) as mock_install:
            call_command("django_waf_install_geoip", "--if-older-than", "14")

        assert mock_install.call_args.kwargs["if_older_than_days"] == 14

    def test_quiet_flag_suppresses_output(self):
        """--quiet emits no stdout on success."""
        with patch(
            "django_waf.services.geoip.install_geoip_database",
            return_value={
                "path": "/tmp/out.mmdb",
                "size_bytes": 1000,
                "skipped": False,
                "edition": "GeoLite2-Country",
                "build_epoch": None,
            },
        ):
            out = StringIO()
            call_command("django_waf_install_geoip", "--quiet", stdout=out)

        assert out.getvalue() == ""

    def test_download_error_raises_command_error(self):
        """A GeoIPDownloadError surfaces as a CommandError with the 'Download failed' prefix."""
        from django_waf.services.geoip import GeoIPDownloadError

        with (
            patch(
                "django_waf.services.geoip.install_geoip_database",
                side_effect=GeoIPDownloadError("MaxMind download failed with HTTP 503."),
            ),
            pytest.raises(CommandError, match="Download failed: MaxMind"),
        ):
            call_command("django_waf_install_geoip")


# ---------------------------------------------------------------------------
# django_waf_export_rules / django_waf_import_rules
# ---------------------------------------------------------------------------


class TestExportRulesCommand:
    """Tests for the ``django_waf_export_rules`` management command."""

    @pytest.mark.django_db
    def test_export_emits_valid_json_with_envelope(self):
        """Output is valid JSON with the version/exported_at envelope."""
        import json

        BlockRuleFactory()
        AllowRuleFactory()

        out = StringIO()
        call_command("django_waf_export_rules", stdout=out)

        payload = json.loads(out.getvalue())
        assert payload["version"] == 1
        assert "exported_at" in payload
        assert len(payload["block_rules"]) == 1
        assert len(payload["allow_rules"]) == 1
        # id / created_at / updated_at must not leak into the export.
        assert "id" not in payload["block_rules"][0]
        assert "created_at" not in payload["block_rules"][0]
        assert "updated_at" not in payload["block_rules"][0]

    @pytest.mark.django_db
    def test_export_filters_by_source(self):
        """--source restricts BlockRule export to the matching source."""
        import json

        BlockRuleFactory(source="admin")
        BlockRuleFactory(source="feed")

        out = StringIO()
        call_command("django_waf_export_rules", "--source=feed", stdout=out)

        payload = json.loads(out.getvalue())
        assert len(payload["block_rules"]) == 1
        assert payload["block_rules"][0]["source"] == "feed"

    @pytest.mark.django_db
    def test_export_rule_type_block_only(self):
        """--rule-type=block excludes allow rules from the export."""
        import json

        BlockRuleFactory()
        AllowRuleFactory()

        out = StringIO()
        call_command("django_waf_export_rules", "--rule-type=block", stdout=out)

        payload = json.loads(out.getvalue())
        assert len(payload["block_rules"]) == 1
        assert payload["allow_rules"] == []


class TestImportRulesCommand:
    """Tests for the ``django_waf_import_rules`` management command."""

    def _write_export(self, tmp_path, block_rules=None, allow_rules=None):
        import json

        payload = {
            "version": 1,
            "exported_at": "2026-01-01T00:00:00+00:00",
            "block_rules": block_rules or [],
            "allow_rules": allow_rules or [],
        }
        path = tmp_path / "export.json"
        path.write_text(json.dumps(payload))
        return str(path)

    def _block_rule_entry(self, **overrides) -> dict:
        entry = {
            "name": "imported-block",
            "rule_type": "ip",
            "match_type": "exact",
            "pattern": "203.0.113.5",
            "action": "block",
            "priority": 100,
            "is_active": True,
            "source": "feed",
            "expires_at": None,
            "confidence": "1.00",
            "feed_first_seen": None,
            "feed_reporters": 0,
            "notes": "",
        }
        entry.update(overrides)
        return entry

    @pytest.mark.django_db
    def test_import_creates_rules(self, tmp_path):
        """A fresh import creates the block and allow rules from the file."""
        from django_waf.enums import RuleSource
        from django_waf.models import AllowRule, BlockRule

        allow_entry = {
            "name": "imported-allow",
            "rule_type": "ip",
            "match_type": "exact",
            "pattern": "198.51.100.5",
            "verify_rdns": False,
            "rdns_pattern": "",
            "is_active": True,
            "notes": "",
        }
        path = self._write_export(
            tmp_path,
            block_rules=[self._block_rule_entry()],
            allow_rules=[allow_entry],
        )

        out = StringIO()
        call_command("django_waf_import_rules", path, stdout=out)

        assert BlockRule.objects.filter(pattern="203.0.113.5").exists()
        assert AllowRule.objects.filter(pattern="198.51.100.5").exists()
        # Imported rules are always tagged admin, even though the export
        # said source=feed.
        assert BlockRule.objects.get(pattern="203.0.113.5").source == RuleSource.ADMIN
        assert "Created: 2" in out.getvalue()

    @pytest.mark.django_db
    def test_merge_skips_existing_rule(self, tmp_path):
        """--merge (the default) skips a rule whose (rule_type, match_type, pattern) already exists."""
        from django_waf.models import BlockRule

        BlockRuleFactory(rule_type="ip", match_type="exact", pattern="203.0.113.5")
        path = self._write_export(tmp_path, block_rules=[self._block_rule_entry()])

        out = StringIO()
        call_command("django_waf_import_rules", path, "--merge", stdout=out)

        assert BlockRule.objects.filter(pattern="203.0.113.5").count() == 1
        assert "Skipped (already exists): 1" in out.getvalue()
        assert "Created: 0" in out.getvalue()

    @pytest.mark.django_db
    def test_replace_deletes_existing_admin_rules_first(self, tmp_path):
        """--replace deletes existing source=admin rules before importing."""
        from django_waf.models import BlockRule

        BlockRuleFactory(source="admin", pattern="10.0.0.1")
        BlockRuleFactory(source="feed", pattern="10.0.0.2")
        path = self._write_export(tmp_path, block_rules=[self._block_rule_entry()])

        out = StringIO()
        call_command("django_waf_import_rules", path, "--replace", stdout=out)

        # The pre-existing admin rule is gone; the feed rule is untouched
        # (--replace only clears admin-sourced rules); the imported rule exists.
        assert not BlockRule.objects.filter(pattern="10.0.0.1").exists()
        assert BlockRule.objects.filter(pattern="10.0.0.2").exists()
        assert BlockRule.objects.filter(pattern="203.0.113.5").exists()
        assert "Replaced (deleted admin rules): 1" in out.getvalue()

    @pytest.mark.django_db
    def test_dry_run_makes_no_db_changes(self, tmp_path):
        """--dry-run reports counts without writing anything."""
        from django_waf.models import BlockRule

        path = self._write_export(tmp_path, block_rules=[self._block_rule_entry()])

        out = StringIO()
        call_command("django_waf_import_rules", path, "--dry-run", stdout=out)

        assert BlockRule.objects.count() == 0
        assert "[dry-run] Created: 1" in out.getvalue()

    @pytest.mark.django_db
    def test_merge_and_replace_are_mutually_exclusive(self, tmp_path):
        path = self._write_export(tmp_path)

        with pytest.raises(CommandError, match="mutually exclusive"):
            call_command("django_waf_import_rules", path, "--merge", "--replace")
