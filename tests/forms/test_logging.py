"""Tests for the structured-logging + signal-dispatch layer."""

from __future__ import annotations

from unittest.mock import MagicMock, patch


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request():
    req = MagicMock()
    req.META = {"REMOTE_ADDR": "1.2.3.4", "HTTP_USER_AGENT": "Mozilla/5.0"}
    req.user = MagicMock(is_authenticated=False)
    return req


def _result(verdict, outcomes=None, total_score=0.0):
    from icv_waf.forms.protection import FormEvaluationResult, FormVerdict

    return FormEvaluationResult(
        verdict=FormVerdict(verdict),
        total_score=total_score,
        outcomes=outcomes or [],
        token_payload=None,
    )


# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------


class TestLogging:
    def test_blocked_emits_warning_with_payload(self, settings, caplog):
        import logging as stdlib_logging

        from icv_waf.forms.defences.base import Outcome
        from icv_waf.forms.logging import log_form_submission

        outcomes = [Outcome(verdict="block", score=5.0, reason="honeypot:url")]
        with caplog.at_level(stdlib_logging.WARNING, logger="icv_waf.forms"):
            log_form_submission(form_id="c", request=_request(), result=_result("blocked", outcomes, 5.0))

        # One record, level WARNING, structured payload attached.
        records = [r for r in caplog.records if r.message == "waf.form_submission"]
        assert len(records) == 1
        record = records[0]
        assert record.levelno == stdlib_logging.WARNING
        assert record.verdict == "blocked"
        assert record.form_id == "c"
        assert record.ip == "1.2.3.4"
        assert record.defences[0]["reason"] == "honeypot:url"

    def test_flagged_emits_info(self, settings, caplog):
        import logging as stdlib_logging

        from icv_waf.forms.defences.base import Outcome
        from icv_waf.forms.logging import log_form_submission

        outcomes = [Outcome(verdict="flag", score=2.0, reason="time_trap:fast")]
        with caplog.at_level(stdlib_logging.INFO, logger="icv_waf.forms"):
            log_form_submission(form_id="c", request=_request(), result=_result("flagged", outcomes, 2.0))

        records = [r for r in caplog.records if r.message == "waf.form_submission"]
        assert any(r.levelno == stdlib_logging.INFO for r in records)

    def test_passed_sampled_by_log_sample_rate(self, settings, caplog):
        """ICV_WAF_LOG_SAMPLE_RATE controls how often PASSED logs.

        With rate=0.0, no PASSED log entries are emitted.
        """
        import logging as stdlib_logging

        import icv_waf.conf as conf_mod
        from icv_waf.forms.logging import log_form_submission

        with (
            patch.object(conf_mod, "ICV_WAF_LOG_SAMPLE_RATE", 0.0),
            caplog.at_level(stdlib_logging.INFO, logger="icv_waf.forms"),
        ):
            for _ in range(10):
                log_form_submission(form_id="c", request=_request(), result=_result("passed"))

        # No log entries — sampling suppressed all of them.
        records = [r for r in caplog.records if r.message == "waf.form_submission"]
        assert records == []


# ---------------------------------------------------------------------------
# Signal dispatch
# ---------------------------------------------------------------------------


class TestSignals:
    def test_blocked_signal_fires_with_reason(self):
        from icv_waf.forms.defences.base import Outcome
        from icv_waf.forms.logging import log_form_submission
        from icv_waf.forms.signals import form_submission_blocked

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        form_submission_blocked.connect(handler, dispatch_uid="test_blocked")
        try:
            outcomes = [Outcome(verdict="block", score=5.0, reason="honeypot:url")]
            log_form_submission(form_id="c", request=_request(), result=_result("blocked", outcomes, 5.0))
        finally:
            form_submission_blocked.disconnect(dispatch_uid="test_blocked")

        assert len(received) == 1
        assert received[0]["form_id"] == "c"
        assert received[0]["reason"] == "honeypot:url"

    def test_flagged_signal_fires(self):
        from icv_waf.forms.defences.base import Outcome
        from icv_waf.forms.logging import log_form_submission
        from icv_waf.forms.signals import form_submission_flagged

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        form_submission_flagged.connect(handler, dispatch_uid="test_flagged")
        try:
            outcomes = [Outcome(verdict="flag", score=2.0, reason="time_trap:fast")]
            log_form_submission(form_id="c", request=_request(), result=_result("flagged", outcomes, 2.0))
        finally:
            form_submission_flagged.disconnect(dispatch_uid="test_flagged")

        assert len(received) == 1
        assert received[0]["total_score"] == 2.0

    def test_passed_signal_off_by_default(self, settings):
        """ICV_WAF_FORM_EMIT_PASSED_SIGNAL=False → no signal for PASSED."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.logging import log_form_submission
        from icv_waf.forms.signals import form_submission_passed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        form_submission_passed.connect(handler, dispatch_uid="test_passed_off")
        try:
            with (
                patch.object(conf_mod, "ICV_WAF_FORM_EMIT_PASSED_SIGNAL", False),
                patch.object(conf_mod, "ICV_WAF_LOG_SAMPLE_RATE", 1.0),
            ):
                log_form_submission(form_id="c", request=_request(), result=_result("passed"))
        finally:
            form_submission_passed.disconnect(dispatch_uid="test_passed_off")

        assert received == []

    def test_passed_signal_opt_in(self, settings):
        """ICV_WAF_FORM_EMIT_PASSED_SIGNAL=True → signal fires."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.logging import log_form_submission
        from icv_waf.forms.signals import form_submission_passed

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        form_submission_passed.connect(handler, dispatch_uid="test_passed_on")
        try:
            with (
                patch.object(conf_mod, "ICV_WAF_FORM_EMIT_PASSED_SIGNAL", True),
                patch.object(conf_mod, "ICV_WAF_LOG_SAMPLE_RATE", 1.0),
            ):
                log_form_submission(form_id="c", request=_request(), result=_result("passed"))
        finally:
            form_submission_passed.disconnect(dispatch_uid="test_passed_on")

        assert len(received) == 1

    def test_signal_receiver_exception_does_not_propagate(self):
        """A misbehaving receiver must NOT break the request lifecycle."""
        from icv_waf.forms.defences.base import Outcome
        from icv_waf.forms.logging import log_form_submission
        from icv_waf.forms.signals import form_submission_blocked

        def broken_handler(sender, **kwargs):
            raise RuntimeError("receiver bug")

        form_submission_blocked.connect(broken_handler, dispatch_uid="test_broken")
        try:
            outcomes = [Outcome(verdict="block", score=5.0, reason="honeypot:url")]
            # Must NOT raise.
            log_form_submission(form_id="c", request=_request(), result=_result("blocked", outcomes, 5.0))
        finally:
            form_submission_blocked.disconnect(dispatch_uid="test_broken")
