"""Structured logging for form-protection events + signal dispatch.

One ``waf.form_submission`` log entry per submission. Plus the four
signals from ``signals.py`` fired at the appropriate verdicts.

Per PRD §8 + §9.
"""

from __future__ import annotations

import logging
import random
from typing import Any

from icv_waf.forms.protection import FormEvaluationResult, FormVerdict
from icv_waf.forms.signals import (
    form_submission_blocked,
    form_submission_flagged,
    form_submission_passed,
)

logger = logging.getLogger("icv_waf.forms")


def _extract_ip(request) -> str:
    return request.META.get("REMOTE_ADDR", "") if request else ""


def _extract_user_id(request) -> str | None:
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    return str(getattr(user, "pk", "") or "")


def log_form_submission(*, form_id: str, request, result: FormEvaluationResult) -> None:
    """Emit one structured log entry + the appropriate signal.

    Sampling:
      * PASSED → ``ICV_WAF_LOG_SAMPLE_RATE``
      * FLAGGED / BLOCKED → always logged (sampling N/A)

    Signal emission:
      * PASSED  → form_submission_passed iff ICV_WAF_FORM_EMIT_PASSED_SIGNAL
      * FLAGGED → form_submission_flagged
      * BLOCKED → form_submission_blocked

    Signal handlers are isolated via try/except so a misbehaving
    receiver can't break the request lifecycle.
    """
    from icv_waf import conf

    verdict_str = result.verdict.value
    ip = _extract_ip(request)
    user_agent = request.META.get("HTTP_USER_AGENT", "") if request else ""
    user_id = _extract_user_id(request)

    # Sampling decision for passed submissions.
    if result.verdict == FormVerdict.PASSED:  # noqa: SIM102 — nested reads clearer with the comment
        if random.random() >= conf.ICV_WAF_LOG_SAMPLE_RATE:
            # Suppressed by sampling; still dispatch the signal if
            # operators opted in.
            _maybe_emit_passed_signal(form_id=form_id, ip=ip, user_agent=user_agent, user_id=user_id)
            return

    payload: dict[str, Any] = {
        "event": "waf.form_submission",
        "form_id": form_id,
        "verdict": verdict_str,
        "ip": ip,
        "user_agent": user_agent,
        "user_id": user_id,
        "total_score": result.total_score,
        "defences": [
            {
                "name": _name_from_reason(outcome.reason),
                "verdict": outcome.verdict,
                "score": outcome.score,
                "reason": outcome.reason,
            }
            for outcome in result.outcomes
        ],
    }
    # Log level mirrors the verdict so log routing can filter.
    if result.verdict == FormVerdict.BLOCKED:
        logger.warning("waf.form_submission", extra=payload)
    elif result.verdict == FormVerdict.FLAGGED:
        logger.info("waf.form_submission", extra=payload)
    else:
        logger.info("waf.form_submission", extra=payload)

    _dispatch_signal(
        form_id=form_id,
        ip=ip,
        user_agent=user_agent,
        user_id=user_id,
        result=result,
    )


def _name_from_reason(reason: str) -> str:
    """Extract the defence name from a ``defence:detail`` reason string."""
    if not reason:
        return ""
    return reason.split(":", 1)[0]


def _maybe_emit_passed_signal(*, form_id: str, ip: str, user_agent: str, user_id: str | None) -> None:
    from icv_waf import conf

    if not conf.ICV_WAF_FORM_EMIT_PASSED_SIGNAL:
        return
    try:
        form_submission_passed.send(
            sender=None,
            form_id=form_id,
            ip=ip,
            user_agent=user_agent,
            user_id=user_id,
        )
    except Exception:
        logger.exception("icv-waf: form_submission_passed receiver raised")


def _dispatch_signal(
    *,
    form_id: str,
    ip: str,
    user_agent: str,
    user_id: str | None,
    result: FormEvaluationResult,
) -> None:
    """Fire the verdict-appropriate signal, swallowing any receiver errors."""
    try:
        if result.verdict == FormVerdict.PASSED:
            _maybe_emit_passed_signal(form_id=form_id, ip=ip, user_agent=user_agent, user_id=user_id)
        elif result.verdict == FormVerdict.FLAGGED:
            form_submission_flagged.send(
                sender=None,
                form_id=form_id,
                ip=ip,
                user_agent=user_agent,
                user_id=user_id,
                total_score=result.total_score,
                outcomes=result.outcomes,
            )
        else:  # BLOCKED
            # Pick a representative reason — first block outcome, or
            # the highest-scoring flag if scores crossed the block
            # threshold without any single defence blocking.
            reason = ""
            for outcome in result.outcomes:
                if outcome.verdict == "block":
                    reason = outcome.reason
                    break
            if not reason and result.outcomes:
                worst = max(result.outcomes, key=lambda o: o.score)
                reason = worst.reason
            form_submission_blocked.send(
                sender=None,
                form_id=form_id,
                ip=ip,
                user_agent=user_agent,
                user_id=user_id,
                total_score=result.total_score,
                outcomes=result.outcomes,
                reason=reason,
            )
    except Exception:
        logger.exception("icv-waf: form-submission signal receiver raised")
