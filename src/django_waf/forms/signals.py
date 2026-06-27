"""Signals emitted by the form-protection orchestrator + entry points.

Receivers must not raise; failures are caught at the emission site
and logged. Pin: existing signals in ``django_waf.signals`` follow the
same contract.

Per PRD §8.
"""

from __future__ import annotations

from django.dispatch import Signal

# Emitted on PASSED submissions only when
# DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL=True (default False). See PRD §8.
# kwargs: form_id, ip, user_agent, user_id (or None)
form_submission_passed = Signal()


# Emitted when total score crosses DJANGO_WAF_FORM_FLAG_THRESHOLD.
# kwargs: form_id, ip, user_agent, user_id, total_score, outcomes
form_submission_flagged = Signal()


# Emitted on BLOCKED verdict (defence block OR score >= block threshold).
# kwargs: form_id, ip, user_agent, user_id, total_score, outcomes, reason
form_submission_blocked = Signal()


# Emitted by the credential-throttle when a per-account counter
# crosses its threshold. Consumer projects connect a handler to
# email the legitimate account holder, notify ops, etc. Critical:
# does NOT affect the user-visible response (enumeration safety).
# kwargs: identifier_hash, attempt_count, window_seconds, ip
credential_attack_observed = Signal()
