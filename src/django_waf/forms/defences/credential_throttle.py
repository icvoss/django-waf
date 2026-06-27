"""CredentialThrottleDefence — per-IP + per-account failure tracking.

The most security-sensitive defence. Per PRD §3.6.1 it carries a
hard constraint: **the form's user-visible behaviour must not reveal
whether an account exists**. This implementation enforces that by:

* incrementing the per-account counter on every failed login
  regardless of whether the account exists (the caller records the
  failure unconditionally),
* triggering the user-visible challenge on the **per-IP** counter only
  — the per-account counter is observation-only,
* emitting a separate ``credential_attack_observed`` signal when the
  per-account counter crosses its threshold, for consumers to wire
  up an email-to-owner handler.

The defence runs at submit time, *before* the auth check. It reads
the current per-IP count; if it's at-or-above threshold the
submission is flagged (challenge redirect). The actual increment
happens via the orchestrator's ``record_credential_failure`` call
after auth fails — which the consuming project hooks into its
login view.

Per PRD §3.6 + §3.6.1.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from django_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    flagged,
    passed,
)
from django_waf.forms.services.counters import credential_ip_count

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.safestring import SafeString


_FLAG_SCORE = 5.0


class CredentialThrottleDefence:
    """Per-IP credential-failure throttle (enumeration-safe)."""

    name = "credential_throttle"

    def __init__(self, redis_client_factory) -> None:
        """``redis_client_factory`` matches the RenderTokenDefence pattern."""
        self._redis = redis_client_factory

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """No fields — this is a Redis-backed check."""
        return {}

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        from django_waf import conf

        ip = ctx.request.META.get("REMOTE_ADDR", "") if ctx.request else ""
        if not ip:
            # No IP → no enforcement. The WAF's IP-extraction logic
            # runs upstream; reaching here without one is anomalous
            # but not actionable.
            return passed()

        limit = ctx.config.get("ip_limit", conf.DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT)

        try:
            count = credential_ip_count(self._redis(), ip=ip)
        except Exception:
            # Redis down → fail-open. Login attempts continue as
            # normal; the throttle just doesn't fire.
            return passed()

        if count >= limit:
            # The same reason for any IP, regardless of which accounts
            # were tried — enumeration-safe.
            return flagged(_FLAG_SCORE, "credential_throttle:ip")

        return passed()
