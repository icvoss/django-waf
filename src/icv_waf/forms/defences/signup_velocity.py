"""SignupVelocityDefence — per-IP signup-rate throttle.

Counts *completed* signups per IP rather than attempts, so the user
who crosses the threshold sees the challenge on their *next* submit
— not the one that crossed it. The orchestrator calls
``record_signup()`` only when the form's overall verdict is PASS.

Per PRD §3.7.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from icv_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    flagged,
    passed,
)
from icv_waf.forms.services.counters import signup_count

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.safestring import SafeString


_FLAG_SCORE = 5.0


class SignupVelocityDefence:
    """Throttle signup forms by completed-registration rate per IP."""

    name = "signup_velocity"

    def __init__(self, redis_client_factory) -> None:
        self._redis = redis_client_factory

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        return {}

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        from icv_waf import conf

        ip = ctx.request.META.get("REMOTE_ADDR", "") if ctx.request else ""
        if not ip:
            return passed()

        limit = ctx.config.get("limit", conf.ICV_WAF_FORM_SIGNUP_VELOCITY_LIMIT)

        try:
            count = signup_count(self._redis(), ip=ip)
        except Exception:
            return passed()

        if count >= limit:
            return flagged(_FLAG_SCORE, "signup_velocity:ip")

        return passed()
