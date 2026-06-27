"""UaConsistencyDefence — flag when User-Agent changes between render and submit.

Real browsers don't change their User-Agent header mid-form. A
mismatch suggests either:

* a scraped form being submitted from a different client (the bot
  fetched the form once and now submits from a headless tool), or
* a different process running on the same network (rare and benign).

Score is low (2.0) so this never blocks alone — it only contributes
when combined with another flag. A browser update happens on restart,
not mid-session, so the false-positive rate is very small.

Per PRD §3.4.
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
from django_waf.forms.services.tokens import hash_user_agent

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.safestring import SafeString


_FLAG_SCORE = 2.0


class UaConsistencyDefence:
    """Compare submit-time UA to the hash captured in the render token."""

    name = "ua_consistency"

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """No fields — UA hash rides on the render token."""
        return {}

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        payload = ctx.token_payload
        if payload is None:
            # RenderTokenDefence already blocked; don't compound.
            return passed()

        current_ua = ctx.request.META.get("HTTP_USER_AGENT", "") if ctx.request else ""
        current_hash = hash_user_agent(current_ua)

        if current_hash != payload.ua_hash:
            return flagged(_FLAG_SCORE, "ua_consistency:changed")

        return passed()
