"""TimeTrapDefence — submissions that come back implausibly fast or slow.

Reads ``render_time`` off the verified token payload (set on
``EvaluateContext.token_payload`` by the orchestrator after
``RenderTokenDefence`` succeeds) and compares to ``now``:

* delta < 0.5s        → block (``time_trap:too_fast``)
* 0.5s ≤ delta < min  → flag  (``time_trap:fast``)
* delta > max         → flag  (``time_trap:expired``)
* otherwise           → pass

The 0.5s hard cutoff is the only deterministic threshold — anything
that comes back in under half a second is mechanically impossible for
a human to read-and-fill. The flag bands are configurable per-form
(short forms like newsletter signups lower the min).

No render-time fields needed (the token already carries the timestamp).

Per PRD §3.2.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from icv_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    blocked,
    flagged,
    passed,
)

if TYPE_CHECKING:  # pragma: no cover
    from django.utils.safestring import SafeString


# Hard floor — any submission faster than this is mechanically
# impossible for a human, regardless of form length or per-form
# configuration. Block, don't flag.
_TOO_FAST_THRESHOLD_SECONDS = 0.5

# Default scores. Operators override via defence_weights, but these
# defaults match PRD §3.2 and produce sensible behaviour when the
# defence is used standalone.
_TOO_FAST_SCORE = 5.0  # paired with block; recorded for logs
_FAST_FLAG_SCORE = 2.0
_EXPIRED_FLAG_SCORE = 2.0


class TimeTrapDefence:
    """Detect submissions too fast (bot) or too slow (stale/replay)."""

    name = "time_trap"

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """No fields needed — render time rides on the render token."""
        return {}

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        # No token payload → render_token defence already blocked.
        # Don't compound penalties; pass silently.
        payload = ctx.token_payload
        if payload is None:
            return passed()

        from icv_waf import conf

        min_seconds = ctx.config.get("min_fill_seconds", conf.ICV_WAF_FORM_TIME_TRAP_MIN_SECONDS)
        max_seconds = ctx.config.get("max_fill_seconds", conf.ICV_WAF_FORM_TIME_TRAP_MAX_SECONDS)

        rt = payload.render_time
        if rt.tzinfo is None:
            rt = rt.replace(tzinfo=UTC)
        delta = (datetime.now(tz=UTC) - rt).total_seconds()

        # Negative deltas indicate clock skew between processes. Treat
        # as too fast — better to flag a false positive than to ignore
        # a genuine replay-from-the-future.
        if delta < _TOO_FAST_THRESHOLD_SECONDS:
            return blocked("time_trap:too_fast", score=_TOO_FAST_SCORE)

        if delta < min_seconds:
            return flagged(_FAST_FLAG_SCORE, "time_trap:fast")

        if delta > max_seconds:
            return flagged(_EXPIRED_FLAG_SCORE, "time_trap:expired")

        return passed()
