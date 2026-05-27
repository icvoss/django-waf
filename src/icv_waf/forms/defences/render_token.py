"""RenderTokenDefence — the foundation defence.

A signed render token embedded in the form proves the submission
originated from a real form render this server issued. Other defences
read fields off the verified payload (time_trap, ua_consistency,
js_touch), so render_token always runs first.

Failure modes and outcomes (per PRD §3.3):

* missing / malformed / wrong signature → block (`render_token:invalid`)
* expired (render_time + TTL < now)     → block (`render_token:expired`)
* marker missing past 5s grace window   → block (`render_token:replayed`)
* IP changed since render               → flag (`render_token:ip_changed`)

The 5s grace handles the marker-delete race between two near-
simultaneous successful submits (e.g. double-clicked form). Inside
the grace window the missing marker is tolerated as a non-failure.

Per PRD §3.3 and §4.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from django.utils.safestring import SafeString, mark_safe

from icv_waf.forms.defences.base import (
    EvaluateContext,
    Outcome,
    RenderContext,
    blocked,
    flagged,
    passed,
)
from icv_waf.forms.services.markers import issue_marker, marker_exists
from icv_waf.forms.services.tokens import (
    TokenPayload,
    hash_user_agent,
    issue_token,
    verify_token,
)

if TYPE_CHECKING:  # pragma: no cover
    pass


# Hidden field name the token rides in. Stable so consumer projects
# can grep for it and so legacy forms can be detected by name.
TOKEN_FIELD_NAME = "waf_token"

# Grace window for the marker-delete race (PRD §4.4).
_MARKER_GRACE_SECONDS = 5

# Score weight when the IP changes between render and submit. Below
# the flag threshold on its own (default 2.0 flag, ip_changed score
# 3.0) so it crosses the threshold alone but can be downweighted by
# operators on mobile-heavy sites.
_IP_CHANGED_SCORE = 3.0


def _extract_ip(request) -> str:
    """Pull the client IP from the request.

    Defence-time helper — the orchestrator already does the same
    via the WAF's request_ip logic, but defences are also constructed
    in tests where the orchestrator isn't in the loop. Falling back
    to ``REMOTE_ADDR`` is fine because the WAF's trusted-proxy logic
    runs upstream; by the time a defence sees the request the IP is
    already authoritative.
    """
    return request.META.get("REMOTE_ADDR", "") if request else ""


def _user_id(request) -> str:
    """Return the authenticated user's primary key as a string, or ''.

    Stored on the token so a token issued to one user can't be
    replayed under a different session.
    """
    user = getattr(request, "user", None)
    if user is None or not getattr(user, "is_authenticated", False):
        return ""
    pk = getattr(user, "pk", None)
    return str(pk) if pk is not None else ""


class RenderTokenDefence:
    """Issues + verifies the form's render token.

    Each ``FormProtection`` constructs one instance per form. Stateless
    apart from the configured TTL; safe to share across requests, but
    instantiated per-form by the orchestrator so per-form TTL
    overrides flow through ``config``.
    """

    name = "render_token"

    def __init__(self, redis_client_factory) -> None:
        """``redis_client_factory`` is a zero-arg callable returning a
        Redis client. Injected so tests can supply a MagicMock and so
        the defence doesn't depend on the WAF's redis-resolution
        path at import time.
        """
        self._redis = redis_client_factory

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """Issue a new token + Redis marker for this render."""
        from icv_waf import conf

        ttl = ctx.config.get("token_ttl", conf.ICV_WAF_FORM_TOKEN_TTL)
        token, payload = issue_token(
            form_id=ctx.form_id,
            ip=_extract_ip(ctx.request),
            user_id=_user_id(ctx.request),
            user_agent=ctx.request.META.get("HTTP_USER_AGENT", "") if ctx.request else "",
        )

        # Redis unavailable at render time → fail-open. The token still
        # works for verification (signature is self-contained); the
        # replay-protection guarantee weakens to \"no protection beyond
        # TTL\", consistent with the rest of the WAF's policy.
        with contextlib.suppress(Exception):
            issue_marker(self._redis(), nonce=payload.nonce, ttl_seconds=ttl)

        # The token is base64url-encoded — no HTML-special characters
        # can appear in it, so mark_safe is XSS-safe by construction.
        return {TOKEN_FIELD_NAME: mark_safe(token)}  # noqa: S308

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        """Verify the submitted token + check expiry, marker, IP."""
        from icv_waf import conf

        raw = ctx.submitted_data.get(TOKEN_FIELD_NAME) or ""
        if not raw:
            return blocked("render_token:missing", score=5.0)

        try:
            payload = verify_token(raw)
        except ValueError:
            return blocked("render_token:invalid", score=5.0)

        # Expiry check uses the token's render_time + configured TTL.
        ttl = ctx.config.get("token_ttl", conf.ICV_WAF_FORM_TOKEN_TTL)
        now = datetime.now(tz=UTC)
        # ``payload.render_time`` should already be UTC; coerce if naive
        # (shouldn't happen but defends against a future bug).
        rt = payload.render_time
        if rt.tzinfo is None:
            rt = rt.replace(tzinfo=UTC)
        if rt + timedelta(seconds=ttl) < now:
            return blocked("render_token:expired", score=5.0)

        # Marker check. Missing marker is OK inside the 5s grace
        # window (handles the marker-delete race for near-simultaneous
        # submissions). Outside the window, treat as replay.
        try:
            present = marker_exists(self._redis(), payload.nonce)
        except Exception:
            # Redis down — fail-open on replay protection. Signature
            # check has already passed, so the token is at least
            # authentic.
            present = True

        if not present:
            elapsed = (now - rt).total_seconds()
            if elapsed > _MARKER_GRACE_SECONDS:
                return blocked("render_token:replayed", score=5.0)

        # IP-change check. Flag rather than block — mobile clients
        # legitimately roam between networks mid-session.
        if payload.ip and payload.ip != _extract_ip(ctx.request):
            # Stash the verified payload on the context for later
            # defences (time_trap, ua_consistency, js_touch). We can't
            # mutate the frozen dataclass — the orchestrator constructs
            # a fresh EvaluateContext with token_payload after this
            # defence returns; see orchestrator in a later block. For
            # now, returning the outcome is enough; the orchestrator
            # threads the payload through.
            return flagged(_IP_CHANGED_SCORE, "render_token:ip_changed")

        return passed()


# Re-exported for the orchestrator: when render_token returns pass or
# flag, the orchestrator parses the payload again to thread it onto
# subsequent EvaluateContexts. Exposing the helpers keeps that logic
# in one place rather than duplicating it inside the orchestrator.
def parse_submitted_payload(submitted_data: dict) -> TokenPayload | None:
    """Best-effort parse of the token in submitted data.

    Returns ``None`` if the token is missing or invalid — the
    orchestrator uses this to populate ``EvaluateContext.token_payload``
    for downstream defences. None means \"this submission had no
    verifiable token,\" which downstream defences treat as
    \"don't penalise further; render_token already blocked.\"
    """
    raw = submitted_data.get(TOKEN_FIELD_NAME) or ""
    if not raw:
        return None
    try:
        return verify_token(raw)
    except ValueError:
        return None


__all__ = [
    "TOKEN_FIELD_NAME",
    "RenderTokenDefence",
    "hash_user_agent",
    "parse_submitted_payload",
]
