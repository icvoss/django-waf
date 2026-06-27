"""Redis one-shot markers for render-token replay protection.

A marker is a short-lived Redis key whose **presence** means "this
token has not yet been spent on a successful submission." Lifecycle:

1. ``issue_marker(nonce)`` at form render — SETEX with ``token_ttl``.
2. ``marker_exists(nonce)`` on submit — read; if absent and the token's
   render-time is older than the 5-second grace window, treat as
   replayed.
3. ``consume_marker(nonce)`` **only on overall PASS verdict** — DEL
   the key so the token can't be reused.

The "only on PASS" rule is the load-bearing semantic for HTMX
re-renders. A form that fails Django-level validation (missing field)
keeps the same marker; the user can submit again with the same token
once they've fixed the error. A form that passes consumes the marker
and any subsequent reuse of the token is a replay.

Per PRD §4.3.
"""

from __future__ import annotations

_MARKER_KEY = "waf:form:token:{nonce}"


def _key(nonce: str) -> str:
    return _MARKER_KEY.format(nonce=nonce)


def issue_marker(redis_client, nonce: str, ttl_seconds: int) -> None:
    """Set the one-shot marker for a freshly-issued token.

    Idempotent under Redis semantics — re-issuing the same nonce just
    refreshes the TTL. In practice the nonce is random per call so
    collisions don't happen, but the contract holds either way.
    """
    redis_client.setex(_key(nonce), ttl_seconds, "1")


def marker_exists(redis_client, nonce: str) -> bool:
    """Return True iff the marker for this nonce is still present.

    A False return after a token's render-time has passed the grace
    window indicates replay (the marker was consumed by a previous
    successful submission, or expired by TTL).

    Defensive against Redis returning a falsy non-None — coerced via
    bool() rather than ``is not None`` so values of ``0`` from a wrong
    key type don't read as "present."
    """
    return bool(redis_client.exists(_key(nonce)))


def consume_marker(redis_client, nonce: str) -> None:
    """Delete the marker after a successful submission.

    Called only when the orchestrator's overall verdict is PASS.
    Subsequent submissions with the same token will see the marker
    missing and (if past the grace window) treat the token as replayed.
    """
    redis_client.delete(_key(nonce))
