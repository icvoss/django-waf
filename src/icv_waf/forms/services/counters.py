"""Redis counters used by throttle and velocity defences.

A counter is a Redis INCR'd integer with a TTL. The TTL acts as the
sliding window — when the key expires, the count resets. Coarse but
matches what every other rate-limit-style defence in the WAF does.

Keys:

* ``waf:form:cred_fail:account:<sha256(identifier)>``
* ``waf:form:cred_fail:ip:<ip>``
* ``waf:form:signup:<ip>``

The identifier is hashed (not stored raw) so a Redis dump doesn't
leak attempted usernames.

All operations fail-open on Redis errors — the rest of the WAF's
fail-open policy applies. Callers receive 0 (counter unread) or
silently swallowed (counter unincremented) rather than exceptions.
"""

from __future__ import annotations

import hashlib

_CRED_ACCOUNT_KEY = "waf:form:cred_fail:account:{identifier_hash}"
_CRED_IP_KEY = "waf:form:cred_fail:ip:{ip}"
_SIGNUP_IP_KEY = "waf:form:signup:{ip}"


def _hash_identifier(identifier: str) -> str:
    """Return a stable hash of the typed identifier (username/email).

    Hashed not for security per se (the identifier is on a wire we
    control) but so a Redis dump doesn't expose typed credentials.
    """
    return hashlib.sha256(identifier.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Credential-fail counters
# ---------------------------------------------------------------------------


def record_credential_failure(redis_client, *, identifier: str, ip: str, window_seconds: int) -> tuple[int, int]:
    """Increment both per-account and per-IP failure counters.

    Returns ``(account_count, ip_count)`` after incrementing. Either
    being 0 indicates a Redis failure was silently swallowed — the
    caller can treat 0 as 'don't escalate'.

    The increment must be unconditional with respect to whether the
    account exists — see PRD §3.6.1's enumeration-safety constraint.
    The caller is the login-flow code; it calls this every time the
    password check fails, not just when the account exists.
    """
    if not identifier or not ip:
        return (0, 0)

    account_key = _CRED_ACCOUNT_KEY.format(identifier_hash=_hash_identifier(identifier))
    ip_key = _CRED_IP_KEY.format(ip=ip)

    try:
        pipe = redis_client.pipeline()
        pipe.incr(account_key)
        pipe.expire(account_key, window_seconds)
        pipe.incr(ip_key)
        pipe.expire(ip_key, window_seconds)
        results = pipe.execute()
        # pipe.execute() returns [incr_a, expire_a, incr_b, expire_b];
        # indices 0 and 2 are the INCR results.
        account_count = int(results[0]) if results and len(results) >= 3 else 0
        ip_count = int(results[2]) if results and len(results) >= 3 else 0
        return account_count, ip_count
    except Exception:
        return (0, 0)


def credential_ip_count(redis_client, *, ip: str) -> int:
    """Read the current per-IP credential-failure count without incrementing.

    Used by the defence's evaluate() at submission time before the
    auth check has run, so the defence can choose to challenge on the
    very next attempt after the threshold was crossed.
    """
    if not ip:
        return 0
    try:
        raw = redis_client.get(_CRED_IP_KEY.format(ip=ip))
        if raw is None:
            return 0
        return int(raw)
    except Exception:
        return 0


def credential_account_count(redis_client, *, identifier: str) -> int:
    """Read the current per-account credential-failure count.

    Used for the observation-only signal emission (PRD §3.6.1) —
    never returned to the user, so leaks don't matter operationally.
    """
    if not identifier:
        return 0
    try:
        raw = redis_client.get(_CRED_ACCOUNT_KEY.format(identifier_hash=_hash_identifier(identifier)))
        if raw is None:
            return 0
        return int(raw)
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Signup-velocity counter
# ---------------------------------------------------------------------------


def record_signup(redis_client, *, ip: str, window_seconds: int) -> int:
    """Increment the per-IP signup counter; return the new value.

    Called by the orchestrator after a signup form passes — counts
    completed registrations, not attempts. The user who crosses the
    threshold sees the challenge on their *next* attempt.
    """
    if not ip:
        return 0
    try:
        pipe = redis_client.pipeline()
        pipe.incr(_SIGNUP_IP_KEY.format(ip=ip))
        pipe.expire(_SIGNUP_IP_KEY.format(ip=ip), window_seconds)
        results = pipe.execute()
        return int(results[0]) if results else 0
    except Exception:
        return 0


def signup_count(redis_client, *, ip: str) -> int:
    """Read the current signup count for ``ip`` without incrementing."""
    if not ip:
        return 0
    try:
        raw = redis_client.get(_SIGNUP_IP_KEY.format(ip=ip))
        if raw is None:
            return 0
        return int(raw)
    except Exception:
        return 0
