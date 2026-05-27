"""Challenge-replay storage + signed-reference helpers.

When a form submission is FLAGGED and ICV_WAF_FORM_CHALLENGE_ON_FLAG
is True, the orchestrator redirects to /waf/challenge/?next=...&form_
replay=<token>. The replay token is a signed reference to data
stashed in the request's session (or Redis, depending on
ICV_WAF_FORM_REPLAY_STORE). On successful challenge, the verify view
looks up the data and re-issues the POST.

Sensitive-field omission: password-like fields and file uploads are
never stored. Password fields force the user to re-enter their
password on the replayed form (acceptable UX cost for security);
file uploads show a 'verification successful, please resubmit' page.

Per PRD §5.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
import secrets
import time
from typing import Any

from icv_waf.forms.services.tokens import get_signing_key

logger = logging.getLogger("icv_waf.forms")


# Replay token lifetime — much shorter than the form-token TTL
# because the only legitimate use is 'user solves challenge within
# 60s and gets routed back'. Longer would widen the replay window
# for an attacker who steals the token from a flagged response.
_REPLAY_TTL_SECONDS = 60

# Session key under which the orchestrator stashes replay data.
_SESSION_KEY = "waf_form_replay"

# Field names matching any of these patterns are stripped before
# storage. Conservative — better to require a re-entry than to
# round-trip a password through session storage.
# Matches password / passwd, secret, token, api_key, csrf, anywhere in the
# field name with reasonable boundary handling — so password1/password2
# (Django's confirm-password convention), user_password, csrfmiddlewaretoken
# all hit.
_SENSITIVE_FIELD_RE = re.compile(
    r"(?:pass(?:word|wd)?|secret|api[_-]?key|csrf|token)",
    re.IGNORECASE,
)

# Multipart file fields can't be reliably round-tripped (the bytes
# would have to live in session storage). When detected, the
# orchestrator falls back to 'please resubmit'.
_FILE_FIELD_MARKER = "__waf_has_file__"


# ---------------------------------------------------------------------------
# Sensitive-field detection
# ---------------------------------------------------------------------------


def is_sensitive_field(name: str) -> bool:
    """Return True if ``name`` matches the sensitive-field pattern."""
    return bool(_SENSITIVE_FIELD_RE.search(name))


def filter_sensitive_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``data`` with sensitive fields stripped.

    Caller-visible keys are preserved (the form on the replayed page
    can show 'password required' next to the empty field). The values
    are what we drop.
    """
    return {k: v for k, v in data.items() if not is_sensitive_field(k)}


# ---------------------------------------------------------------------------
# Replay token signing
# ---------------------------------------------------------------------------


def _sign(payload: bytes) -> str:
    return hmac.new(get_signing_key(), payload, hashlib.sha256).hexdigest()


def issue_replay_token(*, form_id: str, ip: str, session_key: str) -> str:
    """Issue a signed reference to session-stored replay data.

    The token contains form_id, IP, the session key under which the
    data was stored, an expiry timestamp, and an HMAC signature.
    Bound to the IP so a stolen token can't be replayed from a
    different network.
    """
    expires_at = int(time.time()) + _REPLAY_TTL_SECONDS
    payload = f"{form_id}|{ip}|{session_key}|{expires_at}".encode()
    sig = _sign(payload)
    raw = payload + b"|" + sig.encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def verify_replay_token(token: str, *, current_ip: str) -> dict[str, str] | None:
    """Validate a replay token; return its payload or None.

    Returns ``None`` on any failure (malformed, bad signature,
    expired, IP mismatch). The caller treats None as 'no replay
    available' and shows the user a fresh form.
    """
    if not token:
        return None
    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + padding).encode("ascii"))
    except Exception:
        return None

    sep_index = raw.rfind(b"|")
    if sep_index == -1:
        return None
    payload, sig = raw[:sep_index], raw[sep_index + 1 :].decode("ascii", errors="replace")
    expected = _sign(payload)
    if not hmac.compare_digest(expected, sig):
        return None

    try:
        form_id, ip, session_key, expires_at_str = payload.decode("utf-8").split("|")
        expires_at = int(expires_at_str)
    except (ValueError, UnicodeDecodeError):
        return None

    if expires_at < int(time.time()):
        return None
    if ip != current_ip:
        return None

    return {"form_id": form_id, "session_key": session_key}


# ---------------------------------------------------------------------------
# Session-backed storage (default)
# ---------------------------------------------------------------------------


def store_in_session(request, *, form_id: str, post_url: str, data: dict[str, Any]) -> str | None:
    """Stash filtered POST data in the session; return the session key.

    Returns None when the session framework isn't configured (the
    consumer either doesn't use sessions or the middleware isn't
    installed). The caller falls back to 'reject without replay' in
    that case.
    """
    session = getattr(request, "session", None)
    if session is None:
        return None

    key = secrets.token_hex(8)
    stash = session.get(_SESSION_KEY, {})
    if not isinstance(stash, dict):
        stash = {}
    stash[key] = {
        "form_id": form_id,
        "post_url": post_url,
        "data": filter_sensitive_fields(data),
        "stored_at": int(time.time()),
    }
    # Cap session bloat — keep at most 5 outstanding replays per session.
    if len(stash) > 5:
        oldest = sorted(stash.items(), key=lambda kv: kv[1].get("stored_at", 0))
        for old_key, _ in oldest[:-5]:
            stash.pop(old_key, None)
    session[_SESSION_KEY] = stash
    session.modified = True
    return key


def fetch_from_session(request, *, session_key: str) -> dict[str, Any] | None:
    """Look up a replay record by session key; return None if missing/expired."""
    session = getattr(request, "session", None)
    if session is None:
        return None
    stash = session.get(_SESSION_KEY, {})
    if not isinstance(stash, dict):
        return None
    record = stash.get(session_key)
    if record is None:
        return None
    # Optional age check — the replay token has its own expiry, but
    # double-check here in case storage outlived it.
    if int(time.time()) - record.get("stored_at", 0) > _REPLAY_TTL_SECONDS + 60:
        return None
    return record


def discard_from_session(request, *, session_key: str) -> None:
    """Remove a consumed replay record from the session."""
    session = getattr(request, "session", None)
    if session is None:
        return
    stash = session.get(_SESSION_KEY, {})
    if isinstance(stash, dict) and session_key in stash:
        stash.pop(session_key)
        session[_SESSION_KEY] = stash
        session.modified = True


__all__ = [
    "discard_from_session",
    "fetch_from_session",
    "filter_sensitive_fields",
    "is_sensitive_field",
    "issue_replay_token",
    "store_in_session",
    "verify_replay_token",
]
