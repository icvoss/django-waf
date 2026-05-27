"""HMAC-signed render tokens for protected forms.

A render token carries everything the verifier needs to authenticate a
submission as coming from a form this server actually issued:

* ``form_id``       — which form the token is for (per-form scoping)
* ``ip``            — IP at render time (binds the token to a session-ish thing)
* ``user_id``       — authenticated user id, or empty string
* ``render_time``   — ISO 8601 timestamp at render
* ``nonce``         — 16 random bytes hex; pairs with the Redis marker
* ``ua_hash``       — SHA-256 of the User-Agent header at render time

The token is the base64url-encoded ``payload + "|" + signature`` where
``signature = HMAC-SHA256(signing_key, payload)``. Verification is
constant-time. Expiry, IP-mismatch, and replay are detected by callers;
this module only owns the signing format and the helpers around it.

Per the PRD §4.1, §4.2, §7.4.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime

# ---------------------------------------------------------------------------
# Signing key resolution
# ---------------------------------------------------------------------------


def get_signing_key() -> bytes:
    """Return the package's HMAC signing key as raw bytes.

    Resolution order:

    1. ``ICV_WAF_SIGNING_KEY`` if non-empty.
    2. A value derived from Django's ``SECRET_KEY`` via HKDF-style hash,
       namespaced so it differs from any other SECRET_KEY-derived
       secret in the project (e.g. Django's own signers).

    The fallback is documented and surfaced via the ``icv_waf.W003``
    system check; callers don't need to handle the unset case
    themselves.
    """
    from django.conf import settings

    from icv_waf import conf

    if conf.ICV_WAF_SIGNING_KEY:
        return conf.ICV_WAF_SIGNING_KEY.encode("utf-8")

    # Fallback: namespace-derive from SECRET_KEY so we never use the raw
    # secret directly. ``b"icv-waf:signing:v1"`` is the namespace; bumping
    # the suffix would let us rotate the derivation without changing the
    # source SECRET_KEY.
    raw = settings.SECRET_KEY.encode("utf-8") if isinstance(settings.SECRET_KEY, str) else settings.SECRET_KEY
    return hashlib.sha256(b"icv-waf:signing:v1|" + raw).digest()


# ---------------------------------------------------------------------------
# Token payload
# ---------------------------------------------------------------------------


_DELIM = "|"
# Payload field count — bumped when the format changes so old tokens
# fail signature check cleanly rather than parsing into garbage.
_PAYLOAD_FIELDS = 6


@dataclass(frozen=True, slots=True)
class TokenPayload:
    """The data carried by a form render token.

    Frozen so accidental mutation can't desync the signature.
    """

    form_id: str
    ip: str
    user_id: str  # "" when anonymous; stored as str so the format is stable
    render_time: datetime
    nonce: str
    ua_hash: str

    def encode(self) -> str:
        """Render the canonical pipe-separated payload string for signing."""
        return _DELIM.join(
            (
                self.form_id,
                self.ip,
                self.user_id,
                self.render_time.isoformat(),
                self.nonce,
                self.ua_hash,
            )
        )

    @classmethod
    def decode(cls, raw: str) -> TokenPayload:
        """Parse a payload string back into a ``TokenPayload``.

        Raises ``ValueError`` if the field count is wrong or the
        timestamp doesn't parse — callers should treat any exception as
        a malformed token and fail verification.
        """
        parts = raw.split(_DELIM)
        if len(parts) != _PAYLOAD_FIELDS:
            raise ValueError(f"expected {_PAYLOAD_FIELDS} payload fields, got {len(parts)}")
        form_id, ip, user_id, render_time_iso, nonce, ua_hash = parts
        # ``fromisoformat`` accepts what ``isoformat`` produced.
        render_time = datetime.fromisoformat(render_time_iso)
        return cls(
            form_id=form_id,
            ip=ip,
            user_id=user_id,
            render_time=render_time,
            nonce=nonce,
            ua_hash=ua_hash,
        )


# ---------------------------------------------------------------------------
# Issuance + verification
# ---------------------------------------------------------------------------


def hash_user_agent(user_agent: str) -> str:
    """Stable SHA-256 hash of a User-Agent header.

    Hashed (not stored raw) so the token doesn't bloat with long UA
    strings and so a change in any byte produces a fresh hash.
    """
    return hashlib.sha256(user_agent.encode("utf-8", errors="replace")).hexdigest()


def issue_token(
    *,
    form_id: str,
    ip: str,
    user_id: str = "",
    user_agent: str = "",
    nonce: str | None = None,
    render_time: datetime | None = None,
) -> tuple[str, TokenPayload]:
    """Issue a signed render token for a form.

    Returns ``(token_string, payload)``. ``token_string`` is what goes
    into the hidden field; ``payload`` is returned so callers can store
    auxiliary state keyed on the same nonce (the Redis marker).

    All keyword-only because positional argument order doesn't carry
    meaning here and the call site will be at form-render time where
    explicit keywords read better.
    """
    if nonce is None:
        nonce = secrets.token_hex(16)
    if render_time is None:
        render_time = datetime.now(tz=UTC)

    payload = TokenPayload(
        form_id=form_id,
        ip=ip,
        user_id=user_id,
        render_time=render_time,
        nonce=nonce,
        ua_hash=hash_user_agent(user_agent),
    )

    payload_str = payload.encode()
    signature = hmac.new(get_signing_key(), payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    raw = payload_str + _DELIM + signature
    token = base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii").rstrip("=")
    return token, payload


def verify_token(token: str) -> TokenPayload:
    """Validate the signature and return the parsed payload.

    Raises ``ValueError`` on any failure — malformed encoding, wrong
    field count, bad signature. Callers translate that into the
    defence's Block outcome (``render_token:invalid``).

    Constant-time signature comparison via ``hmac.compare_digest``.
    """
    # Restore base64 padding stripped during issuance.
    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode((token + padding).encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("token is not valid base64url-encoded utf-8") from exc

    # Signature is the final pipe-delimited segment; everything before
    # it is the signed payload. We can't use ``split('|', ...)`` because
    # the payload itself contains pipes — rsplit on a single delimiter
    # is the correct seam.
    sep_index = raw.rfind(_DELIM)
    if sep_index == -1:
        raise ValueError("token has no signature delimiter")
    payload_str = raw[:sep_index]
    signature = raw[sep_index + 1 :]

    expected = hmac.new(get_signing_key(), payload_str.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise ValueError("signature mismatch")

    return TokenPayload.decode(payload_str)
