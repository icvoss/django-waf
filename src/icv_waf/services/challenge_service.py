"""
Challenge service for icv-waf.

Manages the JS proof-of-work challenge lifecycle: token issuance, solution
verification, and waf_pass cookie management.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import time

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger("icv_waf.challenge_service")

# ---------------------------------------------------------------------------
# Custom exceptions
# ---------------------------------------------------------------------------


class ChallengeExpiredError(Exception):
    """Raised when a challenge token has expired (BR-CHAL-009)."""


class ChallengeMismatchError(Exception):
    """Raised when the solution IP does not match the issuing IP (BR-CHAL-004)."""


class ChallengeInvalidError(Exception):
    """Raised when the nonce does not satisfy the proof-of-work condition."""


# ---------------------------------------------------------------------------
# Redis key helpers
# ---------------------------------------------------------------------------

_CHALLENGE_KEY = "waf:challenge:{token}"


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def issue_challenge(ip_address: str, redis_client) -> object:
    """Create a new challenge token for the given IP address.

    Stores the token in both the DB and Redis. Emits challenge_issued signal.

    Args:
        ip_address: Client IP address that will be challenged.
        redis_client: Configured Redis client instance.

    Returns:
        ChallengeToken model instance.
    """
    from icv_waf import conf
    from icv_waf.models import ChallengeToken

    token = secrets.token_hex(64)
    difficulty = conf.ICV_WAF_CHALLENGE_DIFFICULTY
    ttl = conf.ICV_WAF_CHALLENGE_COOKIE_TTL
    expires_at = timezone.now() + timezone.timedelta(seconds=ttl)

    challenge_token = ChallengeToken.objects.create(
        token=token,
        ip_address=ip_address,
        difficulty=difficulty,
        expires_at=expires_at,
    )

    # Cache in Redis for fast lookup during verify
    redis_key = _CHALLENGE_KEY.format(token=token)
    payload = {
        "ip": ip_address,
        "difficulty": difficulty,
        "expires": expires_at.isoformat(),
    }
    redis_client.setex(redis_key, ttl, json.dumps(payload))

    # Emit signal
    try:
        from icv_waf.signals import challenge_issued

        challenge_issued.send(
            sender=ChallengeToken,
            token=challenge_token,
            ip_address=ip_address,
        )
    except Exception:
        logger.exception("icv-waf: failed to emit challenge_issued signal")

    return challenge_token


def verify_challenge_solution(
    token: str,
    nonce: str,
    ip_address: str,
    redis_client,
) -> bool:
    """Verify that the submitted nonce solves the challenge for the given token.

    Lookup order: Redis first, fallback to DB.

    Per BR-CHAL-002, verifies SHA-256(token + nonce) has `difficulty` leading
    zero bytes. Per BR-CHAL-003, verification is always server-side.

    Args:
        token: The challenge token string.
        nonce: The nonce submitted by the browser.
        ip_address: IP address of the submitting client.
        redis_client: Configured Redis client instance.

    Returns:
        True if solution is valid.

    Raises:
        ChallengeExpiredError: Token has expired.
        ChallengeMismatchError: IP does not match issuing IP.
        ChallengeInvalidError: Nonce does not satisfy proof-of-work.
    """
    from icv_waf.enums import ChallengeStatus
    from icv_waf.models import ChallengeToken

    # --- Look up challenge data ---
    redis_key = _CHALLENGE_KEY.format(token=token)
    raw = redis_client.get(redis_key)
    db_token_obj = None
    difficulty = None
    stored_ip = None

    if raw:
        try:
            data = json.loads(raw)
            stored_ip = data["ip"]
            difficulty = int(data["difficulty"])
        except (json.JSONDecodeError, KeyError):
            raw = None  # fall through to DB

    if not raw:
        try:
            db_token_obj = ChallengeToken.objects.get(token=token)
            stored_ip = db_token_obj.ip_address
            difficulty = db_token_obj.difficulty
        except ChallengeToken.DoesNotExist:
            raise ChallengeInvalidError("Challenge token not found.") from None

    # --- Check expiry (BR-CHAL-009) ---
    if db_token_obj is None:
        db_token_obj = ChallengeToken.objects.get(token=token)

    if db_token_obj.status in (ChallengeStatus.EXPIRED, ChallengeStatus.SOLVED, ChallengeStatus.FAILED):
        raise ChallengeExpiredError("Challenge token is no longer valid.")

    if db_token_obj.expires_at < timezone.now():
        db_token_obj.status = ChallengeStatus.EXPIRED
        db_token_obj.save(update_fields=["status"])
        raise ChallengeExpiredError("Challenge token has expired.")

    # --- IP binding check (BR-CHAL-004) ---
    if stored_ip != ip_address:
        raise ChallengeMismatchError(f"Challenge was issued to {stored_ip}, not {ip_address}.")

    # --- Proof-of-work verification (BR-CHAL-002, BR-CHAL-003) ---
    digest = hashlib.sha256(f"{token}{nonce}".encode()).digest()
    leading_zero_bytes = difficulty
    if any(b != 0 for b in digest[:leading_zero_bytes]):
        # Solution incorrect
        db_token_obj.status = ChallengeStatus.FAILED
        db_token_obj.save(update_fields=["status"])
        try:
            from icv_waf.signals import challenge_failed

            challenge_failed.send(
                sender=ChallengeToken,
                token=db_token_obj,
                ip_address=ip_address,
                reason="invalid_nonce",
            )
        except Exception:
            logger.exception("icv-waf: failed to emit challenge_failed signal")
        raise ChallengeInvalidError("Nonce does not satisfy proof-of-work requirement.")

    # --- Mark as solved ---
    db_token_obj.status = ChallengeStatus.SOLVED
    db_token_obj.solved_at = timezone.now()
    db_token_obj.nonce = nonce
    db_token_obj.save(update_fields=["status", "solved_at", "nonce"])

    # Remove Redis key — token is consumed
    redis_client.delete(redis_key)

    try:
        from icv_waf.signals import challenge_solved

        challenge_solved.send(
            sender=ChallengeToken,
            token=db_token_obj,
            ip_address=ip_address,
        )
    except Exception:
        logger.exception("icv-waf: failed to emit challenge_solved signal")

    return True


def issue_pass_cookie(
    response,
    token: str,
    ip_address: str,
    secure: bool = True,
) -> None:
    """Set the waf_pass cookie on the response to mark successful challenge completion.

    Cookie value format: ``{token}:{ip_address}:{expiry_timestamp}:{signature}``
    where signature is HMAC-SHA256 of the value prefix.

    Per BR-CHAL-005 and BR-CHAL-007.

    Args:
        response: Django HttpResponse object to set the cookie on.
        token: The solved challenge token.
        ip_address: Client IP (embedded for later validation).
        secure: Whether to set the Secure flag (True in production).
    """
    from icv_waf import conf

    ttl = conf.ICV_WAF_CHALLENGE_COOKIE_TTL
    expiry_ts = int(time.time()) + ttl

    value_prefix = f"{token}:{ip_address}:{expiry_ts}"
    signature = _hmac_sign(value_prefix)
    cookie_value = f"{value_prefix}:{signature}"

    response.set_cookie(
        "waf_pass",
        cookie_value,
        max_age=ttl,
        httponly=True,
        samesite="Lax",
        secure=secure,
    )


def validate_pass_cookie(cookie_value: str, ip_address: str) -> bool:
    """Validate the waf_pass cookie value from a request.

    Pure function — no DB or Redis access.

    Per BR-CHAL-006.

    Args:
        cookie_value: Raw waf_pass cookie string.
        ip_address: Client IP address (must match cookie's embedded IP).

    Returns:
        True if the cookie is valid (HMAC verifies, not expired, IP matches).
    """
    try:
        parts = cookie_value.rsplit(":", 1)
        if len(parts) != 2:
            return False
        value_prefix, signature = parts

        # Verify HMAC
        expected_sig = _hmac_sign(value_prefix)
        if not hmac.compare_digest(expected_sig, signature):
            return False

        # Parse value prefix: token:ip:expiry
        prefix_parts = value_prefix.split(":", 2)
        if len(prefix_parts) != 3:
            return False
        _token, cookie_ip, expiry_str = prefix_parts

        # Check expiry
        expiry_ts = int(expiry_str)
        if time.time() > expiry_ts:
            return False

        # Check IP binding
        return cookie_ip == ip_address

    except (ValueError, AttributeError, TypeError):
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _hmac_sign(value: str) -> str:
    """Sign a string with HMAC-SHA256 using Django's SECRET_KEY."""
    secret = settings.SECRET_KEY.encode()
    return hmac.new(secret, value.encode(), hashlib.sha256).hexdigest()
