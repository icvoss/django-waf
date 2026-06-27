"""
Challenge service for django-waf.

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

logger = logging.getLogger("django_waf.challenge_service")

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


def _is_mobile_user_agent(user_agent: str) -> bool:
    """Cheap UA-string heuristic for mobile-class devices.

    Honest about its limits: UA strings lie, "tablet" sits in the middle,
    and a high-end phone can outpace a low-end laptop. Used only to pick a
    PoW difficulty band — wrong guesses cost a 1–3s solve discrepancy, not
    a lockout. Refer to ``DJANGO_WAF_CHALLENGE_DIFFICULTY_*`` to tune.
    """
    if not user_agent:
        return False
    ua = user_agent.lower()
    # "Mobi" covers Firefox Mobile + Chrome Mobile per their official UAs;
    # "Android" without "Mobi" is a tablet, which we treat as desktop-class.
    return "mobi" in ua or "iphone" in ua or "ipod" in ua


def _pick_difficulty(user_agent: str) -> int:
    """Return the configured PoW difficulty for a request's device class.

    Resolves in this order:
      1. The device-class setting (mobile vs desktop) if it is set (non-None).
      2. The single-value fallback ``DJANGO_WAF_CHALLENGE_DIFFICULTY``.

    Lets operators either use the device-aware split (default) or pin a
    single value by setting the desktop/mobile keys to ``None``.
    """
    from django_waf import conf

    if _is_mobile_user_agent(user_agent):
        value = conf.DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE
    else:
        value = conf.DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP
    if value is None:
        value = conf.DJANGO_WAF_CHALLENGE_DIFFICULTY
    return value


def _digest_has_leading_zero_bits(digest: bytes, bits: int) -> bool:
    """Return True iff ``digest`` starts with at least ``bits`` zero bits."""
    if bits <= 0:
        return True
    full_bytes, remainder = divmod(bits, 8)
    if len(digest) < full_bytes + (1 if remainder else 0):
        return False
    if any(b != 0 for b in digest[:full_bytes]):
        return False
    if remainder == 0:
        return True
    # Top `remainder` bits of the next byte must be zero.
    mask = 0xFF << (8 - remainder) & 0xFF
    return (digest[full_bytes] & mask) == 0


def issue_challenge(ip_address: str, redis_client, *, user_agent: str = "") -> object:
    """Create a new challenge token for the given IP address.

    Stores the token in both the DB and Redis. Emits challenge_issued signal.

    Args:
        ip_address: Client IP address that will be challenged.
        redis_client: Configured Redis client instance.
        user_agent: Optional User-Agent string; selects mobile vs desktop
            difficulty. Falls back to the desktop value when empty or unset.

    Returns:
        ChallengeToken model instance.
    """
    from django_waf import conf
    from django_waf.models import ChallengeToken

    token = secrets.token_hex(64)
    difficulty = _pick_difficulty(user_agent)
    ttl = conf.DJANGO_WAF_CHALLENGE_COOKIE_TTL
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
        from django_waf.signals import challenge_issued

        challenge_issued.send(
            sender=ChallengeToken,
            token=challenge_token,
            ip_address=ip_address,
        )
    except Exception:
        logger.exception("django-waf: failed to emit challenge_issued signal")

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
    zero **bits**. Per BR-CHAL-003, verification is always server-side.

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
    from django_waf.enums import ChallengeStatus
    from django_waf.models import ChallengeToken

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
    if not _digest_has_leading_zero_bits(digest, difficulty):
        # Solution incorrect
        db_token_obj.status = ChallengeStatus.FAILED
        db_token_obj.save(update_fields=["status"])
        try:
            from django_waf.signals import challenge_failed

            challenge_failed.send(
                sender=ChallengeToken,
                token=db_token_obj,
                ip_address=ip_address,
                reason="invalid_nonce",
            )
        except Exception:
            logger.exception("django-waf: failed to emit challenge_failed signal")
        raise ChallengeInvalidError("Nonce does not satisfy proof-of-work requirement.")

    # --- Mark as solved ---
    db_token_obj.status = ChallengeStatus.SOLVED
    db_token_obj.solved_at = timezone.now()
    db_token_obj.nonce = nonce
    db_token_obj.save(update_fields=["status", "solved_at", "nonce"])

    # Remove Redis key — token is consumed
    redis_client.delete(redis_key)

    try:
        from django_waf.signals import challenge_solved

        challenge_solved.send(
            sender=ChallengeToken,
            token=db_token_obj,
            ip_address=ip_address,
        )
    except Exception:
        logger.exception("django-waf: failed to emit challenge_solved signal")

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
    from django_waf import conf

    ttl = conf.DJANGO_WAF_CHALLENGE_COOKIE_TTL
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
