"""
HTTP request fingerprinting for icv-waf.

Computes a deterministic fingerprint from HTTP headers that identifies the
real client software, independent of the User-Agent string. Bots that rotate
UAs but use the same HTTP library produce identical fingerprints.

Key signals:
- Sec-CH-UA / Sec-CH-UA-Platform (Chrome 89+, Edge, Opera — absent from bots)
- Sec-Fetch-Site / Sec-Fetch-Mode / Sec-Fetch-Dest (all modern browsers)
- Accept-Language (bots omit or send ``*``)
- Accept header (browsers send complex content negotiation, bots send ``*/*``)
- Header ordering (each HTTP library has a distinct ordering)

The fingerprint hash is a SHA-256 of the normalised header tuple. The
mismatch score detects when a UA claims to be a browser but the headers
don't match — a deterministic signal with near-zero false positives.
"""

from __future__ import annotations

import hashlib
import logging
import re

logger = logging.getLogger("icv_waf.fingerprint")

# Headers used for fingerprinting (order matters for the hash)
_FINGERPRINT_HEADERS = [
    "HTTP_ACCEPT",
    "HTTP_ACCEPT_LANGUAGE",
    "HTTP_ACCEPT_ENCODING",
    "HTTP_SEC_CH_UA",
    "HTTP_SEC_CH_UA_MOBILE",
    "HTTP_SEC_CH_UA_PLATFORM",
    "HTTP_SEC_FETCH_SITE",
    "HTTP_SEC_FETCH_MODE",
    "HTTP_SEC_FETCH_DEST",
    "HTTP_SEC_FETCH_USER",
    "HTTP_CONNECTION",
    "HTTP_UPGRADE_INSECURE_REQUESTS",
]

# Browsers that MUST send Sec-CH-UA (Chromium 89+)
_CHROMIUM_UA_RE = re.compile(r"Chrome/(\d+)", re.IGNORECASE)
_CHROMIUM_MIN_VERSION_FOR_CH = 89

# Browsers that MUST send Sec-Fetch-* headers
_SEC_FETCH_BROWSERS_RE = re.compile(r"(Chrome|Firefox|Safari|Edge|Opera)/\d+", re.IGNORECASE)


def compute_fingerprint(meta: dict) -> str:
    """Compute a SHA-256 fingerprint hash from HTTP request headers.

    Args:
        meta: Django ``request.META`` dict.

    Returns:
        Hex-encoded SHA-256 hash (64 chars).
    """
    parts = []
    for header in _FINGERPRINT_HEADERS:
        value = meta.get(header, "")
        # Normalise: strip, lowercase
        parts.append(value.strip().lower() if value else "")

    raw = "|".join(parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def score_fingerprint_mismatch(user_agent: str, meta: dict) -> float:
    """Score the mismatch between claimed UA and actual HTTP headers.

    Returns a score from 0.0 (consistent) to 5.0 (definite mismatch).
    Each missing expected header adds to the score.

    Args:
        user_agent: The User-Agent header value.
        meta: Django ``request.META`` dict.

    Returns:
        Float score (0.0 = no mismatch, 5.0 = maximum mismatch).
    """
    if not user_agent:
        return 0.0  # No UA claim to verify against

    score = 0.0

    # Check 1: Chromium UA claims Chrome 89+ but no Sec-CH-UA
    chrome_match = _CHROMIUM_UA_RE.search(user_agent)
    if chrome_match:
        chrome_version = int(chrome_match.group(1))
        if chrome_version >= _CHROMIUM_MIN_VERSION_FOR_CH and not meta.get("HTTP_SEC_CH_UA"):
            score += 2.0  # Strong signal — deterministic

    # Check 2: Browser UA but no Sec-Fetch-* headers
    if _SEC_FETCH_BROWSERS_RE.search(user_agent):
        has_sec_fetch = any(meta.get(h) for h in ("HTTP_SEC_FETCH_SITE", "HTTP_SEC_FETCH_MODE", "HTTP_SEC_FETCH_DEST"))
        if not has_sec_fetch:
            score += 1.5  # All modern browsers send these

    # Check 3: Browser UA but Accept-Language missing or is just "*"
    if _SEC_FETCH_BROWSERS_RE.search(user_agent):
        accept_lang = meta.get("HTTP_ACCEPT_LANGUAGE", "").strip()
        if not accept_lang or accept_lang == "*":
            score += 1.0  # Real browsers always send Accept-Language

    # Check 4: Browser UA but Accept is just "*/*"
    if _SEC_FETCH_BROWSERS_RE.search(user_agent):
        accept = meta.get("HTTP_ACCEPT", "").strip()
        if accept in ("*/*", ""):
            score += 0.5  # Browsers send rich Accept headers

    return min(score, 5.0)


def classify_fingerprint(user_agent: str, meta: dict) -> str:
    """Classify a request as 'browser', 'bot', or 'suspicious' based on fingerprint.

    Args:
        user_agent: The User-Agent header value.
        meta: Django ``request.META`` dict.

    Returns:
        One of: 'browser', 'bot', 'suspicious', 'unknown'.
    """
    mismatch = score_fingerprint_mismatch(user_agent, meta)

    if mismatch >= 3.0:
        return "bot"
    if mismatch >= 1.5:
        return "suspicious"
    if mismatch == 0.0 and not user_agent:
        return "unknown"
    return "browser"


# ---------------------------------------------------------------------------
# Dynamic known-good fingerprint registry
# ---------------------------------------------------------------------------

_KNOWN_FP_KEY = "waf:known_fp:{fp}"
_KNOWN_FP_TTL = 86400 * 30  # 30 days


def register_known_fingerprint(fp_hash: str, redis_client) -> None:
    """Register a fingerprint as known-good (observed from a solved challenge).

    Called by VerifyView when a real user solves the JS proof-of-work. This
    builds a dynamic allowlist of browser fingerprints without any static
    profile list — as new browser versions roll out, real users solving
    challenges automatically register their fingerprints.

    Args:
        fp_hash: The SHA-256 fingerprint hash.
        redis_client: Redis client instance.
    """
    if not fp_hash:
        return
    try:
        key = _KNOWN_FP_KEY.format(fp=fp_hash)
        redis_client.incr(key)
        redis_client.expire(key, _KNOWN_FP_TTL)
    except Exception:
        pass


def is_known_fingerprint(fp_hash: str, redis_client) -> bool:
    """Check whether a fingerprint has been seen from a verified browser.

    Args:
        fp_hash: The SHA-256 fingerprint hash.
        redis_client: Redis client instance.

    Returns:
        True if the fingerprint has been registered by at least one
        successful challenge solve.
    """
    if not fp_hash:
        return False
    try:
        key = _KNOWN_FP_KEY.format(fp=fp_hash)
        return bool(redis_client.get(key))
    except Exception:
        return False
