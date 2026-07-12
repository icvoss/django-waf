"""
Rate limiter service for django-waf.

Implements Redis sliding-window rate limiting per IP address. Three windows are
checked: per-second burst, per-minute, and per-5-minute (BR-RATE-001).
"""

from __future__ import annotations

import hashlib
import time
from typing import NamedTuple


class RateLimitResult(NamedTuple):
    """Result of a rate limit check."""

    exceeded: bool
    window: str | None
    retry_after: int | None


# ---------------------------------------------------------------------------
# Window definitions: (name, seconds, threshold_setting_attr, ttl_buffer)
# ---------------------------------------------------------------------------

_WINDOWS: list[tuple[str, int]] = [
    ("1s", 1),
    ("1m", 60),
    ("5m", 300),
]


def _check_path_rate_limit(
    ip_address: str,
    path: str,
    redis_client,
    now: float,
) -> RateLimitResult | None:
    """Check the per-path rate limit for the longest matching configured prefix.

    Mirrors the sliding-window sorted-set algorithm used by the global
    windows in ``check_rate_limit`` (ZADD, ZREMRANGEBYSCORE, ZCARD, EXPIRE),
    but keyed per-prefix so a hot path can be throttled independently of
    the IP's overall traffic.

    Args:
        ip_address: Client IP address string.
        path: Request path to match against configured prefixes.
        redis_client: Configured Redis client instance.
        now: Current time (``time.time()``), passed in so callers share a
            single timestamp across the path and global checks.

    Returns:
        A ``RateLimitResult`` with ``window="path"`` if the matching prefix's
        limit was breached, or ``None`` if no prefix matched or the matching
        prefix's limit was not breached.
    """
    from django_waf import conf  # lazy — avoids circular import at module load

    rate_limit_paths = conf.DJANGO_WAF_RATE_LIMIT_PATHS
    if not path or not rate_limit_paths:
        return None

    # Longest-prefix match wins.
    matched_prefix = None
    for prefix in rate_limit_paths:
        if path.startswith(prefix) and (matched_prefix is None or len(prefix) > len(matched_prefix)):
            matched_prefix = prefix

    if matched_prefix is None:
        return None

    max_requests, window_seconds = rate_limit_paths[matched_prefix]
    # Not a security use — just a stable, short cache-key fragment derived
    # from the configured prefix string.
    prefix_hash = hashlib.sha1(matched_prefix.encode(), usedforsecurity=False).hexdigest()[:12]
    key = f"waf:rate:{ip_address}:path:{prefix_hash}"
    cutoff = now - window_seconds

    pipe = redis_client.pipeline()
    pipe.zadd(key, {str(now): now})
    pipe.zremrangebyscore(key, 0, cutoff)
    pipe.zcard(key)
    pipe.expire(key, window_seconds + 10)
    results = pipe.execute()

    count = results[2]

    if count > max_requests:
        retry_after = int(window_seconds - (now - cutoff))
        retry_after = max(1, retry_after)
        return RateLimitResult(exceeded=True, window="path", retry_after=retry_after)

    return None


def check_rate_limit(
    ip_address: str,
    redis_client,
    path: str = "",
) -> RateLimitResult:
    """Check whether the IP has exceeded any rate limit window.

    Uses Redis sorted sets with request timestamps as scores. For each window:
    1. ZADD the current timestamp
    2. ZREMRANGEBYSCORE to remove entries outside the window
    3. ZCARD to count remaining entries
    4. EXPIRE the key with window_seconds + small buffer

    When ``path`` is supplied and ``DJANGO_WAF_RATE_LIMIT_PATHS`` configures a
    matching prefix, that per-path limit is checked first using the same
    sliding-window algorithm, keyed independently of the global IP windows.
    The longest matching prefix wins. A breach there returns immediately
    with ``window="path"`` without touching the global windows.

    Per BR-RATE-001 and BR-RATE-002.

    Args:
        ip_address: Client IP address string.
        redis_client: Configured Redis client instance.
        path: Request path, used to match per-path rate limits. Empty string
            (default) skips per-path checking entirely.

    Returns:
        RateLimitResult namedtuple. If any window is exceeded, ``exceeded``
        is True, ``window`` names the first exceeded window, and
        ``retry_after`` gives seconds until the window resets.
    """
    from django_waf import conf  # lazy — avoids circular import at module load

    thresholds = {
        "1s": conf.DJANGO_WAF_RATE_LIMIT_BURST,
        "1m": conf.DJANGO_WAF_RATE_LIMIT_PER_MINUTE,
        "5m": conf.DJANGO_WAF_RATE_LIMIT_PER_5MIN,
    }
    ttl_buffers = {
        "1s": 2,
        "1m": 10,
        "5m": 10,
    }

    now = time.time()

    path_result = _check_path_rate_limit(ip_address, path, redis_client, now)
    if path_result is not None:
        return path_result

    for window_name, window_seconds in _WINDOWS:
        key = f"waf:rate:{ip_address}:{window_name}"
        threshold = thresholds[window_name]
        ttl = window_seconds + ttl_buffers[window_name]
        cutoff = now - window_seconds

        pipe = redis_client.pipeline()
        pipe.zadd(key, {str(now): now})
        pipe.zremrangebyscore(key, 0, cutoff)
        pipe.zcard(key)
        pipe.expire(key, ttl)
        results = pipe.execute()

        count = results[2]

        if count > threshold:
            retry_after = int(window_seconds - (now - cutoff))
            retry_after = max(1, retry_after)
            return RateLimitResult(exceeded=True, window=window_name, retry_after=retry_after)

    return RateLimitResult(exceeded=False, window=None, retry_after=None)


def get_request_count(
    ip_address: str,
    window: str,
    redis_client,
) -> int:
    """Return the current request count for an IP in the given window.

    Read-only operation — does not add to the sorted set.

    Args:
        ip_address: Client IP address string.
        window: One of '1s', '1m', '5m'.
        redis_client: Configured Redis client instance.

    Returns:
        Integer count of requests in the window.
    """
    window_seconds_map = {"1s": 1, "1m": 60, "5m": 300}
    window_seconds = window_seconds_map.get(window, 60)
    key = f"waf:rate:{ip_address}:{window}"
    now = time.time()
    cutoff = now - window_seconds
    return redis_client.zcount(key, cutoff, "+inf")
