"""Single source of truth for resolving django-waf's Redis client.

``django-redis`` is a hard dependency of this package (see
``pyproject.toml``), so it is always importable. The failure mode this
module exists to close (#44) is not "django-redis is missing": it is
``django_redis.get_redis_connection(alias)`` raising ``NotImplementedError``
whenever the configured cache alias is backed by something other than
``django_redis.cache.RedisCache`` (``LocMemCache`` is the common case, for
example under ``DEBUG=True``). Before #44, three call sites each caught that
broadly and fell back to returning ``django.core.cache.cache`` itself, a
plain Django cache object with no ``setex``, no incr-with-init, no pipeline,
and no sorted-set support. Redis-only calls several frames downstream
(sliding-window rate limiting, ``SETEX``, ``INCR`` on a key that has never
been set, ``HINCRBY``) then raised ``AttributeError``, caught by the
middleware's outermost handler, which failed the whole WAF open per
BR-EVAL-007. A security control that reports healthy while blocking nothing
is the worst possible failure mode for this package specifically.

The fix is not to build a full adapter over the Django cache API: rate
limiting (``services/rate_limiter.py``) uses Redis sorted sets and
pipelines, for which the generic cache API has no safe equivalent. Building
a partial adapter would let the WAF look healthy while its rate limiter
silently no-ops or behaves incorrectly, which is the same failure mode in a
different disguise. Instead:

* ``get_redis_client`` returns a real Redis client or ``None``, never a
  non-Redis object pretending to be one. Every existing
  ``if redis_client is None: <fail open>`` call site (already correct per
  BR-EVAL-007 / AC-EVAL-007) then triggers deterministically, once, at the
  top of the request, instead of a fake client crashing three frames
  deeper with a traceback that reads like noise.
* ``django_waf.E004`` (see ``checks.py``) surfaces the misconfiguration
  (wrong backend configured) at boot as an Error, so an operator catches it
  via ``manage.py check`` before it reaches production, rather than only
  learning about it from a stream of per-request tracebacks.

BR-EVAL-007 itself is unchanged: a genuine Redis outage, where the correctly
configured backend is temporarily unreachable, must still fail the request
through rather than 500. This module only makes the "is this actually
Redis" determination once, cleanly, in one place.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("django_waf.redis_client")

# The package's own Redis version floor. GETDEL (Redis 6.2+) is the only
# command anywhere in this package that needs anything newer than the
# 2.0-2.6 era; flush_rule_hit_counts no longer calls it (see tasks.py, a
# GET+DEL pipeline replaces it), so this floor stays 6.0 rather than
# rising to 6.2. Read by django_waf.E005 (checks.py), the single source of
# truth so the check and the package's actual command usage cannot desync.
MIN_REDIS_VERSION = (6, 0, 0)

# Logged once per process (not once per request) so a misconfigured
# deployment doesn't drown its own logs in a repeat of the same message on
# every single request.
_warned_aliases: set[str] = set()


def get_redis_client(alias: str | None = None):
    """Return a Redis client for ``alias``, or ``None`` if unavailable.

    Args:
        alias: Django cache alias to resolve. Defaults to
            ``django_waf.conf.DJANGO_WAF_REDIS_ALIAS`` when not given.

    Returns:
        A ``django_redis``-backed Redis client instance, or ``None``. Never
        returns a non-Redis cache object: callers that receive ``None`` must
        take their own fail-open (or fail-closed, for a boot-time check)
        path rather than attempting to call Redis-only commands on a
        fallback object.
    """
    from django_waf import conf

    resolved_alias = alias or conf.DJANGO_WAF_REDIS_ALIAS

    try:
        from django_redis import get_redis_connection

        return get_redis_connection(resolved_alias)
    except (NotImplementedError, ImportError):
        # NotImplementedError: the configured cache alias exists but is not
        # a django-redis backend (e.g. LocMemCache), a misconfiguration,
        # not a transient outage.
        # ImportError: django-redis itself is not installed, despite being
        # a declared dependency (e.g. a broken or partial install).
        if resolved_alias not in _warned_aliases:
            _warned_aliases.add(resolved_alias)
            logger.error(
                "django-waf: cache alias %r is not a django-redis backend. "
                "The WAF requires Redis for rule evaluation, rate limiting, "
                "and challenge state, and has no safe equivalent for these "
                "on a generic Django cache backend. The WAF is failing open "
                "(BR-EVAL-007) for every request on this alias until this is "
                "fixed. Set CACHES[%r] to a django_redis.cache.RedisCache "
                "backend, or point DJANGO_WAF_REDIS_ALIAS at one that is. "
                "Run `manage.py check` to see this as django_waf.E004.",
                resolved_alias,
                resolved_alias,
            )
        return None
    except Exception:
        # A genuine runtime failure talking to an otherwise correctly
        # configured Redis (connection refused, timeout, auth failure).
        # This is exactly the outage BR-EVAL-007 exists for: fail open,
        # but don't spam an ERROR per request for a condition operators
        # already monitor via Redis's own health checks.
        logger.warning("django-waf: Redis unavailable for alias %r, failing open", resolved_alias)
        return None


def is_redis_backend(alias: str | None = None) -> bool:
    """Return True if ``alias`` is configured as a django-redis backend.

    Used by ``django_waf.E004`` (``checks.py``) to distinguish "correctly
    configured, just unreachable right now" (not our concern, that is the
    outage BR-EVAL-007 handles) from "the wrong kind of cache backend is
    configured" (a boot-time misconfiguration this check should catch).

    Never raises: any error while inspecting the configured backend is
    treated as "cannot confirm this is Redis", which is the safer answer
    for a check whose job is to flag a possible misconfiguration.
    """
    from django.conf import settings

    resolved_alias = alias or getattr(settings, "DJANGO_WAF_REDIS_ALIAS", "default")

    caches_setting = getattr(settings, "CACHES", {})
    backend = caches_setting.get(resolved_alias, {}).get("BACKEND", "")
    return backend.startswith("django_redis.cache.")


def get_redis_server_version(alias: str | None = None) -> tuple[int, int, int] | None:
    """Return the connected Redis server's version as ``(major, minor, patch)``.

    Used by ``django_waf.E005`` (``checks.py``) to compare the live server
    against ``MIN_REDIS_VERSION``. Returns ``None`` when a client cannot be
    obtained (unreachable, or not a django-redis backend) or the server's
    ``INFO`` response omits/cannot parse ``redis_version``: the caller
    treats ``None`` as "cannot confirm", not as a failing version, since
    this helper's job is to answer the question when it safely can, not to
    force a live connection at times a check should stay side-effect-free
    (see ``is_redis_backend`` for that guard).

    Never raises.
    """
    client = get_redis_client(alias)
    if client is None:
        return None

    try:
        info = client.info(section="server")
        version_str = info.get("redis_version", "")
        # redis_version can carry a trailing suffix on some forks/builds
        # (e.g. "7.2.4" is standard, but be defensive about anything past
        # the first three dot-separated numeric parts).
        parts = version_str.split(".")[:3]
        return tuple(int(part) for part in parts) if len(parts) == 3 else None  # type: ignore[return-value]
    except Exception:
        logger.warning("django-waf: could not read Redis server version for alias %r", alias)
        return None
