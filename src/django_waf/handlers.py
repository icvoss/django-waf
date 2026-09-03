"""Signal handlers for django-waf.

Connects post_save and post_delete signals on BlockRule and AllowRule to
increment the Redis rule-cache version key, ensuring the middleware always
re-fetches compiled rules after any change.

Also connects request_blocked to a structured logger for observability.

Connected automatically in ``DjangoWafConfig.ready()`` via
``from . import handlers``.
"""

from __future__ import annotations

import logging
from typing import Any

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from django_waf.signals import request_blocked

logger = logging.getLogger(__name__)

# Redis cache key that stores the current rule-set version number.
# The middleware increments this on every rule change so that worker
# processes know to reload.
_RULES_VERSION_KEY = "waf:rules:version"


def _get_cache() -> tuple[Any, bool]:
    """
    Return the configured cache backend for WAF operations, plus whether it
    is a native Redis connection.

    Unlike ``django_waf.services.redis_client.get_redis_client`` (#44), this
    is intentionally allowed to fall back to the plain Django cache API,
    because every call site below only ever calls ``incr``/``set``, both of
    which the Django cache API implements directly. That is the one part of
    #44's advertised fallback that was already genuinely safe: this
    function's contract does not change.

    The boolean is the fix for a real defect: every Django cache backend
    (including LocMemCache) implements ``incr``, so a caller cannot tell a
    django-redis connection from a Django cache-API object by probing
    ``hasattr(conn, "incr")``, the two disagree on what an ``incr`` of a
    missing key does. Redis's native ``INCR`` auto-vivifies a missing key to
    0 before incrementing; Django's cache API raises ``ValueError`` instead.
    Returning which branch actually fired lets the caller pick the right
    behaviour instead of guessing from the object's shape.
    """
    from django.conf import settings

    alias = getattr(settings, "DJANGO_WAF_REDIS_ALIAS", "default")
    try:
        from django_redis import get_redis_connection  # type: ignore[import-untyped]

        return get_redis_connection(alias), True
    except (NotImplementedError, ImportError):
        # NotImplementedError: alias is configured but not django-redis
        # backed (e.g. LocMemCache), safe to fall back to here, unlike
        # the Redis-only callers in middleware.py/views.py/rule_engine.py.
        from django.core.cache import caches

        return caches[alias], False


def _invalidate_rule_cache() -> None:
    """Increment the rules version key to signal a cache invalidation."""
    try:
        conn, is_redis = _get_cache()
        if is_redis:
            # Native Redis INCR auto-vivifies a missing key to 0 before
            # incrementing, so this is always safe on a cold cache.
            conn.incr(_RULES_VERSION_KEY)
        else:
            # Django's cache API raises ValueError on incr() of a missing
            # key (locmem, filebased, and any other non-Redis backend), so
            # a cold cache must be seeded explicitly rather than relying on
            # the increment itself to create it.
            try:
                conn.incr(_RULES_VERSION_KEY)
            except ValueError:
                conn.set(_RULES_VERSION_KEY, 1)
        logger.debug("WAF rule cache version incremented.")
    except Exception:
        logger.exception("Failed to invalidate WAF rule cache.")


# ---------------------------------------------------------------------------
# BlockRule, invalidate rule cache on every change
# ---------------------------------------------------------------------------


@receiver(post_save, sender="django_waf.BlockRule")
def on_block_rule_save(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when a BlockRule is saved."""
    _invalidate_rule_cache()
    logger.debug("BlockRule %r saved, rule cache invalidated.", str(instance))


@receiver(post_delete, sender="django_waf.BlockRule")
def on_block_rule_delete(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when a BlockRule is deleted."""
    _invalidate_rule_cache()
    logger.debug("BlockRule %r deleted, rule cache invalidated.", str(instance))


# ---------------------------------------------------------------------------
# AllowRule, invalidate rule cache on every change
# ---------------------------------------------------------------------------


@receiver(post_save, sender="django_waf.AllowRule")
def on_allow_rule_save(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when an AllowRule is saved."""
    _invalidate_rule_cache()
    logger.debug("AllowRule %r saved, rule cache invalidated.", str(instance))


@receiver(post_delete, sender="django_waf.AllowRule")
def on_allow_rule_delete(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when an AllowRule is deleted."""
    _invalidate_rule_cache()
    logger.debug("AllowRule %r deleted, rule cache invalidated.", str(instance))


# ---------------------------------------------------------------------------
# request_blocked, structured logging
# ---------------------------------------------------------------------------


@receiver(request_blocked)
def on_request_blocked(sender, ip_address: str, path: str, rule, verdict: str = "", **kwargs) -> None:
    """Write a structured log entry when a request is blocked."""
    rule_id = str(rule.id) if rule is not None else None
    rule_name = str(rule) if rule is not None else None
    logger.info(
        "WAF blocked request",
        extra={
            "waf_event": "request_blocked",
            "ip_address": ip_address,
            "user_agent": kwargs.get("user_agent", ""),
            "path": path,
            "verdict": verdict,
            "rule_id": rule_id,
            "rule_name": rule_name,
        },
    )
