"""Signal handlers for icv-waf.

Connects post_save and post_delete signals on BlockRule and AllowRule to
increment the Redis rule-cache version key, ensuring the middleware always
re-fetches compiled rules after any change.

Also connects request_blocked to a structured logger for observability.

Connected automatically in ``IcvWafConfig.ready()`` via
``from . import handlers``.
"""

from __future__ import annotations

import logging

from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from icv_waf.signals import request_blocked

logger = logging.getLogger(__name__)

# Redis cache key that stores the current rule-set version number.
# The middleware increments this on every rule change so that worker
# processes know to reload.
_RULES_VERSION_KEY = "waf:rules:version"


def _get_cache():
    """
    Return the configured cache backend for WAF operations.

    Prefers django-redis (which supports atomic INCR) but falls back to
    Django's default cache so the package works without django-redis in tests.
    """
    from django.conf import settings

    alias = getattr(settings, "ICV_WAF_REDIS_ALIAS", "default")
    try:
        from django_redis import get_redis_connection  # type: ignore[import-untyped]

        return get_redis_connection(alias)
    except ImportError:
        from django.core.cache import caches

        return caches[alias]


def _invalidate_rule_cache() -> None:
    """Increment the rules version key to signal a cache invalidation."""
    try:
        conn = _get_cache()
        # django-redis connection supports INCR directly.
        if hasattr(conn, "incr"):
            conn.incr(_RULES_VERSION_KEY)
        else:
            # Fallback: increment via Django cache API.
            try:
                conn.incr(_RULES_VERSION_KEY)
            except ValueError:
                conn.set(_RULES_VERSION_KEY, 1)
        logger.debug("WAF rule cache version incremented.")
    except Exception:
        logger.exception("Failed to invalidate WAF rule cache.")


# ---------------------------------------------------------------------------
# BlockRule — invalidate rule cache on every change
# ---------------------------------------------------------------------------


@receiver(post_save, sender="icv_waf.BlockRule")
def on_block_rule_save(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when a BlockRule is saved."""
    _invalidate_rule_cache()
    logger.debug("BlockRule %r saved — rule cache invalidated.", str(instance))


@receiver(post_delete, sender="icv_waf.BlockRule")
def on_block_rule_delete(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when a BlockRule is deleted."""
    _invalidate_rule_cache()
    logger.debug("BlockRule %r deleted — rule cache invalidated.", str(instance))


# ---------------------------------------------------------------------------
# AllowRule — invalidate rule cache on every change
# ---------------------------------------------------------------------------


@receiver(post_save, sender="icv_waf.AllowRule")
def on_allow_rule_save(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when an AllowRule is saved."""
    _invalidate_rule_cache()
    logger.debug("AllowRule %r saved — rule cache invalidated.", str(instance))


@receiver(post_delete, sender="icv_waf.AllowRule")
def on_allow_rule_delete(sender, instance, **kwargs) -> None:
    """Invalidate the compiled rule cache when an AllowRule is deleted."""
    _invalidate_rule_cache()
    logger.debug("AllowRule %r deleted — rule cache invalidated.", str(instance))


# ---------------------------------------------------------------------------
# request_blocked — structured logging
# ---------------------------------------------------------------------------


@receiver(request_blocked)
def on_request_blocked(sender, ip_address: str, path: str, rule, verdict: str, **kwargs) -> None:
    """Write a structured log entry when a request is blocked."""
    rule_id = str(rule.id) if rule is not None else None
    rule_name = str(rule) if rule is not None else None
    logger.info(
        "WAF blocked request",
        extra={
            "waf_event": "request_blocked",
            "ip_address": ip_address,
            "path": path,
            "verdict": verdict,
            "rule_id": rule_id,
            "rule_name": rule_name,
        },
    )
