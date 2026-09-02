"""
Flush-path liveness probe for django-waf (#100).

Proves that a hit recorded against Redis by the real producer
(``rule_engine._record_rule_hit``) actually reaches the ``BlockRule`` row
via the real consumer (``tasks.flush_rule_hit_counts``), end to end,
against the real Redis client and the real database.

The defect this exists to catch: ``flush_rule_hit_counts`` used to call
Redis ``GETDEL``, which requires Redis 6.2+. Production ran 6.0.16, so
every call raised inside a bare ``except Exception: continue``, and
40,936 scheduled task runs reported success while flushing nothing. It
passed tests, review and release; only reading production found it.

The trap that makes this class of defect invisible without a probe: on a
quiet site the healthy result is ``{"flushed": 0, "keys_seen": 0,
"errors": 0}``, which is IDENTICAL to the Redis-down result and IDENTICAL
to what the getdel bug produced. Zero against unknown real traffic is
ambiguous. Zero against a counter this probe just wrote itself is
unambiguously a defect, which is why this module drives a real counter
through the real producer and consumer rather than inspecting the flush
task's return value in isolation.

No environment guard of any kind gates this module, mirroring
``detector_probe.py``'s own note: #97's staging skip was exactly that
class of defect, a probe that quietly does nothing in some environments
is the next one.
"""

from __future__ import annotations

import logging

from django.db import transaction

logger = logging.getLogger("django_waf.flush_probe")

# A TEST-NET address (RFC 5737), distinct from every octet range
# detector_probe.py uses (192.0.2.10/50/90, 198.51.100.10-15,
# 203.0.113.10/20-40), so a leftover row from either probe can never
# collide with, or be mistaken for, the other's. Real production traffic
# is never sourced from this range, so a match here can only be this
# probe's own prior run, and the forced rollback below means no prior run
# can ever leave one behind to match against in the first place.
_PROBE_PATTERN = "203.0.113.77"

_REDIS_HIT_PREFIX = "waf:rule_hits:"

# The producer's own TTL (rule_engine._record_rule_hit): kept as a local
# constant purely to restore it on a reconciled real key below, matching
# what the producer itself would have set. Not shared with the producer
# via import: this is a probe-side implementation detail of the
# reconciliation, not a claim about the producer's contract.
_HIT_COUNTER_TTL_SECONDS = 86400 * 2


def run_flush_probe() -> dict:
    """Drive one hit through the real producer and the real consumer and
    prove it reached the database.

    Sequence, all inside a single ``transaction.atomic()`` that is
    unconditionally rolled back before returning (see the ``finally``
    below):

    1. Create a real, synthetic ``BlockRule`` row. The flush task does
       ``BlockRule.objects.filter(id=rule_id).update(...)``, which only
       increments ``flushed`` when a row actually matches; without a real
       row to own the counter, the probe would report ``flushed=0`` for
       the mundane reason "no such rule", indistinguishable from the
       defect it exists to catch.
    2. Write the Redis counter by calling the REAL producer,
       ``django_waf.services.rule_engine._record_rule_hit``, never a
       hand-written ``SET``/``INCR``. This is load-bearing: the key
       literal ``"waf:rule_hits:"`` is duplicated with no shared constant
       between the producer (``rule_engine.py``) and the consumer
       (``tasks.py``). A probe that hardcoded a third copy of that prefix
       would not catch the two drifting apart; driving the real producer
       does.
    3. Run the REAL ``django_waf.tasks.flush_rule_hit_counts``. Never
       patched, stubbed, or reimplemented.
    4. Re-read the probe's own ``BlockRule`` row (still inside the atomic
       block, before the rollback fires) and confirm ``hit_count``
       advanced by exactly what was written, and ``last_hit_at`` was set.
    5. Confirm the probe's own Redis key is gone.

    Concurrency and isolation hazard, and why this differs from
    ``detector_probe.run_detector_probe``:

    ``transaction.set_rollback(True)`` discards the DB work (the
    synthetic ``BlockRule`` and the ``F()`` update the flush applied to
    it), but a Redis key is NOT transactional and does not roll back with
    it. Two consequences follow, handled separately:

    - The probe's OWN key must be explicitly deleted in the ``finally``,
      so a run that raises before the flush completes cannot leave it
      behind. ``_record_rule_hit``'s own 2-day TTL is the backstop if even
      that explicit cleanup somehow fails.

    - ``flush_rule_hit_counts`` does not take a scope argument: it scans
      ``waf:rule_hits:*`` unconditionally and flushes EVERY key it finds,
      not just this probe's. On a live site with real traffic, the real
      flush this probe triggers will therefore also sweep up real rule
      counters as a side effect. Those real ``BlockRule.hit_count``
      updates happen to land inside THIS probe's transaction, so without
      correction they would be rolled back and lost, while the Redis
      counters that fed them are deleted regardless (Redis deletion is
      never transactional), which would silently discard real hit counts
      on every probe run. This is a genuine hazard, not a hypothetical,
      given the task has no way to scope itself to synthetic keys only.

      The fix: before writing anything, snapshot every OTHER real
      ``waf:rule_hits:*`` key's value (this is a plain ``GET``, so it
      cannot itself race the flush's own read/delete in a way that loses
      data; at worst a concurrent ``INCR`` between this read and the
      flush's own read is under-counted by this reconciliation by exactly
      the same margin the flush's own non-atomic GET+DELETE pipeline
      already accepts, per BR-EVAL-007). After the real flush has run and
      the transaction has rolled back, re-write each snapshotted Redis
      key with its original value and the producer's own TTL, so the
      count is once again pending for the next real flush.

      The reconciliation restores the REDIS KEY ONLY, never the database
      row. The rollback already returned every real row to where it
      started, so the count is still owed, and putting it back in Redis
      hands it to the next scheduled flush, which is the system's own
      normal path for an unflushed counter. Restoring both would
      double-count; ``_reconcile_other_keys`` records the measurement
      behind that. This reconciliation runs unconditionally in the
      ``finally``, whether the probe itself reports ``alive`` or not, so
      a failing probe cannot leave real counters lost either.

      Residual risk: a real hit that lands on a given key strictly
      between this probe's snapshot read and the real flush's own
      read/delete of that same key is not captured by the snapshot and is
      lost when the flush deletes the key, exactly as it would be lost by
      two real concurrent flush runs today (the flush's own GET+DELETE
      pipeline is explicitly documented as non-atomic against a
      concurrent ``INCR``). This probe does not widen that existing race;
      it neither adds an increment of exposure beyond what the flush
      already accepts, nor closes it. It is stated here rather than
      papered over.

    Must not corrupt real ``hit_count`` values (issue #100's own
    constraint): the probe's synthetic row lives entirely inside the
    rolled-back transaction and is never committed, and the reconciliation
    above puts every real row back to the value it would have reached had
    the probe not run at all.

    Returns:
        Dict with keys:
            - ``alive`` (bool): the overall verdict. True only when the
              counter this probe itself wrote demonstrably reached the
              database with the correct delta and the correct
              ``last_hit_at``, and the Redis key was cleared.
            - ``flushed``, ``keys_seen``, ``errors``: echoed verbatim from
              the real ``flush_rule_hit_counts`` result.
            - ``hit_count_delta`` (int): what actually landed on the
              probe's own ``BlockRule.hit_count``, 0 if the flush never
              applied it.
            - ``key_deleted`` (bool): whether the probe's own Redis key
              was gone after the flush ran.
            - ``failure_reason`` (str | None): ``None`` when ``alive`` is
              True; otherwise a specific, human-readable reason naming the
              step that failed, since this is what an operator reads at
              3am.
    """
    from django_waf.models import BlockRule
    from django_waf.services.rule_engine import _record_rule_hit
    from django_waf.tasks import flush_rule_hit_counts

    try:
        from django_redis import get_redis_connection

        from django_waf import conf

        redis_client = get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except Exception as exc:
        logger.warning("django-waf: flush probe could not obtain a Redis connection: %s", exc)
        return _failure_result(f"could not obtain a Redis connection: {exc}")

    probe_key = None
    other_keys_snapshot: dict[str, bytes] = {}
    hit_count_delta = 0
    key_deleted = False
    flush_result: dict = {}

    try:
        with transaction.atomic():
            try:
                rule = BlockRule.objects.create(
                    name="django-waf flush probe (synthetic, rolled back)",
                    rule_type="ip",
                    match_type="exact",
                    pattern=_PROBE_PATTERN,
                    action="log_only",
                    is_active=False,
                    source="admin",
                    hit_count=0,
                )
                probe_key = f"{_REDIS_HIT_PREFIX}{rule.id}"

                # Snapshot every OTHER real hit-count key before this probe
                # writes its own or triggers the real flush, so the
                # reconciliation in `finally` can restore them afterwards.
                # See the "Concurrency and isolation hazard" section of
                # this function's docstring for why this is necessary.
                other_keys_snapshot = _snapshot_other_keys(redis_client, exclude_key=probe_key)

                _record_rule_hit(str(rule.id), redis_client)

                flush_result = flush_rule_hit_counts()

                rule.refresh_from_db()
                hit_count_delta = rule.hit_count
                key_deleted = _key_is_absent(redis_client, probe_key)
            finally:
                # Unconditional: even if a step above raises, no synthetic
                # BlockRule row may survive this function. The Redis-side
                # cleanup and reconciliation happen in the outer finally,
                # after this rollback has fired, since Redis writes are not
                # covered by it.
                transaction.set_rollback(True)
    finally:
        _cleanup_probe_key(redis_client, probe_key)
        _reconcile_other_keys(redis_client, other_keys_snapshot)

    flushed = flush_result.get("flushed", 0)
    keys_seen = flush_result.get("keys_seen", 0)
    errors = flush_result.get("errors", 0)

    failure_reason = None
    if hit_count_delta != 1:
        failure_reason = (
            f"expected the probe's BlockRule.hit_count to advance by 1, advanced by "
            f"{hit_count_delta}: the flush ran (flushed={flushed}, keys_seen={keys_seen}, "
            f"errors={errors}) but did not apply the counter this probe wrote"
        )
    elif not key_deleted:
        failure_reason = "the probe's Redis hit-count key was still present after the flush ran"

    alive = failure_reason is None

    if alive:
        logger.info(
            "django-waf: flush probe alive, hit_count_delta=%d flushed=%d keys_seen=%d errors=%d",
            hit_count_delta,
            flushed,
            keys_seen,
            errors,
        )
    else:
        logger.warning("django-waf: flush probe FAILED: %s", failure_reason)

    return {
        "alive": alive,
        "flushed": flushed,
        "keys_seen": keys_seen,
        "errors": errors,
        "hit_count_delta": hit_count_delta,
        "key_deleted": key_deleted,
        "failure_reason": failure_reason,
    }


def _key_is_absent(redis_client, key: str) -> bool:
    """Whether ``key`` is gone, tolerating a Redis-side read failure here
    (a broken client at this final check is reported as "key not deleted",
    a correct and specific failure_reason for run_flush_probe to surface)
    rather than letting an unhandled exception escape past the rollback
    and cleanup this function's caller still needs to run."""
    try:
        return redis_client.get(key) is None
    except Exception:
        logger.warning("django-waf: flush probe could not confirm its own Redis key was cleared", exc_info=True)
        return False


def _failure_result(failure_reason: str) -> dict:
    return {
        "alive": False,
        "flushed": 0,
        "keys_seen": 0,
        "errors": 0,
        "hit_count_delta": 0,
        "key_deleted": False,
        "failure_reason": failure_reason,
    }


def _snapshot_other_keys(redis_client, *, exclude_key: str) -> dict[str, bytes]:
    """Read (never delete) every real ``waf:rule_hits:*`` key's current
    value, excluding the probe's own key, so it can be restored after the
    real flush sweeps it up as a side effect. Failure to snapshot is
    treated as "no other keys": logged at WARNING and the probe proceeds,
    since refusing to run the liveness check over an unrelated listing
    failure would defeat the point of a liveness probe.
    """
    try:
        keys = redis_client.keys(f"{_REDIS_HIT_PREFIX}*")
    except Exception:
        logger.warning(
            "django-waf: flush probe could not snapshot existing hit-count keys before running; "
            "proceeding, any real keys present will not be reconciled",
            exc_info=True,
        )
        return {}

    snapshot: dict[str, bytes] = {}
    for key in keys:
        key_str = key.decode() if isinstance(key, bytes) else key
        if key_str == exclude_key:
            continue
        try:
            value = redis_client.get(key_str)
        except Exception:
            logger.warning(
                "django-waf: flush probe could not snapshot hit-count key %s before running",
                key_str,
                exc_info=True,
            )
            continue
        if value is not None:
            snapshot[key_str] = value
    return snapshot


def _cleanup_probe_key(redis_client, probe_key: str | None) -> None:
    if probe_key is None:
        return
    try:
        redis_client.delete(probe_key)
    except Exception:
        # _record_rule_hit's own 2-day TTL is the backstop here: even if
        # this explicit cleanup fails, the key cannot accumulate forever.
        logger.warning("django-waf: flush probe could not clean up its own Redis key %s", probe_key, exc_info=True)


def _reconcile_other_keys(redis_client, snapshot: dict[str, bytes]) -> None:
    """Restore every real hit-count key the probe's own flush run swept up,
    by re-writing the Redis key with its snapshotted value and the
    producer's own TTL. Runs unconditionally, whether the probe reports
    alive or not, so a failing probe cannot leave real counters lost.

    Restoring the REDIS KEY ONLY is deliberate, and restoring the DB row
    as well would be a defect. The real flush this probe triggers applied
    each real count to its BlockRule inside the probe's own transaction,
    which is then rolled back, so the DB row is left exactly where it
    started and the count is still owed. Putting the count back in Redis
    leaves it pending for the next real flush (5 minutes away on the
    default beat), which is the system's own normal path for a counter
    that has not been flushed yet.

    An earlier revision of this function restored BOTH: it re-applied the
    count to the row with an F() update AND re-wrote the Redis key. That
    double-counts every real counter present whenever the probe runs, once
    from the reconciliation and once more when the next real flush reads
    the key it just restored. Verified before this was corrected: a real
    counter of 5 reached hit_count=10 after one probe run followed by one
    scheduled flush. A liveness probe that corrupts the numbers it exists
    to protect is worse than no probe, and issue #100 names not corrupting
    real hit_count values as an explicit constraint.
    """
    if not snapshot:
        return

    for key_str, raw_value in snapshot.items():
        rule_id = key_str[len(_REDIS_HIT_PREFIX) :]
        try:
            count = int(raw_value)
        except (TypeError, ValueError):
            logger.error(
                "django-waf: flush probe could not parse snapshotted hit count for rule %s "
                "(value=%r), real hit count for this rule may now be understated",
                rule_id,
                raw_value,
                exc_info=True,
            )
            continue
        if count <= 0:
            continue

        try:
            redis_client.set(key_str, count, ex=_HIT_COUNTER_TTL_SECONDS)
        except Exception:
            logger.error(
                "django-waf: flush probe could not restore real hit-count key %s (count=%d) "
                "after its own run swept it up; this rule's hit count is understated by %d",
                key_str,
                count,
                count,
                exc_info=True,
            )
