"""
Detector production-outcome report for django-waf (wave 2, BR-ANOM-015).

Closes the fourth link of the chain-of-command rule: identity, action,
justification and, until now, nothing reported outcome. ``detect_cloud_spray``
was the most productive detector in production (2,188 hits attributed, six
rules created in 24h) while ``django_waf_probe_detectors`` reported it
SILENT under default settings, and the only way to get the real per-detector
picture was ad-hoc ORM queries run directly against a production database.
This module is that query, built once, run repeatably, and zero-filled so a
detector producing nothing is an explicit zero row rather than a name that
never appears.

Two things about ``BlockRule.detectors`` this module has to get right, both
established in ``anomaly_detector._merge_detector_names`` and
``anomaly_detector._update_or_create_auto_rule`` before this module existed:

1. It is a comma-separated, sorted, deduplicated SET of every detector name
   that has ever written to the row (additive, #97), not a single owner. A
   naive substring match (``detectors__contains="detect_cloud_spray"``) would
   also match a hypothetical ``detect_cloud_spray_v2``, so this module splits
   on ``,`` and tests exact membership rather than substring containment.
2. It is a SUPERSET of ``anomaly_detector.DETECTOR_NAMES``.
   ``rule_engine._create_escalation_rule`` writes ``challenge_escalation`` to
   this field (pinned by ``tests/test_services.py``,
   ``test_detector_field_populated_by_every_detector_passing_it``), and
   ``challenge_escalation`` is not, and never has been, a member of
   ``DETECTOR_NAMES``: it is not a detector in the sense that word is used
   elsewhere in this package (it does not run in ``run_all_detectors``, does
   not appear in the probe, and has no fixture), it is ``rule_engine``'s own
   two-stage escalation writing a provenance stamp onto a rule it promotes.
   Dropping it would silently discard real provenance data already present
   in the table; folding it into the registry would misrepresent it as a
   seventh detector nothing else in the package treats as one. This module
   therefore reports it in its own, clearly separate section
   (``unregistered_detectors``), keyed by whatever name shows up, rather than
   silently dropping it or silently merging it into a registry row.

Query cost (the plan's own flagged risk, "measure, do not guess"): measured
against real PostgreSQL with 60,000 ``BlockRule`` rows (exceeding the 54,319
measured on the production deployment that motivated this wave), a realistic
mixed detector-name distribution and a 30-day window narrowing the table to
roughly 1,900 matching rows. The report issues exactly TWO queries, verified
with ``CaptureQueriesContext`` rather than asserted: ONE scan for the
per-detector aggregate (``.values_list("detectors", "created_at",
"hit_count")`` over the window-filtered queryset), aggregated per detector in
Python, plus the single ``GROUP BY`` that ``auto_rule_review_outcomes``
(BR-ANOM-010) issues for the review-outcome section this module reuses rather
than reimplements. The per-detector aggregate is one scan rather than one
``LIKE``-filtered query per registry entry: ``EXPLAIN ANALYZE`` on a
single per-name ``detectors__contains`` filter showed a sequential scan
(the ``db_index=True`` btree index on ``detectors`` cannot serve a
leading-wildcard ``LIKE '%name%'``, only a prefix match) costing ~5.5ms
execution time once narrowed by the indexed ``created_at`` filter; multiplied
across seven names that is comparable in DB time to the single-scan Python
aggregation this module actually uses, and the single-scan form additionally
gets exact-membership parsing for free rather than needing seven separate
non-indexable filters. Both forms complete in well under 200ms at this row
count, an operator-invoked reporting command's budget, so no new index or
migration is added in this change: the existing ``db_index=True`` on
``detectors`` and the composite indexes already on ``BlockRule`` (notably
``created_at`` itself being individually indexed) are sufficient. If a future
deployment's row count makes this slow, the fix is a composite index
targeting the window filter, not a change to how the field is parsed.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta

from django.utils import timezone

logger = logging.getLogger("django_waf.detector_outcomes")


def report_detector_outcomes(window_days: int = 30) -> dict:
    """Report, per detector, what actually happened in production.

    Read-only: issues one SELECT against ``BlockRule`` and one further
    query inside ``auto_rule_review_outcomes`` (BR-ANOM-010). Creates and
    modifies nothing, and emits no signal.

    Args:
        window_days: How far back, in days, to look at ``BlockRule.created_at``.
            Default 30, matching the plan's "Why now" table window.

    Returns:
        Dict with keys:
            - ``window_days`` (int): echoed back, the window actually used.
            - ``detectors`` (dict[str, dict]): one entry per name in
              ``anomaly_detector.DETECTOR_NAMES``, zero-filled. A detector
              that created nothing in the window still appears here with
              ``rules_created=0`` rather than being omitted, which is the
              entire point (an absent row is indistinguishable from a
              detector nobody noticed had died). Each value is a dict with:
                - ``rules_created`` (int)
                - ``rules_ever_hit`` (int): rules with ``hit_count > 0``.
                - ``hit_rate`` (float): ``rules_ever_hit / rules_created``,
                  rounded to 4 decimal places, ``0.0`` when
                  ``rules_created`` is 0 (never a ZeroDivisionError).
                - ``total_hits`` (int): sum of ``hit_count`` across every
                  rule attributed to this detector in the window.
                - ``most_recent_rule_created`` (datetime | None): the
                  latest ``created_at`` among this detector's rules in the
                  window, ``None`` when ``rules_created`` is 0.
            - ``unregistered_detectors`` (dict[str, dict]): same per-entry
              shape as ``detectors``, for every name found in
              ``BlockRule.detectors`` within the window that is NOT a
              member of ``DETECTOR_NAMES`` (e.g. ``challenge_escalation``).
              Empty dict when none are found. Kept separate from
              ``detectors`` so a name outside the registry is never
              silently dropped and never silently misrepresented as a
              registered detector.
            - ``review_outcomes`` (dict): the BR-ANOM-010 outcome counts
              from ``anomaly_detector.auto_rule_review_outcomes``, using
              ``window_days * 24`` as its own ``window_hours`` so both
              halves of the report describe the same period.
    """
    from django_waf.models import BlockRule
    from django_waf.services.anomaly_detector import DETECTOR_NAMES, auto_rule_review_outcomes

    if window_days < 1:
        raise ValueError("window_days must be a positive integer")

    window_start = timezone.now() - timedelta(days=window_days)

    rows = BlockRule.objects.filter(created_at__gte=window_start).values_list("detectors", "created_at", "hit_count")

    accumulators: dict[str, _DetectorAccumulator] = {}
    for detectors_field, created_at, hit_count in rows:
        for name in _split_detector_names(detectors_field):
            accumulators.setdefault(name, _DetectorAccumulator()).add(created_at, hit_count)

    detectors_report = {name: _finalise(accumulators.get(name)) for name in sorted(DETECTOR_NAMES)}

    unregistered_names = sorted(set(accumulators) - DETECTOR_NAMES)
    unregistered_report = {name: _finalise(accumulators[name]) for name in unregistered_names}

    if unregistered_names:
        logger.info(
            "django-waf: detector outcome report found %d name(s) in BlockRule.detectors "
            "outside anomaly_detector.DETECTOR_NAMES: %s",
            len(unregistered_names),
            ", ".join(unregistered_names),
        )

    return {
        "window_days": window_days,
        "detectors": detectors_report,
        "unregistered_detectors": unregistered_report,
        "review_outcomes": auto_rule_review_outcomes(window_hours=window_days * 24),
    }


def _split_detector_names(detectors_field: str) -> list[str]:
    """Split a ``BlockRule.detectors`` value into its member names.

    Exact membership, never substring matching: mirrors how
    ``anomaly_detector._merge_detector_names`` builds the field (sorted,
    comma-joined, no empty entries), so a name is only ever counted for a
    row that actually carries it, never for a row whose field merely
    contains it as a substring (the ``detect_cloud_spray`` /
    ``detect_cloud_spray_v2`` prefix-collision this exists to avoid).
    """
    return [name for name in detectors_field.split(",") if name]


class _DetectorAccumulator:
    """Running total for one detector name, built while scanning the window's
    rows once. Not part of this module's public return shape; ``_finalise``
    converts an instance (or ``None``, for a detector with no rows) into the
    dict shape ``report_detector_outcomes`` actually returns."""

    __slots__ = ("rules_created", "rules_ever_hit", "total_hits", "most_recent_rule_created")

    def __init__(self) -> None:
        self.rules_created = 0
        self.rules_ever_hit = 0
        self.total_hits = 0
        self.most_recent_rule_created: datetime | None = None

    def add(self, created_at: datetime, hit_count: int) -> None:
        self.rules_created += 1
        self.total_hits += hit_count
        if hit_count > 0:
            self.rules_ever_hit += 1
        if self.most_recent_rule_created is None or created_at > self.most_recent_rule_created:
            self.most_recent_rule_created = created_at


def _finalise(accumulator: _DetectorAccumulator | None) -> dict:
    if accumulator is None or accumulator.rules_created == 0:
        return {
            "rules_created": 0,
            "rules_ever_hit": 0,
            "hit_rate": 0.0,
            "total_hits": 0,
            "most_recent_rule_created": None,
        }

    return {
        "rules_created": accumulator.rules_created,
        "rules_ever_hit": accumulator.rules_ever_hit,
        "hit_rate": round(accumulator.rules_ever_hit / accumulator.rules_created, 4),
        "total_hits": accumulator.total_hits,
        "most_recent_rule_created": accumulator.most_recent_rule_created,
    }
