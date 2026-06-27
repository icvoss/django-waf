"""Tests for TimeTrapDefence.

Pins every transition in PRD §3.2's truth table. The 0.5s hard floor
is the only threshold not configurable per-form, so it gets a
dedicated test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock


def _payload(render_time):
    """Build a TokenPayload-like object with just the field the defence reads."""
    p = MagicMock()
    p.render_time = render_time
    return p


def _ctx(payload, config=None):
    from django_waf.forms.defences.base import EvaluateContext

    return EvaluateContext(
        form_id="c",
        request=MagicMock(),
        submitted_data={},
        config=config or {},
        token_payload=payload,
    )


def _ago(seconds):
    return datetime.now(tz=UTC) - timedelta(seconds=seconds)


# ---------------------------------------------------------------------------
# render_fields
# ---------------------------------------------------------------------------


class TestRenderFields:
    def test_returns_empty_dict(self):
        """TimeTrap relies on the render-token timestamp; no fields of its own."""
        from django_waf.forms.defences.base import RenderContext
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        fields = defence.render_fields(RenderContext(form_id="c", request=MagicMock()))

        assert fields == {}


# ---------------------------------------------------------------------------
# evaluate — truth table
# ---------------------------------------------------------------------------


class TestEvaluateTruthTable:
    def test_too_fast_blocks(self):
        """delta < 0.5s → hard block."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(0.1))))

        assert outcome.verdict == "block"
        assert outcome.reason == "time_trap:too_fast"
        assert outcome.score == 5.0

    def test_fast_band_flags(self):
        """0.5s ≤ delta < min → flag."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        # Default min is 1.5s; 1.0s is in the fast band.
        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(1.0))))

        assert outcome.verdict == "flag"
        assert outcome.reason == "time_trap:fast"
        assert outcome.score == 2.0

    def test_within_min_max_passes(self):
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(10.0))))

        assert outcome.verdict == "pass"

    def test_expired_flags(self):
        """delta > max → flag with expired reason."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        # Default max is 3600s; 7200 (2h) is well past.
        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(7200))))

        assert outcome.verdict == "flag"
        assert outcome.reason == "time_trap:expired"

    def test_negative_delta_treated_as_too_fast(self):
        """Clock skew producing future render_time → block as too_fast.

        Better to flag a false positive than ignore a genuine replay.
        """
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        future = datetime.now(tz=UTC) + timedelta(seconds=30)
        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(future)))

        assert outcome.verdict == "block"
        assert outcome.reason == "time_trap:too_fast"


# ---------------------------------------------------------------------------
# Configurability
# ---------------------------------------------------------------------------


class TestConfigurable:
    def test_per_form_min_overrides_default(self):
        """Newsletter-style short forms set min_fill_seconds lower."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(0.7)), config={"min_fill_seconds": 0.6}))

        # 0.7s > 0.5 (too_fast floor) AND > configured min 0.6 → pass
        assert outcome.verdict == "pass"

    def test_per_form_max_overrides_default(self):
        """A form with a tight max flags submissions sooner."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(120)), config={"max_fill_seconds": 60}))

        assert outcome.reason == "time_trap:expired"

    def test_hard_floor_is_not_configurable_via_min(self):
        """Setting min_fill_seconds to 0 cannot weaken the 0.5s hard floor.

        The floor is a security invariant — a configuration mistake
        shouldn't lower it.
        """
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(_ago(0.1)), config={"min_fill_seconds": 0.0}))

        # 0.1s is below the hard 0.5s floor regardless of min config.
        assert outcome.verdict == "block"
        assert outcome.reason == "time_trap:too_fast"


# ---------------------------------------------------------------------------
# Defensive defaults
# ---------------------------------------------------------------------------


class TestDefensive:
    def test_missing_token_payload_passes_silently(self):
        """No token_payload means RenderTokenDefence already blocked.
        Don't compound the penalty — just pass."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(payload=None))

        assert outcome.verdict == "pass"

    def test_naive_render_time_treated_as_utc(self):
        """Defensive: if a future bug produces a naive datetime, the
        defence must not crash. Treat as UTC."""
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        # Strip tzinfo from a known-aware datetime so we get a naive value
        # without using the deprecated datetime.utcnow().
        naive_now = (datetime.now(tz=UTC) - timedelta(seconds=5)).replace(tzinfo=None)
        defence = TimeTrapDefence()
        outcome = defence.evaluate(_ctx(_payload(naive_now)))

        # Within fill window → pass
        assert outcome.verdict == "pass"
