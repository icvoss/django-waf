"""Tests for the defence base contract.

The contract itself is small but it underpins eight defences and the
orchestrator. These tests pin the shapes (frozen, factory helpers,
context defaults) so a future refactor can't silently change the
public surface defences depend on.
"""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Outcome dataclass
# ---------------------------------------------------------------------------


class TestOutcome:
    def test_outcome_is_frozen(self):
        """Outcomes are frozen so a defence can't mutate after returning."""
        from django_waf.forms.defences.base import Outcome

        outcome = Outcome(verdict="pass")
        with pytest.raises((AttributeError, TypeError)):
            outcome.verdict = "block"  # type: ignore[misc]

    def test_default_score_is_zero(self):
        from django_waf.forms.defences.base import Outcome

        assert Outcome(verdict="pass").score == 0.0

    def test_default_reason_and_message_are_empty(self):
        from django_waf.forms.defences.base import Outcome

        outcome = Outcome(verdict="flag")
        assert outcome.reason == ""
        assert outcome.public_message == ""


class TestOutcomeFactories:
    def test_passed_returns_pass_verdict(self):
        from django_waf.forms.defences.base import passed

        outcome = passed()
        assert outcome.verdict == "pass"
        assert outcome.score == 0.0
        assert outcome.reason == ""

    def test_flagged_carries_score_and_reason(self):
        from django_waf.forms.defences.base import flagged

        outcome = flagged(2.0, "time_trap:fast")
        assert outcome.verdict == "flag"
        assert outcome.score == 2.0
        assert outcome.reason == "time_trap:fast"

    def test_flagged_accepts_public_message(self):
        from django_waf.forms.defences.base import flagged

        outcome = flagged(2.0, "x:y", public_message="please retry")
        assert outcome.public_message == "please retry"

    def test_blocked_defaults_score_to_zero(self):
        """Most blocks short-circuit; recording a score is optional."""
        from django_waf.forms.defences.base import blocked

        outcome = blocked("honeypot:url")
        assert outcome.verdict == "block"
        assert outcome.score == 0.0
        assert outcome.reason == "honeypot:url"

    def test_blocked_can_record_score(self):
        from django_waf.forms.defences.base import blocked

        outcome = blocked("render_token:invalid", score=5.0)
        assert outcome.score == 5.0


# ---------------------------------------------------------------------------
# RenderContext / EvaluateContext
# ---------------------------------------------------------------------------


class TestRenderContext:
    def test_config_defaults_to_empty_dict(self):
        from django_waf.forms.defences.base import RenderContext

        ctx = RenderContext(form_id="contact", request=object())
        assert ctx.config == {}

    def test_distinct_instances_have_distinct_config_dicts(self):
        """Default factory must give each context its own dict.

        A shared mutable default would leak state between forms — the
        worst kind of test-flake source. Frozen dataclass + default_factory
        avoids it but worth pinning behaviourally.
        """
        from django_waf.forms.defences.base import RenderContext

        a = RenderContext(form_id="a", request=object())
        b = RenderContext(form_id="b", request=object())
        assert a.config is not b.config

    def test_context_is_frozen(self):
        from django_waf.forms.defences.base import RenderContext

        ctx = RenderContext(form_id="contact", request=object())
        with pytest.raises((AttributeError, TypeError)):
            ctx.form_id = "other"  # type: ignore[misc]


class TestEvaluateContext:
    def test_token_payload_defaults_to_none(self):
        """Defences that run before render_token verifies must see None
        rather than a stale payload from a previous request."""
        from django_waf.forms.defences.base import EvaluateContext

        ctx = EvaluateContext(form_id="contact", request=object(), submitted_data={})
        assert ctx.token_payload is None

    def test_submitted_data_is_required(self):
        """Submitted data has no default — the orchestrator always
        passes it. Pin so a future refactor doesn't introduce a
        misleading empty default."""
        from django_waf.forms.defences.base import EvaluateContext

        with pytest.raises(TypeError):
            EvaluateContext(form_id="contact", request=object())  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Defence protocol — structural compliance
# ---------------------------------------------------------------------------


class TestDefenceProtocol:
    def test_minimal_defence_satisfies_protocol(self):
        """A trivial defence with the right shape passes isinstance check.

        Protocols don't enforce at construction time; the check is at
        runtime via ``isinstance`` against a ``@runtime_checkable``
        Protocol. We don't currently mark the base Protocol as
        runtime-checkable (saves the registry overhead), so this test
        instead asserts the duck-typing contract: an object with
        ``name``, ``render_fields``, ``evaluate`` is what the
        orchestrator will iterate over.
        """
        from django_waf.forms.defences.base import EvaluateContext, RenderContext, passed

        class Stub:
            name = "stub"

            def render_fields(self, ctx: RenderContext) -> dict:
                return {}

            def evaluate(self, ctx: EvaluateContext):
                return passed()

        stub = Stub()
        assert stub.name == "stub"
        assert stub.render_fields(RenderContext(form_id="c", request=object())) == {}
        outcome = stub.evaluate(EvaluateContext(form_id="c", request=object(), submitted_data={}))
        assert outcome.verdict == "pass"
