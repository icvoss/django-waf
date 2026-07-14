"""Tests for PowGateDefence."""

from __future__ import annotations

import hashlib
from unittest.mock import MagicMock


def _ctx_render(form_id="contact", config=None):
    from django_waf.forms.defences.base import RenderContext

    return RenderContext(form_id=form_id, request=MagicMock(), config=config or {})


def _ctx_eval(submitted_data, *, payload_nonce=None, config=None):
    from django_waf.forms.defences.base import EvaluateContext

    payload = None
    if payload_nonce is not None:
        payload = MagicMock()
        payload.nonce = payload_nonce

    return EvaluateContext(
        form_id="contact",
        request=MagicMock(),
        submitted_data=submitted_data,
        config=config or {},
        token_payload=payload,
    )


def _solve(token_nonce: str, difficulty: int) -> str:
    """Brute-force a candidate nonce that satisfies the PoW.

    Used in tests to construct valid submissions. Matches the
    defence's hash construction exactly.
    """
    from django_waf.services.challenge_service import _digest_has_leading_zero_bits

    for n in range(1_000_000):
        msg = f"{token_nonce}:{n}".encode()
        if _digest_has_leading_zero_bits(hashlib.sha256(msg).digest(), difficulty):
            return str(n)
    raise RuntimeError("could not solve PoW in 1M iterations — test set difficulty too high")


# ---------------------------------------------------------------------------
# render_fields
# ---------------------------------------------------------------------------


class TestRenderFields:
    def test_renders_nonce_field_and_script(self):
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        defence = PowGateDefence()
        html = defence.render_fields(_ctx_render())[NONCE_FIELD]

        assert f'name="{NONCE_FIELD}"' in html
        assert "<script" in html
        # Synchronous SHA-256 batch loop, not crypto.subtle (v0.10.6+):
        # awaiting crypto.subtle.digest() once per nonce capped throughput
        # at tens of thousands of hashes/sec.
        assert "crypto.subtle" not in html
        assert "function sha256" in html

    def test_solver_script_includes_difficulty(self):
        """The JS solver uses the difficulty value — pin so a future
        bug doesn't silently set it to a different constant."""
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        defence = PowGateDefence()
        html = defence.render_fields(_ctx_render(config={"difficulty": 8}))[NONCE_FIELD]

        assert "difficulty=8" in html

    def test_per_form_difficulty_override(self):
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        defence = PowGateDefence()
        html = defence.render_fields(_ctx_render(config={"difficulty": 4}))[NONCE_FIELD]

        # Difficulty 4 is in the script literal — sanity check that
        # the per-form value, not the default, made it through.
        assert "difficulty=4" in html


# ---------------------------------------------------------------------------
# evaluate
# ---------------------------------------------------------------------------


class TestEvaluate:
    def test_missing_nonce_blocks(self):
        from django_waf.forms.defences.pow_gate import PowGateDefence

        defence = PowGateDefence()
        outcome = defence.evaluate(_ctx_eval({}))

        assert outcome.verdict == "block"
        assert outcome.reason == "pow_gate:missing"
        assert outcome.score == 5.0

    def test_invalid_nonce_blocks(self):
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        defence = PowGateDefence()
        outcome = defence.evaluate(
            _ctx_eval(
                {NONCE_FIELD: "999999999", "waf_pow_token": "some_nonce"},
                config={"difficulty": 12},
            )
        )

        assert outcome.verdict == "block"
        assert outcome.reason == "pow_gate:invalid"

    def test_valid_nonce_passes(self):
        """Solve a low-difficulty PoW in test, submit it, defence passes."""
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        token_nonce = "test_token_nonce"
        # Use difficulty 8 — solves in ~256 attempts, instant.
        candidate = _solve(token_nonce, 8)

        defence = PowGateDefence()
        outcome = defence.evaluate(
            _ctx_eval(
                {NONCE_FIELD: candidate, "waf_pow_token": token_nonce},
                config={"difficulty": 8},
            )
        )

        assert outcome.verdict == "pass"

    def test_uses_token_payload_nonce_when_available(self):
        """When the orchestrator has populated token_payload, prefer
        its nonce over the bind field — the verified token is the
        source of truth."""
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        token_nonce = "verified_nonce"
        candidate = _solve(token_nonce, 8)

        defence = PowGateDefence()
        outcome = defence.evaluate(
            _ctx_eval(
                {NONCE_FIELD: candidate, "waf_pow_token": "tampered_nonce"},
                payload_nonce=token_nonce,  # the trusted source
                config={"difficulty": 8},
            )
        )

        assert outcome.verdict == "pass"

    def test_tampered_bind_field_fails_when_no_payload(self):
        """If a bot bumps the bind field, the PoW won't verify against
        the original token_nonce → block."""
        from django_waf.forms.defences.pow_gate import NONCE_FIELD, PowGateDefence

        original_nonce = "original"
        candidate = _solve(original_nonce, 8)

        defence = PowGateDefence()
        outcome = defence.evaluate(
            _ctx_eval(
                {NONCE_FIELD: candidate, "waf_pow_token": "tampered"},
                config={"difficulty": 8},
            )
        )

        assert outcome.verdict == "block"
        assert outcome.reason == "pow_gate:invalid"

    def test_verifier_matches_page_level_pow(self):
        """The form-level PoW uses the same _digest_has_leading_zero_bits
        helper as the page challenge — pin so a future refactor doesn't
        introduce a parallel implementation that could drift."""
        from django_waf.forms.defences.pow_gate import _verify_nonce
        from django_waf.services.challenge_service import _digest_has_leading_zero_bits

        # _verify_nonce constructs a digest and calls the shared helper.
        # Compute both ways and check the parity.
        nonce = "abc"
        candidate = _solve(nonce, 6)
        msg = f"{nonce}:{candidate}".encode()
        assert _verify_nonce(nonce, candidate, 6) is True
        assert _digest_has_leading_zero_bits(hashlib.sha256(msg).digest(), 6) is True
