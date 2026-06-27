"""Tests for UaConsistencyDefence — short defence, short tests."""

from __future__ import annotations

from unittest.mock import MagicMock


def _ctx(*, payload_ua_hash, current_ua):
    """Build an EvaluateContext with a payload whose ua_hash is given."""
    from django_waf.forms.defences.base import EvaluateContext

    payload = MagicMock()
    payload.ua_hash = payload_ua_hash

    request = MagicMock()
    request.META = {"HTTP_USER_AGENT": current_ua}

    return EvaluateContext(
        form_id="c",
        request=request,
        submitted_data={},
        token_payload=payload,
    )


class TestRenderFields:
    def test_returns_empty_dict(self):
        """UA hash rides on the render token; no fields of its own."""
        from django_waf.forms.defences.base import RenderContext
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence

        defence = UaConsistencyDefence()
        fields = defence.render_fields(RenderContext(form_id="c", request=MagicMock()))

        assert fields == {}


class TestEvaluate:
    def test_matching_ua_passes(self):
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence
        from django_waf.forms.services.tokens import hash_user_agent

        ua = "Mozilla/5.0 ..."
        defence = UaConsistencyDefence()
        outcome = defence.evaluate(_ctx(payload_ua_hash=hash_user_agent(ua), current_ua=ua))

        assert outcome.verdict == "pass"

    def test_changed_ua_flags(self):
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence
        from django_waf.forms.services.tokens import hash_user_agent

        defence = UaConsistencyDefence()
        outcome = defence.evaluate(
            _ctx(
                payload_ua_hash=hash_user_agent("Mozilla/5.0 (browser at render)"),
                current_ua="curl/7.79.1",  # different client at submit
            )
        )

        assert outcome.verdict == "flag"
        assert outcome.reason == "ua_consistency:changed"
        assert outcome.score == 2.0

    def test_missing_token_payload_passes_silently(self):
        """RenderTokenDefence already blocked → don't compound."""
        from django_waf.forms.defences.base import EvaluateContext
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence

        ctx = EvaluateContext(form_id="c", request=MagicMock(), submitted_data={})
        defence = UaConsistencyDefence()
        outcome = defence.evaluate(ctx)

        assert outcome.verdict == "pass"

    def test_empty_current_ua_compares_to_empty_hash(self):
        """A request with no UA header must still compare consistently.

        Anonymous-UA submissions are common (some proxies strip the
        header). The hash function handles empty input identically at
        render and submit time, so identical-empty UAs pass.
        """
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence
        from django_waf.forms.services.tokens import hash_user_agent

        defence = UaConsistencyDefence()
        outcome = defence.evaluate(_ctx(payload_ua_hash=hash_user_agent(""), current_ua=""))

        assert outcome.verdict == "pass"
