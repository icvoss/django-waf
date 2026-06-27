"""Browser-shaped integration test for the form-protection render path.

Regression suite for the v0.11.0 → v0.11.1 bug where
RenderTokenDefence returned the raw token string instead of an
``<input>`` tag. The unit tests in test_render_token_defence,
test_orchestrator, test_mixin all passed against the buggy code
because they constructed POST payloads directly — none of them ever
parsed the rendered HTML and submitted what a browser would
actually submit.

This module fills that gap: render the form, parse the HTML for
hidden inputs, build a POST from those, verify PASS. Any defence
that owns a hidden field is covered by this round trip.
"""

from __future__ import annotations

from html.parser import HTMLParser
from unittest.mock import MagicMock, patch


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request(*, ip="1.2.3.4", ua="Mozilla/5.0"):
    req = MagicMock()
    req.META = {"REMOTE_ADDR": ip, "HTTP_USER_AGENT": ua}
    req.user = MagicMock(is_authenticated=False)
    return req


class _HiddenInputCollector(HTMLParser):
    """Extract name=value pairs from every <input> in a fragment.

    Mirrors what a browser does at form submission: read every
    ``<input>`` (regardless of type) and include its name/value pair
    in the POST. Honeypot ``type="text"`` inputs are included too
    — humans don't fill them, but a browser submits them empty.
    """

    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        attr_dict = dict(attrs)
        name = attr_dict.get("name")
        if not name:
            return
        # Browsers submit "" when the value attribute is missing or empty.
        self.inputs.append((name, attr_dict.get("value", "") or ""))


def _parse_inputs(html: str) -> dict[str, str]:
    """Return {name: value} for every <input> in the fragment.

    Only the first value for each name wins, matching browser
    behaviour for forms with no duplicate names.
    """
    parser = _HiddenInputCollector()
    parser.feed(html)
    result: dict[str, str] = {}
    for name, value in parser.inputs:
        result.setdefault(name, value)
    return result


# ---------------------------------------------------------------------------
# DOM round-trip: render → parse → submit → PASS
# ---------------------------------------------------------------------------


class TestRenderTokenDomRoundTrip:
    """Pin: the token defence renders an <input> the browser will submit."""

    def test_render_then_parse_finds_waf_token_input(self, settings):
        """The rendered HTML contains exactly one waf_token hidden input
        carrying a non-empty value."""
        import django_waf.conf as conf_mod
        from django_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="contact",
                defences=("render_token",),
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request())
            html = "".join(fields[k] for k in sorted(fields))

        inputs = _parse_inputs(html)
        assert "waf_token" in inputs, f"waf_token input missing from rendered DOM. Got inputs: {sorted(inputs)}"
        assert len(inputs["waf_token"]) > 20  # base64url-ish payload

    def test_token_does_not_leak_as_visible_text(self, settings):
        """Acceptance criterion 2 from the bug report: no base64url
        string appears in the DOM outside an input value attribute.

        We approximate 'base64url string' by 'a contiguous run of
        ≥32 chars from the base64url alphabet that isn't inside a
        value="..." attribute'.
        """
        import re

        import django_waf.conf as conf_mod
        from django_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            protection = FormProtection(
                form_id="contact",
                defences=("render_token",),
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request())
            html = "".join(fields[k] for k in sorted(fields))

        # Strip every value="..." span — what's left should not
        # contain a long base64url-looking run.
        stripped = re.sub(r'value="[^"]*"', 'value=""', html)
        # Find runs of base64url characters of length ≥ 32 in the
        # stripped HTML.
        leaks = re.findall(r"[A-Za-z0-9_\-]{32,}", stripped)
        # Filter out the obvious DOM noise (IDs, style classes).
        # ``_waf_js_touch_input`` is the only legitimate >20-char id.
        non_dom = [s for s in leaks if not s.startswith("_waf_") and "waf_" not in s]
        assert non_dom == [], f"Token-shaped strings leaking outside value attributes: {non_dom!r}"

    def test_end_to_end_pass_with_full_defence_chain(self, settings):
        """Full chain: render → parse → submit → PASS.

        Renders a form with every defence that contributes a hidden
        input, parses the DOM, builds a POST from those exact inputs
        (simulating a browser that ran the JS solvers), and asserts
        the orchestrator returns PASSED.

        This is the test that would have caught the v0.11.0 bug
        before release.
        """
        import hashlib

        import django_waf.conf as conf_mod
        from django_waf.forms.protection import FormProtection, FormVerdict
        from django_waf.services.challenge_service import (
            _digest_has_leading_zero_bits,
        )

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            # Drop js_touch from the chain — the simulated 'browser'
            # below can't actually execute the inline <script>, so we
            # focus this end-to-end test on the defences that have a
            # deterministic server-verifiable contract. js_touch is
            # covered by its own unit tests.
            protection = FormProtection(
                form_id="contact",
                defences=("render_token", "honeypot", "pow_gate"),
                redis_client_factory=lambda: _redis(),
            )
            fields = protection.render_fields(_request())
            html = "".join(fields[k] for k in sorted(fields))

            # Parse the DOM exactly as a browser would.
            submitted = _parse_inputs(html)

            # The browser-equivalent runs the PoW solver. Compute a
            # valid nonce server-side at test time so the simulated
            # POST is what a real browser would have produced.
            from django_waf.forms.defences.pow_gate import NONCE_FIELD

            token_nonce = submitted["waf_pow_token"]
            difficulty = conf_mod.DJANGO_WAF_FORM_POW_DIFFICULTY
            for n in range(1_000_000):
                msg = f"{token_nonce}:{n}".encode()
                if _digest_has_leading_zero_bits(hashlib.sha256(msg).digest(), difficulty):
                    submitted[NONCE_FIELD] = str(n)
                    break
            else:  # pragma: no cover
                raise AssertionError("could not solve PoW in 1M iterations")

            # Submit.
            result = protection.evaluate(_request(), submitted_data=submitted)

        assert result.verdict == FormVerdict.PASSED, (
            f"expected PASSED, got {result.verdict.value} "
            f"with outcomes: {[(o.verdict, o.reason) for o in result.outcomes]}"
        )
