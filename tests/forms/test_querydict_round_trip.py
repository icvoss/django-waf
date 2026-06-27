"""Real-browser-shaped tests: defences see a Django QueryDict, not a dict.

The v0.11.0 + v0.11.1 production bugs both passed every unit test
because the tests constructed POST data as plain Python dicts. Real
Django form submissions arrive with ``request.POST`` as a
``QueryDict`` — and ``dict(QueryDict)`` produces list-valued entries
that crash the defence chain.

These tests exercise the mixin and decorator with **real
QueryDicts**, going through ``RequestFactory.post(...)`` for the
decorator path and binding the form to a real ``request.POST`` for
the mixin path. They reproduce the production failure mode and pin
it shut.
"""

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
from unittest.mock import MagicMock, patch

from django import forms
from django.http import QueryDict
from django.test import RequestFactory

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _InputCollector(HTMLParser):
    """Browser-equivalent input extractor — name → value for every <input>."""

    def __init__(self) -> None:
        super().__init__()
        self.inputs: list[tuple[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "input":
            return
        d = dict(attrs)
        name = d.get("name")
        if not name:
            return
        self.inputs.append((name, d.get("value", "") or ""))


def _parse_inputs(html: str) -> dict[str, str]:
    parser = _InputCollector()
    parser.feed(html)
    out: dict[str, str] = {}
    for name, value in parser.inputs:
        out.setdefault(name, value)
    return out


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _solve_pow(token_nonce: str, difficulty: int) -> str:
    """Match the JS solver's hash construction; return a valid nonce."""
    from django_waf.services.challenge_service import _digest_has_leading_zero_bits

    for n in range(1_000_000):
        msg = f"{token_nonce}:{n}".encode()
        if _digest_has_leading_zero_bits(hashlib.sha256(msg).digest(), difficulty):
            return str(n)
    raise AssertionError("could not solve PoW")


# ---------------------------------------------------------------------------
# scalarise_submitted_data — the helper itself
# ---------------------------------------------------------------------------


class TestScalariseSubmittedData:
    def test_querydict_returns_last_value_per_key(self):
        """The bug-fix contract: QueryDict → last-value-per-key strings."""
        from django_waf.forms.protection import scalarise_submitted_data

        qd = QueryDict("waf_token=abc&name=jane&color=red&color=blue")
        out = scalarise_submitted_data(qd)

        assert out["waf_token"] == "abc"
        assert out["name"] == "jane"
        # QueryDict.dict() returns the LAST value per key.
        assert out["color"] == "blue"
        # No list values anywhere.
        assert all(isinstance(v, str) for v in out.values())

    def test_plain_dict_passes_through(self):
        """Tests pass plain dicts; the helper must round-trip them
        without imposing QueryDict semantics."""
        from django_waf.forms.protection import scalarise_submitted_data

        plain = {"waf_token": "abc", "name": "jane"}
        out = scalarise_submitted_data(plain)

        assert out == plain
        # Not the same object — the helper returns a copy so callers
        # can mutate freely.
        assert out is not plain

    def test_none_returns_empty(self):
        """Defensive: an unbound form (data=None) returns {}."""
        from django_waf.forms.protection import scalarise_submitted_data

        assert scalarise_submitted_data(None) == {}

    def test_does_not_lose_waf_token_value(self):
        """Pin the actual production failure mode: a QueryDict
        containing a base64url waf_token must scalarise to that exact
        string, not [string], so the defence's b64decode succeeds."""
        from django_waf.forms.protection import scalarise_submitted_data

        token = "Y29udGFjdHwxLjIuMy40fHwyMDI2LTA1LTI3VDE1OjMyOjA0LjE5ODY0Ny"
        qd = QueryDict(f"waf_token={token}&name=jane")
        out = scalarise_submitted_data(qd)

        assert out["waf_token"] == token
        # Not a list — this is what crashed in production.
        assert not isinstance(out["waf_token"], list)


# ---------------------------------------------------------------------------
# ProtectedForm mixin — bound to a real QueryDict
# ---------------------------------------------------------------------------


def _build_form_class(form_id, defences):
    """Build a ContactForm with the given defence chain."""
    from django_waf.forms.mixin import ProtectedForm
    from django_waf.forms.protection import FormProtection

    redis = _redis()

    class ContactForm(ProtectedForm, forms.Form):
        name = forms.CharField(required=False)
        waf = FormProtection(
            form_id=form_id,
            defences=defences,
            redis_client_factory=lambda: redis,
        )

    return ContactForm


class TestMixinWithQueryDict:
    """The mixin path: Form(request.POST, request=request)."""

    def _bound_request(self, post_data):
        rf = RequestFactory()
        request = rf.post("/contact/", data=post_data)
        request.user = MagicMock(is_authenticated=False)
        return request

    def test_clean_does_not_raise_on_querydict_post(self, settings):
        """Pin the production traceback: Form bound to a real QueryDict
        runs through clean() without TypeError.

        Pre-v0.11.2 this crashed at verify_token with
        ``TypeError: can only concatenate list (not "str") to list``
        because dict(QueryDict) put the token in a list.
        """
        import django_waf.conf as conf_mod

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            ContactForm = _build_form_class("contact-querydict-noraise", ("render_token", "honeypot"))

            # Render to get a real token.
            req = self._bound_request({})  # empty POST just to get a request shape
            form_for_render = ContactForm(request=req)
            inputs = _parse_inputs(form_for_render.waf_fields)

            # Build the submission via a real Django QueryDict (what
            # request.POST is in production).
            request = self._bound_request({"name": "alice", "waf_token": inputs["waf_token"]})
            form = ContactForm(request.POST, request=request)

            # Pre-fix: TypeError. Post-fix: form validates.
            assert form.is_valid(), f"form failed to validate: {form.errors!r}"

    def test_clean_returns_passed_verdict(self, settings):
        """Same as above but assert the verdict explicitly."""
        import django_waf.conf as conf_mod
        from django_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            ContactForm = _build_form_class("contact-querydict-passed", ("render_token", "honeypot"))
            req = self._bound_request({})
            inputs = _parse_inputs(ContactForm(request=req).waf_fields)

            request = self._bound_request({"name": "alice", "waf_token": inputs["waf_token"]})
            form = ContactForm(request.POST, request=request)
            form.is_valid()

        assert form.waf_result is not None
        assert form.waf_result.verdict == FormVerdict.PASSED
        # And the token payload is verified — proof the defences saw
        # the scalar token, not [token].
        assert form.waf_result.token_payload is not None

    def test_clean_with_full_chain_including_pow(self, settings):
        """End-to-end with PoW: render → solve → submit via QueryDict → PASS."""
        import django_waf.conf as conf_mod
        from django_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            ContactForm = _build_form_class("contact-qd-full", ("render_token", "honeypot", "pow_gate"))
            req = self._bound_request({})
            inputs = _parse_inputs(ContactForm(request=req).waf_fields)

            # Browser-equivalent: solve the PoW.
            nonce = _solve_pow(inputs["waf_pow_token"], conf_mod.DJANGO_WAF_FORM_POW_DIFFICULTY)

            # Build the QueryDict the browser would send.
            request = self._bound_request(
                {
                    "name": "alice",
                    "waf_token": inputs["waf_token"],
                    "waf_pow_token": inputs["waf_pow_token"],
                    "waf_pow_nonce": nonce,
                }
            )
            form = ContactForm(request.POST, request=request)
            assert form.is_valid(), f"errors: {form.errors!r}"

        assert form.waf_result.verdict == FormVerdict.PASSED


# ---------------------------------------------------------------------------
# Decorator — request.POST is a real QueryDict
# ---------------------------------------------------------------------------


class TestDecoratorWithQueryDict:
    """The decorator path: @waf_protect_post handles the QueryDict."""

    def test_post_via_request_factory_does_not_raise(self, settings):
        """RequestFactory.post() puts a real QueryDict on request.POST.

        Pre-v0.11.2 the decorator's dict(request.POST) produced list
        values that crashed in render_token.evaluate. Post-fix the
        decorator scalarises before passing to the orchestrator.
        """
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import _registry_get, waf_protect_post

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-decorator-qd",
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                from django.http import HttpResponse

                # If we reach here, the chain didn't crash.
                return HttpResponse(f"verdict={request.waf_form_result.verdict.value}")

            # Render first to get a valid token (via direct render_fields).
            protection = _registry_get("contact-decorator-qd")
            rf = RequestFactory()
            render_req = rf.get("/contact/")
            render_req.user = MagicMock(is_authenticated=False)
            fields = protection.render_fields(render_req)
            inputs = _parse_inputs("".join(fields[k] for k in sorted(fields)))

            # POST as a browser would.
            request = rf.post(
                "/contact/",
                data={"name": "alice", "waf_token": inputs["waf_token"]},
            )
            request.user = MagicMock(is_authenticated=False)
            response = view(request)

        # No crash; view ran; verdict was PASSED (not BLOCKED).
        assert response.status_code == 200
        assert b"verdict=passed" in response.content

    def test_post_via_django_test_client_does_not_raise(self, settings, client):
        """The most realistic shape: Django ``Client.post()`` through the
        full middleware stack, with sessions, CSRF, etc.

        Needs an actual URL wired in. We register one inline via the
        decorator + ``override_settings(ROOT_URLCONF=...)`` so this
        test stands alone without polluting tests/urls.py.
        """
        from django.test import override_settings
        from django.urls import path

        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import _registry_get, waf_protect_post

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-djclient",
                defences=("render_token", "honeypot"),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                from django.http import HttpResponse

                if request.method == "POST":
                    return HttpResponse(f"verdict={request.waf_form_result.verdict.value}")
                return HttpResponse("get-ok")

            url_patterns = [path("contact/", view, name="contact-djclient")]

            with override_settings(ROOT_URLCONF=type("M", (), {"urlpatterns": url_patterns})):
                # Get the form to render and grab a valid token.
                protection = _registry_get("contact-djclient")
                rf = RequestFactory()
                render_req = rf.get("/contact/")
                render_req.user = MagicMock(is_authenticated=False)
                inputs = _parse_inputs(
                    "".join(
                        protection.render_fields(render_req)[k] for k in sorted(protection.render_fields(render_req))
                    )
                )

                # POST through the real test client — this is exactly
                # what a browser does. request.POST will be a real
                # QueryDict here.
                response = client.post(
                    "/contact/",
                    data={"name": "alice", "waf_token": inputs["waf_token"]},
                )

        # Critical: no 500. Pre-v0.11.2 this would 500 with a TypeError.
        assert response.status_code != 500, f"500 from QueryDict crash: {response.content.decode()[:200]}"
        assert response.status_code == 200
        assert b"verdict=passed" in response.content
