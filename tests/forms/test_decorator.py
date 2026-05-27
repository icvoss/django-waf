"""Tests for the waf_protect_post view decorator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import RequestFactory


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _factory_with_user():
    rf = RequestFactory()
    return rf


def _build_request(method, path, post=None):
    rf = _factory_with_user()
    if method == "POST":  # noqa: SIM108 — explicit branch reads clearer than nested ternary
        request = rf.post(path, data=post or {})
    else:
        request = rf.get(path)
    request.user = MagicMock(is_authenticated=False)
    return request


# ---------------------------------------------------------------------------
# Decorator behaviour
# ---------------------------------------------------------------------------


class TestDecorator:
    def test_get_request_passes_through(self):
        """GET requests don't trigger defence evaluation — render is
        the template tag's job, not the decorator's."""
        from icv_waf.forms.decorators import waf_protect_post

        @waf_protect_post(
            form_id="contact-get-test",
            defences=("honeypot",),
            redis_client_factory=lambda: _redis(),
        )
        def view(request):
            return MagicMock(status_code=200)

        request = _build_request("GET", "/contact/")
        response = view(request)

        assert response.status_code == 200

    def test_clean_post_calls_view(self, settings):
        """Honeypot empty → PASSED → view runs."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.decorators import waf_protect_post

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-clean-post",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                response = MagicMock()
                response.status_code = 200
                response.__setitem__ = lambda self, k, v: None
                return response

            request = _build_request("POST", "/contact/", post={"name": "alice"})
            response = view(request)

        assert response.status_code == 200

    def test_blocked_post_returns_403(self, settings):
        """Filled honeypot → BLOCKED → 403, view not called."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.decorators import waf_protect_post
        from icv_waf.forms.defences.honeypot import _pick_field_names

        view_called = MagicMock()

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            form_id = "contact-blocked-post"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                view_called()
                return MagicMock(status_code=200)

            honeypot = _pick_field_names(form_id, conf_mod.ICV_WAF_FORM_HONEYPOT_FIELD_NAMES, 2)[0]
            request = _build_request("POST", "/contact/", post={honeypot: "spam"})
            response = view(request)

        assert response.status_code == 403
        view_called.assert_not_called()
        # Generic body, no defence name leaked.
        body = response.content.decode()
        assert "honeypot" not in body
        assert "rejected" in body.lower()

    def test_decorator_registers_form_id_in_registry(self, settings):
        """The template tag needs to find the FormProtection by form_id."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.decorators import _registry_get, waf_protect_post

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-registry-test",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                return MagicMock(status_code=200)

        assert _registry_get("contact-registry-test") is not None
        assert _registry_get("not-registered") is None


# ---------------------------------------------------------------------------
# X-WAF-Form-Verdict debug header
# ---------------------------------------------------------------------------


class TestDebugHeader:
    def test_header_attached_in_debug(self, settings):
        from django.http import HttpResponse

        import icv_waf.conf as conf_mod
        from icv_waf.forms.decorators import waf_protect_post

        settings.DEBUG = True

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-debug-header",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                return HttpResponse("ok")

            request = _build_request("POST", "/contact/", post={})
            response = view(request)

        # Header present, format pinned.
        assert "X-WAF-Form-Verdict" in response
        assert "passed" in response["X-WAF-Form-Verdict"]
        assert "form_id=contact-debug-header" in response["X-WAF-Form-Verdict"]

    def test_header_absent_in_production(self, settings):
        from django.http import HttpResponse

        import icv_waf.conf as conf_mod
        from icv_waf.forms.decorators import waf_protect_post

        settings.DEBUG = False

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-prod-header",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                return HttpResponse("ok")

            request = _build_request("POST", "/contact/", post={})
            response = view(request)

        assert "X-WAF-Form-Verdict" not in response
