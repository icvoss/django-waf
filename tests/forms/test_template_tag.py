"""Tests for the {% waf_protect %} template tag."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.template import Context, Template
from django.test import RequestFactory


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request():
    rf = RequestFactory()
    request = rf.get("/")
    request.user = MagicMock(is_authenticated=False)
    return request


class TestWafProtectTag:
    def test_renders_protection_fields_when_form_id_registered(self, settings):
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import waf_protect_post

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-tag-renders",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                pass

            tpl = Template("{% load waf_form_tags %}{% waf_protect form_id='contact-tag-renders' %}")
            html = tpl.render(Context({"request": _request()}))

        assert "<input" in html
        assert "position:absolute" in html

    def test_renders_empty_when_form_id_unknown(self):
        """Missing decorator → empty string + log warning, never a crash."""
        tpl = Template("{% load waf_form_tags %}{% waf_protect form_id='never-registered' %}")
        html = tpl.render(Context({"request": _request()}))

        assert html == ""

    def test_renders_empty_when_request_missing_from_context(self, settings):
        """Tag needs request in context — if absent, fail safe (empty)."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import waf_protect_post

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-tag-no-request",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                pass

            tpl = Template("{% load waf_form_tags %}{% waf_protect form_id='contact-tag-no-request' %}")
            html = tpl.render(Context({}))  # No 'request' key

        assert html == ""
