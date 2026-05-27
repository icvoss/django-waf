"""Tests for ProtectedForm mixin.

The mixin's job is small: wire the orchestrator to Django Form's
lifecycle. These tests pin the contract (request kwarg required,
clean raises on BLOCKED, waf_result available on FLAGGED, waf_fields
renders).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from django import forms
from django.core.exceptions import ImproperlyConfigured


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


def _request():
    req = MagicMock()
    req.META = {"REMOTE_ADDR": "1.2.3.4", "HTTP_USER_AGENT": "Mozilla/5.0"}
    req.user = MagicMock(is_authenticated=False)
    return req


# ---------------------------------------------------------------------------
# Subclass-time enforcement
# ---------------------------------------------------------------------------


class TestSubclassEnforcement:
    def test_missing_waf_attribute_raises(self):
        """A subclass without `waf` must raise at class-definition time."""
        from icv_waf.forms.mixin import ProtectedForm

        with pytest.raises(ImproperlyConfigured, match="`waf` attribute"):

            class Bad(ProtectedForm, forms.Form):
                pass


# ---------------------------------------------------------------------------
# Construction contract
# ---------------------------------------------------------------------------


class TestConstruction:
    def _build_form_class(self):
        """Build a ContactForm with a real FormProtection wired up."""
        from icv_waf.forms.mixin import ProtectedForm
        from icv_waf.forms.protection import FormProtection

        redis = _redis()

        class ContactForm(ProtectedForm, forms.Form):
            name = forms.CharField()
            waf = FormProtection(
                form_id="contact",
                defences=("honeypot",),
                redis_client_factory=lambda: redis,
            )

        return ContactForm, redis

    def test_missing_request_kwarg_raises(self):
        ContactForm, _ = self._build_form_class()

        with pytest.raises(ImproperlyConfigured, match="request"):
            ContactForm(data={"name": "alice"})

    def test_request_kwarg_stored(self):
        ContactForm, _ = self._build_form_class()
        req = _request()

        form = ContactForm(data={"name": "alice"}, request=req)
        assert form._waf_request is req


# ---------------------------------------------------------------------------
# waf_fields rendering
# ---------------------------------------------------------------------------


class TestWafFields:
    def test_renders_honeypot_html(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.mixin import ProtectedForm
        from icv_waf.forms.protection import FormProtection

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            redis = _redis()

            class ContactForm(ProtectedForm, forms.Form):
                name = forms.CharField(required=False)
                waf = FormProtection(
                    form_id="c",
                    defences=("honeypot",),
                    redis_client_factory=lambda: redis,
                )

            form = ContactForm(request=_request())
            html = form.waf_fields

        assert "<input" in html
        assert "position:absolute" in html

    def test_renders_empty_when_master_switch_off(self, settings):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.mixin import ProtectedForm
        from icv_waf.forms.protection import FormProtection

        with (
            patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"),
            patch.object(conf_mod, "ICV_WAF_FORM_PROTECTION_ENABLED", False),
        ):
            redis = _redis()

            class ContactForm(ProtectedForm, forms.Form):
                waf = FormProtection(
                    form_id="c",
                    defences=("honeypot",),
                    redis_client_factory=lambda: redis,
                )

            form = ContactForm(request=_request())
            assert form.waf_fields == ""


# ---------------------------------------------------------------------------
# clean() verdict dispatch
# ---------------------------------------------------------------------------


class TestClean:
    def _form_class(self, defences=("honeypot",)):
        from icv_waf.forms.mixin import ProtectedForm
        from icv_waf.forms.protection import FormProtection

        # Patch is applied by callers; the form needs a signing key
        # to render or evaluate render_token.
        redis = _redis()

        class TestForm(ProtectedForm, forms.Form):
            name = forms.CharField()
            waf = FormProtection(
                form_id="c",
                defences=defences,
                redis_client_factory=lambda: redis,
            )

        return TestForm, redis

    def test_blocked_verdict_raises_validation_error(self, settings):
        """Honeypot field filled → BLOCKED → ValidationError on clean."""
        import icv_waf.conf as conf_mod

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            ContactForm, _ = self._form_class()
            # Find the honeypot field name and fill it.
            from icv_waf.forms.defences.honeypot import _pick_field_names

            honeypot_name = _pick_field_names("c", conf_mod.ICV_WAF_FORM_HONEYPOT_FIELD_NAMES, 2)[0]

            form = ContactForm(
                data={"name": "alice", honeypot_name: "spam"},
                request=_request(),
            )
            assert form.is_valid() is False
            # The non-field errors should mention the generic message.
            non_field = form.non_field_errors()
            assert any("rejected" in str(e).lower() for e in non_field)

    def test_passed_verdict_validates_normally(self, settings):
        """Clean honeypot → no validation error from the mixin."""
        import icv_waf.conf as conf_mod

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            ContactForm, _ = self._form_class()

            form = ContactForm(data={"name": "alice"}, request=_request())
            assert form.is_valid()

    def test_waf_result_populated_after_clean(self, settings):
        """The view code reads form.waf_result to decide on FLAGGED handling."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.protection import FormVerdict

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            ContactForm, _ = self._form_class()
            form = ContactForm(data={"name": "alice"}, request=_request())
            form.is_valid()  # triggers clean

        assert form.waf_result is not None
        assert form.waf_result.verdict == FormVerdict.PASSED

    def test_blocked_message_does_not_leak_defence_name(self, settings):
        """Pin enumeration-safety: the user-visible message must not
        say WHICH defence fired. Operators see the detail in the log."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.defences.honeypot import _pick_field_names

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            ContactForm, _ = self._form_class()
            honeypot = _pick_field_names("c", conf_mod.ICV_WAF_FORM_HONEYPOT_FIELD_NAMES, 2)[0]
            form = ContactForm(data={"name": "alice", honeypot: "spam"}, request=_request())
            form.is_valid()

            for err in form.non_field_errors():
                # No defence name should appear in the user-facing message.
                for name in (
                    "honeypot",
                    "render_token",
                    "time_trap",
                    "ua_consistency",
                    "js_touch",
                    "credential_throttle",
                    "signup_velocity",
                    "pow_gate",
                ):
                    assert name not in str(err)


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------


class TestPublicExports:
    def test_public_api_surface(self):
        """The top-level package exposes the documented entry points."""
        import icv_waf.forms as forms_pkg

        # Names match PRD §2.3 and the public API table.
        for name in (
            "FormProtection",
            "FormVerdict",
            "FormEvaluationResult",
            "ProtectedForm",
            "form_submission_passed",
            "form_submission_flagged",
            "form_submission_blocked",
            "credential_attack_observed",
        ):
            assert hasattr(forms_pkg, name), f"icv_waf.forms missing public name {name!r}"
