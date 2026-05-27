"""ProtectedForm mixin — Django Form integration for the orchestrator.

Subclasses declare a class-level ``waf = FormProtection(...)``. The
mixin wires the orchestrator into the Django form lifecycle:

* on instantiation, captures the bound request so ``clean()`` can run
  the defences,
* exposes ``waf_fields`` for the template to render the protected
  hidden inputs,
* in ``clean()``, runs the defence chain against ``self.data`` and
  raises ``ValidationError`` on BLOCKED. FLAGGED is exposed via
  ``self.waf_result`` so the view can decide whether to redirect
  through the challenge flow.

The mixin does NOT do the challenge redirect itself — that's a view
concern, handled by block 6's decorator (and block 7's replay flow).
Keeping the mixin scoped to form validation means it composes with
any view, including class-based generic views.

Per PRD §2.1 (entry-point A) and §6 (verdict actions).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, ClassVar

from django import forms
from django.core.exceptions import ImproperlyConfigured

if TYPE_CHECKING:  # pragma: no cover
    from icv_waf.forms.protection import FormEvaluationResult, FormProtection


logger = logging.getLogger("icv_waf.forms")


# Generic ValidationError message shown on BLOCKED. Deliberately
# uninformative — telling an attacker exactly which defence fired
# would help them tune around it. Operators see the structured log
# for the details (block 6).
_BLOCKED_MESSAGE = "Submission rejected. Please try again."


class ProtectedForm:
    """Django Form mixin that runs WAF defences during clean().

    Usage::

        from django import forms
        from icv_waf.forms import FormProtection, ProtectedForm

        class ContactForm(ProtectedForm, forms.Form):
            name = forms.CharField()
            email = forms.EmailField()
            message = forms.CharField(widget=forms.Textarea)

            waf = FormProtection(
                form_id="contact",
                defences=("render_token", "honeypot", "time_trap"),
            )

    Then in the view::

        form = ContactForm(request.POST, request=request)

    The mixin requires the ``request`` kwarg because defences need
    access to ``request.META`` and ``request.user``. Forgetting to
    pass it is a constructive error (raised at form instantiation),
    not a silent fail-open.
    """

    # Subclasses MUST declare this.
    waf: ClassVar[FormProtection]

    # Populated by clean(); the view inspects this to decide whether
    # to challenge or accept.
    waf_result: FormEvaluationResult | None = None

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        # Pin the contract at class-definition time: subclasses must
        # declare a `waf` attribute. We don't enforce the type
        # strictly (duck-typing keeps tests trivial) but the attribute
        # must exist.
        if not hasattr(cls, "waf") or cls.waf is None:
            raise ImproperlyConfigured(
                f"{cls.__name__} subclasses ProtectedForm but has no `waf` "
                "attribute. Declare one with: waf = FormProtection(form_id='...')"
            )

    def __init__(self, *args: Any, request: Any = None, **kwargs: Any) -> None:
        """Accept a ``request`` kwarg in addition to Django's standard ones.

        Stored on the instance so ``clean()`` and template rendering
        can reach it without the consumer threading the request
        everywhere.
        """
        if request is None:
            raise ImproperlyConfigured(
                f"{type(self).__name__} requires the `request` kwarg. "
                "Construct as `Form(request.POST or None, request=request)`."
            )
        self._waf_request = request
        super().__init__(*args, **kwargs)

    # ------------------------------------------------------------------
    # Template hook
    # ------------------------------------------------------------------

    @property
    def waf_fields(self) -> str:
        """Concatenated HTML for the WAF's hidden inputs.

        Render once in the form template::

            <form method="post">
                {% csrf_token %}
                {{ form.waf_fields }}
                {{ form.as_p }}
                ...
            </form>

        Marked safe in each defence; concatenation here preserves
        that. The mixin is the only place that decides ordering of
        fragments, so the rendered DOM is deterministic.
        """
        from django.utils.safestring import mark_safe

        fields = self.waf.render_fields(self._waf_request)
        # Sort keys for deterministic output — eases testing and
        # cache-key stability on HTMX re-renders.
        html = "".join(fields[k] for k in sorted(fields))
        return mark_safe(html)  # noqa: S308 — each fragment is already SafeString

    # ------------------------------------------------------------------
    # Validation hook
    # ------------------------------------------------------------------

    def clean(self) -> dict[str, Any]:
        """Run the defence chain alongside the form's normal validation.

        The mixin's clean() must run after the field-level clean(s) so
        ``self.data`` and ``self.cleaned_data`` are both populated for
        any defences that care to consult them. We call ``super().clean()``
        first to let Django's normal validation populate ``cleaned_data``.
        """
        cleaned = super().clean() if hasattr(super(), "clean") else None
        if cleaned is None:
            cleaned = getattr(self, "cleaned_data", {}) or {}

        # Run the orchestrator against the raw POST data — defences
        # read their own hidden fields by name, not the cleaned form
        # fields.
        result = self.waf.evaluate(
            self._waf_request,
            submitted_data=dict(self.data),
        )
        self.waf_result = result

        # The view code decides what to do with FLAGGED (challenge
        # redirect vs. plain rejection). The mixin only raises on
        # BLOCKED, which terminates form validation outright.
        from icv_waf.forms.protection import FormVerdict

        if result.verdict == FormVerdict.BLOCKED:
            # Don't reveal which defence blocked. Operators consult
            # the structured log (block 6) for the detail.
            raise forms.ValidationError(_BLOCKED_MESSAGE, code="waf_blocked")

        return cleaned
