"""{% waf_protect %} template tag.

Used in templates whose form bypasses Django's Form layer (the
handwritten-HTML case). Pairs with the ``waf_protect_post`` decorator
on the view::

    # views.py
    @waf_protect_post(form_id='contact-handwritten')
    def contact_view(request):
        ...

    # contact.html
    <form method="post">
      {% csrf_token %}
      {% load waf_form_tags %}
      {% waf_protect form_id='contact-handwritten' %}
      <input type="text" name="email">
      ...
    </form>

The tag looks up the FormProtection that the decorator constructed
(keyed by form_id) and renders its hidden fields. If no matching
decorator has run, the tag renders nothing — so a template typo
doesn't crash the page, it just fails silently (and the logged
``no FormProtection found`` warning surfaces in dev).

Per PRD §2.1 (entry-point C).
"""

from __future__ import annotations

import logging

from django import template
from django.utils.safestring import SafeString, mark_safe

from icv_waf.forms.decorators import _registry_get

logger = logging.getLogger("icv_waf.forms")
register = template.Library()


@register.simple_tag(takes_context=True)
def waf_protect(context, form_id: str) -> SafeString:
    """Render the WAF's hidden fields for a handwritten HTML form.

    ``form_id`` must match the value passed to ``waf_protect_post`` on
    the view that handles this template's submissions.
    """
    protection = _registry_get(form_id)
    if protection is None:
        # The decorator hasn't been imported yet, or the form_id is
        # mis-typed. Log + render nothing — surface in dev via the
        # logger, never crash production.
        logger.warning(
            "icv-waf: {%% waf_protect form_id=%r %%} called but no "
            "FormProtection is registered. Did you forget the "
            "@waf_protect_post decorator?",
            form_id,
        )
        return mark_safe("")  # noqa: S308 — empty string is XSS-safe

    request = context.get("request")
    if request is None:
        logger.warning(
            "icv-waf: {%% waf_protect %%} requires 'request' in the template context. Ensure RequestContext is in use."
        )
        return mark_safe("")  # noqa: S308

    fields = protection.render_fields(request)
    html = "".join(fields[k] for k in sorted(fields))
    return mark_safe(html)  # noqa: S308 — each fragment is already SafeString
