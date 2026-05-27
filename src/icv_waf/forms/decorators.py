"""View decorator for the form-protection orchestrator.

Pairs with the ``{% waf_protect %}`` template tag for forms that
don't go through Django's Form layer (handwritten HTML). The
decorator validates POSTs; the tag renders the hidden fields.

The mixin (block 5) handles Django Forms — that's the recommended
path. The decorator exists because some sites have hand-rolled HTML
forms that bypass the Form layer, and they still need protection.

Per PRD §2.1 (entry-point B).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from functools import wraps
from typing import Any

from django.http import HttpResponse

from icv_waf.forms.logging import log_form_submission
from icv_waf.forms.protection import (
    FormProtection,
    FormVerdict,
)

logger = logging.getLogger("icv_waf.forms")


# Registry of FormProtection objects keyed by form_id so the template
# tag can find the same instance the decorator constructed. Populated
# at decoration time (import time, effectively).
_PROTECTIONS: dict[str, FormProtection] = {}


def _registry_get(form_id: str) -> FormProtection | None:
    return _PROTECTIONS.get(form_id)


def _registry_set(form_id: str, protection: FormProtection) -> None:
    # Allow re-registration (e.g. tests construct the same form_id
    # repeatedly). Last decoration wins.
    _PROTECTIONS[form_id] = protection


def waf_protect_post(
    *,
    form_id: str,
    defences: tuple[str, ...] = ("render_token", "honeypot", "time_trap"),
    **protection_kwargs: Any,
) -> Callable:
    """Wrap a view so POST requests run through the form-protection chain.

    Usage::

        @waf_protect_post(form_id='contact-handwritten',
                          defences=('honeypot', 'time_trap'))
        def contact_view(request):
            ...

    The decorator:

    1. On import, constructs a FormProtection and registers it in the
       per-form_id registry so the template tag can find it.
    2. On each POST, runs ``protection.evaluate(request, request.POST)``
       before the view sees the request.
    3. On BLOCKED, returns 403 with the generic message (enumeration
       safety — no defence name in the response).
    4. On PASSED, calls the view, then consumes the token marker.
    5. On FLAGGED, calls the view. The challenge-redirect flow lands
       in block 7; until then, FLAGGED views run normally — operators
       see the verdict in logs and can act on it themselves.
    6. GET requests pass through untouched (defences only run on
       POST; render happens via the template tag).
    """
    protection = FormProtection(
        form_id=form_id,
        defences=defences,
        **protection_kwargs,
    )
    _registry_set(form_id, protection)

    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request, *args, **kwargs):
            if request.method != "POST":
                return view_func(request, *args, **kwargs)

            result = protection.evaluate(request, submitted_data=dict(request.POST))

            # Structured log — happens regardless of verdict so logs
            # always reflect the chain's verdict.
            log_form_submission(form_id=form_id, request=request, result=result)

            if result.verdict == FormVerdict.BLOCKED:
                # 403 + generic body. Operators see detail in the log.
                # Returning HttpResponse rather than HttpResponseForbidden
                # so we control the body shape exactly.
                response = HttpResponse(
                    "Submission rejected. Please try again.",
                    status=403,
                )
                _maybe_attach_debug_header(response, form_id, result)
                return response

            # PASSED or FLAGGED → call the view. The view-author
            # decides what to do with FLAGGED (consult
            # request.waf_form_result). Block 7 will introduce
            # automatic challenge redirect on FLAGGED.
            request.waf_form_result = result
            response = view_func(request, *args, **kwargs)
            _maybe_attach_debug_header(response, form_id, result)

            # Consume the token marker only on PASSED.
            if result.verdict == FormVerdict.PASSED:
                protection.consume_token_marker(result.token_payload)

            return response

        return wrapper

    return decorator


def _maybe_attach_debug_header(response, form_id: str, result) -> None:
    """In DEBUG, attach X-WAF-Form-Verdict for development convenience.

    Off in production (DEBUG=False). Lets developers see why a form
    blocked without grepping logs. Per PRD §9.2.
    """
    from django.conf import settings

    if not getattr(settings, "DEBUG", False):
        return

    defence_names = (
        ",".join(
            outcome.reason.split(":", 1)[0]
            for outcome in result.outcomes
            if outcome.verdict in ("flag", "block") and ":" in outcome.reason
        )
        or "none"
    )
    response["X-WAF-Form-Verdict"] = (
        f"{result.verdict.value}; score={result.total_score:.1f}; defences={defence_names}; form_id={form_id}"
    )
