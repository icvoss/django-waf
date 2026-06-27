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

from django_waf.forms.logging import log_form_submission
from django_waf.forms.protection import (
    FormProtection,
    FormVerdict,
)

logger = logging.getLogger("django_waf.forms")


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
            # Challenge-replay: GET with ?form_replay=<token> means the
            # user just passed the WAF challenge after a FLAGGED submit.
            # Re-issue the original POST from the session.
            if request.method == "GET" and request.GET.get("form_replay"):
                replayed = _try_replay(request, form_id=form_id)
                if replayed is not None:
                    request = replayed  # falls through to the POST branch
                    # Need to actually invoke the post-handling path:
                    return _handle_post(request, view_func, args, kwargs, form_id, protection)

            if request.method != "POST":
                return view_func(request, *args, **kwargs)

            return _handle_post(request, view_func, args, kwargs, form_id, protection)

        return wrapper

    return decorator


def _handle_post(request, view_func, args, kwargs, form_id, protection):
    """Run the protection chain and dispatch the verdict.

    Extracted from the wrapper so the GET-replay path can reuse it
    without duplicating the verdict logic.
    """
    # Scalarise via ``scalarise_submitted_data`` — see protection.py
    # for the rationale. ``dict(request.POST)`` would produce list
    # values that crash the defence chain.
    from django_waf.forms.protection import scalarise_submitted_data

    result = protection.evaluate(
        request,
        submitted_data=scalarise_submitted_data(request.POST),
    )

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

    if result.verdict == FormVerdict.FLAGGED:
        challenge_response = _maybe_redirect_to_challenge(request=request, form_id=form_id, result=result)
        if challenge_response is not None:
            _maybe_attach_debug_header(challenge_response, form_id, result)
            return challenge_response
        # Challenge redirect disabled or unavailable → fall
        # through to view. The view-author can still inspect
        # request.waf_form_result.

    # PASSED or FLAGGED-without-challenge → call the view.
    request.waf_form_result = result
    response = view_func(request, *args, **kwargs)
    _maybe_attach_debug_header(response, form_id, result)

    # Consume the token marker only on PASSED.
    if result.verdict == FormVerdict.PASSED:
        protection.consume_token_marker(result.token_payload)

    return response


def _try_replay(request, *, form_id: str):
    """Detect a valid form_replay token on a GET; return a request
    mutated to look like the original POST.

    Returns ``None`` if no valid replay is available (token missing,
    malformed, expired, IP mismatch, session missing, or session
    record gone). The caller falls back to normal GET handling.

    The mutation copies the original POST into request.POST and
    discards the session record so the replay can't be re-used.
    """
    from django.http import QueryDict

    from django_waf.forms.services.replay import (
        discard_from_session,
        fetch_from_session,
        verify_replay_token,
    )

    raw_token = request.GET.get("form_replay", "")
    current_ip = request.META.get("REMOTE_ADDR", "")
    payload = verify_replay_token(raw_token, current_ip=current_ip)
    if payload is None or payload.get("form_id") != form_id:
        return None

    record = fetch_from_session(request, session_key=payload["session_key"])
    if record is None or record.get("form_id") != form_id:
        return None

    # Convert stored dict back into a QueryDict for compatibility
    # with code that reads request.POST as Django's MultiValueDict.
    qd = QueryDict(mutable=True)
    for k, v in record.get("data", {}).items():
        if isinstance(v, list):
            qd.setlist(k, v)
        else:
            qd[k] = v
    qd._mutable = False
    request.POST = qd
    request.method = "POST"

    # One-shot — discard so a replay can't be reused.
    discard_from_session(request, session_key=payload["session_key"])
    return request


def _maybe_redirect_to_challenge(*, request, form_id: str, result):
    """Stash POST data + return redirect to /waf/challenge/ when configured.

    Returns ``None`` if challenge redirect is disabled
    (DJANGO_WAF_FORM_CHALLENGE_ON_FLAG=False) or unavailable (no session).
    Per PRD §5.
    """
    from urllib.parse import urlencode

    from django.http import HttpResponseRedirect
    from django.urls import reverse

    from django_waf import conf
    from django_waf.forms.services.replay import issue_replay_token, store_in_session

    if not conf.DJANGO_WAF_FORM_CHALLENGE_ON_FLAG:
        return None

    post_url = request.path
    ip = request.META.get("REMOTE_ADDR", "")

    # Scalarise so the stored session record contains plain strings,
    # not QueryDict-style list values. The QueryDict reconstruction
    # in _try_replay tolerates either shape, but storing scalars
    # keeps the on-disk record minimal and prevents the
    # ``dict(QueryDict)`` shape bug from being recreated on replay.
    from django_waf.forms.protection import scalarise_submitted_data

    session_key = store_in_session(
        request,
        form_id=form_id,
        post_url=post_url,
        data=scalarise_submitted_data(request.POST),
    )
    if session_key is None:
        # Session storage unavailable. Fall back to letting the view
        # handle FLAGGED — operators see the verdict in the log.
        logger.info("django-waf: session storage unavailable for form replay; falling back")
        return None

    replay_token = issue_replay_token(form_id=form_id, ip=ip, session_key=session_key)

    # Use the existing WAF challenge URL — honour DJANGO_WAF_CHALLENGE_URL
    # override for django-hosts setups (same shape as middleware /
    # ChallengeView from v0.10.5/v0.10.6).
    challenge_path = conf.DJANGO_WAF_CHALLENGE_URL or reverse("django_waf:challenge")
    params = urlencode({"next": post_url, "form_replay": replay_token})
    return HttpResponseRedirect(f"{challenge_path}?{params}")


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
