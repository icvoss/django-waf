"""
Auth-signal receivers for django-waf.

Currently home to the trusted-user-cookie login receiver (#23, see
docs/DESIGN-trusted-user-cookie.md). Connected opt-in from
``DjangoWafConfig.ready()``, gated on ``DJANGO_WAF_TRUSTED_COOKIE_ENABLED``
-- see that module for why this is opt-in rather than always connected, and
why toggling the setting needs a process restart to take effect (``ready()``
runs once at process startup, the standard Django app-loading contract).
"""

from __future__ import annotations

import logging

from django.contrib.auth.signals import user_logged_in

logger = logging.getLogger("django_waf.receivers")


def set_trusted_cookie_flag_on_login(sender, request, user, **kwargs) -> None:
    """Flag the request so the WAF middleware sets the trusted-user cookie
    on the login response.

    ``user_logged_in`` fires during login processing and only provides
    ``sender``, ``request``, and ``user`` -- not the response the login view
    is about to build, so the cookie cannot be signed and set here directly.
    Instead this stashes ``request._waf_set_trusted_cookie = True``, and
    ``django_waf.middleware.WafMiddleware._get_response`` checks that flag
    against the response once the view has produced one (see that method's
    docstring for the full flow).

    Only flags the request when both the feature is enabled and ``user``
    meets the configured trust level
    (``django_waf.services.trusted_user_service.user_meets_trust_level``,
    governed by ``DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL``) -- a non-staff
    user under the default "staff" trust level never gets the cookie.

    Never raises: an error here must not break login. Any exception is
    logged and swallowed, matching the fail-open posture the rest of the
    WAF's signal handling already uses (see ``django_waf.middleware``'s
    ``_emit_request_blocked`` / ``_emit_request_throttled``).
    """
    try:
        from django_waf.services.trusted_user_service import (
            is_feature_enabled,
            user_meets_trust_level,
        )

        if not is_feature_enabled():
            return

        if not user_meets_trust_level(user):
            return

        request._waf_set_trusted_cookie = True
    except Exception:
        logger.exception("django-waf: error flagging request for trusted-user cookie on login")


def connect() -> None:
    """Connect the login receiver to ``user_logged_in``.

    Called from ``DjangoWafConfig.ready()`` only when
    ``DJANGO_WAF_TRUSTED_COOKIE_ENABLED`` is True at process startup, so a
    site that never enables the feature never connects this receiver --
    the feature is fully opt-in wiring, not just an opt-in runtime check.
    """
    user_logged_in.connect(
        set_trusted_cookie_flag_on_login,
        dispatch_uid="django_waf.receivers.set_trusted_cookie_flag_on_login",
    )
