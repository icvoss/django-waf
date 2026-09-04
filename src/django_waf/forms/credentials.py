"""Public entry point for recording a credential-login failure.

``CredentialThrottleDefence`` (``defences/credential_throttle.py``) only
*reads* the per-IP counter at submit time, it never increments anything.
The increment happens here, called explicitly by the consuming project's
login flow after its own authentication check fails. Neither the
``ProtectedForm`` mixin nor the ``waf_protect_post`` decorator can do this
on the consumer's behalf: both run *before* the password check, and the
mixin in particular has no way to know which field holds the identifier
or whether the credential check even failed, that is application logic
this package does not own.

Per PRD §3.6 + §3.6.1 and BR-FORM-009.
"""

from __future__ import annotations

import logging

from django_waf.forms.services.counters import hash_identifier, record_credential_failure
from django_waf.forms.signals import credential_attack_observed

logger = logging.getLogger("django_waf.forms")


def waf_record_credential_failure(request, identifier: str) -> tuple[int, int]:
    """Record a failed login attempt, call this from the login view.

    Must be called **unconditionally** whenever the credential check
    fails, whether or not ``identifier`` corresponds to a real account
    (PRD §3.6.1's enumeration-safety constraint: an attacker must not be
    able to distinguish "wrong password" from "no such account" by
    observing side effects). Both the mixin and decorator integration
    paths require this explicit call; see
    ``defences/credential_throttle.py`` for why the chain itself cannot
    make it.

    Increments both the per-account and per-IP failure counters in
    Redis and returns ``(account_count, ip_count)`` after incrementing.
    Emits ``credential_attack_observed`` when ``account_count`` exactly
    equals ``DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT``, i.e. on the
    request that crosses the threshold, not on every attempt at or
    above it. Redis's ``INCR`` is atomic, so exactly one request per
    window observes that exact value; emitting on ``>=`` would fire the
    signal on every subsequent attempt during an ongoing attack, which
    is wrong for the documented consumer (an email-to-owner handler
    that should fire once, not spam the account holder).

    Fails open like the rest of the form-protection subsystem: a Redis
    outage, an empty ``identifier``, or a request with no resolvable
    client IP all return ``(0, 0)`` without raising, and a receiver
    that raises on the signal is caught and logged rather than
    propagated into the caller's login flow.
    """
    from django_waf import conf
    from django_waf.services.client_ip import resolve_client_ip
    from django_waf.services.redis_client import get_redis_client

    if not identifier:
        return (0, 0)

    ip = resolve_client_ip(request) if request else ""
    if not ip:
        return (0, 0)

    redis_client = get_redis_client()
    if redis_client is None:
        return (0, 0)

    window_seconds = conf.DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW
    account_count, ip_count = record_credential_failure(
        redis_client,
        identifier=identifier,
        ip=ip,
        window_seconds=window_seconds,
    )

    # account_count 0 is the fail-open sentinel (Redis outage), never a
    # crossing, even under a misconfigured limit of 0.
    if account_count > 0 and account_count == conf.DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT:
        try:
            credential_attack_observed.send(
                sender=None,
                identifier_hash=hash_identifier(identifier),
                attempt_count=account_count,
                window_seconds=window_seconds,
                ip=ip,
            )
        except Exception:
            logger.exception("django-waf: credential_attack_observed receiver raised")

    return account_count, ip_count
