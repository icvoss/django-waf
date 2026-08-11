"""Client IP resolution service for django-waf.

Centralises what used to be near-duplicate ``X-Forwarded-For`` handling in
``middleware.py``, ``views.py``, and six form-defence call sites (#29). Every
consumer that needs "the real client IP" calls :func:`resolve_client_ip`
instead of reading ``request.META["REMOTE_ADDR"]`` or the XFF header
directly.

Trust model
-----------

``X-Forwarded-For`` is entirely client-controlled unless something upstream
(a load balancer, reverse proxy) overwrites or appends to it. Honouring the
header without first confirming the request actually arrived via a trusted
proxy lets any client spoof its IP by sending its own XFF header.

``DJANGO_WAF_TRUSTED_PROXIES`` (a list of CIDR strings, default empty) is the
hardened path: the header is only honoured when ``REMOTE_ADDR`` itself is
inside one of the configured proxy ranges, and even then only the rightmost
hop that is *not itself* a trusted proxy is taken, the standard walk for a
chain of trusted reverse proxies, each of which appends the previous hop's
address to the header.

``DJANGO_WAF_TRUSTED_UNIX_SOCKET`` is a separate, explicit opt-in for a WSGI
server reached through a unix socket, where ``REMOTE_ADDR`` is empty. It treats
that empty direct peer as trusted and uses the same right-to-left walk. The
operator is responsible for allowing only their reverse proxy to connect to
the socket.

The legacy ``DJANGO_WAF_TRUST_X_FORWARDED_FOR`` setting keeps working for
backwards compatibility: with no trusted proxies configured, it falls back
to the pre-#29 behaviour of trusting the leftmost XFF entry unconditionally.
That path is spoofable by design (the leftmost entry is exactly the one a
client controls) and is only ever exercised when the operator has not
migrated to ``DJANGO_WAF_TRUSTED_PROXIES``. Every resolution taken via that
path logs a warning so it is visible in operational logs; a proper
system-check warning (a new ``django_waf.W0xx`` code) belongs in
``checks.py`` and is not added here because this module does not own that
file, see the implementation report for this follow-up.
"""

from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("django_waf.client_ip")

__all__ = ["resolve_client_ip"]


def resolve_client_ip(request) -> str:
    """Return the best-available client IP address for ``request``.

    Resolution order:

    1. If ``REMOTE_ADDR`` is within ``DJANGO_WAF_TRUSTED_PROXIES``, or it is
       empty and ``DJANGO_WAF_TRUSTED_UNIX_SOCKET`` is enabled, walk
       ``X-Forwarded-For`` from the right and return the first entry that is
       a valid IP address and is not itself inside a trusted-proxy range.
       Malformed or empty entries are skipped. If nothing valid remains after
       the walk, fall back to ``REMOTE_ADDR``.
    2. Otherwise, if ``DJANGO_WAF_TRUST_X_FORWARDED_FOR`` is set (legacy
       opt-in) and the header is present, return the leftmost entry
       unconditionally (spoofable, kept only for backwards compatibility;
       logs a warning on every use).
    3. Otherwise, return ``REMOTE_ADDR`` (empty string if absent).

    The return value is never ``None``; callers that need a non-empty
    fallback (e.g. a NOT NULL database column) apply their own default.
    """
    from django_waf import conf

    remote_addr = request.META.get("REMOTE_ADDR", "") or ""
    trusted_proxies = conf.DJANGO_WAF_TRUSTED_PROXIES
    trusted_unix_socket = conf.DJANGO_WAF_TRUSTED_UNIX_SOCKET and not remote_addr

    if _is_trusted_proxy(remote_addr, trusted_proxies) or trusted_unix_socket:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        resolved = _resolve_from_forwarded_chain(forwarded_for, trusted_proxies)
        if resolved:
            return resolved
        return remote_addr

    if conf.DJANGO_WAF_TRUST_X_FORWARDED_FOR:
        forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
        if forwarded_for:
            candidate = forwarded_for.split(",")[0].strip()
            if _is_valid_ip(candidate):
                logger.warning(
                    "django-waf: trusting the leftmost X-Forwarded-For entry "
                    "without a configured trusted proxy (DJANGO_WAF_TRUSTED_PROXIES "
                    "is empty), this value is client-controlled and spoofable. "
                    "Configure DJANGO_WAF_TRUSTED_PROXIES to use the hardened, "
                    "right-to-left trusted-hop resolution instead."
                )
                return candidate

    return remote_addr


def _resolve_from_forwarded_chain(forwarded_for: str, trusted_proxies: list[str]) -> str:
    """Walk X-Forwarded-For right-to-left, skipping trusted-proxy hops.

    Returns the first entry (scanning from the right) that is a valid IP
    address and is not itself within a trusted-proxy CIDR. Returns an empty
    string if no such entry exists (malformed header, or every hop is a
    trusted proxy).
    """
    if not forwarded_for:
        return ""

    hops = [hop.strip() for hop in forwarded_for.split(",")]
    for hop in reversed(hops):
        if not hop or not _is_valid_ip(hop):
            continue
        if _is_trusted_proxy(hop, trusted_proxies):
            continue
        return hop

    return ""


def _is_trusted_proxy(ip_str: str, trusted_proxies: list[str]) -> bool:
    """Return True if ``ip_str`` falls within any configured trusted-proxy CIDR."""
    if not ip_str:
        return False

    try:
        address = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    for cidr in trusted_proxies:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning("django-waf: invalid entry in DJANGO_WAF_TRUSTED_PROXIES: %r", cidr)
            continue
        if address in network:
            return True

    return False


def _is_valid_ip(ip_str: str) -> bool:
    """Return True if ``ip_str`` parses as a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return True
