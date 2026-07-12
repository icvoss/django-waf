"""Test helpers for projects consuming django-waf.

Thin wrappers over BlockRule creation plus a Django test client request,
for exercising the middleware's block/challenge paths without hand-rolling
the rule setup in every test.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from django.http import HttpResponse
    from django.test import Client


def create_blocked_request(client: Client, path: str = "/", ip: str = "192.0.2.99") -> HttpResponse:
    """Create a block rule for ``ip`` and issue a GET request from it.

    Args:
        client: A Django test client instance.
        path: The path to request. Defaults to "/".
        ip: The IP address to block and request from. Defaults to a
            TEST-NET-1 documentation address.

    Returns:
        The response from ``client.get(path, REMOTE_ADDR=ip)``.
    """
    from django_waf.enums import RuleAction, RuleType
    from django_waf.models import BlockRule

    BlockRule.objects.create(
        name=f"test-block-{ip}",
        rule_type=RuleType.IP,
        match_type="exact",
        pattern=ip,
        action=RuleAction.BLOCK,
    )

    return client.get(path, REMOTE_ADDR=ip)


def create_challenged_request(client: Client, path: str = "/", ua: str = "python-requests/2.28") -> HttpResponse:
    """Create a challenge-action rule for ``ua`` and issue a GET request with it.

    Args:
        client: A Django test client instance.
        path: The path to request. Defaults to "/".
        ua: The User-Agent string to challenge and request with. Defaults
            to a common scripted-client UA.

    Returns:
        The response from ``client.get(path, HTTP_USER_AGENT=ua)``.
    """
    from django_waf.enums import RuleAction, RuleType
    from django_waf.models import BlockRule

    BlockRule.objects.create(
        name=f"test-challenge-{ua}",
        rule_type=RuleType.UA,
        match_type="exact",
        pattern=ua,
        action=RuleAction.CHALLENGE,
    )

    return client.get(path, HTTP_USER_AGENT=ua)
