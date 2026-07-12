"""pytest fixtures for projects consuming django-waf.

These fixtures require ``pytest`` and, for ``waf_redis_mock``,
``fakeredis``. Both are development-only dependencies of django-waf itself
(``pip install django-waf[dev]``); consuming projects that want to use
these fixtures should install ``fakeredis`` alongside ``pytest`` in their
own test dependencies. Imports are kept lazy inside each fixture so that
importing this module never fails for a project that only wants the
non-Redis fixtures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from django_waf.models import AllowRule, BlockRule, ChallengeToken


@pytest.fixture
def disable_waf(monkeypatch: pytest.MonkeyPatch):
    """Disable the WAF middleware for the duration of a test.

    Patches ``django_waf.conf.DJANGO_WAF_ENABLED`` to ``False``. Restored
    automatically by ``monkeypatch`` at teardown.
    """
    from django_waf import conf

    monkeypatch.setattr(conf, "DJANGO_WAF_ENABLED", False)
    yield


@pytest.fixture
def waf_redis_mock(monkeypatch: pytest.MonkeyPatch):
    """Patch every Redis accessor django-waf uses to return a shared fakeredis instance.

    Covers the middleware, the challenge/verify views, and the
    form-protection subsystem's default Redis factory — the three places
    that independently resolve a Redis client via ``django_redis`` or the
    Django cache fallback.

    Requires ``fakeredis``. Raises ``ImportError`` with an actionable
    message if it is not installed.

    Yields:
        The shared ``fakeredis.FakeRedis`` instance, so tests can assert on
        Redis state directly.
    """
    try:
        import fakeredis
    except ImportError as exc:
        raise ImportError(
            "The waf_redis_mock fixture requires fakeredis. Install it with "
            "`pip install fakeredis` (or `pip install django-waf[dev]` when "
            "developing django-waf itself)."
        ) from exc

    import django_waf.forms.protection as protection_mod
    import django_waf.handlers as handlers_mod
    import django_waf.middleware as middleware_mod
    import django_waf.views as views_mod

    fake_client = fakeredis.FakeRedis()

    monkeypatch.setattr(middleware_mod, "_get_redis_client", lambda: fake_client)
    monkeypatch.setattr(views_mod, "_get_redis_client", lambda: fake_client)
    monkeypatch.setattr(protection_mod, "_default_redis_factory", lambda: fake_client)
    monkeypatch.setattr(handlers_mod, "_get_cache", lambda: fake_client)

    yield fake_client


@pytest.fixture
def block_rule(db) -> BlockRule:
    """Create and return a default BlockRule instance via BlockRuleFactory."""
    from django_waf.testing.factories import BlockRuleFactory

    return BlockRuleFactory()


@pytest.fixture
def allow_rule(db) -> AllowRule:
    """Create and return a default AllowRule instance via AllowRuleFactory."""
    from django_waf.testing.factories import AllowRuleFactory

    return AllowRuleFactory()


@pytest.fixture
def challenge_token(db) -> ChallengeToken:
    """Create and return a default ChallengeToken instance via ChallengeTokenFactory."""
    from django_waf.testing.factories import ChallengeTokenFactory

    return ChallengeTokenFactory()
