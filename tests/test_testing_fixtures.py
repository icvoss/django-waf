"""Tests for the pytest fixtures and helpers in django_waf.testing.

Each fixture/helper gets a focused test verifying it does what its name
says. These are consumed by projects via ``django_waf.testing`` — the
tests here double as usage examples.
"""

from __future__ import annotations

import pytest

from django_waf.testing.fixtures import (  # noqa: F401 — re-exported as pytest fixtures
    allow_rule,
    block_rule,
    challenge_token,
    disable_waf,
    waf_redis_mock,
)

# ---------------------------------------------------------------------------
# disable_waf
# ---------------------------------------------------------------------------


class TestDisableWafFixture:
    def test_disable_waf_flips_the_conf_flag(self, disable_waf):
        from django_waf import conf

        assert conf.DJANGO_WAF_ENABLED is False

    def test_disable_waf_restored_after_test(self):
        """Sanity check: outside the fixture, the flag reflects the real setting again."""
        from django_waf import conf

        assert conf.DJANGO_WAF_ENABLED is True


# ---------------------------------------------------------------------------
# block_rule / allow_rule / challenge_token
# ---------------------------------------------------------------------------


class TestModelFixtures:
    @pytest.mark.django_db
    def test_block_rule_fixture_creates_instance(self, block_rule):
        from django_waf.models import BlockRule

        assert isinstance(block_rule, BlockRule)
        assert BlockRule.objects.filter(pk=block_rule.pk).exists()

    @pytest.mark.django_db
    def test_allow_rule_fixture_creates_instance(self, allow_rule):
        from django_waf.models import AllowRule

        assert isinstance(allow_rule, AllowRule)
        assert AllowRule.objects.filter(pk=allow_rule.pk).exists()

    @pytest.mark.django_db
    def test_challenge_token_fixture_creates_instance(self, challenge_token):
        from django_waf.models import ChallengeToken

        assert isinstance(challenge_token, ChallengeToken)
        assert ChallengeToken.objects.filter(pk=challenge_token.pk).exists()


# ---------------------------------------------------------------------------
# waf_redis_mock
# ---------------------------------------------------------------------------


class TestWafRedisMockFixture:
    def test_returns_a_working_fake_redis_client(self, waf_redis_mock):
        waf_redis_mock.set("waf:test:key", "1")
        assert waf_redis_mock.get("waf:test:key") == b"1"

    def test_patches_middleware_redis_accessor(self, waf_redis_mock):
        from django_waf.middleware import _get_redis_client

        assert _get_redis_client() is waf_redis_mock

    def test_patches_views_redis_accessor(self, waf_redis_mock):
        from django_waf.views import _get_redis_client

        assert _get_redis_client() is waf_redis_mock

    def test_patches_form_protection_default_redis_factory(self, waf_redis_mock):
        from django_waf.forms.protection import _default_redis_factory

        assert _default_redis_factory() is waf_redis_mock


# ---------------------------------------------------------------------------
# create_blocked_request / create_challenged_request
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestCreateBlockedRequestHelper:
    def test_creates_ip_block_rule_and_blocks_the_request(self, client, waf_redis_mock):
        from django_waf.testing.helpers import create_blocked_request

        response = create_blocked_request(client, path="/", ip="192.0.2.99")

        assert response.status_code == 403

    def test_creates_a_block_rule_for_the_given_ip(self, client, waf_redis_mock):
        from django_waf.enums import RuleAction, RuleType
        from django_waf.models import BlockRule
        from django_waf.testing.helpers import create_blocked_request

        create_blocked_request(client, path="/", ip="203.0.113.55")

        rule = BlockRule.objects.get(pattern="203.0.113.55")
        assert rule.rule_type == RuleType.IP
        assert rule.action == RuleAction.BLOCK


@pytest.mark.django_db
class TestCreateChallengedRequestHelper:
    def test_creates_ua_challenge_rule_and_challenges_the_request(self, client, waf_redis_mock):
        from django_waf.testing.helpers import create_challenged_request

        response = create_challenged_request(client, path="/", ua="python-requests/2.28")

        assert response.status_code in (302, 403)

    def test_creates_a_challenge_rule_for_the_given_ua(self, client, waf_redis_mock):
        from django_waf.enums import RuleAction, RuleType
        from django_waf.models import BlockRule
        from django_waf.testing.helpers import create_challenged_request

        create_challenged_request(client, path="/", ua="scrapy-bot/1.0")

        rule = BlockRule.objects.get(pattern="scrapy-bot/1.0")
        assert rule.rule_type == RuleType.UA
        assert rule.action == RuleAction.CHALLENGE
