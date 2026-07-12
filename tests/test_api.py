"""Tests for the optional django-waf DRF API.

Requires djangorestframework, which is guaranteed present here via the [dev]
extra (see pyproject.toml). tests/settings.py sets DJANGO_WAF_API_ENABLED =
True so the waf/api/ routes exist at urlconf-import time (mounting is
conditional on that flag when django_waf.urls is first imported); individual
tests exercise the disabled (503) path by patching
django_waf.conf.DJANGO_WAF_API_ENABLED directly, which
WafApiEnabledMixin.initial() reads live on every request.

ROOT_URLCONF is tests.urls, which includes django_waf.urls under "waf/", so
the API lives at /waf/api/.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from django_waf.enums import MatchType, RuleAction, RuleType, Verdict
from django_waf.models import AllowRule, BlockRule
from django_waf.testing.factories import (
    BlockRuleFactory,
    IPReputationFactory,
    RequestLogFactory,
)

User = get_user_model()

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_user(*, username="user", is_staff=False, is_superuser=False, perms=()):
    """Create and return a saved User, optionally staff/superuser with permissions."""
    user = User.objects.create_user(
        username=username,
        email=f"{username}@example.com",
        password="password",
        is_staff=is_staff,
        is_superuser=is_superuser,
    )
    for perm in perms:
        app_label, codename = perm.split(".")
        from django.contrib.auth.models import Permission

        user.user_permissions.add(Permission.objects.get(content_type__app_label=app_label, codename=codename))
    return user


def _waf_admin_user(**kwargs):
    """A staff user with django_waf.change_blockrule — satisfies IsWafAdmin without superuser."""
    return _make_user(is_staff=True, perms=["django_waf.change_blockrule"], **kwargs)


# ---------------------------------------------------------------------------
# API disabled
# ---------------------------------------------------------------------------


class TestApiDisabled:
    def test_returns_503_when_disabled(self):
        superuser = _make_user(username="super1", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=superuser)

        with patch("django_waf.conf.DJANGO_WAF_API_ENABLED", False):
            response = client.get("/waf/api/block-rules/")

        assert response.status_code == 503


# ---------------------------------------------------------------------------
# Permission enforcement
# ---------------------------------------------------------------------------


class TestPermissions:
    def test_unauthenticated_request_is_denied(self):
        client = APIClient()

        response = client.get("/waf/api/block-rules/")

        assert response.status_code in (401, 403)

    def test_non_staff_authenticated_user_denied_on_block_rules(self):
        user = _make_user(username="plainuser")
        client = APIClient()
        client.force_authenticate(user=user)

        response = client.get("/waf/api/block-rules/")

        assert response.status_code == 403


# ---------------------------------------------------------------------------
# BlockRuleViewSet
# ---------------------------------------------------------------------------


class TestBlockRuleViewSet:
    def test_waf_admin_can_list_block_rules(self):
        BlockRuleFactory.create_batch(3)
        admin = _make_user(username="admin1", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.get("/waf/api/block-rules/")

        assert response.status_code == 200
        assert len(response.data) == 3

    def test_waf_admin_can_create_block_rule(self):
        admin = _make_user(username="admin2", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        payload = {
            "name": "block-tor-exit",
            "rule_type": RuleType.IP,
            "match_type": MatchType.EXACT,
            "pattern": "203.0.113.5",
            "action": RuleAction.BLOCK,
            "priority": 50,
            "is_active": True,
            "confidence": "1.00",
            "feed_reporters": 0,
            "notes": "",
        }

        response = client.post("/waf/api/block-rules/", payload, format="json")

        assert response.status_code == 201
        assert BlockRule.objects.filter(name="block-tor-exit", pattern="203.0.113.5").exists()

    def test_waf_admin_can_update_block_rule(self):
        rule = BlockRuleFactory(name="original-name", priority=100)
        admin = _make_user(username="admin3", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.patch(f"/waf/api/block-rules/{rule.id}/", {"priority": 10}, format="json")

        assert response.status_code == 200
        rule.refresh_from_db()
        assert rule.priority == 10

    def test_staff_with_change_blockrule_permission_can_list(self):
        BlockRuleFactory()
        waf_admin = _waf_admin_user(username="wafadmin")
        client = APIClient()
        client.force_authenticate(user=waf_admin)

        response = client.get("/waf/api/block-rules/")

        assert response.status_code == 200


# ---------------------------------------------------------------------------
# AllowRuleViewSet
# ---------------------------------------------------------------------------


class TestAllowRuleViewSet:
    def test_waf_admin_can_create_allow_rule(self):
        admin = _make_user(username="admin4", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        payload = {
            "name": "allow-office-ip",
            "rule_type": RuleType.IP,
            "match_type": MatchType.EXACT,
            "pattern": "198.51.100.10",
            "verify_rdns": False,
            "rdns_pattern": "",
            "is_active": True,
            "notes": "",
        }

        response = client.post("/waf/api/allow-rules/", payload, format="json")

        assert response.status_code == 201
        assert AllowRule.objects.filter(name="allow-office-ip").exists()


# ---------------------------------------------------------------------------
# RequestLogViewSet
# ---------------------------------------------------------------------------


class TestRequestLogViewSet:
    def test_list_is_read_only_for_admin(self):
        RequestLogFactory.create_batch(2)
        admin = _make_user(username="admin5", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.get("/waf/api/request-logs/")

        assert response.status_code == 200
        assert len(response.data) == 2

    def test_post_is_not_allowed(self):
        admin = _make_user(username="admin6", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.post("/waf/api/request-logs/", {"path": "/x/"}, format="json")

        assert response.status_code == 405

    def test_verdict_filter_narrows_results(self):
        RequestLogFactory(verdict=Verdict.ALLOWED)
        RequestLogFactory(verdict=Verdict.BLOCKED)
        RequestLogFactory(verdict=Verdict.BLOCKED)
        admin = _make_user(username="admin7", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.get("/waf/api/request-logs/", {"verdict": Verdict.BLOCKED})

        assert response.status_code == 200
        assert len(response.data) == 2
        assert all(row["verdict"] == Verdict.BLOCKED for row in response.data)


# ---------------------------------------------------------------------------
# IPReputationViewSet
# ---------------------------------------------------------------------------


class TestIPReputationViewSet:
    def test_list_and_min_threat_score_filter(self):
        IPReputationFactory(ip_address="10.9.0.1", threat_score=Decimal("0.10"))
        IPReputationFactory(ip_address="10.9.0.2", threat_score=Decimal("0.80"))
        IPReputationFactory(ip_address="10.9.0.3", threat_score=Decimal("0.90"))
        admin = _make_user(username="admin8", is_staff=True, is_superuser=True)
        client = APIClient()
        client.force_authenticate(user=admin)

        response = client.get("/waf/api/ip-reputation/")
        assert response.status_code == 200
        assert len(response.data) == 3

        filtered = client.get("/waf/api/ip-reputation/", {"min_threat_score": "0.75"})
        assert filtered.status_code == 200
        assert len(filtered.data) == 2
        assert all(Decimal(row["threat_score"]) >= Decimal("0.75") for row in filtered.data)
