"""Tests for icv-waf views.

Tests use Django's test Client and RequestFactory. All Redis calls and
challenge service functions are mocked — no real Redis is available.

URL namespace: "icv_waf" as declared in icv_waf.urls (app_name = "icv_waf").
Because the monorepo root settings use sandbox.urls (which does not include
icv_waf URLs), every test class overrides ROOT_URLCONF to "icv_waf.urls" so
that /challenge/, /verify/, /dashboard/, etc. resolve correctly.

Note on form POSTs: Django's test client only populates request.POST for
multipart/form-data (the default when no content_type is specified). When
content_type="application/x-www-form-urlencoded" is specified explicitly,
the dict is NOT URL-encoded by the client — use the default (multipart) for
form data tests, and content_type="application/json" with json.dumps() for
JSON body tests.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

User = get_user_model()

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Module-level URL override
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def waf_urls(settings):
    """Override ROOT_URLCONF to the test URL conf that includes icv_waf under /waf/
    with the 'icv_waf' namespace, enabling reverse('icv_waf:...') to resolve."""
    settings.ROOT_URLCONF = "urls"  # tests/urls.py (on pythonpath via pyproject.toml)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_staff_user(*, username="staff", email=None, superuser=False):
    """Create and return a saved staff (or superuser) User.

    Uses email as the primary identifier because AUTH_USER_MODEL is
    icv_identity.User (email-based).
    """
    if email is None:
        email = f"{username}@example.com"
    user = User.objects.create_user(
        email=email,
        password="password",
        is_staff=True,
        is_superuser=superuser,
    )
    return user


def _mock_challenge_token(token_str: str = "abc123"):
    """Return a MagicMock with a .token attribute."""
    ct = MagicMock()
    ct.token = token_str
    return ct


def _mock_redis():
    """Return a MagicMock that behaves like a basic Redis client."""
    r = MagicMock()
    r.get.return_value = None
    return r


# ---------------------------------------------------------------------------
# ChallengeView
# ---------------------------------------------------------------------------


class TestChallengeView:
    """GET /challenge/ presents the proof-of-work challenge page."""

    def test_returns_200(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("testtoken123")

            response = client.get("/waf/challenge/")

        assert response.status_code == 200

    def test_renders_challenge_template(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("tok")

            response = client.get("/waf/challenge/")

        assert response.status_code == 200
        assert "icv_waf/challenge.html" in [t.name for t in response.templates]

    def test_token_in_context(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("mytesttoken")

            response = client.get("/waf/challenge/")

        assert response.context["token"] == "mytesttoken"

    def test_next_url_in_context(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("tok")

            response = client.get("/waf/challenge/?next=/my-page/")

        assert response.context["next_url"] == "/my-page/"

    def test_unsafe_next_url_is_sanitised_to_root(self, settings):
        """An absolute URL in ?next= is rejected in favour of '/'."""
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("tok")

            response = client.get("/waf/challenge/?next=https://evil.example.com/steal")

        assert response.context["next_url"] == "/"

    def test_response_has_no_cache_control(self, settings):
        """Challenge page must not be cached (contains a one-time token)."""
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_issue.return_value = _mock_challenge_token("tok")

            response = client.get("/waf/challenge/")

        assert response.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# VerifyView
# ---------------------------------------------------------------------------


class TestVerifyView:
    """POST /verify/ validates proof-of-work solutions.

    Form data is submitted as multipart (Django test client default) so that
    request.POST is populated correctly. JSON tests use content_type="application/json".
    """

    def test_valid_solution_redirects_with_waf_pass_cookie(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("icv_waf.services.challenge_service.issue_pass_cookie") as mock_cookie,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_verify.return_value = True
            mock_cookie.side_effect = lambda response, token, ip, secure: response.set_cookie(
                "waf_pass", f"{token}:fake_sig", max_age=86400
            )

            # No explicit content_type → multipart → request.POST populated
            response = client.post(
                "/waf/verify/",
                data={"token": "validtoken", "nonce": "12345", "next": "/home/"},
            )

        assert response.status_code == 302
        assert "waf_pass" in response.cookies

    def test_valid_solution_redirects_to_next_url(self, settings):
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("icv_waf.services.challenge_service.issue_pass_cookie"),
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_verify.return_value = True

            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "nonce99", "next": "/target/"},
            )

        assert response.status_code == 302
        assert response["Location"] == "/target/"

    def test_missing_token_returns_400(self):
        client = Client()

        with patch("icv_waf.views._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = _mock_redis()

            response = client.post("/waf/verify/", data={"nonce": "12345"})

        assert response.status_code == 400

    def test_missing_nonce_returns_400(self):
        client = Client()

        with patch("icv_waf.views._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = _mock_redis()

            response = client.post("/waf/verify/", data={"token": "sometok"})

        assert response.status_code == 400

    def test_invalid_solution_returns_400_with_new_token(self, settings):
        """A wrong nonce response includes a new_token field for retry."""
        from icv_waf.services.challenge_service import ChallengeInvalidError

        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_verify.side_effect = ChallengeInvalidError("bad nonce")
            mock_issue.return_value = _mock_challenge_token("newtoken456")

            response = client.post(
                "/waf/verify/",
                data={"token": "tok", "nonce": "wrongnonce"},
            )

        assert response.status_code == 400
        data = response.json()
        assert "error" in data
        assert data.get("new_token") == "newtoken456"

    def test_expired_token_returns_400(self, settings):
        from icv_waf.services.challenge_service import ChallengeExpiredError

        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("icv_waf.services.challenge_service.issue_challenge") as mock_issue,
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_verify.side_effect = ChallengeExpiredError("expired")
            mock_issue.return_value = _mock_challenge_token("freshtok")

            response = client.post(
                "/waf/verify/",
                data={"token": "expiredtok", "nonce": "anynonce"},
            )

        assert response.status_code == 400

    def test_accepts_json_body(self, settings):
        """VerifyView parses application/json bodies as well as form data."""
        settings.ICV_WAF_ENABLED = True

        client = Client()

        with (
            patch("icv_waf.views._get_redis_client") as mock_redis_fn,
            patch("icv_waf.services.challenge_service.verify_challenge_solution") as mock_verify,
            patch("icv_waf.services.challenge_service.issue_pass_cookie"),
        ):
            mock_redis_fn.return_value = _mock_redis()
            mock_verify.return_value = True

            response = client.post(
                "/waf/verify/",
                data=json.dumps({"token": "jsontok", "nonce": "jsonnonce", "next": "/"}),
                content_type="application/json",
            )

        assert response.status_code == 302

    def test_malformed_json_body_returns_400(self):
        client = Client()

        with patch("icv_waf.views._get_redis_client") as mock_redis_fn:
            mock_redis_fn.return_value = _mock_redis()

            response = client.post(
                "/waf/verify/",
                data="not-valid-json{{",
                content_type="application/json",
            )

        assert response.status_code == 400


# ---------------------------------------------------------------------------
# DashboardView
# ---------------------------------------------------------------------------


class TestDashboardView:
    """GET /dashboard/ is restricted to staff users."""

    def test_anonymous_redirects_to_login(self):
        client = Client()

        response = client.get("/waf/dashboard/")

        assert response.status_code == 302
        assert "login" in response["Location"].lower()

    def test_non_staff_authenticated_user_gets_403(self):
        """Authenticated but non-staff users receive PermissionDenied (403) from
        StaffRequiredMixin, which calls handle_no_permission() on an authenticated user."""
        client = Client()
        user = User.objects.create_user(
            email="regular@example.com",
            password="pass",
            is_staff=False,
        )
        client.force_login(user)

        response = client.get("/waf/dashboard/")

        # LoginRequiredMixin.handle_no_permission raises PermissionDenied (→ 403)
        # when request.user is already authenticated.
        assert response.status_code == 403

    def test_staff_user_gets_200(self):
        client = Client()
        user = _make_staff_user(username="staffdash", email="staffdash@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/")

        assert response.status_code == 200

    def test_dashboard_uses_correct_template(self):
        client = Client()
        user = _make_staff_user(username="stafftpl", email="stafftpl@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/")

        assert "icv_waf/dashboard.html" in [t.name for t in response.templates]

    def test_dashboard_context_has_panel_urls(self):
        client = Client()
        user = _make_staff_user(username="staffctx", email="staffctx@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/")

        assert "stats_url" in response.context
        assert "top_blocked_url" in response.context
        assert "anomalies_url" in response.context


# ---------------------------------------------------------------------------
# HTMX panel views
# ---------------------------------------------------------------------------


class TestDashboardStatsPanelView:
    """GET /dashboard/stats/ returns a partial HTML fragment for staff."""

    def test_anonymous_redirects(self):
        client = Client()

        response = client.get("/waf/dashboard/stats/")

        assert response.status_code == 302

    def test_staff_gets_200(self):
        client = Client()
        user = _make_staff_user(username="staffstats", email="staffstats@example.com")
        client.force_login(user)

        with patch("icv_waf.views._get_redis_client") as mock_redis_fn:
            mock_redis = MagicMock()
            mock_redis.hgetall.return_value = {b"total": b"10", b"blocked": b"2"}
            mock_redis_fn.return_value = mock_redis

            response = client.get("/waf/dashboard/stats/")

        assert response.status_code == 200
        assert "icv_waf/partials/stats_panel.html" in [t.name for t in response.templates]


class TestDashboardTopBlockedPanelView:
    """GET /dashboard/top-blocked/ returns the top-blocked IP partial."""

    def test_anonymous_redirects(self):
        client = Client()

        response = client.get("/waf/dashboard/top-blocked/")

        assert response.status_code == 302

    def test_staff_gets_200(self):
        client = Client()
        user = _make_staff_user(username="stafftopblk", email="stafftopblk@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/top-blocked/")

        assert response.status_code == 200
        assert "icv_waf/partials/top_blocked_panel.html" in [t.name for t in response.templates]

    def test_ips_in_context_ordered_by_blocked_requests(self):
        from icv_waf.testing.factories import IPReputationFactory

        IPReputationFactory(ip_address="1.1.1.1", blocked_requests=50)
        IPReputationFactory(ip_address="2.2.2.2", blocked_requests=10)

        client = Client()
        user = _make_staff_user(username="staffiprep", email="staffiprep@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/top-blocked/")

        assert response.status_code == 200
        ips = list(response.context["ips"])
        assert len(ips) == 2
        # Ordered by -blocked_requests
        assert str(ips[0].ip_address) == "1.1.1.1"


class TestDashboardAnomalyPanelView:
    """GET /dashboard/anomalies/ returns auto-generated rules from the last 48 hours."""

    def test_anonymous_redirects(self):
        client = Client()

        response = client.get("/waf/dashboard/anomalies/")

        assert response.status_code == 302

    def test_staff_gets_200(self):
        client = Client()
        user = _make_staff_user(username="staffanom", email="staffanom@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/anomalies/")

        assert response.status_code == 200
        assert "icv_waf/partials/anomalies_panel.html" in [t.name for t in response.templates]

    def test_rules_in_context_are_auto_sourced(self):
        from icv_waf.enums import RuleSource
        from icv_waf.testing.factories import BlockRuleFactory

        # Auto-generated rule within 48 h
        auto_rule = BlockRuleFactory(source=RuleSource.AUTO)
        # Admin rule should not appear
        BlockRuleFactory(source=RuleSource.ADMIN)

        client = Client()
        user = _make_staff_user(username="staffanomrules", email="staffanomrules@example.com")
        client.force_login(user)

        response = client.get("/waf/dashboard/anomalies/")

        rules = list(response.context["rules"])
        assert all(r.source == RuleSource.AUTO for r in rules)
        rule_ids = [r.id for r in rules]
        assert auto_rule.id in rule_ids


# ---------------------------------------------------------------------------
# Anomaly confirm / reject views (superuser only)
# ---------------------------------------------------------------------------


class TestAnomalyConfirmView:
    """POST /dashboard/anomalies/<id>/confirm/ promotes an auto rule to admin."""

    def test_requires_superuser_not_just_staff(self):
        """Staff-but-not-superuser users receive 403 (PermissionDenied).

        SuperuserRequiredMixin calls handle_no_permission() on an authenticated
        non-superuser, which raises PermissionDenied rather than redirecting.
        """
        from icv_waf.enums import RuleSource
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory(source=RuleSource.AUTO)
        client = Client()
        staff_user = User.objects.create_user(
            email="staffonly@example.com",
            password="pass",
            is_staff=True,
            is_superuser=False,
        )
        client.force_login(staff_user)

        response = client.post(f"/waf/dashboard/anomalies/{rule.id}/confirm/")

        assert response.status_code == 403

    def test_superuser_can_confirm_rule(self):
        from icv_waf.enums import RuleSource
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory(source=RuleSource.AUTO)
        client = Client()
        superuser = User.objects.create_user(
            email="superconf@example.com",
            password="pass",
            is_staff=True,
            is_superuser=True,
        )
        client.force_login(superuser)

        response = client.post(f"/waf/dashboard/anomalies/{rule.id}/confirm/")

        assert response.status_code == 200
        rule.refresh_from_db()
        assert rule.source == RuleSource.ADMIN
        assert rule.expires_at is None


class TestAnomalyRejectView:
    """POST /dashboard/anomalies/<id>/reject/ deactivates a rule."""

    def test_superuser_can_reject_rule(self):
        from icv_waf.enums import RuleSource
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory(source=RuleSource.AUTO, is_active=True)
        client = Client()
        superuser = User.objects.create_user(
            email="superrej@example.com",
            password="pass",
            is_staff=True,
            is_superuser=True,
        )
        client.force_login(superuser)

        response = client.post(f"/waf/dashboard/anomalies/{rule.id}/reject/")

        assert response.status_code == 200
        rule.refresh_from_db()
        assert rule.is_active is False

    def test_reject_returns_empty_response_for_htmx_delete(self):
        """VerifyView returns empty body so HTMX hx-swap='delete' removes the row."""
        from icv_waf.enums import RuleSource
        from icv_waf.testing.factories import BlockRuleFactory

        rule = BlockRuleFactory(source=RuleSource.AUTO)
        client = Client()
        superuser = User.objects.create_user(
            email="superrejempty@example.com",
            password="pass",
            is_staff=True,
            is_superuser=True,
        )
        client.force_login(superuser)

        response = client.post(f"/waf/dashboard/anomalies/{rule.id}/reject/")

        assert response.content == b""
