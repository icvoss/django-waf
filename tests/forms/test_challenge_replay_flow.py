"""End-to-end tests for the FLAGGED → challenge → replay flow."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import RequestFactory


def _redis():
    r = MagicMock(name="redis")
    r.exists.return_value = 1
    pipe = MagicMock()
    pipe.execute.return_value = [1, True, 1, True]
    r.pipeline.return_value = pipe
    r.get.return_value = None
    return r


class _FakeSession(dict):
    """A dict that also supports the ``.modified`` attribute Django uses."""

    modified = False


def _request_with_session(method, path, post=None, get_params=None):
    rf = RequestFactory()
    if method == "POST":  # noqa: SIM108 — explicit branch reads clearer here
        request = rf.post(path, data=post or {})
    else:
        # rf.get accepts a data dict for query params.
        request = rf.get(path, data=get_params or {})
    request.user = MagicMock(is_authenticated=False)
    # Stub out a session — RequestFactory doesn't add one by default.
    request.session = _FakeSession()
    return request


def _flagged_protection_for(form_id):
    """Build a FormProtection whose evaluate() always returns FLAGGED.

    Simpler than constructing a real flagged submission — the focus
    is the decorator's redirect-and-replay behaviour, not the
    orchestrator's verdict logic (which has its own tests).
    """
    from django_waf.forms.protection import (
        FormEvaluationResult,
        FormProtection,
        FormVerdict,
    )

    protection = FormProtection(
        form_id=form_id,
        defences=("honeypot",),
        redis_client_factory=lambda: _redis(),
    )

    def always_flagged(request, submitted_data):
        return FormEvaluationResult(
            verdict=FormVerdict.FLAGGED,
            total_score=3.0,
            outcomes=[],
            token_payload=None,
        )

    protection.evaluate = always_flagged
    return protection


# ---------------------------------------------------------------------------
# FLAGGED → redirect
# ---------------------------------------------------------------------------


class TestFlaggedRedirect:
    def test_flagged_post_redirects_to_challenge(self, settings):
        """FLAGGED + session + setting True → 302 to /waf/challenge/?form_replay=..."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import _registry_get, waf_protect_post
        from django_waf.forms.protection import FormEvaluationResult, FormVerdict

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            form_id = "contact-flagged-redirect"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):  # noqa: ARG001
                from django.http import HttpResponse

                return HttpResponse("view-ran")

            # Force the protection to always FLAG so we test the
            # redirect path deterministically.
            protection = _registry_get(form_id)
            protection.evaluate = lambda request, submitted_data: FormEvaluationResult(
                verdict=FormVerdict.FLAGGED, total_score=3.0, outcomes=[], token_payload=None
            )

            request = _request_with_session("POST", "/contact/", post={"name": "alice"})
            response = view(request)

        assert response.status_code == 302
        location = response["Location"]
        assert "/waf/challenge/" in location
        assert "form_replay=" in location
        # Session now has the stashed data. scalarise_submitted_data
        # gives last-value-per-key strings — pre-v0.11.2 this was
        # ``dict(QueryDict)`` producing list-valued entries, which
        # was the upstream of the bug that broke every real submission.
        stash = request.session.get("waf_form_replay", {})
        assert len(stash) == 1
        only_record = next(iter(stash.values()))
        assert only_record["data"]["name"] == "alice"
        assert only_record["post_url"] == "/contact/"

    def test_flagged_without_session_falls_back_to_view(self, settings):
        """If the request has no session, the decorator falls back to
        calling the view (operators see FLAGGED in request.waf_form_result)."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import (
            _registry_get,
            waf_protect_post,
        )
        from django_waf.forms.protection import FormEvaluationResult, FormVerdict

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            form_id = "contact-no-session"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                from django.http import HttpResponse

                return HttpResponse("view-ran")

            protection = _registry_get(form_id)
            protection.evaluate = lambda r, submitted_data: FormEvaluationResult(
                verdict=FormVerdict.FLAGGED, total_score=3.0, outcomes=[], token_payload=None
            )

            # RequestFactory without a session attribute.
            rf = RequestFactory()
            request = rf.post("/contact/", data={"name": "alice"})
            request.user = MagicMock(is_authenticated=False)
            # NO request.session set.

            response = view(request)

        # View ran (decorator fell back); the redirect did not happen.
        assert response.status_code == 200
        assert response.content.decode() == "view-ran"

    def test_challenge_redirect_disabled_setting(self, settings):
        """DJANGO_WAF_FORM_CHALLENGE_ON_FLAG=False → no redirect; view runs."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import (
            _registry_get,
            waf_protect_post,
        )
        from django_waf.forms.protection import FormEvaluationResult, FormVerdict

        with (
            patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"),
            patch.object(conf_mod, "DJANGO_WAF_FORM_CHALLENGE_ON_FLAG", False),
        ):
            form_id = "contact-challenge-disabled"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                from django.http import HttpResponse

                return HttpResponse("view-ran")

            protection = _registry_get(form_id)
            protection.evaluate = lambda r, submitted_data: FormEvaluationResult(
                verdict=FormVerdict.FLAGGED, total_score=3.0, outcomes=[], token_payload=None
            )

            request = _request_with_session("POST", "/contact/", post={"name": "alice"})
            response = view(request)

        assert response.status_code == 200
        assert response.content.decode() == "view-ran"


# ---------------------------------------------------------------------------
# GET ?form_replay=... triggers replay
# ---------------------------------------------------------------------------


class TestReplayDispatch:
    def test_valid_replay_invokes_view_as_post(self, settings):
        """GET ?form_replay=<valid> + matching session → view sees POST."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import (
            _registry_get,
            waf_protect_post,
        )
        from django_waf.forms.protection import FormEvaluationResult, FormVerdict
        from django_waf.forms.services.replay import (
            issue_replay_token,
            store_in_session,
        )

        captured = {}

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            form_id = "contact-replay-valid"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                captured["method"] = request.method
                captured["name"] = request.POST.get("name")
                from django.http import HttpResponse

                return HttpResponse("ok")

            # Replace evaluate so the replayed POST passes through.
            protection = _registry_get(form_id)
            protection.evaluate = lambda r, submitted_data: FormEvaluationResult(
                verdict=FormVerdict.PASSED, total_score=0.0, outcomes=[], token_payload=None
            )

            request = _request_with_session("GET", "/contact/", get_params={"form_replay": ""})
            # Stash data, then mint a token referring to that session key.
            session_key = store_in_session(request, form_id=form_id, post_url="/contact/", data={"name": "alice"})
            token = issue_replay_token(form_id=form_id, ip="127.0.0.1", session_key=session_key)
            request.GET = request.GET.copy()
            request.GET["form_replay"] = token

            response = view(request)

        assert response.status_code == 200
        assert captured["method"] == "POST"
        assert captured["name"] == "alice"

    def test_invalid_replay_falls_back_to_normal_get(self, settings):
        """GET ?form_replay=garbage → no replay → view sees GET."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import waf_protect_post

        captured = {}

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):

            @waf_protect_post(
                form_id="contact-replay-invalid",
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                captured["method"] = request.method
                from django.http import HttpResponse

                return HttpResponse("ok")

            request = _request_with_session("GET", "/contact/", get_params={"form_replay": "garbage"})
            response = view(request)

        assert response.status_code == 200
        assert captured["method"] == "GET"

    def test_replay_consumed_after_use(self, settings):
        """The session record is removed after a successful replay so
        the same token can't be re-used."""
        import django_waf.conf as conf_mod
        from django_waf.forms.decorators import _registry_get, waf_protect_post
        from django_waf.forms.protection import FormEvaluationResult, FormVerdict
        from django_waf.forms.services.replay import (
            issue_replay_token,
            store_in_session,
        )

        with patch.object(conf_mod, "DJANGO_WAF_SIGNING_KEY", "k"):
            form_id = "contact-replay-consumed"

            @waf_protect_post(
                form_id=form_id,
                defences=("honeypot",),
                redis_client_factory=lambda: _redis(),
            )
            def view(request):
                from django.http import HttpResponse

                return HttpResponse("ok")

            protection = _registry_get(form_id)
            protection.evaluate = lambda r, submitted_data: FormEvaluationResult(
                verdict=FormVerdict.PASSED, total_score=0.0, outcomes=[], token_payload=None
            )

            request = _request_with_session("GET", "/contact/")
            session_key = store_in_session(request, form_id=form_id, post_url="/contact/", data={"name": "alice"})
            token = issue_replay_token(form_id=form_id, ip="127.0.0.1", session_key=session_key)
            request.GET = request.GET.copy()
            request.GET["form_replay"] = token

            view(request)

        # Session record gone.
        stash = request.session.get("waf_form_replay", {})
        assert session_key not in stash
