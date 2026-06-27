"""Tests for the form-token Redis marker service.

Markers are the load-bearing primitive for replay protection. The
"delete only on PASS" rule (see PRD §4.3) is what makes HTMX
re-renders work — these tests pin that rule so a future change to the
orchestrator can't quietly regress the semantics.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def _redis():
    """Return a Redis MagicMock with the methods the marker service uses."""
    r = MagicMock(name="redis")
    r.exists.return_value = 0
    return r


class TestIssueMarker:
    def test_setex_called_with_namespaced_key_and_ttl(self):
        from django_waf.forms.services.markers import issue_marker

        r = _redis()
        issue_marker(r, nonce="abc", ttl_seconds=3600)

        r.setex.assert_called_once_with("waf:form:token:abc", 3600, "1")

    def test_distinct_nonces_use_distinct_keys(self):
        from django_waf.forms.services.markers import issue_marker

        r = _redis()
        issue_marker(r, nonce="aaa", ttl_seconds=60)
        issue_marker(r, nonce="bbb", ttl_seconds=60)

        keys = [c.args[0] for c in r.setex.call_args_list]
        assert keys == ["waf:form:token:aaa", "waf:form:token:bbb"]


class TestMarkerExists:
    def test_returns_true_when_redis_exists_returns_one(self):
        from django_waf.forms.services.markers import marker_exists

        r = _redis()
        r.exists.return_value = 1

        assert marker_exists(r, "abc") is True
        r.exists.assert_called_once_with("waf:form:token:abc")

    def test_returns_false_when_redis_exists_returns_zero(self):
        from django_waf.forms.services.markers import marker_exists

        r = _redis()
        r.exists.return_value = 0

        assert marker_exists(r, "abc") is False

    def test_returns_false_for_none_response(self):
        """Defensive — some Redis clients return None instead of 0."""
        from django_waf.forms.services.markers import marker_exists

        r = _redis()
        r.exists.return_value = None

        assert marker_exists(r, "abc") is False


class TestConsumeMarker:
    def test_delete_called_with_namespaced_key(self):
        from django_waf.forms.services.markers import consume_marker

        r = _redis()
        consume_marker(r, "abc")

        r.delete.assert_called_once_with("waf:form:token:abc")

    def test_consume_does_not_touch_other_redis_state(self):
        """Marker consumption must NOT trigger setex or exists calls."""
        from django_waf.forms.services.markers import consume_marker

        r = _redis()
        consume_marker(r, "abc")

        r.setex.assert_not_called()
        r.exists.assert_not_called()
