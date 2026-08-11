"""Tests for django_waf.services.client_ip.resolve_client_ip (#29).

Covers the trusted-proxy resolution contract:
  - No trusted proxies configured -> X-Forwarded-For from an untrusted
    peer is ignored; REMOTE_ADDR is returned.
  - Trusted proxies configured -> X-Forwarded-For is honoured only when
    REMOTE_ADDR is itself a trusted proxy, and the rightmost non-proxy
    hop is returned.
  - Chained trusted proxies resolve to the real client at the front of
    the chain.
  - Malformed / empty X-Forwarded-For entries fall back safely.
  - IPv4 and IPv6 proxies and clients.
  - middleware._extract_ip, views._get_ip, and a forms defence all
    resolve identically for the same request.
"""

from __future__ import annotations

import importlib

from django.test import RequestFactory, override_settings

import django_waf.conf as conf_mod


def _reload_conf():
    importlib.reload(conf_mod)


# ---------------------------------------------------------------------------
# No trusted proxies configured (default) -- legacy / safe-default behaviour
# ---------------------------------------------------------------------------


class TestNoTrustedProxiesConfigured:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=[], DJANGO_WAF_TRUST_X_FORWARDED_FOR=False)
    def test_spoofed_xff_from_untrusted_peer_is_ignored(self):
        """With no trusted proxies and the legacy trust flag off, XFF is never honoured."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=[], DJANGO_WAF_TRUST_X_FORWARDED_FOR=True)
    def test_legacy_trust_flag_preserves_leftmost_behaviour(self):
        """Legacy DJANGO_WAF_TRUST_X_FORWARDED_FOR=True with no trusted proxies
        preserves the old leftmost-XFF behaviour for backwards compatibility."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="1.2.3.4, 10.0.0.1",
        )

        assert resolve_client_ip(request) == "1.2.3.4"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=[], DJANGO_WAF_TRUST_X_FORWARDED_FOR=False)
    def test_no_xff_header_returns_remote_addr(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get("/", REMOTE_ADDR="203.0.113.9")

        assert resolve_client_ip(request) == "203.0.113.9"


# ---------------------------------------------------------------------------
# Trusted proxies configured -- hardened path
# ---------------------------------------------------------------------------


class TestTrustedProxiesConfigured:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_xff_honoured_only_when_remote_addr_is_trusted_proxy(self):
        """A request from an untrusted REMOTE_ADDR never gets XFF honoured,
        even with trusted proxies configured."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_xff_honoured_when_remote_addr_is_trusted_proxy(self):
        """REMOTE_ADDR inside the trusted range -> rightmost non-proxy hop returned."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_multiple_chained_trusted_proxies_resolve_to_real_client(self):
        """A chain of trusted proxies is walked right-to-left, skipping trusted
        hops, until the real (untrusted) client IP is found."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        # Real client 203.0.113.9 -> proxy 10.0.0.1 -> proxy 10.0.0.2 (REMOTE_ADDR)
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR="203.0.113.9, 10.0.0.1",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_spoofed_leftmost_entry_behind_trusted_proxy_is_rejected(self):
        """A client behind a trusted proxy cannot spoof by injecting a fake
        leftmost XFF entry -- only the rightmost non-proxy hop is trusted,
        so a forged entry ahead of the proxy-appended real IP is ignored."""
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        # Attacker sends "X-Forwarded-For: 6.6.6.6" from behind the trusted
        # proxy; the proxy appends the attacker's real address.
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.7",
        )

        assert resolve_client_ip(request) == "198.51.100.7"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_all_hops_trusted_falls_back_to_remote_addr(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR="10.0.0.3, 10.0.0.1",
        )

        assert resolve_client_ip(request) == "10.0.0.2"


# ---------------------------------------------------------------------------
# Trusted unix-socket peer
# ---------------------------------------------------------------------------


class TestTrustedUnixSocket:
    @override_settings(DJANGO_WAF_TRUSTED_UNIX_SOCKET=False)
    def test_empty_remote_addr_does_not_trust_xff_by_default(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
        )

        assert resolve_client_ip(request) == ""

    @override_settings(DJANGO_WAF_TRUSTED_UNIX_SOCKET=True)
    def test_empty_remote_addr_uses_hardened_xff_walk(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="",
            HTTP_X_FORWARDED_FOR="6.6.6.6, 198.51.100.7",
        )

        assert resolve_client_ip(request) == "198.51.100.7"

    @override_settings(DJANGO_WAF_TRUSTED_UNIX_SOCKET=True)
    def test_empty_remote_addr_with_no_valid_xff_remains_empty(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="",
            HTTP_X_FORWARDED_FOR="not-an-ip, ",
        )

        assert resolve_client_ip(request) == ""

    @override_settings(
        DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"],
        DJANGO_WAF_TRUSTED_UNIX_SOCKET=True,
    )
    def test_nonempty_untrusted_remote_addr_still_ignores_xff(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="198.51.100.7",
        )

        assert resolve_client_ip(request) == "203.0.113.9"


# ---------------------------------------------------------------------------
# Malformed / empty XFF entries
# ---------------------------------------------------------------------------


class TestMalformedForwardedFor:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_malformed_entries_are_skipped(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR="not-an-ip, 203.0.113.9",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_empty_entries_are_skipped(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.2",
            HTTP_X_FORWARDED_FOR=", 203.0.113.9, ",
        )

        assert resolve_client_ip(request) == "203.0.113.9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_empty_header_falls_back_to_remote_addr(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get("/", REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="")

        assert resolve_client_ip(request) == "10.0.0.2"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_entirely_malformed_header_falls_back_to_remote_addr(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get("/", REMOTE_ADDR="10.0.0.2", HTTP_X_FORWARDED_FOR="garbage, ,,,")

        assert resolve_client_ip(request) == "10.0.0.2"


# ---------------------------------------------------------------------------
# IPv6
# ---------------------------------------------------------------------------


class TestIPv6:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["fd00::/8"])
    def test_ipv6_trusted_proxy_and_ipv6_client(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="fd00::1",
            HTTP_X_FORWARDED_FOR="2001:db8::9",
        )

        assert resolve_client_ip(request) == "2001:db8::9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_ipv4_trusted_proxy_with_ipv6_client(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="2001:db8::9",
        )

        assert resolve_client_ip(request) == "2001:db8::9"

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["fd00::/8"])
    def test_ipv6_remote_addr_not_in_trusted_range_ignores_xff(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="2001:db8::1",
            HTTP_X_FORWARDED_FOR="2001:db8::9",
        )

        assert resolve_client_ip(request) == "2001:db8::1"


# ---------------------------------------------------------------------------
# Cross-subsystem consistency: middleware, views, and a forms defence all
# resolve the same request identically.
# ---------------------------------------------------------------------------


class TestCrossSubsystemConsistency:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["10.0.0.0/8"])
    def test_middleware_views_and_forms_defence_agree(self):
        _reload_conf()
        from django_waf.forms.defences.render_token import _extract_ip as forms_extract_ip
        from django_waf.middleware import _extract_ip as middleware_extract_ip
        from django_waf.services.client_ip import resolve_client_ip
        from django_waf.views import _get_ip as views_get_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="10.0.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.9",
        )

        expected = resolve_client_ip(request)
        assert expected == "203.0.113.9"
        assert middleware_extract_ip(request) == expected
        assert views_get_ip(request) == expected
        assert forms_extract_ip(request) == expected

    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=[], DJANGO_WAF_TRUST_X_FORWARDED_FOR=False)
    def test_agree_on_spoofed_untrusted_request_too(self):
        _reload_conf()
        from django_waf.forms.defences.render_token import _extract_ip as forms_extract_ip
        from django_waf.middleware import _extract_ip as middleware_extract_ip
        from django_waf.services.client_ip import resolve_client_ip
        from django_waf.views import _get_ip as views_get_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="6.6.6.6",
        )

        expected = resolve_client_ip(request)
        assert expected == "203.0.113.9"
        assert middleware_extract_ip(request) == expected
        assert views_get_ip(request) == expected
        assert forms_extract_ip(request) == expected


# ---------------------------------------------------------------------------
# Invalid DJANGO_WAF_TRUSTED_PROXIES entries
# ---------------------------------------------------------------------------


class TestInvalidTrustedProxyEntries:
    @override_settings(DJANGO_WAF_TRUSTED_PROXIES=["not-a-cidr"])
    def test_invalid_cidr_entry_is_skipped_not_fatal(self):
        _reload_conf()
        from django_waf.services.client_ip import resolve_client_ip

        factory = RequestFactory()
        request = factory.get(
            "/",
            REMOTE_ADDR="203.0.113.9",
            HTTP_X_FORWARDED_FOR="1.2.3.4",
        )

        # No valid trusted proxy entries -> REMOTE_ADDR is not considered
        # trusted, so XFF is ignored and REMOTE_ADDR is returned.
        assert resolve_client_ip(request) == "203.0.113.9"
