"""Tests for the form-protection token service.

Covers the signing key resolution, token issuance/verification round
trips, signature tampering, and payload-format strictness. Marker
behaviour is tested separately in ``test_markers.py`` so each module's
tests pin a single concern.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# get_signing_key
# ---------------------------------------------------------------------------


class TestGetSigningKey:
    def test_uses_icv_waf_signing_key_when_set(self):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import get_signing_key

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "explicit-key-value"):
            assert get_signing_key() == b"explicit-key-value"

    def test_falls_back_to_secret_key_derivative_when_unset(self, settings):
        """An empty ICV_WAF_SIGNING_KEY derives from Django's SECRET_KEY.

        Critical: the derived key must NOT equal SECRET_KEY directly —
        if a future bug exposed it, leaking it would not also leak the
        Django session secret. The namespace byte string in the
        derivation is the load-bearing detail here.
        """
        import hashlib

        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import get_signing_key

        fake_secret = "django-secret-do-not-leak"
        settings.SECRET_KEY = fake_secret
        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", ""):
            derived = get_signing_key()

        assert derived != fake_secret.encode()
        expected = hashlib.sha256(b"icv-waf:signing:v1|" + fake_secret.encode()).digest()
        assert derived == expected

    def test_derived_key_is_stable_across_calls(self, settings):
        """Same SECRET_KEY input must produce the same derived key.

        Otherwise tokens issued under one process couldn't be verified
        by another, breaking horizontally-scaled deployments.
        """
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import get_signing_key

        settings.SECRET_KEY = "stable-secret"
        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", ""):
            assert get_signing_key() == get_signing_key()


# ---------------------------------------------------------------------------
# issue_token / verify_token round-trip
# ---------------------------------------------------------------------------


class TestTokenRoundTrip:
    def test_issue_then_verify_returns_same_payload(self):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import issue_token, verify_token

        render_time = datetime(2026, 5, 27, 10, 0, 0, tzinfo=UTC)
        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "test-key"):
            token, original = issue_token(
                form_id="contact",
                ip="1.2.3.4",
                user_id="42",
                user_agent="Mozilla/5.0",
                render_time=render_time,
                nonce="deadbeef",
            )
            recovered = verify_token(token)

        assert recovered.form_id == "contact"
        assert recovered.ip == "1.2.3.4"
        assert recovered.user_id == "42"
        assert recovered.render_time == render_time
        assert recovered.nonce == "deadbeef"
        assert recovered.ua_hash == original.ua_hash

    def test_issued_token_is_url_safe(self):
        """Token must survive being placed into an HTML attribute and a URL.

        We base64url-encode and strip padding, which is exactly that
        — but the test pins the contract so future changes don't
        silently introduce `+` or `/` characters that would break
        attribute serialisation.
        """
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.1.1.1")

        # Only base64url alphabet plus optional `=` padding (we strip it,
        # but tolerate if a future change adds it back).
        assert all(c.isalnum() or c in "-_=" for c in token)

    def test_anonymous_user_round_trips_as_empty_string(self):
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import issue_token, verify_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            token, _ = issue_token(form_id="c", ip="1.1.1.1")
            payload = verify_token(token)

        assert payload.user_id == ""

    def test_nonce_is_random_when_not_supplied(self):
        """Two tokens issued in quick succession must have distinct nonces."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import issue_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            _, p1 = issue_token(form_id="c", ip="1.1.1.1")
            _, p2 = issue_token(form_id="c", ip="1.1.1.1")

        assert p1.nonce != p2.nonce
        # 16 bytes hex = 32 chars; pin so a future change to length is deliberate.
        assert len(p1.nonce) == 32


# ---------------------------------------------------------------------------
# verify_token failure modes
# ---------------------------------------------------------------------------


class TestVerifyTokenFailures:
    def _issue(self, **kwargs):
        from icv_waf.forms.services.tokens import issue_token

        defaults = {"form_id": "c", "ip": "1.1.1.1"}
        defaults.update(kwargs)
        return issue_token(**defaults)

    def test_tampered_payload_fails_signature_check(self):
        """Flipping a single byte of the payload must invalidate the token."""
        import base64

        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import verify_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            token, _ = self._issue(form_id="contact")
            # Decode, mutate the payload (the IP field), re-encode.
            padding = "=" * (-len(token) % 4)
            raw = base64.urlsafe_b64decode((token + padding).encode("ascii")).decode("utf-8")
            tampered_raw = raw.replace("1.1.1.1", "9.9.9.9", 1)
            tampered = base64.urlsafe_b64encode(tampered_raw.encode("utf-8")).decode("ascii").rstrip("=")

            with pytest.raises(ValueError, match="signature mismatch"):
                verify_token(tampered)

    def test_wrong_signing_key_fails_signature_check(self):
        """Token issued under key A must not verify under key B."""
        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import issue_token, verify_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "key-a"):
            token, _ = issue_token(form_id="c", ip="1.1.1.1")

        with (
            patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "key-b"),
            pytest.raises(ValueError, match="signature mismatch"),
        ):
            verify_token(token)

    def test_malformed_base64_raises_value_error(self):
        from icv_waf.forms.services.tokens import verify_token

        with pytest.raises(ValueError):
            verify_token("not!!base64!!at!!all")

    def test_missing_signature_delimiter_raises_value_error(self):
        """A base64-clean string with no '|' inside is invalid."""
        import base64

        from icv_waf.forms.services.tokens import verify_token

        bad = base64.urlsafe_b64encode(b"no-pipes-here").decode("ascii").rstrip("=")
        with pytest.raises(ValueError, match="no signature delimiter"):
            verify_token(bad)

    def test_wrong_field_count_in_payload_raises_value_error(self):
        """A signature-valid token with the wrong payload shape still fails.

        Pin: if we ever extend the payload, old short-format tokens
        signed with the same key must NOT silently parse into
        defaulted fields. They must blow up loudly.
        """
        import base64
        import hashlib
        import hmac

        import icv_waf.conf as conf_mod
        from icv_waf.forms.services.tokens import verify_token

        with patch.object(conf_mod, "ICV_WAF_SIGNING_KEY", "k"):
            payload_str = "only|three|fields"  # 3 fields, not the required 6
            sig = hmac.new(b"k", payload_str.encode(), hashlib.sha256).hexdigest()
            raw = payload_str + "|" + sig
            token = base64.urlsafe_b64encode(raw.encode()).decode("ascii").rstrip("=")

            with pytest.raises(ValueError, match="expected .* payload fields"):
                verify_token(token)


# ---------------------------------------------------------------------------
# hash_user_agent
# ---------------------------------------------------------------------------


class TestHashUserAgent:
    def test_same_ua_hashes_to_same_value(self):
        from icv_waf.forms.services.tokens import hash_user_agent

        assert hash_user_agent("Mozilla/5.0") == hash_user_agent("Mozilla/5.0")

    def test_different_ua_hashes_to_different_value(self):
        from icv_waf.forms.services.tokens import hash_user_agent

        assert hash_user_agent("Mozilla/5.0") != hash_user_agent("curl/7.0")

    def test_empty_ua_hashes_to_stable_value(self):
        """Anonymous-UA submissions are common; the hash must be stable."""
        from icv_waf.forms.services.tokens import hash_user_agent

        assert hash_user_agent("") == hash_user_agent("")
        # Sanity: SHA-256 hex length.
        assert len(hash_user_agent("")) == 64
