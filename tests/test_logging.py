"""Tests for django_waf.logging.WafStructuredFormatter.

Distinct from django_waf.forms.logging, which is the form-protection
subsystem's own structured logger — this covers the general-purpose
JSON formatter consuming projects attach to the ``django_waf`` logger.
"""

from __future__ import annotations

import json
import logging

from django_waf.logging import WafStructuredFormatter


def _make_record(message: str = "test message", **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name="django_waf.middleware",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg=message,
        args=None,
        exc_info=None,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestWafStructuredFormatter:
    def test_produces_valid_json(self):
        formatter = WafStructuredFormatter()
        record = _make_record("blocked request", ip="203.0.113.1", verdict="blocked")

        output = formatter.format(record)

        parsed = json.loads(output)
        assert parsed["message"] == "blocked request"
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "django_waf.middleware"
        assert "timestamp" in parsed
        assert parsed["ip"] == "203.0.113.1"
        assert parsed["verdict"] == "blocked"

    def test_absent_optional_fields_are_omitted(self):
        formatter = WafStructuredFormatter()
        record = _make_record("plain message")

        output = json.loads(formatter.format(record))

        for field in ("ip", "verdict", "rule_id", "anomaly_score", "latency_ms", "path", "method", "user_agent"):
            assert field not in output

    def test_none_optional_fields_are_omitted(self):
        formatter = WafStructuredFormatter()
        record = _make_record("plain message", ip=None, verdict=None)

        output = json.loads(formatter.format(record))

        assert "ip" not in output
        assert "verdict" not in output

    def test_user_agent_is_truncated_to_200_chars(self):
        formatter = WafStructuredFormatter()
        long_ua = "Mozilla/5.0 " + ("A" * 300)
        record = _make_record("request logged", user_agent=long_ua)

        output = json.loads(formatter.format(record))

        assert len(output["user_agent"]) == 200
        assert output["user_agent"] == long_ua[:200]

    def test_all_optional_fields_included_when_present(self):
        formatter = WafStructuredFormatter()
        record = _make_record(
            "full record",
            ip="198.51.100.7",
            verdict="challenged",
            rule_id="abc-123",
            anomaly_score=6.5,
            latency_ms=12.3,
            path="/login/",
            method="POST",
            user_agent="curl/8.0",
        )

        output = json.loads(formatter.format(record))

        assert output["ip"] == "198.51.100.7"
        assert output["verdict"] == "challenged"
        assert output["rule_id"] == "abc-123"
        assert output["anomaly_score"] == 6.5
        assert output["latency_ms"] == 12.3
        assert output["path"] == "/login/"
        assert output["method"] == "POST"
        assert output["user_agent"] == "curl/8.0"
