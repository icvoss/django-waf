"""Structured (JSON) logging formatter for django-waf.

Distinct from ``django_waf.forms.logging``, which is the form-protection
subsystem's own structured logger. This module provides a general-purpose
``logging.Formatter`` for consuming projects to attach to the ``django_waf``
logger (and its ``django_waf.middleware``, ``django_waf.views``,
``django_waf.tasks`` children) so WAF log lines can be ingested by a log
aggregator as one JSON object per line.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

# Fields pulled from the LogRecord when present. user_agent is truncated;
# everything else is included verbatim. A field absent from the record
# (getattr returns None) is omitted from the output entirely rather than
# being written as null.
_OPTIONAL_FIELDS = (
    "ip",
    "verdict",
    "rule_id",
    "anomaly_score",
    "latency_ms",
    "path",
    "method",
    "user_agent",
)

_USER_AGENT_MAX_LENGTH = 200


class WafStructuredFormatter(logging.Formatter):
    """JSON log formatter: one object per line.

    Always includes ``timestamp`` (ISO 8601, from ``record.created``),
    ``level``, ``logger``, and ``message``. Optionally includes ``ip``,
    ``verdict``, ``rule_id``, ``anomaly_score``, ``latency_ms``, ``path``,
    ``method``, and ``user_agent`` when present as attributes on the log
    record (e.g. via ``logger.info(..., extra={"ip": ip, ...})``).
    ``user_agent`` is truncated to 200 characters. Fields that are missing
    or ``None`` on the record are omitted from the output entirely, not
    written as ``null``.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        for field in _OPTIONAL_FIELDS:
            value = getattr(record, field, None)
            if value is None:
                continue
            if field == "user_agent":
                value = str(value)[:_USER_AGENT_MAX_LENGTH]
            payload[field] = value

        return json.dumps(payload)
