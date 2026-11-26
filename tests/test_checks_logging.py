"""Tests for the django_waf.checks logging-handler boot check (django_waf.E010).

ADR-101 decision 3 (umbrella icvoss/icv-oss-umbrella#678). The check function
is driven directly with ``app_configs=None``; one test also asserts it is
registered with Django's check registry.
"""

from __future__ import annotations

import contextlib
import logging

from django.core import checks
from django.core.checks.registry import registry

from django_waf.checks import check_logging_handler_configured


class TestLoggingHandlerConfigured:
    """ADR-101 decision 3 (django_waf.E010): error when nothing would receive a record
    logged by the django_waf logger hierarchy (umbrella icvoss/icv-oss-umbrella#678)."""

    @staticmethod
    @contextlib.contextmanager
    def _logger_state(*names):
        """Snapshot and restore handlers, propagate and level of the named loggers."""
        loggers = [logging.getLogger(name) for name in names]
        saved = [(list(lg.handlers), lg.propagate, lg.level) for lg in loggers]
        try:
            yield loggers
        finally:
            for lg, (handlers, propagate, level) in zip(loggers, saved, strict=True):
                lg.handlers = handlers
                lg.propagate = propagate
                lg.setLevel(level)

    def test_errors_when_no_handler_and_no_propagation(self):
        with self._logger_state("django_waf") as (logger,):
            logger.handlers = []
            logger.propagate = False

            errors = check_logging_handler_configured(None)

        assert [e.id for e in errors] == ["django_waf.E010"]

    def test_error_names_the_logger_and_a_remedy(self):
        with self._logger_state("django_waf") as (logger,):
            logger.handlers = []
            logger.propagate = False

            (error,) = check_logging_handler_configured(None)

        assert "'django_waf'" in error.msg
        assert "LOGGING" in error.hint

    def test_silent_when_a_handler_is_attached_to_the_package_logger(self):
        with self._logger_state("django_waf") as (logger,):
            logger.handlers = [logging.NullHandler()]
            logger.propagate = False

            errors = check_logging_handler_configured(None)

        assert errors == []

    def test_silent_when_a_propagating_ancestor_has_a_handler(self):
        """A handler on the root logger counts, provided the package logger
        still propagates up to it."""
        with self._logger_state("django_waf", "") as (logger, root):
            logger.handlers = []
            logger.propagate = True
            root.handlers = [logging.NullHandler()]

            errors = check_logging_handler_configured(None)

        assert errors == []

    def test_errors_when_propagation_is_cut_before_a_handled_ancestor(self):
        with self._logger_state("django_waf", "") as (logger, root):
            logger.handlers = []
            logger.propagate = False
            root.handlers = [logging.NullHandler()]

            errors = check_logging_handler_configured(None)

        assert [e.id for e in errors] == ["django_waf.E010"]

    def test_ignores_lastresort_as_a_configured_handler(self):
        """logging.lastResort is the stdlib's unmanaged stderr fallback, not
        a handler the consumer configured; it must not silence the error."""
        with self._logger_state("django_waf") as (logger,):
            logger.handlers = [logging.lastResort]
            logger.propagate = False

            errors = check_logging_handler_configured(None)

        assert [e.id for e in errors] == ["django_waf.E010"]

    def test_is_registered_with_the_django_check_framework(self):
        """The check must run under ``manage.py check``, not only when called directly."""
        assert check_logging_handler_configured in registry.registered_checks


def test_logging_handler_check_is_an_error_not_a_warning():
    """ADR-101 decision 3 and docs/STANDARDS.md section 15: the boot check is an Error."""
    logger = logging.getLogger("django_waf")
    saved = (list(logger.handlers), logger.propagate, logger.level)
    try:
        logger.handlers = []
        logger.propagate = False
        (message,) = check_logging_handler_configured(None)
    finally:
        logger.handlers, logger.propagate = saved[0], saved[1]
        logger.setLevel(saved[2])

    assert message.level == checks.ERROR
    assert message.id == "django_waf.E010"
