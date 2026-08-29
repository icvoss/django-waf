"""Shared pytest fixtures for django-waf tests."""

import pytest


@pytest.fixture(autouse=True)
def _clear_rule_cache():
    """Reset the in-process rule cache between tests."""
    import django_waf.services.rule_engine as re_mod

    re_mod._process_cache = None
    re_mod._process_cache_version = -1
    yield
    re_mod._process_cache = None
    re_mod._process_cache_version = -1


def pytest_configure(config):
    """Ensure django_waf is in INSTALLED_APPS when running from the project root."""
    from django.conf import settings

    if not settings.configured:
        return
    for app in ("django_waf",):
        if app not in settings.INSTALLED_APPS:
            settings.INSTALLED_APPS = [*settings.INSTALLED_APPS, app]
    if not hasattr(settings, "MIGRATION_MODULES"):
        settings.MIGRATION_MODULES = {}
    settings.MIGRATION_MODULES.setdefault("django_waf", None)

    # Ensure ROOT_URLCONF is always set — Django 6 removed the global default,
    # and override_settings can lose it if a site-packages "tests" package
    # shadows the project's tests/ directory during re-resolution.
    if not hasattr(settings, "ROOT_URLCONF"):
        settings.ROOT_URLCONF = "tests.urls"

    # Ensure WAF settings exist for tests
    defaults = {
        "DJANGO_WAF_ENABLED": True,
        "DJANGO_WAF_FEED_ENABLED": False,
        "DJANGO_WAF_FEED_REPORT": False,
        "DJANGO_WAF_LOG_SAMPLE_RATE": 1.0,
    }
    for key, value in defaults.items():
        if not hasattr(settings, key):
            setattr(settings, key, value)
