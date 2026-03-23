"""Shared pytest fixtures for icv-waf tests."""


def pytest_configure(config):
    """Ensure icv_waf is in INSTALLED_APPS when running from the project root."""
    from django.conf import settings

    if not settings.configured:
        return
    for app in ("icv_waf",):
        if app not in settings.INSTALLED_APPS:
            settings.INSTALLED_APPS = [*settings.INSTALLED_APPS, app]
    if not hasattr(settings, "MIGRATION_MODULES"):
        settings.MIGRATION_MODULES = {}
    settings.MIGRATION_MODULES.setdefault("icv_waf", None)

    # Ensure WAF settings exist for tests
    defaults = {
        "ICV_WAF_ENABLED": True,
        "ICV_WAF_FEED_ENABLED": False,
        "ICV_WAF_FEED_REPORT": False,
        "ICV_WAF_LOG_SAMPLE_RATE": 1.0,
    }
    for key, value in defaults.items():
        if not hasattr(settings, key):
            setattr(settings, key, value)
