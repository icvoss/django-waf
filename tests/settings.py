"""
Django settings for icv-waf tests.

Minimal configuration — MIGRATION_MODULES set to None so syncdb creates
tables directly without running migrations.
"""

SECRET_KEY = "icv-waf-test-secret-key"  # noqa: S105

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "django.contrib.admin",
    "django.contrib.sessions",
    "icv_core",
    "icv_waf",
]

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

MIGRATION_MODULES = {
    "icv_core": None,
    "icv_waf": None,
    "contenttypes": None,
    "auth": None,
    "admin": None,
    "sessions": None,
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

USE_TZ = True
TIME_ZONE = "UTC"

ROOT_URLCONF = "icv_waf.urls"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# icv-waf settings
ICV_WAF_ENABLED = True
ICV_WAF_FEED_ENABLED = False  # Never hit the real feed in tests
ICV_WAF_FEED_REPORT = False  # Never report to the feed in tests
ICV_WAF_LOG_SAMPLE_RATE = 1.0  # Log everything in tests
