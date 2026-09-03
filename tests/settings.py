"""Django settings for django-waf tests."""

import os

SECRET_KEY = "django-waf-test-secret-key"  # noqa: S105
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Registered so the browsable API and DRF's own app config work when the
    # dev extra (which pulls in djangorestframework) is installed. The
    # package itself never requires this, see django_waf/api/__init__.py.
    "rest_framework",
    "django_waf",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django_waf.middleware.WafMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "tests.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# The suite runs on sqlite by default, which keeps a local run dependency-free,
# but sqlite is materially more permissive than the PostgreSQL that consumers
# actually deploy on. It does not validate GenericIPAddressField values on
# bulk_create, and it differs on constraint and transaction behaviour, so a
# regression test for a defect of that class can pass on sqlite whether or not
# the defect is fixed (issue #72). Setting DJANGO_WAF_TEST_DB=postgres runs the
# same suite against a real PostgreSQL server; CI does this on a dedicated leg.
if os.environ.get("DJANGO_WAF_TEST_DB") == "postgres":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.environ.get("POSTGRES_DB", "django_waf_test"),
            "USER": os.environ.get("POSTGRES_USER", "postgres"),
            "PASSWORD": os.environ.get("POSTGRES_PASSWORD", "postgres"),
            "HOST": os.environ.get("POSTGRES_HOST", "localhost"),
            "PORT": os.environ.get("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    }

# Schema is built directly from the models rather than by running migrations,
# which is faster but means the suite cannot see a model-vs-migration
# divergence: that is exactly how issue #105 shipped a BlockRule.detectors
# default that disagreed with migration 0006 and broke makemigrations --check
# for every consumer. tests/test_migrations.py covers that gap explicitly by
# running the autodetector, and it handles this setting deliberately; read it
# before changing anything here.
MIGRATION_MODULES = {
    "django_waf": None,
    "contenttypes": None,
    "auth": None,
    "admin": None,
    "sessions": None,
}

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-gb"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
    }
}

# Celery
CELERY_TASK_ALWAYS_EAGER = True

# django-waf settings
DJANGO_WAF_ENABLED = True
DJANGO_WAF_FEED_ENABLED = False  # Never hit the real feed in tests
DJANGO_WAF_FEED_REPORT = False  # Never report to the feed in tests
DJANGO_WAF_LOG_SAMPLE_RATE = 1.0  # Log everything in tests
# Never run the real `nginx -t` in tests. On a runner where an nginx binary
# exists (CI), validation would actually execute and fail as a non-root user
# (cannot open /run/nginx.pid), rolling the generated file away underneath
# any test that reads it. Tests covering the validation/rollback behaviour
# itself set this True explicitly and mock the validator (#31).
DJANGO_WAF_NGINX_VALIDATE = False

# Enabled at urlconf-import time so waf/api/ routes exist for tests/test_api.py.
# Individual tests exercise the disabled (503) path by patching
# django_waf.conf.DJANGO_WAF_API_ENABLED directly, which api/viewsets.py reads
# live on every request via WafApiEnabledMixin.initial().
DJANGO_WAF_API_ENABLED = True
