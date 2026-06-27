"""django-waf — Self-hosted WAF middleware for Django."""

from importlib.metadata import version

__version__ = version("django-waf")

default_app_config = "django_waf.apps.DjangoWafConfig"
