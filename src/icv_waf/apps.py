from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class IcvWafConfig(AppConfig):
    name = "icv_waf"
    label = "icv_waf"
    verbose_name = _("ICV WAF")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import checks, handlers  # noqa: F401 — register handlers & system checks
