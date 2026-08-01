from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class DjangoWafConfig(AppConfig):
    name = "django_waf"
    label = "django_waf"
    verbose_name = _("Django WAF")
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from . import checks, handlers  # noqa: F401 — register handlers & system checks

        # #23: connect the trusted-user-cookie login receiver only when the
        # feature is enabled at process startup. ready() runs once, so
        # toggling DJANGO_WAF_TRUSTED_COOKIE_ENABLED needs a restart to take
        # effect — the standard Django app-loading contract, and consistent
        # with every other opt-in wiring in this method.
        from django_waf import conf

        if conf.DJANGO_WAF_TRUSTED_COOKIE_ENABLED:
            from . import receivers

            receivers.connect()
