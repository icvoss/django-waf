"""URL routing for the optional django-waf DRF API.

Mounted by ``django_waf/urls.py`` under ``waf/api/`` when
``DJANGO_WAF_API_ENABLED`` is true and ``djangorestframework`` is installed.
See the module docstring in ``api/serializers.py`` for why a plain
``rest_framework`` import is safe here.
"""

from __future__ import annotations

from rest_framework.routers import DefaultRouter

from django_waf.api.viewsets import (
    AllowRuleViewSet,
    BlockRuleViewSet,
    IPReputationViewSet,
    RequestLogViewSet,
)

app_name = "django_waf_api"

router = DefaultRouter()
router.register(r"block-rules", BlockRuleViewSet, basename="block-rule")
router.register(r"allow-rules", AllowRuleViewSet, basename="allow-rule")
router.register(r"request-logs", RequestLogViewSet, basename="request-log")
router.register(r"ip-reputation", IPReputationViewSet, basename="ip-reputation")

urlpatterns = router.urls
