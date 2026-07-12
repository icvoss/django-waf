"""DRF viewsets for the django-waf API.

See the module docstring in ``api/serializers.py`` for why a plain
``rest_framework`` import is safe here.
"""

from __future__ import annotations

from django.utils.translation import gettext_lazy as _
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAdminUser
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet

from django_waf.api.permissions import IsWafAdmin
from django_waf.api.serializers import (
    AllowRuleSerializer,
    BlockRuleSerializer,
    IPReputationSerializer,
    RequestLogSerializer,
)
from django_waf.models import AllowRule, BlockRule, IPReputation, RequestLog


class ServiceUnavailable(APIException):
    """Raised by every django-waf API viewset when the API is disabled."""

    status_code = 503
    default_detail = _("The django-waf API is disabled. Set DJANGO_WAF_API_ENABLED = True to enable it.")


class WafApiEnabledMixin:
    """Raises a 503 before dispatching when DJANGO_WAF_API_ENABLED is False.

    Read live rather than at import time, so a test (or a runtime setting
    change) that flips the flag takes effect on the next request.
    """

    def initial(self, request, *args, **kwargs):
        from django_waf import conf

        if not conf.DJANGO_WAF_API_ENABLED:
            raise ServiceUnavailable()
        super().initial(request, *args, **kwargs)


class BlockRuleViewSet(WafApiEnabledMixin, ModelViewSet):
    """Full CRUD on BlockRule, restricted to WAF admins."""

    queryset = BlockRule.objects.all()
    serializer_class = BlockRuleSerializer
    permission_classes = [IsWafAdmin]


class AllowRuleViewSet(WafApiEnabledMixin, ModelViewSet):
    """Full CRUD on AllowRule, restricted to WAF admins."""

    queryset = AllowRule.objects.all()
    serializer_class = AllowRuleSerializer
    permission_classes = [IsWafAdmin]


class RequestLogViewSet(WafApiEnabledMixin, ReadOnlyModelViewSet):
    """Read-only access to the request audit log, restricted to Django admin users.

    Supports ``?verdict=``, ``?ip_address=``, and ``?from_ts=`` (an ISO 8601
    datetime, filtering to ``timestamp__gte``) query filters.
    """

    queryset = RequestLog.objects.all().order_by("-timestamp")
    serializer_class = RequestLogSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()
        params = self.request.query_params

        verdict = params.get("verdict")
        if verdict:
            queryset = queryset.filter(verdict=verdict)

        ip_address = params.get("ip_address")
        if ip_address:
            queryset = queryset.filter(ip_address=ip_address)

        from_ts = params.get("from_ts")
        if from_ts:
            from django.utils.dateparse import parse_datetime

            parsed = parse_datetime(from_ts)
            if parsed is not None:
                queryset = queryset.filter(timestamp__gte=parsed)

        return queryset


class IPReputationViewSet(WafApiEnabledMixin, ReadOnlyModelViewSet):
    """Read-only access to aggregated IP reputation, restricted to Django admin users.

    Supports a ``?min_threat_score=`` query filter (``threat_score__gte``).
    """

    queryset = IPReputation.objects.all().order_by("-threat_score")
    serializer_class = IPReputationSerializer
    permission_classes = [IsAdminUser]

    def get_queryset(self):
        queryset = super().get_queryset()
        min_threat_score = self.request.query_params.get("min_threat_score")
        if min_threat_score:
            queryset = queryset.filter(threat_score__gte=min_threat_score)
        return queryset
