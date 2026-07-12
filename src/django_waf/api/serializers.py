"""DRF serializers for the django-waf API.

This module is only ever imported from within the API wiring (``api/urls.py``
via ``django_waf/urls.py``, guarded by ``DJANGO_WAF_API_ENABLED`` and a
``try``/``except ImportError``), so a plain ``rest_framework`` import here is
safe: nothing at package-import time reaches this module.
"""

from __future__ import annotations

from rest_framework import serializers

from django_waf.models import AllowRule, BlockRule, IPReputation, RequestLog


class BlockRuleSerializer(serializers.ModelSerializer):
    """Full CRUD serializer for BlockRule.

    Hit-tracking and provenance fields are maintained by the rule engine and
    the threat-feed sync task, not by API clients, so they are read-only.
    """

    class Meta:
        model = BlockRule
        fields = "__all__"
        read_only_fields = [
            "id",
            "created_at",
            "updated_at",
            "hit_count",
            "last_hit_at",
            "source",
        ]


class AllowRuleSerializer(serializers.ModelSerializer):
    """Full CRUD serializer for AllowRule."""

    class Meta:
        model = AllowRule
        fields = "__all__"
        read_only_fields = ["id", "created_at", "updated_at"]


class RequestLogSerializer(serializers.ModelSerializer):
    """Read-only serializer for RequestLog — an audit log, never written via the API."""

    class Meta:
        model = RequestLog
        fields = "__all__"
        read_only_fields = [field.name for field in RequestLog._meta.get_fields() if hasattr(field, "attname")]


class IPReputationSerializer(serializers.ModelSerializer):
    """Read-only serializer for IPReputation — maintained by the scoring service."""

    class Meta:
        model = IPReputation
        fields = "__all__"
        read_only_fields = [field.name for field in IPReputation._meta.get_fields() if hasattr(field, "attname")]
