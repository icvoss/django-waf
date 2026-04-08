"""Admin registrations for icv-waf models."""

from django.contrib import admin
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from icv_waf.models import (
    AllowRule,
    BlockRule,
    ChallengeToken,
    IPReputation,
    RequestLog,
)

# ---------------------------------------------------------------------------
# Admin actions
# ---------------------------------------------------------------------------


@admin.action(description=_("Activate selected rules"))
def activate_rules(modeladmin, request, queryset):
    """Set is_active=True on all selected rules."""
    updated = queryset.update(is_active=True)
    modeladmin.message_user(
        request,
        _("%(count)d rule(s) activated.") % {"count": updated},
    )


@admin.action(description=_("Deactivate selected rules"))
def deactivate_rules(modeladmin, request, queryset):
    """Set is_active=False on all selected rules."""
    updated = queryset.update(is_active=False)
    modeladmin.message_user(
        request,
        _("%(count)d rule(s) deactivated.") % {"count": updated},
    )


@admin.action(description=_("Extend expiry by 24 hours"))
def extend_expiry(modeladmin, request, queryset):
    """Add 24 hours to expires_at for selected rules (or set it from now if blank)."""
    updated = 0
    for rule in queryset:
        if rule.expires_at is None:
            rule.expires_at = timezone.now() + timezone.timedelta(hours=24)
        else:
            rule.expires_at = rule.expires_at + timezone.timedelta(hours=24)
        rule.save(update_fields=["expires_at"])
        updated += 1
    modeladmin.message_user(
        request,
        _("%(count)d rule(s) extended by 24 hours.") % {"count": updated},
    )


# ---------------------------------------------------------------------------
# BlockRule
# ---------------------------------------------------------------------------


@admin.register(BlockRule)
class BlockRuleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "rule_type",
        "match_type",
        "action",
        "priority",
        "is_active",
        "source",
        "hit_count",
        "expires_at",
        "confidence",
    ]
    list_filter = ["rule_type", "action", "is_active", "source"]
    search_fields = ["name", "pattern", "notes"]
    ordering = ["priority", "name"]
    readonly_fields = ["hit_count", "last_hit_at", "created_at", "updated_at"]
    actions = [activate_rules, deactivate_rules, extend_expiry]
    fieldsets = [
        (
            None,
            {
                "fields": [
                    "name",
                    "rule_type",
                    "match_type",
                    "pattern",
                    "action",
                    "priority",
                    "is_active",
                    "source",
                    "notes",
                ]
            },
        ),
        (
            _("Expiry"),
            {
                "fields": ["expires_at"],
            },
        ),
        (
            _("Feed metadata"),
            {
                "fields": ["confidence", "feed_first_seen", "feed_reporters"],
                "classes": ["collapse"],
            },
        ),
        (
            _("Statistics"),
            {
                "fields": ["hit_count", "last_hit_at"],
                "classes": ["collapse"],
            },
        ),
        (
            _("Timestamps"),
            {
                "fields": ["created_at", "updated_at"],
                "classes": ["collapse"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# AllowRule
# ---------------------------------------------------------------------------


@admin.register(AllowRule)
class AllowRuleAdmin(admin.ModelAdmin):
    list_display = [
        "name",
        "rule_type",
        "match_type",
        "pattern",
        "is_active",
        "verify_rdns",
    ]
    list_filter = ["rule_type", "is_active", "verify_rdns"]
    search_fields = ["name", "pattern", "rdns_pattern", "notes"]
    ordering = ["name"]
    readonly_fields = ["created_at", "updated_at"]
    actions = [activate_rules, deactivate_rules]
    fieldsets = [
        (
            None,
            {
                "fields": [
                    "name",
                    "rule_type",
                    "match_type",
                    "pattern",
                    "is_active",
                    "notes",
                ]
            },
        ),
        (
            _("Reverse DNS verification"),
            {
                "fields": ["verify_rdns", "rdns_pattern"],
                "classes": ["collapse"],
            },
        ),
        (
            _("Timestamps"),
            {
                "fields": ["created_at", "updated_at"],
                "classes": ["collapse"],
            },
        ),
    ]


# ---------------------------------------------------------------------------
# RequestLog (read-only)
# ---------------------------------------------------------------------------


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = [
        "timestamp",
        "ip_address",
        "method",
        "path",
        "verdict",
        "response_code",
        "anomaly_score",
        "referer",
        "fingerprint_verdict",
        "country_code",
    ]
    list_filter = ["verdict", "method", "fingerprint_verdict", "country_code"]
    search_fields = ["ip_address", "path", "user_agent", "referer", "http_fingerprint"]
    ordering = ["-timestamp"]
    date_hierarchy = "timestamp"
    readonly_fields = [
        "timestamp",
        "ip_address",
        "user_agent",
        "path",
        "method",
        "verdict",
        "matched_rule_id",
        "matched_rule_type",
        "anomaly_score",
        "response_code",
        "referer",
        "http_fingerprint",
        "fingerprint_verdict",
        "country_code",
        "created_at",
        "updated_at",
    ]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False


# ---------------------------------------------------------------------------
# IPReputation (read-only)
# ---------------------------------------------------------------------------


@admin.register(IPReputation)
class IPReputationAdmin(admin.ModelAdmin):
    list_display = [
        "ip_address",
        "threat_score",
        "total_requests",
        "blocked_requests",
        "challenged_requests",
        "distinct_ua_count",
        "last_seen_at",
    ]
    list_filter = []
    search_fields = ["ip_address"]
    ordering = ["-threat_score"]
    readonly_fields = [
        "ip_address",
        "total_requests",
        "blocked_requests",
        "challenged_requests",
        "challenge_passes",
        "challenge_failures",
        "distinct_ua_count",
        "threat_score",
        "last_seen_at",
        "window_start",
        "window_end",
        "created_at",
        "updated_at",
    ]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False


# ---------------------------------------------------------------------------
# ChallengeToken (read-only)
# ---------------------------------------------------------------------------


@admin.register(ChallengeToken)
class ChallengeTokenAdmin(admin.ModelAdmin):
    list_display = [
        "token_short",
        "ip_address",
        "status",
        "difficulty",
        "issued_at",
        "expires_at",
        "solved_at",
    ]
    list_filter = ["status", "difficulty"]
    search_fields = ["ip_address", "token"]
    ordering = ["-issued_at"]
    readonly_fields = [
        "token",
        "ip_address",
        "difficulty",
        "nonce",
        "status",
        "issued_at",
        "expires_at",
        "solved_at",
        "created_at",
        "updated_at",
    ]

    @admin.display(description=_("Token"))
    def token_short(self, obj) -> str:
        """Display the first 12 characters of the token for readability."""
        return f"{obj.token[:12]}..."

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False
