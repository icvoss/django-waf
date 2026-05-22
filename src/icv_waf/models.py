"""Models for icv-waf."""

from __future__ import annotations

import uuid
from decimal import Decimal

from django.db import models
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from icv_waf.enums import (
    ChallengeStatus,
    MatchType,
    RuleAction,
    RuleSource,
    RuleType,
    Verdict,
)

# ---------------------------------------------------------------------------
# Abstract base model — UUID PK + timestamps
# ---------------------------------------------------------------------------


class BaseModel(models.Model):
    """Abstract base with UUID primary key and created/updated timestamps.

    Field-compatible with ``icv_core.models.BaseModel`` for projects that use
    the ICV-Django ecosystem, but fully standalone — no external dependency.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True
        ordering = ["-created_at"]


# ---------------------------------------------------------------------------
# BlockRule
# ---------------------------------------------------------------------------


class BlockRuleManager(models.Manager):
    """Custom manager for BlockRule with convenience querysets."""

    def active(self) -> models.QuerySet:
        """Return all active rules ordered by priority."""
        return self.filter(is_active=True).order_by("priority")

    def for_nginx(self) -> models.QuerySet:
        """Return active IP/CIDR/UA block or throttle rules suitable for nginx export."""
        return self.active().filter(
            rule_type__in=[RuleType.IP, RuleType.CIDR, RuleType.UA],
            action__in=[RuleAction.BLOCK, RuleAction.THROTTLE],
        )

    def auto_generated(self) -> models.QuerySet:
        """Return active auto-generated rules."""
        return self.active().filter(source=RuleSource.AUTO)

    def feed_sourced(self) -> models.QuerySet:
        """Return active rules sourced from the collective threat feed."""
        return self.active().filter(source=RuleSource.FEED)

    def expired(self) -> models.QuerySet:
        """Return active rules whose expiry time has passed."""
        return self.filter(is_active=True, expires_at__lte=timezone.now())


class BlockRule(BaseModel):
    """
    A WAF rule that triggers a block, challenge, throttle, or log action.

    Rules are evaluated in priority order (lowest number first). The first
    matching rule's action is applied to the request.
    """

    name = models.CharField(
        max_length=255,
        verbose_name=_("name"),
    )
    rule_type = models.CharField(
        max_length=20,
        choices=RuleType.choices,
        db_index=True,
        verbose_name=_("rule type"),
    )
    match_type = models.CharField(
        max_length=20,
        choices=MatchType.choices,
        verbose_name=_("match type"),
    )
    pattern = models.CharField(
        max_length=2048,
        db_index=True,
        verbose_name=_("pattern"),
        help_text=_("Value to match against (IP, CIDR, user-agent string, or regex)."),
    )
    action = models.CharField(
        max_length=20,
        choices=RuleAction.choices,
        default=RuleAction.BLOCK,
        verbose_name=_("action"),
    )
    priority = models.PositiveIntegerField(
        default=100,
        db_index=True,
        verbose_name=_("priority"),
        help_text=_("Lower numbers are evaluated first."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("active"),
    )
    source = models.CharField(
        max_length=20,
        choices=RuleSource.choices,
        default=RuleSource.ADMIN,
        verbose_name=_("source"),
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("expires at"),
        help_text=_("Leave blank for rules that never expire."),
    )
    hit_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("hit count"),
    )
    last_hit_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("last hit at"),
    )
    confidence = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal("1.00"),
        verbose_name=_("confidence"),
        help_text=_("Confidence score from 0.00 to 1.00 (feed-sourced rules only)."),
    )
    feed_first_seen = models.DateField(
        null=True,
        blank=True,
        verbose_name=_("feed first seen"),
    )
    feed_reporters = models.PositiveIntegerField(
        default=0,
        verbose_name=_("feed reporters"),
        help_text=_("Number of sites that reported this threat to the collective feed."),
    )
    notes = models.TextField(
        blank=True,
        verbose_name=_("notes"),
    )

    objects = BlockRuleManager()

    class Meta:
        db_table = "icv_waf_block_rule"
        ordering = ["priority", "-created_at"]
        verbose_name = _("block rule")
        verbose_name_plural = _("block rules")
        indexes = [
            models.Index(fields=["rule_type", "is_active"], name="icv_waf_br_type_active_idx"),
            models.Index(fields=["source", "is_active"], name="icv_waf_br_source_active_idx"),
            models.Index(fields=["priority", "is_active"], name="icv_waf_br_priority_active_idx"),
            models.Index(
                fields=["expires_at"],
                condition=Q(is_active=True),
                name="icv_waf_br_expires_active_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"[{self.action}] {self.name}"


# ---------------------------------------------------------------------------
# AllowRule
# ---------------------------------------------------------------------------


class AllowRuleManager(models.Manager):
    """Custom manager for AllowRule with convenience querysets."""

    def active(self) -> models.QuerySet:
        """Return all active allow rules."""
        return self.filter(is_active=True)

    def requiring_rdns(self) -> models.QuerySet:
        """Return active rules that require reverse-DNS verification."""
        return self.active().filter(verify_rdns=True)


class AllowRule(BaseModel):
    """
    A WAF allowlist rule that exempts matching requests from block evaluation.

    Allow rules are evaluated before block rules. A match here bypasses all
    block/challenge/throttle logic for that request.
    """

    name = models.CharField(
        max_length=255,
        verbose_name=_("name"),
    )
    rule_type = models.CharField(
        max_length=20,
        choices=RuleType.choices,
        db_index=True,
        verbose_name=_("rule type"),
    )
    match_type = models.CharField(
        max_length=20,
        choices=MatchType.choices,
        verbose_name=_("match type"),
    )
    pattern = models.CharField(
        max_length=2048,
        verbose_name=_("pattern"),
        help_text=_("Value to match against (IP, CIDR, user-agent string, or regex)."),
    )
    verify_rdns = models.BooleanField(
        default=False,
        verbose_name=_("verify rDNS"),
        help_text=_("Require reverse-DNS lookup to confirm the IP belongs to a trusted network."),
    )
    rdns_pattern = models.CharField(
        max_length=255,
        blank=True,
        verbose_name=_("rDNS pattern"),
        help_text=_("Regex or suffix matched against the PTR record when verify_rdns is enabled."),
    )
    is_active = models.BooleanField(
        default=True,
        db_index=True,
        verbose_name=_("active"),
    )
    notes = models.TextField(
        blank=True,
        verbose_name=_("notes"),
    )

    objects = AllowRuleManager()

    class Meta:
        db_table = "icv_waf_allow_rule"
        ordering = ["name"]
        verbose_name = _("allow rule")
        verbose_name_plural = _("allow rules")
        indexes = [
            models.Index(fields=["rule_type", "is_active"], name="icv_waf_ar_type_active_idx"),
            models.Index(fields=["is_active"], name="icv_waf_ar_active_idx"),
        ]

    def __str__(self) -> str:
        return f"[allow] {self.name}"


# ---------------------------------------------------------------------------
# RequestLog
# ---------------------------------------------------------------------------


class RequestLogManager(models.Manager):
    """Custom manager for RequestLog with convenience querysets."""

    def recent(self, hours: int = 24) -> models.QuerySet:
        """Return log entries from the last N hours."""
        cutoff = timezone.now() - timezone.timedelta(hours=hours)
        return self.filter(timestamp__gte=cutoff)

    def for_ip(self, ip: str) -> models.QuerySet:
        """Return all log entries for a given IP address."""
        return self.filter(ip_address=ip)

    def blocked(self) -> models.QuerySet:
        """Return log entries with a blocked verdict."""
        return self.filter(verdict=Verdict.BLOCKED)

    def purgeable(self, days: int = 30) -> models.QuerySet:
        """Return log entries older than N days, suitable for deletion."""
        cutoff = timezone.now() - timezone.timedelta(days=days)
        return self.filter(timestamp__lt=cutoff)


class RequestLog(BaseModel):
    """
    Sampled log of requests evaluated by the WAF middleware.

    Not every request is recorded — the sample rate is controlled by
    ICV_WAF_LOG_SAMPLE_RATE. Blocked and challenged requests are always logged
    regardless of the sample rate.

    matched_rule_id is stored as a plain UUID (not a ForeignKey) so that
    log rows survive rule deletion without cascading.
    """

    MATCHED_RULE_TYPE_CHOICES = [
        ("block", _("Block rule")),
        ("allow", _("Allow rule")),
    ]

    timestamp = models.DateTimeField(
        db_index=True,
        verbose_name=_("timestamp"),
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        verbose_name=_("IP address"),
    )
    user_agent = models.CharField(
        max_length=1024,
        blank=True,
        verbose_name=_("user-agent"),
    )
    path = models.CharField(
        max_length=2048,
        verbose_name=_("path"),
    )
    method = models.CharField(
        # 16 fits the longest IANA-registered method (BASELINE-CONTROL).
        max_length=16,
        default="GET",
        verbose_name=_("method"),
    )
    verdict = models.CharField(
        max_length=20,
        choices=Verdict.choices,
        db_index=True,
        verbose_name=_("verdict"),
    )
    # Plain UUID — not a FK so log rows survive rule deletion.
    matched_rule_id = models.UUIDField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("matched rule ID"),
    )
    matched_rule_type = models.CharField(
        max_length=10,
        choices=MATCHED_RULE_TYPE_CHOICES,
        blank=True,
        default="",
        verbose_name=_("matched rule type"),
        help_text=_(
            "Which rule table matched — 'block' = a BlockRule, 'allow' = an "
            "AllowRule. This is the source table, NOT the enforced action: a "
            "BlockRule with action=challenge produces matched_rule_type='block' "
            "and verdict='challenged'. Use the verdict column for enforcement "
            "reporting; use this column for rule-source auditing."
        ),
    )
    anomaly_score = models.DecimalField(
        max_digits=4,
        decimal_places=2,
        null=True,
        blank=True,
        verbose_name=_("anomaly score"),
    )
    response_code = models.PositiveSmallIntegerField(
        null=True,
        blank=True,
        verbose_name=_("response code"),
    )
    referer = models.CharField(
        max_length=2048,
        blank=True,
        verbose_name=_("referer"),
        help_text=_("HTTP Referer header value, useful for identifying bot traffic sources."),
    )
    http_fingerprint = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        verbose_name=_("HTTP fingerprint"),
        help_text=_("SHA-256 hash of normalised HTTP headers — identifies real client software."),
    )
    fingerprint_verdict = models.CharField(
        max_length=20,
        blank=True,
        verbose_name=_("fingerprint verdict"),
        help_text=_("Fingerprint classification: browser, bot, suspicious, unknown."),
    )
    country_code = models.CharField(
        max_length=2,
        blank=True,
        verbose_name=_("country code"),
    )

    objects = RequestLogManager()

    class Meta:
        db_table = "icv_waf_request_log"
        ordering = ["-timestamp"]
        verbose_name = _("request log")
        verbose_name_plural = _("request logs")
        indexes = [
            models.Index(fields=["timestamp", "verdict"], name="icv_waf_rl_ts_verdict_idx"),
            models.Index(fields=["ip_address", "timestamp"], name="icv_waf_rl_ip_ts_idx"),
            models.Index(fields=["verdict", "timestamp"], name="icv_waf_rl_verdict_ts_idx"),
            models.Index(fields=["matched_rule_id"], name="icv_waf_rl_rule_id_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.timestamp} {self.ip_address} {self.verdict}"


# ---------------------------------------------------------------------------
# IPReputation
# ---------------------------------------------------------------------------


class IPReputationManager(models.Manager):
    """Custom manager for IPReputation with convenience querysets."""

    def high_threat(self, threshold: float = 0.7) -> models.QuerySet:
        """Return IPs whose threat score exceeds the given threshold."""
        return self.filter(threat_score__gte=threshold)

    def top_offenders(self, limit: int = 10) -> models.QuerySet:
        """Return the top N IPs ordered by threat score descending."""
        return self.order_by("-threat_score")[:limit]


class IPReputation(BaseModel):
    """
    Aggregated reputation metrics for a single IP address.

    Maintained by the scoring service as requests are processed. One row per IP.
    The threat_score is a normalised value in [0.00, 1.00] derived from the
    ratio of blocked/challenged requests, UA rotation count, and other signals.
    """

    ip_address = models.GenericIPAddressField(
        unique=True,
        db_index=True,
        verbose_name=_("IP address"),
    )
    total_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("total requests"),
    )
    blocked_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("blocked requests"),
    )
    challenged_requests = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenged requests"),
    )
    challenge_passes = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenge passes"),
    )
    challenge_failures = models.PositiveIntegerField(
        default=0,
        verbose_name=_("challenge failures"),
    )
    distinct_ua_count = models.PositiveIntegerField(
        default=0,
        verbose_name=_("distinct UA count"),
    )
    threat_score = models.DecimalField(
        max_digits=3,
        decimal_places=2,
        default=Decimal("0.00"),
        verbose_name=_("threat score"),
        help_text=_("Normalised threat score from 0.00 (clean) to 1.00 (high threat)."),
    )
    last_seen_at = models.DateTimeField(
        null=True,
        blank=True,
        db_index=True,
        verbose_name=_("last seen at"),
    )
    window_start = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("window start"),
        help_text=_("Start of the current scoring window."),
    )
    window_end = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("window end"),
        help_text=_("End of the current scoring window."),
    )

    objects = IPReputationManager()

    class Meta:
        db_table = "icv_waf_ip_reputation"
        ordering = ["-threat_score"]
        verbose_name = _("IP reputation")
        verbose_name_plural = _("IP reputations")
        indexes = [
            models.Index(fields=["threat_score"], name="icv_waf_ipr_score_idx"),
            models.Index(fields=["last_seen_at"], name="icv_waf_ipr_last_seen_idx"),
            models.Index(fields=["distinct_ua_count"], name="icv_waf_ipr_ua_count_idx"),
        ]

    def __str__(self) -> str:
        return f"{self.ip_address} (score={self.threat_score})"


# ---------------------------------------------------------------------------
# ChallengeToken
# ---------------------------------------------------------------------------


class ChallengeToken(BaseModel):
    """
    A proof-of-work challenge token issued to a suspicious client.

    The client must solve a hashcash-style puzzle (finding a nonce such that
    SHA-256(token + nonce) has ``difficulty`` leading zero bits) before
    receiving a solved-challenge cookie that bypasses future challenges.
    """

    token = models.CharField(
        max_length=128,
        unique=True,
        db_index=True,
        verbose_name=_("token"),
    )
    ip_address = models.GenericIPAddressField(
        db_index=True,
        verbose_name=_("IP address"),
    )
    difficulty = models.PositiveSmallIntegerField(
        default=4,
        verbose_name=_("difficulty"),
        help_text=_("Number of leading zero bits required in the solution hash."),
    )
    nonce = models.CharField(
        max_length=128,
        blank=True,
        verbose_name=_("nonce"),
        help_text=_("The nonce submitted by the client when solving the challenge."),
    )
    status = models.CharField(
        max_length=20,
        choices=ChallengeStatus.choices,
        default=ChallengeStatus.PENDING,
        db_index=True,
        verbose_name=_("status"),
    )
    issued_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("issued at"),
    )
    expires_at = models.DateTimeField(
        db_index=True,
        verbose_name=_("expires at"),
    )
    solved_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name=_("solved at"),
    )

    class Meta:
        db_table = "icv_waf_challenge_token"
        ordering = ["-issued_at"]
        verbose_name = _("challenge token")
        verbose_name_plural = _("challenge tokens")
        indexes = [
            models.Index(fields=["ip_address", "status"], name="icv_waf_ct_ip_status_idx"),
            models.Index(fields=["expires_at"], name="icv_waf_ct_expires_idx"),
        ]

    def __str__(self) -> str:
        return f"Challenge {self.token[:12]}... ({self.status})"
