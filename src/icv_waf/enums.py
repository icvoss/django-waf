"""TextChoices enums for icv-waf models."""

from django.db import models
from django.utils.translation import gettext_lazy as _


class RuleAction(models.TextChoices):
    """What the WAF does when a rule matches a request."""

    BLOCK = "block", _("Block")
    CHALLENGE = "challenge", _("Challenge")
    THROTTLE = "throttle", _("Throttle")
    LOG_ONLY = "log_only", _("Log only")


class RuleType(models.TextChoices):
    """The dimension a rule matches against."""

    UA = "ua", _("User-agent")
    IP = "ip", _("IP address")
    CIDR = "cidr", _("CIDR range")
    COMPOSITE = "composite", _("Composite")


class MatchType(models.TextChoices):
    """How the rule pattern is applied during matching."""

    EXACT = "exact", _("Exact")
    REGEX = "regex", _("Regex")
    CONTAINS = "contains", _("Contains")
    CIDR = "cidr", _("CIDR")


class RuleSource(models.TextChoices):
    """How a rule was created."""

    ADMIN = "admin", _("Admin")
    AUTO = "auto", _("Auto-generated")
    FEED = "feed", _("Threat feed")


class Verdict(models.TextChoices):
    """The outcome recorded for a logged request."""

    ALLOWED = "allowed", _("Allowed")
    BLOCKED = "blocked", _("Blocked")
    CHALLENGED = "challenged", _("Challenged")
    THROTTLED = "throttled", _("Throttled")
    PASSED = "passed", _("Passed")
    LOGGED = "logged", _("Logged")


class ChallengeStatus(models.TextChoices):
    """Current status of a proof-of-work challenge token."""

    PENDING = "pending", _("Pending")
    SOLVED = "solved", _("Solved")
    EXPIRED = "expired", _("Expired")
    FAILED = "failed", _("Failed")


class AnomalyType(models.TextChoices):
    """The category of anomaly detected by the scoring engine."""

    UA_ROTATION = "ua_rotation", _("UA rotation")
    BURST = "burst", _("Burst")
    SUBNET_FLOOD = "subnet_flood", _("Subnet flood")
    PATH_HAMMERING = "path_hammering", _("Path hammering")
    CHALLENGE_FARM = "challenge_farm", _("Challenge farm")
