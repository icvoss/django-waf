"""TextChoices enums for django-waf models."""

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


class ReviewStatus(models.TextChoices):
    """Review state for an auto-generated ``BlockRule`` (BR-ANOM-010, #48).

    Only meaningful for ``source=auto`` rows. ``admin`` and ``feed`` rows
    are created, and stay, ``not_applicable``: they have no review workflow.
    An auto-generated rule stays ``not_applicable`` too when it is created
    enforcing (quarantine off, detector not observe-only, the pre-#47
    default): it was never queued for review, so ``pending`` would
    misrepresent it as awaiting a decision nobody was ever going to make.
    """

    NOT_APPLICABLE = "not_applicable", _("Not applicable")
    PENDING = "pending", _("Pending review")
    CONFIRMED = "confirmed", _("Confirmed")
    REJECTED = "rejected", _("Rejected")
    EXPIRED_UNREVIEWED = "expired_unreviewed", _("Expired unreviewed")


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
    UNSOLVED_CHALLENGE = "unsolved_challenge", _("Unsolved challenge")
    CLOUD_SPRAY = "cloud_spray", _("Cloud spray")


class RequestLogSource(models.TextChoices):
    """How a RequestLog row was created (#32).

    ``MIDDLEWARE`` is the DB default so every existing and future
    middleware-written row is correctly tagged without middleware.py having
    to pass ``source`` explicitly. ``NGINX_LOG`` is set only by the
    ``parse_access_log`` ingestion path, which infers a verdict from the
    nginx status code rather than observing a real WAF decision.
    """

    MIDDLEWARE = "middleware", _("Middleware")
    NGINX_LOG = "nginx_log", _("Nginx access log")
