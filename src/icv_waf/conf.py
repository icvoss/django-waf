"""
Package-level settings with defaults.

All settings are namespaced under ICV_WAF_* and accessed via this module.
Do not import these at module level into model methods — call getattr()
at call time to respect pytest settings overrides.
"""

from django.conf import settings

# Enable or disable the WAF middleware entirely.
ICV_WAF_ENABLED: bool = getattr(settings, "ICV_WAF_ENABLED", True)

# Proof-of-work challenge difficulty (leading zero bits required).
ICV_WAF_CHALLENGE_DIFFICULTY: int = getattr(settings, "ICV_WAF_CHALLENGE_DIFFICULTY", 4)

# TTL in seconds for a solved-challenge cookie.
ICV_WAF_CHALLENGE_COOKIE_TTL: int = getattr(settings, "ICV_WAF_CHALLENGE_COOKIE_TTL", 86400)

# Maximum requests per IP per minute before throttling.
ICV_WAF_RATE_LIMIT_PER_MINUTE: int = getattr(settings, "ICV_WAF_RATE_LIMIT_PER_MINUTE", 120)

# Maximum requests per IP per 5 minutes before throttling.
ICV_WAF_RATE_LIMIT_PER_5MIN: int = getattr(settings, "ICV_WAF_RATE_LIMIT_PER_5MIN", 600)

# Burst allowance — requests that may exceed the rate limit momentarily.
ICV_WAF_RATE_LIMIT_BURST: int = getattr(settings, "ICV_WAF_RATE_LIMIT_BURST", 10)

# Fraction of allowed requests to log (0.0–1.0). 1.0 = log everything.
ICV_WAF_LOG_SAMPLE_RATE: float = getattr(settings, "ICV_WAF_LOG_SAMPLE_RATE", 0.01)

# Filesystem path for the generated nginx IP/UA blocklist include file.
ICV_WAF_NGINX_BLOCKLIST_PATH: str = getattr(
    settings,
    "ICV_WAF_NGINX_BLOCKLIST_PATH",
    "/etc/nginx/conf.d/icv-waf-blocklist.conf",
)

# Path to the nginx access log file parsed by the log-analysis command.
ICV_WAF_ACCESS_LOG_PATH: str = getattr(
    settings,
    "ICV_WAF_ACCESS_LOG_PATH",
    "/var/log/nginx/access.log",
)

# Number of distinct user-agents from a single IP that triggers a UA-rotation anomaly.
ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS: int = getattr(settings, "ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 20)

# Hours after which auto-generated rules expire automatically.
ICV_WAF_AUTO_RULE_EXPIRY_HOURS: int = getattr(settings, "ICV_WAF_AUTO_RULE_EXPIRY_HOURS", 24)

# URL path prefixes that bypass WAF evaluation entirely.
ICV_WAF_EXEMPT_PATHS: list[str] = getattr(
    settings,
    "ICV_WAF_EXEMPT_PATHS",
    ["/static/", "/media/", "/health/", "/favicon.ico"],
)

# Trust the X-Forwarded-For header when extracting the real client IP.
ICV_WAF_TRUST_X_FORWARDED_FOR: bool = getattr(settings, "ICV_WAF_TRUST_X_FORWARDED_FOR", False)

# Django cache alias used for Redis rate-limit counters and rule-version keys.
ICV_WAF_REDIS_ALIAS: str = getattr(settings, "ICV_WAF_REDIS_ALIAS", "default")

# Enable syncing rules from the collective threat feed.
ICV_WAF_FEED_ENABLED: bool = getattr(settings, "ICV_WAF_FEED_ENABLED", True)

# URL of the collective threat feed JSON endpoint.
ICV_WAF_FEED_URL: str = getattr(settings, "ICV_WAF_FEED_URL", "https://threats.icv.dev/v1/feed.json")

# Minimum confidence score (0.0–1.0) required to import a feed entry as a rule.
ICV_WAF_FEED_MIN_CONFIDENCE: float = getattr(settings, "ICV_WAF_FEED_MIN_CONFIDENCE", 0.8)

# Enable reporting local detections back to the collective feed.
ICV_WAF_FEED_REPORT: bool = getattr(settings, "ICV_WAF_FEED_REPORT", False)

# URL for reporting detections to the collective feed.
ICV_WAF_FEED_REPORT_URL: str = getattr(settings, "ICV_WAF_FEED_REPORT_URL", "https://threats.icv.dev/v1/report")

# API key for authenticating with the collective threat feed.
ICV_WAF_FEED_API_KEY: str = getattr(settings, "ICV_WAF_FEED_API_KEY", "")

# Number of days to retain RequestLog entries before purging.
ICV_WAF_LOG_RETENTION_DAYS: int = getattr(settings, "ICV_WAF_LOG_RETENTION_DAYS", 30)
