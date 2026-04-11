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

# Path to the nginx PID file. When set, reload_nginx() sends SIGHUP to the
# master process directly — no subprocess, no sudo, no PATH required. Just
# needs read access to the PID file. Set to None to use the command fallback.
ICV_WAF_NGINX_PID_PATH: str | None = getattr(
    settings,
    "ICV_WAF_NGINX_PID_PATH",
    "/run/nginx.pid",
)

# Fallback command for nginx reload (used when ICV_WAF_NGINX_PID_PATH is None
# or the PID file is unreadable).
ICV_WAF_NGINX_RELOAD_COMMAND: list[str] = getattr(
    settings,
    "ICV_WAF_NGINX_RELOAD_COMMAND",
    ["nginx", "-s", "reload"],
)

# Path prefixes exempt from no-referer challenge (only evaluated when
# ICV_WAF_CHALLENGE_NO_REFERER is True).
ICV_WAF_CHALLENGE_NO_REFERER: bool = getattr(settings, "ICV_WAF_CHALLENGE_NO_REFERER", False)
ICV_WAF_NO_REFERER_EXEMPT_PATHS: list[str] = getattr(
    settings,
    "ICV_WAF_NO_REFERER_EXEMPT_PATHS",
    ["/", "/search/", "/robots.txt", "/sitemap.xml", "/favicon.ico"],
)

# Path to a MaxMind GeoLite2-Country.mmdb database for GeoIP lookups.
# Set to None to disable GeoIP (default).
ICV_WAF_GEOIP_PATH: str | None = getattr(settings, "ICV_WAF_GEOIP_PATH", None)

# HTTP methods allowed through the WAF. Requests with other methods receive
# a 405 response before any rule evaluation. Set to None to allow all methods.
ICV_WAF_ALLOWED_METHODS: list[str] | None = getattr(settings, "ICV_WAF_ALLOWED_METHODS", None)

# Regex patterns for suspicious paths (credential probes, known webshells,
# backup archives, and vendor-specific exploit targets).
#
# Each matched pattern adds ICV_WAF_SUSPICIOUS_PATH_SCORE to the request's
# anomaly score. Patterns are picked so that a legitimate user on a Django
# site is extremely unlikely to trigger them — any match is a strong signal.
#
# Patterns that would overlap legitimate apps (``.ini``, ``.conf``, ``.aspx``,
# ``.jsp``, ``/cgi-bin/``) are intentionally omitted to keep the
# false-positive rate near-zero on mixed-tech estates.
#
# Patterns use re.search (anywhere-in-path, case-insensitive). Anchor with
# ^ or $ when position matters.
ICV_WAF_SUSPICIOUS_PATH_PATTERNS: list[str] = getattr(
    settings,
    "ICV_WAF_SUSPICIOUS_PATH_PATTERNS",
    [
        # Environment and secrets files
        r"\.env",
        r"\.aws",
        r"\.ssh",
        r"id_rsa",
        r"id_dsa",
        r"\.pem$",
        r"\.key$",
        r"credentials",
        r"\.bash_history",
        r"\.zsh_history",
        # Config files (framework-specific — avoid broad ``.conf``/``.ini``)
        r"wp-config\.php",
        r"config\.php",
        r"settings\.py",
        r"/admin/config",
        r"\.yml$",
        r"\.yaml$",
        # Version control exposure
        r"\.git",
        r"\.svn",
        r"\.hg",
        # Database and backup artefacts
        r"\.sql$",
        r"\.sql\.gz$",
        r"\.bak$",
        r"\.backup$",
        r"dump\.sql",
        r"backup\.zip",
        r"db\.sqlite",
        # WordPress exploit targets
        r"wp-admin",
        r"wp-login",
        r"xmlrpc\.php",
        # Generic webshells (named explicitly — avoid broad plugin/upload
        # wildcards that would catch legitimate WP sites)
        r"shell\.php",
        r"alfa.*\.php",
        r"r57\.php",
        r"c99\.php",
        r"filemanager\.php",
        r"webshell",
        r"cmd\.php",
        r"/eval\.php",
        # Information disclosure
        r"phpinfo",
        r"phpmyadmin",
        r"/server-status",
        r"/server-info",
        # IoT / vendor exploits (path-anchored to avoid colliding with
        # legitimate /onvif-meeting-room-booking etc.)
        r"/onvif/",
        r"/boaform/",
        r"/HNAP1",
        r"/goform/",
    ],
)

# Anomaly score thresholds for verdict escalation.
ICV_WAF_SCORE_THRESHOLD_LOG: float = getattr(settings, "ICV_WAF_SCORE_THRESHOLD_LOG", 3.0)
ICV_WAF_SCORE_THRESHOLD_CHALLENGE: float = getattr(settings, "ICV_WAF_SCORE_THRESHOLD_CHALLENGE", 5.0)
ICV_WAF_SCORE_THRESHOLD_BLOCK: float = getattr(settings, "ICV_WAF_SCORE_THRESHOLD_BLOCK", 7.0)

# Number of unanswered challenges before auto-escalating from challenge to block.
ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD: int = getattr(settings, "ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD", 10)

# Score added per suspicious path match.
ICV_WAF_SUSPICIOUS_PATH_SCORE: float = getattr(settings, "ICV_WAF_SUSPICIOUS_PATH_SCORE", 3.0)

# TTL in seconds for escalation blocks (challenges that were never solved).
ICV_WAF_ESCALATION_BLOCK_TTL: int = getattr(settings, "ICV_WAF_ESCALATION_BLOCK_TTL", 3600)

# Cloud spray detection: many distinct IPs with identical behaviour.
ICV_WAF_CLOUD_SPRAY_MIN_IPS: int = getattr(settings, "ICV_WAF_CLOUD_SPRAY_MIN_IPS", 20)
ICV_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP: int = getattr(settings, "ICV_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3)
