"""
Package-level settings with defaults.

All settings are namespaced under ICV_WAF_* and accessed via this module.
Do not import these at module level into model methods — call getattr()
at call time to respect pytest settings overrides.
"""

from django.conf import settings

# Enable or disable the WAF middleware entirely.
ICV_WAF_ENABLED: bool = getattr(settings, "ICV_WAF_ENABLED", True)

# Package-wide HMAC signing secret. Used by every signed artefact the WAF
# issues — form render tokens (v0.11.0), and any future signed verdicts
# or challenge tokens that migrate off ``SECRET_KEY``. Kept deliberately
# separate from Django's ``SECRET_KEY`` so operators can rotate WAF
# signatures on a security-driven cadence without invalidating sessions.
#
# When empty (the default for backwards compatibility) callers must use
# the helper in ``icv_waf.services.tokens.get_signing_key()`` which falls
# back to a ``SECRET_KEY``-derived value and the ``icv_waf.W003`` system
# check emits a warning at startup. In production, set this to a value
# generated with ``python -c "import secrets; print(secrets.token_urlsafe(64))"``
# and load it from environment.
ICV_WAF_SIGNING_KEY: str = getattr(settings, "ICV_WAF_SIGNING_KEY", "")

# ---------------------------------------------------------------------------
# Form-protection subsystem (v0.11.0)
# ---------------------------------------------------------------------------
# All settings below are read by the form-protection defences and
# orchestrator. Nothing in the existing middleware uses them. Adding
# ``ProtectedForm`` (or the decorator / template tag) to a form is the
# opt-in step; until that happens these settings are inert.

# Master kill switch for the form-protection subsystem. When False,
# ``ProtectedForm.clean()`` and the decorator/template-tag short-circuit
# to pass without running any defences. Useful for incident response.
ICV_WAF_FORM_PROTECTION_ENABLED: bool = getattr(settings, "ICV_WAF_FORM_PROTECTION_ENABLED", True)

# Aggregate-score thresholds. The orchestrator sums ``flag`` scores;
# crossing FLAG triggers logging + signal + (optionally) challenge
# redirect; crossing BLOCK rejects the submission outright. A single
# defence returning ``block`` short-circuits the chain regardless of
# total.
ICV_WAF_FORM_FLAG_THRESHOLD: float = getattr(settings, "ICV_WAF_FORM_FLAG_THRESHOLD", 2.0)
ICV_WAF_FORM_BLOCK_THRESHOLD: float = getattr(settings, "ICV_WAF_FORM_BLOCK_THRESHOLD", 5.0)

# Whether to redirect flagged submissions through the existing
# /waf/challenge/ flow rather than rejecting them. When True (default)
# false-positive users get a way through; when False they get a
# generic form error.
ICV_WAF_FORM_CHALLENGE_ON_FLAG: bool = getattr(settings, "ICV_WAF_FORM_CHALLENGE_ON_FLAG", True)

# Whether the orchestrator fires the ``form_submission_passed`` signal.
# Off by default — busy sites have 1000× more passed submissions than
# flagged/blocked ones and firing in the hot path is wasted work. The
# structured log still records passes (sampled). Operators who want
# pass-event analytics opt in here.
ICV_WAF_FORM_EMIT_PASSED_SIGNAL: bool = getattr(settings, "ICV_WAF_FORM_EMIT_PASSED_SIGNAL", False)

# Lifetime of a render token. After this many seconds the token is
# expired and the user gets a fresh one on the next render. Also the
# TTL of the Redis marker that backs replay protection.
ICV_WAF_FORM_TOKEN_TTL: int = getattr(settings, "ICV_WAF_FORM_TOKEN_TTL", 3600)

# Honeypot field-name pool. The HoneypotDefence picks names from this
# list by hashing form_id, so a given form gets a stable set of names
# (cache-friendly) but different forms get different names (bots can't
# learn one global set).
ICV_WAF_FORM_HONEYPOT_FIELD_NAMES: list[str] = getattr(
    settings,
    "ICV_WAF_FORM_HONEYPOT_FIELD_NAMES",
    ["url", "website", "homepage", "email_confirm"],
)

# Time-trap thresholds in seconds. Submissions faster than the min are
# flagged; faster than 0.5s are blocked outright. Submissions older
# than the max have either been sitting open too long (UA changed, IP
# changed) or are replays — flagged either way.
ICV_WAF_FORM_TIME_TRAP_MIN_SECONDS: float = getattr(settings, "ICV_WAF_FORM_TIME_TRAP_MIN_SECONDS", 1.5)
ICV_WAF_FORM_TIME_TRAP_MAX_SECONDS: float = getattr(settings, "ICV_WAF_FORM_TIME_TRAP_MAX_SECONDS", 3600)

# Credential-throttle settings. Per-IP threshold drives the visible
# challenge (enumeration-safe — same behaviour whether the typed
# username exists). Per-account threshold drives an observation-only
# ``credential_attack_observed`` signal so consumers can email the
# legitimate owner.
ICV_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW: int = getattr(settings, "ICV_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW", 900)
ICV_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT: int = getattr(settings, "ICV_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT", 5)
ICV_WAF_FORM_CREDENTIAL_IP_LIMIT: int = getattr(settings, "ICV_WAF_FORM_CREDENTIAL_IP_LIMIT", 20)

# Signup-velocity settings. Counts *successful* signups per IP, so the
# user crossing the threshold sees a challenge on their *next* attempt.
ICV_WAF_FORM_SIGNUP_VELOCITY_WINDOW: int = getattr(settings, "ICV_WAF_FORM_SIGNUP_VELOCITY_WINDOW", 86400)
ICV_WAF_FORM_SIGNUP_VELOCITY_LIMIT: int = getattr(settings, "ICV_WAF_FORM_SIGNUP_VELOCITY_LIMIT", 5)

# Form-level PoW difficulty (leading zero bits). Lighter than the
# page-level challenge because it runs per-submission rather than once
# per session. 12 bits ≈ 4k SHA-256 hashes ≈ 50ms desktop, ~200ms
# mobile. Reuses the same _digest_has_leading_zero_bits verifier as
# the page challenge (no parallel implementation, no drift risk).
ICV_WAF_FORM_POW_DIFFICULTY: int = getattr(settings, "ICV_WAF_FORM_POW_DIFFICULTY", 12)

# Replay-store backend. ``session`` uses Django's session framework
# (signed cookie + server-side data); ``redis`` uses the same Redis
# the rest of the WAF talks to. Most sites use session.
ICV_WAF_FORM_REPLAY_STORE: str = getattr(settings, "ICV_WAF_FORM_REPLAY_STORE", "session")

# Global per-defence score weights. Overridable per-form via the
# ``defence_weights={...}`` kwarg on ``FormProtection``. The dict
# collapses what would otherwise be eight separate weight settings
# into one declaration.
ICV_WAF_FORM_DEFENCE_WEIGHTS: dict[str, float] = getattr(
    settings,
    "ICV_WAF_FORM_DEFENCE_WEIGHTS",
    {
        "honeypot": 5.0,
        "time_trap": 2.0,
        "render_token": 5.0,
        "ua_consistency": 2.0,
        "js_touch": 1.5,
        "credential_throttle": 5.0,
        "signup_velocity": 5.0,
        "pow_gate": 5.0,
    },
)

# Proof-of-work challenge difficulty — number of leading zero **bits** the
# SHA-256(token + nonce) digest must contain. Average solve cost is
# ``2 ** difficulty`` hashes. Acts as the single-value fallback when the
# desktop/mobile overrides below are unset.
ICV_WAF_CHALLENGE_DIFFICULTY: int = getattr(settings, "ICV_WAF_CHALLENGE_DIFFICULTY", 20)

# Desktop-class clients (default 22 bits ≈ 4M hashes, ~1–2s on a laptop).
# Slightly stronger than mobile because desktops have more CPU headroom.
# Set to ``None`` to fall back to ``ICV_WAF_CHALLENGE_DIFFICULTY``.
ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP: int | None = getattr(settings, "ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP", 22)

# Mobile-class clients (default 18 bits ≈ 260k hashes, ~1–3s on a phone).
# Set lower than desktop so budget devices don't time out.
# Set to ``None`` to fall back to ``ICV_WAF_CHALLENGE_DIFFICULTY``.
ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE: int | None = getattr(settings, "ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE", 18)

# Optional literal-path overrides for the WAF's own challenge/verify URLs.
# When set, the middleware uses these strings directly instead of calling
# ``reverse()``. Recommended for projects using per-request urlconf routing
# (django-hosts and similar) that don't mount icv_waf URLs on every host.
ICV_WAF_CHALLENGE_URL: str = getattr(settings, "ICV_WAF_CHALLENGE_URL", "")
ICV_WAF_VERIFY_URL: str = getattr(settings, "ICV_WAF_VERIFY_URL", "")

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

# Hostnames that bypass WAF evaluation entirely. Matching mirrors Django's
# ALLOWED_HOSTS convention: an exact host match, or a leading-dot entry
# (".example.com") that matches the domain and any subdomain. The port is
# stripped before matching. Empty by default (no host is exempt).
ICV_WAF_EXEMPT_HOSTS: list[str] = getattr(
    settings,
    "ICV_WAF_EXEMPT_HOSTS",
    [],
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

# MaxMind licence key for downloading GeoLite2 databases via the
# ``manage.py icv_waf_install_geoip`` command or the
# ``update_geoip_database`` Celery task. Sign up for a free key at
# https://www.maxmind.com/en/geolite2/signup and load it from your
# environment (e.g. ``os.environ.get("MAXMIND_LICENSE_KEY", "")``).
ICV_WAF_MAXMIND_LICENSE_KEY: str = getattr(settings, "ICV_WAF_MAXMIND_LICENSE_KEY", "")

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
