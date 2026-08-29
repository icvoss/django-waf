"""
Package-level settings with defaults.

All settings are namespaced under DJANGO_WAF_* and accessed via this module.
Do not import these at module level into model methods — call getattr()
at call time to respect pytest settings overrides.
"""

from django.conf import settings

try:
    from celery.schedules import crontab
except ImportError:
    crontab = None  # type: ignore[assignment]

# Enable or disable the WAF middleware entirely.
DJANGO_WAF_ENABLED: bool = getattr(settings, "DJANGO_WAF_ENABLED", True)

# Package-wide HMAC signing secret. Used by every signed artefact the WAF
# issues — form render tokens (v0.11.0), and any future signed verdicts
# or challenge tokens that migrate off ``SECRET_KEY``. Kept deliberately
# separate from Django's ``SECRET_KEY`` so operators can rotate WAF
# signatures on a security-driven cadence without invalidating sessions.
#
# When empty (the default for backwards compatibility) callers must use
# the helper in ``django_waf.services.tokens.get_signing_key()`` which falls
# back to a ``SECRET_KEY``-derived value and the ``django_waf.W003`` system
# check emits a warning at startup. In production, set this to a value
# generated with ``python -c "import secrets; print(secrets.token_urlsafe(64))"``
# and load it from environment.
DJANGO_WAF_SIGNING_KEY: str = getattr(settings, "DJANGO_WAF_SIGNING_KEY", "")

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
DJANGO_WAF_FORM_PROTECTION_ENABLED: bool = getattr(settings, "DJANGO_WAF_FORM_PROTECTION_ENABLED", True)

# Aggregate-score thresholds. The orchestrator sums ``flag`` scores;
# crossing FLAG triggers logging + signal + (optionally) challenge
# redirect; crossing BLOCK rejects the submission outright. A single
# defence returning ``block`` short-circuits the chain regardless of
# total.
DJANGO_WAF_FORM_FLAG_THRESHOLD: float = getattr(settings, "DJANGO_WAF_FORM_FLAG_THRESHOLD", 2.0)
DJANGO_WAF_FORM_BLOCK_THRESHOLD: float = getattr(settings, "DJANGO_WAF_FORM_BLOCK_THRESHOLD", 5.0)

# Whether to redirect flagged submissions through the existing
# /waf/challenge/ flow rather than rejecting them. When True (default)
# false-positive users get a way through; when False they get a
# generic form error.
DJANGO_WAF_FORM_CHALLENGE_ON_FLAG: bool = getattr(settings, "DJANGO_WAF_FORM_CHALLENGE_ON_FLAG", True)

# Whether the orchestrator fires the ``form_submission_passed`` signal.
# Off by default — busy sites have 1000× more passed submissions than
# flagged/blocked ones and firing in the hot path is wasted work. The
# structured log still records passes (sampled). Operators who want
# pass-event analytics opt in here.
DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL: bool = getattr(settings, "DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL", False)

# Lifetime of a render token. After this many seconds the token is
# expired and the user gets a fresh one on the next render. Also the
# TTL of the Redis marker that backs replay protection.
DJANGO_WAF_FORM_TOKEN_TTL: int = getattr(settings, "DJANGO_WAF_FORM_TOKEN_TTL", 3600)

# Honeypot field-name pool. The HoneypotDefence picks names from this
# list by hashing form_id, so a given form gets a stable set of names
# (cache-friendly) but different forms get different names (bots can't
# learn one global set).
DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES: list[str] = getattr(
    settings,
    "DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES",
    ["url", "website", "homepage", "email_confirm"],
)

# Time-trap thresholds in seconds. Submissions faster than the min are
# flagged; faster than 0.5s are blocked outright. Submissions older
# than the max have either been sitting open too long (UA changed, IP
# changed) or are replays — flagged either way.
DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS: float = getattr(settings, "DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS", 1.5)
DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS: float = getattr(settings, "DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS", 3600)

# Credential-throttle settings. Per-IP threshold drives the visible
# challenge (enumeration-safe — same behaviour whether the typed
# username exists). Per-account threshold drives an observation-only
# ``credential_attack_observed`` signal so consumers can email the
# legitimate owner.
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW: int = getattr(settings, "DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW", 900)
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT: int = getattr(settings, "DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT", 5)
DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT: int = getattr(settings, "DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT", 20)

# Signup-velocity settings. Counts *successful* signups per IP, so the
# user crossing the threshold sees a challenge on their *next* attempt.
DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW: int = getattr(settings, "DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW", 86400)
DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT: int = getattr(settings, "DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT", 5)

# Form-level PoW difficulty (leading zero bits). Lighter than the
# page-level challenge because it runs per-submission rather than once
# per session. 12 bits ≈ 4k SHA-256 hashes ≈ 50ms desktop, ~200ms
# mobile. Reuses the same _digest_has_leading_zero_bits verifier as
# the page challenge (no parallel implementation, no drift risk).
DJANGO_WAF_FORM_POW_DIFFICULTY: int = getattr(settings, "DJANGO_WAF_FORM_POW_DIFFICULTY", 12)

# Replay-store backend. ``session`` uses Django's session framework
# (signed cookie + server-side data); ``redis`` uses the same Redis
# the rest of the WAF talks to. Most sites use session.
DJANGO_WAF_FORM_REPLAY_STORE: str = getattr(settings, "DJANGO_WAF_FORM_REPLAY_STORE", "session")

# Global per-defence score weights. Overridable per-form via the
# ``defence_weights={...}`` kwarg on ``FormProtection``. The dict
# collapses what would otherwise be eight separate weight settings
# into one declaration.
DJANGO_WAF_FORM_DEFENCE_WEIGHTS: dict[str, float] = getattr(
    settings,
    "DJANGO_WAF_FORM_DEFENCE_WEIGHTS",
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
# ``2 ** difficulty`` hashes. This single value is the default and is
# authoritative unless an operator explicitly overrides a device band below.
DJANGO_WAF_CHALLENGE_DIFFICULTY: int = getattr(settings, "DJANGO_WAF_CHALLENGE_DIFFICULTY", 16)

# Desktop-class clients. Defaults to ``None``, which falls back to
# ``DJANGO_WAF_CHALLENGE_DIFFICULTY``. Set an explicit value only to give
# desktop clients a different (typically higher) cost than mobile.
DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP: int | None = getattr(settings, "DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", None)

# Mobile-class clients. Defaults to ``None``, which falls back to
# ``DJANGO_WAF_CHALLENGE_DIFFICULTY``. Set an explicit value only to give
# budget devices a lower cost than desktop.
DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE: int | None = getattr(settings, "DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", None)

# Optional literal-path overrides for the WAF's own challenge/verify URLs.
# When set, the middleware uses these strings directly instead of calling
# ``reverse()``. Recommended for projects using per-request urlconf routing
# (django-hosts and similar) that don't mount django_waf URLs on every host.
DJANGO_WAF_CHALLENGE_URL: str = getattr(settings, "DJANGO_WAF_CHALLENGE_URL", "")
DJANGO_WAF_VERIFY_URL: str = getattr(settings, "DJANGO_WAF_VERIFY_URL", "")

# TTL in seconds for a solved-challenge cookie.
DJANGO_WAF_CHALLENGE_COOKIE_TTL: int = getattr(settings, "DJANGO_WAF_CHALLENGE_COOKIE_TTL", 86400)

# Maximum requests per IP per minute before throttling.
DJANGO_WAF_RATE_LIMIT_PER_MINUTE: int = getattr(settings, "DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120)

# Maximum requests per IP per 5 minutes before throttling.
DJANGO_WAF_RATE_LIMIT_PER_5MIN: int = getattr(settings, "DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600)

# Burst allowance — requests that may exceed the rate limit momentarily.
DJANGO_WAF_RATE_LIMIT_BURST: int = getattr(settings, "DJANGO_WAF_RATE_LIMIT_BURST", 10)

# Fraction of allowed requests to log (0.0–1.0). 1.0 = log everything.
DJANGO_WAF_LOG_SAMPLE_RATE: float = getattr(settings, "DJANGO_WAF_LOG_SAMPLE_RATE", 0.01)

# Filesystem path for the generated nginx IP/UA blocklist include file.
DJANGO_WAF_NGINX_BLOCKLIST_PATH: str = getattr(
    settings,
    "DJANGO_WAF_NGINX_BLOCKLIST_PATH",
    "/etc/nginx/conf.d/django-waf-blocklist.conf",
)

# Path to the nginx access log file parsed by the log-analysis command.
DJANGO_WAF_ACCESS_LOG_PATH: str = getattr(
    settings,
    "DJANGO_WAF_ACCESS_LOG_PATH",
    "/var/log/nginx/access.log",
)

# Number of distinct user-agents from a single IP that triggers a UA-rotation anomaly.
DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS: int = getattr(settings, "DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 20)

# Hours after which auto-generated rules expire automatically.
DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS: int = getattr(settings, "DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24)

# URL path prefixes that bypass WAF evaluation entirely.
DJANGO_WAF_EXEMPT_PATHS: list[str] = getattr(
    settings,
    "DJANGO_WAF_EXEMPT_PATHS",
    ["/static/", "/media/", "/health/", "/favicon.ico"],
)

# Hostnames that bypass WAF evaluation entirely. Matching mirrors Django's
# ALLOWED_HOSTS convention: an exact host match, or a leading-dot entry
# (".example.com") that matches the domain and any subdomain. The port is
# stripped before matching. Empty by default (no host is exempt).
DJANGO_WAF_EXEMPT_HOSTS: list[str] = getattr(
    settings,
    "DJANGO_WAF_EXEMPT_HOSTS",
    [],
)

# Guarantee active, rDNS-gated AllowRules for the major verified search
# crawlers (Googlebot, Bingbot), seeded by migration 0003 (ADR-035,
# BR-CHAL-001). Without this, a crawler's UA scores into the challenge band
# (it sends none of the Sec-CH-UA / Sec-Fetch-* headers a real browser
# sends), never solves the JS proof-of-work challenge, and is silently
# deindexed. Default True fixes that footgun out of the box. Set to False to
# opt out, or deactivate the seeded AllowRule rows directly.
DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS: bool = getattr(settings, "DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS", True)

# TTL in seconds for a NEGATIVE forward-confirmed reverse DNS (FCrDNS)
# verification result — a PTR/hostname pattern match that then failed the
# forward-resolution check, or any DNS error on either lookup (#34). Kept
# short (5 minutes) rather than the 24-hour positive-result TTL, because a
# negative result can come from a transient resolver outage, and a long
# negative cache would suppress a legitimate crawler's AllowRule match for
# a full day per IP on every hiccup. A positive FCrDNS verification is
# always cached for 24 hours, unaffected by this setting — legitimate
# crawler infrastructure's DNS records change rarely.
DJANGO_WAF_RDNS_FAILURE_CACHE_TTL: int = getattr(settings, "DJANGO_WAF_RDNS_FAILURE_CACHE_TTL", 300)

# Trust the X-Forwarded-For header when extracting the real client IP.
DJANGO_WAF_TRUST_X_FORWARDED_FOR: bool = getattr(settings, "DJANGO_WAF_TRUST_X_FORWARDED_FOR", False)

# Django cache alias used for Redis rate-limit counters and rule-version keys.
DJANGO_WAF_REDIS_ALIAS: str = getattr(settings, "DJANGO_WAF_REDIS_ALIAS", "default")

# Enable syncing rules from the collective threat feed.
DJANGO_WAF_FEED_ENABLED: bool = getattr(settings, "DJANGO_WAF_FEED_ENABLED", True)

# URL of the collective threat feed JSON endpoint. Points at the operated
# feed server (threats.drystane.com); override for a self-hosted or
# third-party compatible server.
DJANGO_WAF_FEED_URL: str = getattr(settings, "DJANGO_WAF_FEED_URL", "https://threats.drystane.com/v1/feed.json")

# Minimum confidence score (0.0–1.0) required to import a feed entry as a rule.
DJANGO_WAF_FEED_MIN_CONFIDENCE: float = getattr(settings, "DJANGO_WAF_FEED_MIN_CONFIDENCE", 0.8)

# Enable reporting local detections back to the collective feed. Opt-in by
# design (ADR-021 point 4): telemetry is never sent unless an operator sets
# this to True, regardless of whether DJANGO_WAF_FEED_REPORT_URL is
# configured. Setting this to True is the only step a site needs to start
# reporting.
DJANGO_WAF_FEED_REPORT: bool = getattr(settings, "DJANGO_WAF_FEED_REPORT", False)

# URL for reporting detections to the collective feed. Points at the
# operated feed server (threats.drystane.com); override for a self-hosted
# or third-party compatible server.
DJANGO_WAF_FEED_REPORT_URL: str = getattr(
    settings, "DJANGO_WAF_FEED_REPORT_URL", "https://threats.drystane.com/v1/report"
)

# API key for authenticating with the collective threat feed.
DJANGO_WAF_FEED_API_KEY: str = getattr(settings, "DJANGO_WAF_FEED_API_KEY", "")

# Number of days to retain RequestLog entries before purging.
DJANGO_WAF_LOG_RETENTION_DAYS: int = getattr(settings, "DJANGO_WAF_LOG_RETENTION_DAYS", 30)

# Path to the nginx PID file. When set, reload_nginx() sends SIGHUP to the
# master process directly — no subprocess, no sudo, no PATH required. Just
# needs read access to the PID file. Set to None to use the command fallback.
DJANGO_WAF_NGINX_PID_PATH: str | None = getattr(
    settings,
    "DJANGO_WAF_NGINX_PID_PATH",
    "/run/nginx.pid",
)

# Fallback command for nginx reload (used when DJANGO_WAF_NGINX_PID_PATH is None
# or the PID file is unreadable).
DJANGO_WAF_NGINX_RELOAD_COMMAND: list[str] = getattr(
    settings,
    "DJANGO_WAF_NGINX_RELOAD_COMMAND",
    ["nginx", "-s", "reload"],
)

# Path prefixes exempt from no-referer challenge (only evaluated when
# DJANGO_WAF_CHALLENGE_NO_REFERER is True).
DJANGO_WAF_CHALLENGE_NO_REFERER: bool = getattr(settings, "DJANGO_WAF_CHALLENGE_NO_REFERER", False)
DJANGO_WAF_NO_REFERER_EXEMPT_PATHS: list[str] = getattr(
    settings,
    "DJANGO_WAF_NO_REFERER_EXEMPT_PATHS",
    ["/", "/search/", "/robots.txt", "/sitemap.xml", "/favicon.ico"],
)

# Path to a MaxMind GeoLite2-Country.mmdb database for GeoIP lookups.
# Set to None to disable GeoIP (default).
DJANGO_WAF_GEOIP_PATH: str | None = getattr(settings, "DJANGO_WAF_GEOIP_PATH", None)

# MaxMind licence key for downloading GeoLite2 databases via the
# ``manage.py django_waf_install_geoip`` command or the
# ``update_geoip_database`` Celery task. Sign up for a free key at
# https://www.maxmind.com/en/geolite2/signup and load it from your
# environment (e.g. ``os.environ.get("MAXMIND_LICENSE_KEY", "")``).
DJANGO_WAF_MAXMIND_LICENSE_KEY: str = getattr(settings, "DJANGO_WAF_MAXMIND_LICENSE_KEY", "")

# HTTP methods allowed through the WAF. Requests with other methods receive
# a 405 response before any rule evaluation. Set to None to allow all methods.
DJANGO_WAF_ALLOWED_METHODS: list[str] | None = getattr(settings, "DJANGO_WAF_ALLOWED_METHODS", None)

# Regex patterns for suspicious paths (credential probes, known webshells,
# backup archives, and vendor-specific exploit targets).
#
# Each matched pattern adds DJANGO_WAF_SUSPICIOUS_PATH_SCORE to the request's
# anomaly score. Patterns are picked so that a legitimate user on a Django
# site is extremely unlikely to trigger them — any match is a strong signal.
#
# Patterns that would overlap legitimate apps (``.ini``, ``.conf``, ``.aspx``,
# ``.jsp``, ``/cgi-bin/``) are intentionally omitted to keep the
# false-positive rate near-zero on mixed-tech estates.
#
# Patterns use re.search (anywhere-in-path, case-insensitive). Anchor with
# ^ or $ when position matters.
DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS: list[str] = getattr(
    settings,
    "DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS",
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
DJANGO_WAF_SCORE_THRESHOLD_LOG: float = getattr(settings, "DJANGO_WAF_SCORE_THRESHOLD_LOG", 3.0)
DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE: float = getattr(settings, "DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE", 5.0)
DJANGO_WAF_SCORE_THRESHOLD_BLOCK: float = getattr(settings, "DJANGO_WAF_SCORE_THRESHOLD_BLOCK", 7.0)

# Number of challenges from a single IP before auto-escalating from
# challenge to block. From 2.0.0, this counts challenges issued to a
# client whose HTTP fingerprint is classified "bot" (BR-FP-001) regardless
# of whether the client goes on to solve the proof-of-work: a datacentre
# CPU solves hashcash almost for free, so a bot that solves every challenge
# no longer resets the count to zero. For every other fingerprint verdict,
# a solved challenge still resets the count, unchanged from before 2.0.0.
DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD: int = getattr(settings, "DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD", 10)

# Score added per suspicious path match.
DJANGO_WAF_SUSPICIOUS_PATH_SCORE: float = getattr(settings, "DJANGO_WAF_SUSPICIOUS_PATH_SCORE", 3.0)

# TTL in seconds for escalation blocks (challenges that were never solved).
DJANGO_WAF_ESCALATION_BLOCK_TTL: int = getattr(settings, "DJANGO_WAF_ESCALATION_BLOCK_TTL", 3600)

# Cloud spray detection: many distinct IPs with identical behaviour.
DJANGO_WAF_CLOUD_SPRAY_MIN_IPS: int = getattr(settings, "DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 20)
DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP: int = getattr(settings, "DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3)

# Per-path rate limits: {path_prefix: (max_requests, window_seconds)}.
# Longest-prefix match wins; checked before the global IP windows.
DJANGO_WAF_RATE_LIMIT_PATHS: dict = getattr(settings, "DJANGO_WAF_RATE_LIMIT_PATHS", {})

# ISO 3166-1 alpha-2 country codes to block outright (e.g. ["CN", "RU"]).
# Empty disables country blocking. Requires a GeoIP database (see
# django_waf_install_geoip); fails open when lookup is unavailable.
DJANGO_WAF_BLOCKED_COUNTRIES: list = getattr(settings, "DJANGO_WAF_BLOCKED_COUNTRIES", [])

# Enable the optional DRF API under waf/api/ (requires the [api] extra).
DJANGO_WAF_API_ENABLED: bool = getattr(settings, "DJANGO_WAF_API_ENABLED", False)

# ---------------------------------------------------------------------------
# Site password gate (BR-SP series)
# ---------------------------------------------------------------------------
# A middleware-level shared-password wall gating the whole site (and every
# subdomain it serves) before any application view. See
# docs/specs/site-password/PRD.md.

# The shared password. Unset/empty means the gate is off (BR-SP-001).
# Never rendered, never logged (BR-SP-005). Load from environment in
# production.
DJANGO_WAF_SITE_PASSWORD: str = getattr(settings, "DJANGO_WAF_SITE_PASSWORD", "")

# Explicit on/off switch. Defaults to whether a password is set. Enabling
# this with an empty password fails closed rather than opening the gate
# (BR-SP-002) -- every gated request is denied and a system check warns at
# boot (django_waf.checks.check_site_password_configured).
DJANGO_WAF_SITE_PASSWORD_ENABLED: bool = getattr(
    settings, "DJANGO_WAF_SITE_PASSWORD_ENABLED", bool(DJANGO_WAF_SITE_PASSWORD)
)

# Verified-session lifetime in seconds. Default 12 hours (BR-SP-004).
DJANGO_WAF_SITE_PASSWORD_TTL: int = getattr(settings, "DJANGO_WAF_SITE_PASSWORD_TTL", 43200)

# Path prefixes that bypass the gate even when locked (BR-SP-003): health
# checks, ACME/well-known probes, robots.txt, and the WAF's own
# challenge/verify interstitials (so the WAF's existing defences keep
# working and the site-password gate never traps its own prompt-and-verify
# round trip in a loop).
DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS: list[str] = getattr(
    settings,
    "DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS",
    ["/health/", "/.well-known/", "/robots.txt", "/waf/challenge/", "/waf/verify/"],
)

# Path the prompt form posts to. The middleware intercepts POSTs to this
# path directly (before URL resolution), so it works even on hosts that
# don't mount django_waf.urls -- but the same path is also routed in
# urls.py so reverse() and direct access resolve to a real view.
DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH: str = getattr(
    settings, "DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH", "/waf/site-password/"
)

# Domain for the gate's own verified-flag cookie (see
# django_waf.services.site_password_service -- the gate uses its own signed
# cookie, not Django's session, because WafMiddleware runs before
# SessionMiddleware). Defaults to None, which means
# site_password_service.set_verified_cookie() falls back to
# settings.SESSION_COOKIE_DOMAIN at call time -- so a site that already sets
# SESSION_COOKIE_DOMAIN=".example.com" for subdomain coverage gets the same
# coverage on this cookie without configuring it twice. Set explicitly only
# when the gate's subdomain scope must differ from the session cookie's.
DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN: str | None = getattr(settings, "DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN", None)

# ---------------------------------------------------------------------------
# Celery Beat schedule helper
# ---------------------------------------------------------------------------
# Ready-made CELERY_BEAT_SCHEDULE entries for every periodic django-waf task.
# Consuming projects merge this into their own schedule rather than
# hand-transcribing task names and cadences::
#
#     CELERY_BEAT_SCHEDULE = {
#         **DJANGO_WAF_CELERY_BEAT_SCHEDULE,
#         "my-other-task": {...},
#     }
#
# Building this dict never imports celery at settings-module-import time in a
# way that can fail: the ``crontab`` import above is guarded, so entries that
# need a wall-clock time (``crontab(hour=.., minute=..)``) are only included
# when celery is installed. The ``*/N minute`` entries use a plain integer
# number of seconds, which Celery Beat accepts without importing
# ``crontab`` at all, so they are always present regardless of whether
# celery is installed. This module must remain importable even when celery
# is entirely absent from the environment (e.g. projects that don't use
# Celery at all still import django_waf.conf indirectly via checks/admin).
_CELERY_BEAT_INTERVAL_ENTRIES: dict = {
    "django-waf-generate-blocklist": {
        "task": "django_waf.tasks.generate_blocklist",
        "schedule": 300.0,  # every 5 minutes
    },
    "django-waf-flush-rule-hit-counts": {
        "task": "django_waf.tasks.flush_rule_hit_counts",
        "schedule": 300.0,  # every 5 minutes
    },
    "django-waf-detect-anomalies": {
        "task": "django_waf.tasks.detect_anomalies",
        "schedule": 900.0,  # every 15 minutes
    },
    "django-waf-parse-access-log": {
        "task": "django_waf.tasks.parse_access_log",
        "schedule": 600.0,  # every 10 minutes
    },
    "django-waf-expire-rules": {
        "task": "django_waf.tasks.expire_rules",
        "schedule": 1800.0,  # every 30 minutes
    },
    "django-waf-update-ip-reputation": {
        "task": "django_waf.tasks.update_ip_reputation",
        "schedule": 21600.0,  # every 6 hours
    },
}

if crontab is not None:
    _CELERY_BEAT_CRON_ENTRIES: dict = {
        "django-waf-prune-request-logs": {
            "task": "django_waf.tasks.prune_request_logs",
            "schedule": crontab(hour=4, minute=0),
        },
        "django-waf-prune-challenge-tokens": {
            "task": "django_waf.tasks.prune_challenge_tokens",
            "schedule": crontab(hour=4, minute=15),
        },
        "django-waf-sync-threat-feed": {
            "task": "django_waf.tasks.sync_threat_feed",
            "schedule": crontab(hour=4, minute=30),
        },
        "django-waf-report-threat-telemetry": {
            "task": "django_waf.tasks.report_threat_telemetry",
            "schedule": crontab(hour=5, minute=0),
        },
        "django-waf-update-geoip-database": {
            "task": "django_waf.tasks.update_geoip_database",
            "schedule": crontab(day_of_week=0, hour=3, minute=0),  # weekly, Sunday 03:00 UTC
        },
    }
else:
    # celery is not installed — the cron-time entries above need
    # crontab() to build a schedule, so they are omitted rather than
    # guessed at with a plain interval. The */N minute entries above still
    # work fine as they don't touch crontab at all.
    _CELERY_BEAT_CRON_ENTRIES = {}

# Ready-made CELERY_BEAT_SCHEDULE fragment covering every periodic
# django-waf task. See the module docstring above this block for usage.
DJANGO_WAF_CELERY_BEAT_SCHEDULE: dict = getattr(
    settings,
    "DJANGO_WAF_CELERY_BEAT_SCHEDULE",
    {**_CELERY_BEAT_INTERVAL_ENTRIES, **_CELERY_BEAT_CRON_ENTRIES},
)

# ---------------------------------------------------------------------------
# Client IP resolution (#29)
# ---------------------------------------------------------------------------
# See django_waf.services.client_ip for the resolver these settings feed.

# CIDR strings identifying reverse proxies allowed to set X-Forwarded-For.
# When REMOTE_ADDR falls inside one of these ranges, the resolver honours
# X-Forwarded-For by walking it right-to-left and returning the first hop
# that is not itself a trusted proxy. Empty by default: with no trusted
# proxies configured, DJANGO_WAF_TRUST_X_FORWARDED_FOR (legacy, spoofable)
# governs whether the header is honoured at all. This is the hardened
# replacement for that setting and should be preferred in any deployment
# that sits behind a known reverse-proxy layer (e.g. ["10.0.0.0/8"] for an
# internal load balancer, or the exact /32 of a single fronting proxy).
DJANGO_WAF_TRUSTED_PROXIES: list[str] = getattr(settings, "DJANGO_WAF_TRUSTED_PROXIES", [])

# Trust an empty REMOTE_ADDR from a unix-socket WSGI peer as the direct proxy
# hop. This is deliberately opt-in: an operator must ensure that only their
# reverse proxy can connect to the socket before the X-Forwarded-For header is
# honoured.
DJANGO_WAF_TRUSTED_UNIX_SOCKET: bool = getattr(settings, "DJANGO_WAF_TRUSTED_UNIX_SOCKET", False)

# ---------------------------------------------------------------------------
# Threat-feed import constraints (#33)
# ---------------------------------------------------------------------------
# When True (the default), an allow rule created from the threat feed is
# imported inactive (is_active=False), so a compromised or mistaken feed
# cannot open an exemption without an operator confirming it. Set False only
# if you fully trust the feed source to publish allow rules.
DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES: bool = getattr(settings, "DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES", True)

# ---------------------------------------------------------------------------
# nginx blocklist export validation (#31)
# ---------------------------------------------------------------------------
# When True (the default), a freshly generated blocklist is validated with
# DJANGO_WAF_NGINX_TEST_COMMAND before the reload is signalled. On failure
# the previous known-good file is restored and no reload happens, so a bad
# generated file cannot break a later full nginx restart. If the nginx
# binary is absent the validation step is skipped gracefully. Set False to
# restore the pre-1.7.0 write-then-reload behaviour without validation.
DJANGO_WAF_NGINX_VALIDATE: bool = getattr(settings, "DJANGO_WAF_NGINX_VALIDATE", True)

# The command run to validate the candidate configuration. Defaults to a
# plain syntax check; override if nginx is not on PATH or needs a specific
# prefix (e.g. ["sudo", "nginx", "-t"]).
DJANGO_WAF_NGINX_TEST_COMMAND: list[str] = getattr(settings, "DJANGO_WAF_NGINX_TEST_COMMAND", ["nginx", "-t"])

# ---------------------------------------------------------------------------
# Anomaly detector review-before-enforce (#45/#46/#47/#48)
# ---------------------------------------------------------------------------
# When True, a newly-created auto-generated BlockRule is created
# is_active=False, review_status=PENDING, pending operator confirmation via
# the dashboard's Anomalies panel, rather than enforcing (challenging or
# blocking) from the moment it is written (BR-ANOM-007). The default is
# False, deliberately NOT a mirror of DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES
# (default True): every existing django-waf deployment already relies on an
# auto-generated rule enforcing immediately, and flipping this default to
# quarantine-first would silently stop enforcement on every upgrade with no
# code change on the consumer's side. A site that wants approve-before-
# enforce sets this explicitly.
DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES: bool = getattr(settings, "DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", False)

# Detector function names (e.g. ["detect_cloud_spray"]) that must always
# create quarantined rules (is_active=False, review_status=PENDING),
# regardless of DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES above (BR-ANOM-008).
# Lets an operator build trust in one detector's output without quarantining
# every detector's rules. A name that does not match a known detector is
# caught at boot by django_waf.checks.check_observe_only_detector_names
# (django_waf.W008), so a detector rename cannot silently desync this list
# from the functions it names.
DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS: list[str] = getattr(
    settings, "DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", []
)

# ---------------------------------------------------------------------------
# Trusted-user cookie (#23)
# ---------------------------------------------------------------------------
# A signed, WAF-owned cookie that carries "this request is from a trusted
# (staff) user" independently of request.user, so the staff/superuser bypass
# (BR-RATE-003, django_waf.middleware._is_staff_user) works even when
# WafMiddleware runs before django.contrib.auth.middleware.AuthenticationMiddleware
# -- the security-first ordering the WAF's own README recommends, and the
# ordering django_waf.checks.check_middleware_ordering (django_waf.W004) has
# historically warned against. See docs/DESIGN-trusted-user-cookie.md and
# django_waf.services.trusted_user_service, which mirrors
# django_waf.services.site_password_service's TimestampSigner pattern.

# Master switch. Off by default (opt-in): existing sites see no behaviour
# change, and no stray cookie can grant the bypass, until a project both
# enables this setting and wires the login receiver (see
# django_waf.receivers / DjangoWafConfig.ready()). Read live (not cached) by
# django_waf.services.trusted_user_service.is_feature_enabled() so tests can
# toggle it with patch.object without a module reload.
DJANGO_WAF_TRUSTED_COOKIE_ENABLED: bool = getattr(settings, "DJANGO_WAF_TRUSTED_COOKIE_ENABLED", False)

# Which users the login receiver issues the cookie to. "staff" (default)
# limits the bypass to the same population the pre-existing request.user
# check already trusted (is_staff or is_superuser); "authenticated" widens
# it to any logged-in user, which broadens the bypass and weakens the WAF
# for that population, so it is an explicit opt-in, not the default. Any
# other value is treated as "staff" by the receiver (fails to the narrower,
# safer population) and is flagged by a system check
# (django_waf.checks.check_trusted_cookie_trust_level, django_waf.W006).
DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL: str = getattr(settings, "DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "staff")

# Cookie lifetime in seconds. Default 3600 (1 hour) -- deliberately SHORT.
# Unlike the site-password verified cookie (a low-value "is this visitor
# allowed to see the site at all" flag with a 12-hour default), this cookie
# grants a security-relevant bypass of WAF evaluation, so a stolen cookie is
# more valuable to an attacker and the exposure window is kept tight. The
# cookie also binds to the client IP (see trusted_user_service), which
# further limits a stolen cookie's value but does not eliminate it entirely
# on shared/NAT'd networks, hence the short TTL as the primary control.
DJANGO_WAF_TRUSTED_COOKIE_TTL: int = getattr(settings, "DJANGO_WAF_TRUSTED_COOKIE_TTL", 3600)

# Domain for the trusted-user cookie. Defaults to None, which means
# trusted_user_service.set_trusted_cookie() falls back to
# settings.SESSION_COOKIE_DOMAIN at call time -- the same fallback
# convention as DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN, so a site that
# already sets SESSION_COOKIE_DOMAIN for subdomain coverage gets the same
# coverage on this cookie without configuring it twice. Set explicitly only
# when this cookie's subdomain scope must differ from the session cookie's.
DJANGO_WAF_TRUSTED_COOKIE_DOMAIN: str | None = getattr(settings, "DJANGO_WAF_TRUSTED_COOKIE_DOMAIN", None)

# ---------------------------------------------------------------------------
# detect_unsolved_challenges (issue #84)
# ---------------------------------------------------------------------------
# Traced against a live deployment: an attacker rotating roughly 120
# addresses per /24 abandons challenges (never attempts them, not failures)
# at a rate that is unmistakable in aggregate but invisible per IP. Reading
# these values from settings, not only the function's own parameter
# defaults, lets an operator tune the detector without calling it directly.
# Per #75 (still open), every value here is a conf.py import-time snapshot:
# tests overriding it must use patch.object(conf, "NAME", ...), not
# override_settings, or the override will not be seen.

# Minimum challenged verdicts a single IP must accumulate within the
# detection window before it is considered a candidate. Unchanged from the
# pre-#84 function default: traced live, this threshold was not the
# bottleneck for the IPs that reached it (3 of 3 survivors passed every
# later check). The problem is that almost no individual IP reaches it at
# all when the attacker spreads across a /24.
DJANGO_WAF_UNSOLVED_MIN_CHALLENGED: int = getattr(settings, "DJANGO_WAF_UNSOLVED_MIN_CHALLENGED", 3)

# Fraction of an IP's non-root requests that must carry an empty referer
# before the per-IP path flags it. Unchanged from the pre-#84 function
# default: traced live, this rejected nobody among the survivors, so it is
# not the current bottleneck (kept as a safety margin for when the
# candidate pool grows, per the issue's false-positive discipline).
DJANGO_WAF_UNSOLVED_REFERER_RATIO: float = getattr(settings, "DJANGO_WAF_UNSOLVED_REFERER_RATIO", 0.8)

# How far back to look for a SOLVED ChallengeToken before granting an IP (or
# a subnet, see DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS below) permanent immunity
# from this detector. Before #84 the solved-challenge exemption had no time
# bound at all: a single solve at any point in an IP's history granted
# immunity forever. Traced live, this removed half the candidates in a
# 60-minute window. 24 hours is chosen to be comfortably longer than the
# detector's own 60-minute default window (a recent, deliberate solve still
# exempts the IP for a full day) while no longer letting a solve from weeks
# or months ago paper over current abandonment behaviour.
DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS: int = getattr(
    settings, "DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS", 24
)

# Minimum total challenged-verdict count across an entire /24 (IPv4) or /48
# (IPv6) subnet before the subnet itself becomes a candidate. Necessarily
# far higher than DJANGO_WAF_UNSOLVED_MIN_CHALLENGED: a /24 carries up to
# 256 addresses, and the measured attack produced up to 3,232 abandoned
# challenges from one /24 in a week. 30 is chosen so ten distributed IPs
# challenged 3 times each (the per-IP threshold) would already qualify,
# while a handful of genuine visitors sharing a /24 who each abandon one
# or two challenges does not.
DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED: int = getattr(settings, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30)

# Minimum number of DISTINCT contributing IPs within the subnet, required
# alongside DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED. This is the guard
# against one noisy host escalating its neighbours: without it, a single
# IP hammering the site could cross the total-count threshold alone and
# get an entire /24 challenged. Measured subnets in the traced attack
# carried 100+ distinct contributing IPs; 10 is set far below that so the
# detector catches a materially smaller, still-clearly-distributed pool
# rather than only the extreme case already seen.
DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS: int = getattr(settings, "DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10)

# ---------------------------------------------------------------------------
# Verify-endpoint rate limit (issue #81)
# ---------------------------------------------------------------------------
# POST /waf/verify/ accepts proof-of-work solutions with no rate limit of
# its own. Each POST costs a signature check and Redis work, so unbounded
# it is a cheap way to consume server resources; hardening, not a response
# to observed abuse (production data showed zero failed challenges over 7
# days at the time this was added).
#
# DJANGO_WAF_RATE_LIMIT_PATHS cannot cover this path in the WAF's own
# recommended deployment shape: the challenge and verify paths are
# typically listed in DJANGO_WAF_EXEMPT_PATHS (a challenged user must
# always be able to reach them to clear themselves), and
# WafMiddleware.__call__ returns on the exempt-path match before rule
# evaluation, where check_rate_limit runs, is ever reached. So VerifyView
# calls django_waf.services.rate_limiter.check_verify_rate_limit directly,
# using its own dedicated Redis key, independent of the general per-path
# and global IP windows.
#
# The default sits well above the 2 to 3 round trips a real client needs
# (GET the challenge, POST the solution, follow the redirect) and above
# retry traffic from a NAT gateway or corporate proxy legitimately serving
# many simultaneous solvers behind one IP (#82 measured that a coarse
# per-IP signal there would have caught over a third of real users on a
# production deployment). 20 solves per 5 minutes covers a genuine burst
# of shared-egress traffic while still bounding a farm's unbounded solve
# rate. A breach degrades to a 429 with an accurate Retry-After (matching
# the existing throttle response shape) rather than a block, so a false
# positive is always recoverable.
DJANGO_WAF_VERIFY_RATE_LIMIT_MAX: int = getattr(settings, "DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20)
DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS: int = getattr(settings, "DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300)
