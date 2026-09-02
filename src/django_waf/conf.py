"""
Package-level settings with defaults.

All settings are namespaced under DJANGO_WAF_* and resolved at call time via
this module's ``__getattr__`` (PEP 562): ``django_waf.conf.DJANGO_WAF_X``
looks exactly like a plain module attribute to a caller, but every read
re-consults ``django.conf.settings`` rather than a value frozen at import
time. This is what makes ``override_settings`` and the pytest ``settings``
fixture work: neither reloads this module, so a constant computed once at
import time would never see either override.

Do not import these names directly into another module
(``from django_waf.conf import X``) or capture them at class/module scope
elsewhere in the package (``X = conf.Y`` or ``def f(x=conf.Y)``): either
pattern freezes the value again, defeating the point of this module. Always
read ``conf.X`` inside a function body, at the point of use.

When ``django.conf.settings`` is not yet configured (for example, a
consumer's own settings module importing a name from here before calling
``settings.configure()``), every name in this module resolves to its
documented default rather than raising ``ImproperlyConfigured``. This is a
deliberate, uniform contract across all 92 settings, not a per-setting
special case: see ``DJANGO_WAF_CELERY_BEAT_SCHEDULE`` below, which the
README documents as importable directly from a consumer's ``settings.py``.
"""

from __future__ import annotations

from typing import Any

from django.conf import settings

try:
    from celery.schedules import crontab
except ImportError:
    crontab = None  # type: ignore[assignment]


def _get_setting(name: str, default: Any) -> Any:
    """Resolve a single DJANGO_WAF_* setting at call time.

    Returns ``default`` without touching ``settings`` at all when Django
    settings are not yet configured, so importing this module (directly or
    transitively) from inside a consumer's own settings module, before
    ``settings.configure()`` / ``DJANGO_SETTINGS_MODULE`` has run, never
    raises ``ImproperlyConfigured``. Once configured, this is a plain
    ``getattr(settings, name, default)``.
    """
    if not settings.configured:
        return default
    return getattr(settings, name, default)


# Enable or disable the WAF middleware entirely.
def _DJANGO_WAF_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_ENABLED", True)


# Package-wide HMAC signing secret. Used by every signed artefact the WAF
# issues, form render tokens (v0.11.0), and any future signed verdicts
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
def _DJANGO_WAF_SIGNING_KEY() -> str:
    return _get_setting("DJANGO_WAF_SIGNING_KEY", "")


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
def _DJANGO_WAF_FORM_PROTECTION_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_FORM_PROTECTION_ENABLED", True)


# Aggregate-score thresholds. The orchestrator sums ``flag`` scores;
# crossing FLAG triggers logging + signal + (optionally) challenge
# redirect; crossing BLOCK rejects the submission outright. A single
# defence returning ``block`` short-circuits the chain regardless of
# total.
def _DJANGO_WAF_FORM_FLAG_THRESHOLD() -> float:
    return _get_setting("DJANGO_WAF_FORM_FLAG_THRESHOLD", 2.0)


def _DJANGO_WAF_FORM_BLOCK_THRESHOLD() -> float:
    return _get_setting("DJANGO_WAF_FORM_BLOCK_THRESHOLD", 5.0)


# Whether to redirect flagged submissions through the existing
# /waf/challenge/ flow rather than rejecting them. When True (default)
# false-positive users get a way through; when False they get a
# generic form error.
def _DJANGO_WAF_FORM_CHALLENGE_ON_FLAG() -> bool:
    return _get_setting("DJANGO_WAF_FORM_CHALLENGE_ON_FLAG", True)


# Whether the orchestrator fires the ``form_submission_passed`` signal.
# Off by default: busy sites have 1000x more passed submissions than
# flagged/blocked ones and firing in the hot path is wasted work. The
# structured log still records passes (sampled). Operators who want
# pass-event analytics opt in here.
def _DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL() -> bool:
    return _get_setting("DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL", False)


# Lifetime of a render token. After this many seconds the token is
# expired and the user gets a fresh one on the next render. Also the
# TTL of the Redis marker that backs replay protection.
def _DJANGO_WAF_FORM_TOKEN_TTL() -> int:
    return _get_setting("DJANGO_WAF_FORM_TOKEN_TTL", 3600)


# Honeypot field-name pool. The HoneypotDefence picks names from this
# list by hashing form_id, so a given form gets a stable set of names
# (cache-friendly) but different forms get different names (bots can't
# learn one global set).
def _DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES() -> list[str]:
    return _get_setting(
        "DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES",
        ["url", "website", "homepage", "email_confirm"],
    )


# Time-trap thresholds in seconds. Submissions faster than the min are
# flagged; faster than 0.5s are blocked outright. Submissions older
# than the max have either been sitting open too long (UA changed, IP
# changed) or are replays: flagged either way.
def _DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS() -> float:
    return _get_setting("DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS", 1.5)


def _DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS() -> float:
    return _get_setting("DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS", 3600)


# Credential-throttle settings. Per-IP threshold drives the visible
# challenge (enumeration-safe, same behaviour whether the typed
# username exists). Per-account threshold drives an observation-only
# ``credential_attack_observed`` signal so consumers can email the
# legitimate owner.
def _DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW() -> int:
    return _get_setting("DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW", 900)


def _DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT() -> int:
    return _get_setting("DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT", 5)


def _DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT() -> int:
    return _get_setting("DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT", 20)


# Signup-velocity settings. Counts *successful* signups per IP, so the
# user crossing the threshold sees a challenge on their *next* attempt.
def _DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW() -> int:
    return _get_setting("DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW", 86400)


def _DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT() -> int:
    return _get_setting("DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT", 5)


# Form-level PoW difficulty (leading zero bits). Lighter than the
# page-level challenge because it runs per-submission rather than once
# per session. 12 bits is about 4k SHA-256 hashes, about 50ms desktop,
# about 200ms mobile. Reuses the same _digest_has_leading_zero_bits
# verifier as the page challenge (no parallel implementation, no drift
# risk).
def _DJANGO_WAF_FORM_POW_DIFFICULTY() -> int:
    return _get_setting("DJANGO_WAF_FORM_POW_DIFFICULTY", 12)


# Replay-store backend. ``session`` uses Django's session framework
# (signed cookie + server-side data); ``redis`` uses the same Redis
# the rest of the WAF talks to. Most sites use session.
def _DJANGO_WAF_FORM_REPLAY_STORE() -> str:
    return _get_setting("DJANGO_WAF_FORM_REPLAY_STORE", "session")


# Global per-defence score weights. Overridable per-form via the
# ``defence_weights={...}`` kwarg on ``FormProtection``. The dict
# collapses what would otherwise be eight separate weight settings
# into one declaration.
def _DJANGO_WAF_FORM_DEFENCE_WEIGHTS() -> dict[str, float]:
    return _get_setting(
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


# Proof-of-work challenge difficulty: number of leading zero **bits** the
# SHA-256(token + nonce) digest must contain. Average solve cost is
# ``2 ** difficulty`` hashes. This single value is the default and is
# authoritative unless an operator explicitly overrides a device band below.
def _DJANGO_WAF_CHALLENGE_DIFFICULTY() -> int:
    return _get_setting("DJANGO_WAF_CHALLENGE_DIFFICULTY", 16)


# Desktop-class clients. Defaults to ``None``, which falls back to
# ``DJANGO_WAF_CHALLENGE_DIFFICULTY``. Set an explicit value only to give
# desktop clients a different (typically higher) cost than mobile.
def _DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP() -> int | None:
    return _get_setting("DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP", None)


# Mobile-class clients. Defaults to ``None``, which falls back to
# ``DJANGO_WAF_CHALLENGE_DIFFICULTY``. Set an explicit value only to give
# budget devices a lower cost than desktop.
def _DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE() -> int | None:
    return _get_setting("DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE", None)


# Optional literal-path overrides for the WAF's own challenge/verify URLs.
# When set, the middleware uses these strings directly instead of calling
# ``reverse()``. Recommended for projects using per-request urlconf routing
# (django-hosts and similar) that don't mount django_waf URLs on every host.
def _DJANGO_WAF_CHALLENGE_URL() -> str:
    return _get_setting("DJANGO_WAF_CHALLENGE_URL", "")


def _DJANGO_WAF_VERIFY_URL() -> str:
    return _get_setting("DJANGO_WAF_VERIFY_URL", "")


# TTL in seconds for a solved-challenge cookie.
def _DJANGO_WAF_CHALLENGE_COOKIE_TTL() -> int:
    return _get_setting("DJANGO_WAF_CHALLENGE_COOKIE_TTL", 86400)


# Maximum requests per IP per minute before throttling.
def _DJANGO_WAF_RATE_LIMIT_PER_MINUTE() -> int:
    return _get_setting("DJANGO_WAF_RATE_LIMIT_PER_MINUTE", 120)


# Maximum requests per IP per 5 minutes before throttling.
def _DJANGO_WAF_RATE_LIMIT_PER_5MIN() -> int:
    return _get_setting("DJANGO_WAF_RATE_LIMIT_PER_5MIN", 600)


# Burst allowance: requests that may exceed the rate limit momentarily.
def _DJANGO_WAF_RATE_LIMIT_BURST() -> int:
    return _get_setting("DJANGO_WAF_RATE_LIMIT_BURST", 10)


# Fraction of allowed requests to log (0.0 to 1.0). 1.0 = log everything.
def _DJANGO_WAF_LOG_SAMPLE_RATE() -> float:
    return _get_setting("DJANGO_WAF_LOG_SAMPLE_RATE", 0.01)


# Filesystem path for the generated nginx IP/UA blocklist include file.
def _DJANGO_WAF_NGINX_BLOCKLIST_PATH() -> str:
    return _get_setting(
        "DJANGO_WAF_NGINX_BLOCKLIST_PATH",
        "/etc/nginx/conf.d/django-waf-blocklist.conf",
    )


# Path to the nginx access log file parsed by the log-analysis command.
def _DJANGO_WAF_ACCESS_LOG_PATH() -> str:
    return _get_setting(
        "DJANGO_WAF_ACCESS_LOG_PATH",
        "/var/log/nginx/access.log",
    )


# Number of distinct user-agents from a single IP that triggers a UA-rotation anomaly.
def _DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS() -> int:
    return _get_setting("DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS", 20)


# Hours after which auto-generated rules expire automatically.
def _DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS() -> int:
    return _get_setting("DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS", 24)


# URL path prefixes that bypass WAF evaluation entirely.
def _DJANGO_WAF_EXEMPT_PATHS() -> list[str]:
    return _get_setting(
        "DJANGO_WAF_EXEMPT_PATHS",
        ["/static/", "/media/", "/health/", "/favicon.ico"],
    )


# Hostnames that bypass WAF evaluation entirely. Matching mirrors Django's
# ALLOWED_HOSTS convention: an exact host match, or a leading-dot entry
# (".example.com") that matches the domain and any subdomain. The port is
# stripped before matching. Empty by default (no host is exempt).
def _DJANGO_WAF_EXEMPT_HOSTS() -> list[str]:
    return _get_setting(
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
def _DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS() -> bool:
    return _get_setting("DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS", True)


# TTL in seconds for a NEGATIVE forward-confirmed reverse DNS (FCrDNS)
# verification result: a PTR/hostname pattern match that then failed the
# forward-resolution check, or any DNS error on either lookup (#34). Kept
# short (5 minutes) rather than the 24-hour positive-result TTL, because a
# negative result can come from a transient resolver outage, and a long
# negative cache would suppress a legitimate crawler's AllowRule match for
# a full day per IP on every hiccup. A positive FCrDNS verification is
# always cached for 24 hours, unaffected by this setting: legitimate
# crawler infrastructure's DNS records change rarely.
def _DJANGO_WAF_RDNS_FAILURE_CACHE_TTL() -> int:
    return _get_setting("DJANGO_WAF_RDNS_FAILURE_CACHE_TTL", 300)


# Trust the X-Forwarded-For header when extracting the real client IP.
def _DJANGO_WAF_TRUST_X_FORWARDED_FOR() -> bool:
    return _get_setting("DJANGO_WAF_TRUST_X_FORWARDED_FOR", False)


# Django cache alias used for Redis rate-limit counters and rule-version keys.
def _DJANGO_WAF_REDIS_ALIAS() -> str:
    return _get_setting("DJANGO_WAF_REDIS_ALIAS", "default")


# Enable syncing rules from the collective threat feed.
def _DJANGO_WAF_FEED_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_FEED_ENABLED", True)


# URL of the collective threat feed JSON endpoint. Points at the operated
# feed server (threats.drystane.com); override for a self-hosted or
# third-party compatible server.
def _DJANGO_WAF_FEED_URL() -> str:
    return _get_setting("DJANGO_WAF_FEED_URL", "https://threats.drystane.com/v1/feed.json")


# Minimum confidence score (0.0 to 1.0) required to import a feed entry as a rule.
def _DJANGO_WAF_FEED_MIN_CONFIDENCE() -> float:
    return _get_setting("DJANGO_WAF_FEED_MIN_CONFIDENCE", 0.8)


# Enable reporting local detections back to the collective feed. Opt-in by
# design (ADR-021 point 4): telemetry is never sent unless an operator sets
# this to True, regardless of whether DJANGO_WAF_FEED_REPORT_URL is
# configured. Setting this to True is the only step a site needs to start
# reporting.
def _DJANGO_WAF_FEED_REPORT() -> bool:
    return _get_setting("DJANGO_WAF_FEED_REPORT", False)


# URL for reporting detections to the collective feed. Points at the
# operated feed server (threats.drystane.com); override for a self-hosted
# or third-party compatible server.
def _DJANGO_WAF_FEED_REPORT_URL() -> str:
    return _get_setting("DJANGO_WAF_FEED_REPORT_URL", "https://threats.drystane.com/v1/report")


# API key for authenticating with the collective threat feed.
def _DJANGO_WAF_FEED_API_KEY() -> str:
    return _get_setting("DJANGO_WAF_FEED_API_KEY", "")


# Number of days to retain RequestLog entries before purging.
def _DJANGO_WAF_LOG_RETENTION_DAYS() -> int:
    return _get_setting("DJANGO_WAF_LOG_RETENTION_DAYS", 30)


# Path to the nginx PID file. When set, reload_nginx() sends SIGHUP to the
# master process directly: no subprocess, no sudo, no PATH required. Just
# needs read access to the PID file. Set to None to use the command fallback.
def _DJANGO_WAF_NGINX_PID_PATH() -> str | None:
    return _get_setting(
        "DJANGO_WAF_NGINX_PID_PATH",
        "/run/nginx.pid",
    )


# Fallback command for nginx reload (used when DJANGO_WAF_NGINX_PID_PATH is None
# or the PID file is unreadable).
def _DJANGO_WAF_NGINX_RELOAD_COMMAND() -> list[str]:
    return _get_setting(
        "DJANGO_WAF_NGINX_RELOAD_COMMAND",
        ["nginx", "-s", "reload"],
    )


# Path prefixes exempt from no-referer challenge (only evaluated when
# DJANGO_WAF_CHALLENGE_NO_REFERER is True).
def _DJANGO_WAF_CHALLENGE_NO_REFERER() -> bool:
    return _get_setting("DJANGO_WAF_CHALLENGE_NO_REFERER", False)


def _DJANGO_WAF_NO_REFERER_EXEMPT_PATHS() -> list[str]:
    return _get_setting(
        "DJANGO_WAF_NO_REFERER_EXEMPT_PATHS",
        ["/", "/search/", "/robots.txt", "/sitemap.xml", "/favicon.ico"],
    )


# Path to a MaxMind GeoLite2-Country.mmdb database for GeoIP lookups.
# Set to None to disable GeoIP (default).
def _DJANGO_WAF_GEOIP_PATH() -> str | None:
    return _get_setting("DJANGO_WAF_GEOIP_PATH", None)


# MaxMind licence key for downloading GeoLite2 databases via the
# ``manage.py django_waf_install_geoip`` command or the
# ``update_geoip_database`` Celery task. Sign up for a free key at
# https://www.maxmind.com/en/geolite2/signup and load it from your
# environment (e.g. ``os.environ.get("MAXMIND_LICENSE_KEY", "")``).
def _DJANGO_WAF_MAXMIND_LICENSE_KEY() -> str:
    return _get_setting("DJANGO_WAF_MAXMIND_LICENSE_KEY", "")


# HTTP methods allowed through the WAF. Requests with other methods receive
# a 405 response before any rule evaluation. Set to None to allow all methods.
def _DJANGO_WAF_ALLOWED_METHODS() -> list[str] | None:
    return _get_setting("DJANGO_WAF_ALLOWED_METHODS", None)


# Regex patterns for suspicious paths (credential probes, known webshells,
# backup archives, and vendor-specific exploit targets).
#
# Each matched pattern adds DJANGO_WAF_SUSPICIOUS_PATH_SCORE to the request's
# anomaly score. Patterns are picked so that a legitimate user on a Django
# site is extremely unlikely to trigger them: any match is a strong signal.
#
# Patterns that would overlap legitimate apps (``.ini``, ``.conf``, ``.aspx``,
# ``.jsp``, ``/cgi-bin/``) are intentionally omitted to keep the
# false-positive rate near-zero on mixed-tech estates.
#
# Patterns use re.search (anywhere-in-path, case-insensitive). Anchor with
# ^ or $ when position matters.
def _DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS() -> list[str]:
    return _get_setting(
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
            # Config files (framework-specific: avoid broad ``.conf``/``.ini``)
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
            # Generic webshells (named explicitly: avoid broad plugin/upload
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
def _DJANGO_WAF_SCORE_THRESHOLD_LOG() -> float:
    return _get_setting("DJANGO_WAF_SCORE_THRESHOLD_LOG", 3.0)


def _DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE() -> float:
    return _get_setting("DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE", 5.0)


def _DJANGO_WAF_SCORE_THRESHOLD_BLOCK() -> float:
    return _get_setting("DJANGO_WAF_SCORE_THRESHOLD_BLOCK", 7.0)


# Number of challenges from a single IP before auto-escalating from
# challenge to block. From 2.0.0, this counts challenges issued to a
# client whose HTTP fingerprint is classified "bot" (BR-FP-001) regardless
# of whether the client goes on to solve the proof-of-work: a datacentre
# CPU solves hashcash almost for free, so a bot that solves every challenge
# no longer resets the count to zero. For every other fingerprint verdict,
# a solved challenge still resets the count, unchanged from before 2.0.0.
def _DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD() -> int:
    return _get_setting("DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD", 10)


# Score added per suspicious path match.
def _DJANGO_WAF_SUSPICIOUS_PATH_SCORE() -> float:
    return _get_setting("DJANGO_WAF_SUSPICIOUS_PATH_SCORE", 3.0)


# TTL in seconds for escalation blocks (challenges that were never solved).
def _DJANGO_WAF_ESCALATION_BLOCK_TTL() -> int:
    return _get_setting("DJANGO_WAF_ESCALATION_BLOCK_TTL", 3600)


# Cloud spray detection: many distinct IPs with identical behaviour.
def _DJANGO_WAF_CLOUD_SPRAY_MIN_IPS() -> int:
    return _get_setting("DJANGO_WAF_CLOUD_SPRAY_MIN_IPS", 20)


def _DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP() -> int:
    return _get_setting("DJANGO_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP", 3)


# Top-N spray UAs (ranked by distinct suspicious IPs) considered per
# detect_cloud_spray run, replacing the previous hardcoded [:5] cap.
def _DJANGO_WAF_CLOUD_SPRAY_TOP_N() -> int:
    return _get_setting("DJANGO_WAF_CLOUD_SPRAY_TOP_N", 5)


# Enable detect_cloud_spray's diffuse-spray UA path: when a UA alone clears
# DJANGO_WAF_CLOUD_SPRAY_MIN_IPS distinct suspicious IPs, create a single
# CHALLENGE rule for that exact UA, independent of subnet clustering.
# Default False: a shared UA can be a corporate NAT, a CGNAT range, or an
# embedded webview, so this is opt-in and does not change behaviour for an
# existing consumer on upgrade.
def _DJANGO_WAF_CLOUD_SPRAY_UA_RULE() -> bool:
    return _get_setting("DJANGO_WAF_CLOUD_SPRAY_UA_RULE", False)


# Per-path rate limits: {path_prefix: (max_requests, window_seconds)}.
# Longest-prefix match wins; checked before the global IP windows.
def _DJANGO_WAF_RATE_LIMIT_PATHS() -> dict:
    return _get_setting("DJANGO_WAF_RATE_LIMIT_PATHS", {})


# ISO 3166-1 alpha-2 country codes to block outright (e.g. ["CN", "RU"]).
# Empty disables country blocking. Requires a GeoIP database (see
# django_waf_install_geoip); fails open when lookup is unavailable.
def _DJANGO_WAF_BLOCKED_COUNTRIES() -> list:
    return _get_setting("DJANGO_WAF_BLOCKED_COUNTRIES", [])


# Enable the optional DRF API under waf/api/ (requires the [api] extra).
def _DJANGO_WAF_API_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_API_ENABLED", False)


# ---------------------------------------------------------------------------
# Site password gate (BR-SP series)
# ---------------------------------------------------------------------------
# A middleware-level shared-password wall gating the whole site (and every
# subdomain it serves) before any application view. See
# docs/specs/site-password/PRD.md.


# The shared password. Unset/empty means the gate is off (BR-SP-001).
# Never rendered, never logged (BR-SP-005). Load from environment in
# production.
def _DJANGO_WAF_SITE_PASSWORD() -> str:
    return _get_setting("DJANGO_WAF_SITE_PASSWORD", "")


# Explicit on/off switch. Defaults to whether a password is set. Enabling
# this with an empty password fails closed rather than opening the gate
# (BR-SP-002): every gated request is denied and a system check warns at
# boot (django_waf.checks.check_site_password_configured).
#
# The default recurses through the resolver for DJANGO_WAF_SITE_PASSWORD
# rather than reading a frozen value: this is the one intra-conf
# cross-reference among all 92 settings, and it must reflect whatever
# DJANGO_WAF_SITE_PASSWORD resolves to on THIS call, not whatever it
# happened to resolve to at import time (BR-SP-002's fail-closed guarantee
# depends on this).
def _DJANGO_WAF_SITE_PASSWORD_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_SITE_PASSWORD_ENABLED", bool(_DJANGO_WAF_SITE_PASSWORD()))


# Verified-session lifetime in seconds. Default 12 hours (BR-SP-004).
def _DJANGO_WAF_SITE_PASSWORD_TTL() -> int:
    return _get_setting("DJANGO_WAF_SITE_PASSWORD_TTL", 43200)


# Path prefixes that bypass the gate even when locked (BR-SP-003): health
# checks, ACME/well-known probes, robots.txt, and the WAF's own
# challenge/verify interstitials (so the WAF's existing defences keep
# working and the site-password gate never traps its own prompt-and-verify
# round trip in a loop).
def _DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS() -> list[str]:
    return _get_setting(
        "DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS",
        ["/health/", "/.well-known/", "/robots.txt", "/waf/challenge/", "/waf/verify/"],
    )


# Path the prompt form posts to. The middleware intercepts POSTs to this
# path directly (before URL resolution), so it works even on hosts that
# don't mount django_waf.urls, but the same path is also routed in
# urls.py so reverse() and direct access resolve to a real view.
def _DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH() -> str:
    return _get_setting("DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH", "/waf/site-password/")


# Domain for the gate's own verified-flag cookie (see
# django_waf.services.site_password_service, the gate uses its own signed
# cookie, not Django's session, because WafMiddleware runs before
# SessionMiddleware). Defaults to None, which means
# site_password_service.set_verified_cookie() falls back to
# settings.SESSION_COOKIE_DOMAIN at call time, so a site that already sets
# SESSION_COOKIE_DOMAIN=".example.com" for subdomain coverage gets the same
# coverage on this cookie without configuring it twice. Set explicitly only
# when the gate's subdomain scope must differ from the session cookie's.
def _DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN() -> str | None:
    return _get_setting("DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN", None)


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
    "django-waf-probe-detectors": {
        "task": "django_waf.tasks.probe_detectors",
        "schedule": 3600.0,  # every hour (BR-ANOM-012)
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
    # celery is not installed: the cron-time entries above need
    # crontab() to build a schedule, so they are omitted rather than
    # guessed at with a plain interval. The */N minute entries above still
    # work fine as they don't touch crontab at all.
    _CELERY_BEAT_CRON_ENTRIES = {}


# Ready-made CELERY_BEAT_SCHEDULE fragment covering every periodic
# django-waf task. See the module docstring above this block for usage.
#
# Resolves to the merged default whenever Django settings are not yet
# configured (the general contract documented at the top of this module),
# which is what makes the README's documented consumer pattern,
# ``from django_waf.conf import DJANGO_WAF_CELERY_BEAT_SCHEDULE`` inside a
# settings module, before that settings module has finished executing,
# safe rather than a hard ``ImproperlyConfigured`` boot failure.
def _DJANGO_WAF_CELERY_BEAT_SCHEDULE() -> dict:
    return _get_setting(
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
def _DJANGO_WAF_TRUSTED_PROXIES() -> list[str]:
    return _get_setting("DJANGO_WAF_TRUSTED_PROXIES", [])


# Trust an empty REMOTE_ADDR from a unix-socket WSGI peer as the direct proxy
# hop. This is deliberately opt-in: an operator must ensure that only their
# reverse proxy can connect to the socket before the X-Forwarded-For header is
# honoured.
def _DJANGO_WAF_TRUSTED_UNIX_SOCKET() -> bool:
    return _get_setting("DJANGO_WAF_TRUSTED_UNIX_SOCKET", False)


# ---------------------------------------------------------------------------
# Threat-feed import constraints (#33)
# ---------------------------------------------------------------------------
# When True (the default), an allow rule created from the threat feed is
# imported inactive (is_active=False), so a compromised or mistaken feed
# cannot open an exemption without an operator confirming it. Set False only
# if you fully trust the feed source to publish allow rules.
def _DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES() -> bool:
    return _get_setting("DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES", True)


# ---------------------------------------------------------------------------
# nginx blocklist export validation (#31)
# ---------------------------------------------------------------------------
# When True (the default), a freshly generated blocklist is validated with
# DJANGO_WAF_NGINX_TEST_COMMAND before the reload is signalled. On failure
# the previous known-good file is restored and no reload happens, so a bad
# generated file cannot break a later full nginx restart. If the nginx
# binary is absent the validation step is skipped gracefully. Set False to
# restore the pre-1.7.0 write-then-reload behaviour without validation.
def _DJANGO_WAF_NGINX_VALIDATE() -> bool:
    return _get_setting("DJANGO_WAF_NGINX_VALIDATE", True)


# The command run to validate the candidate configuration. Defaults to a
# plain syntax check; override if nginx is not on PATH or needs a specific
# prefix (e.g. ["sudo", "nginx", "-t"]).
def _DJANGO_WAF_NGINX_TEST_COMMAND() -> list[str]:
    return _get_setting("DJANGO_WAF_NGINX_TEST_COMMAND", ["nginx", "-t"])


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
def _DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES() -> bool:
    return _get_setting("DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES", False)


# Detector function names (e.g. ["detect_cloud_spray"]) that must always
# create quarantined rules (is_active=False, review_status=PENDING),
# regardless of DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES above (BR-ANOM-008).
# Lets an operator build trust in one detector's output without quarantining
# every detector's rules. A name that does not match a known detector is
# caught at boot by django_waf.checks.check_observe_only_detector_names
# (django_waf.W008), so a detector rename cannot silently desync this list
# from the functions it names.
def _DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS() -> list[str]:
    return _get_setting("DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS", [])


# ---------------------------------------------------------------------------
# Trusted-user cookie (#23)
# ---------------------------------------------------------------------------
# A signed, WAF-owned cookie that carries "this request is from a trusted
# (staff) user" independently of request.user, so the staff/superuser bypass
# (BR-RATE-003, django_waf.middleware._is_staff_user) works even when
# WafMiddleware runs before django.contrib.auth.middleware.AuthenticationMiddleware,
# the security-first ordering the WAF's own README recommends, and the
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
def _DJANGO_WAF_TRUSTED_COOKIE_ENABLED() -> bool:
    return _get_setting("DJANGO_WAF_TRUSTED_COOKIE_ENABLED", False)


# Which users the login receiver issues the cookie to. "staff" (default)
# limits the bypass to the same population the pre-existing request.user
# check already trusted (is_staff or is_superuser); "authenticated" widens
# it to any logged-in user, which broadens the bypass and weakens the WAF
# for that population, so it is an explicit opt-in, not the default. Any
# other value is treated as "staff" by the receiver (fails to the narrower,
# safer population) and is flagged by a system check
# (django_waf.checks.check_trusted_cookie_trust_level, django_waf.W006).
def _DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL() -> str:
    return _get_setting("DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL", "staff")


# Cookie lifetime in seconds. Default 3600 (1 hour), deliberately SHORT.
# Unlike the site-password verified cookie (a low-value "is this visitor
# allowed to see the site at all" flag with a 12-hour default), this cookie
# grants a security-relevant bypass of WAF evaluation, so a stolen cookie is
# more valuable to an attacker and the exposure window is kept tight. The
# cookie also binds to the client IP (see trusted_user_service), which
# further limits a stolen cookie's value but does not eliminate it entirely
# on shared/NAT'd networks, hence the short TTL as the primary control.
def _DJANGO_WAF_TRUSTED_COOKIE_TTL() -> int:
    return _get_setting("DJANGO_WAF_TRUSTED_COOKIE_TTL", 3600)


# Domain for the trusted-user cookie. Defaults to None, which means
# trusted_user_service.set_trusted_cookie() falls back to
# settings.SESSION_COOKIE_DOMAIN at call time, the same fallback
# convention as DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN, so a site that
# already sets SESSION_COOKIE_DOMAIN for subdomain coverage gets the same
# coverage on this cookie without configuring it twice. Set explicitly only
# when this cookie's subdomain scope must differ from the session cookie's.
def _DJANGO_WAF_TRUSTED_COOKIE_DOMAIN() -> str | None:
    return _get_setting("DJANGO_WAF_TRUSTED_COOKIE_DOMAIN", None)


# ---------------------------------------------------------------------------
# detect_subnet_burst (issue #80)
# ---------------------------------------------------------------------------
# Absolute floor a subnet's request count must clear before it can ever be
# flagged as a burst, in addition to the existing 3x-median ratio check.
# Before #80 the ratio was judged against the arithmetic MEAN of the
# window's own per-subnet counts, which the measured population itself
# moves: a botnet spread across more adjacent /24s at a similar volume
# raises the mean it is judged against, so occupying more prefixes made
# every one of them safer. Traced live: a cohort sustaining ~1.2
# requests/hour per prefix across several adjacent /24s and /25s was never
# flagged. The ratio now compares against the MEDIAN, which resists this
# far better (adding more low-volume attacker entries does not move the
# middle-ranked value the way it moves the mean), but the median is still
# only resistant, not immune: if attacker subnets come to outnumber
# legitimate ones in the window, the median itself becomes an
# attacker-typical value. This floor is what actually delivers the required
# guarantee, since it is a fixed number read from settings and never
# derived from subnet_counts, so no amount of dilution by additional
# attacker subnets can move it. Default 30 mirrors the existing
# DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED order of magnitude used
# elsewhere in this module for a comparable "aggregate looks wrong even
# though nothing else does" signal, and is deliberately far below the
# default window's typical single-subnet volume on a low-traffic
# deployment, while still requiring more than a handful of incidental
# requests before a subnet can be flagged at all.
def _DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT() -> int:
    return _get_setting("DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT", 30)


# detect_unsolved_challenges (issue #84)
# ---------------------------------------------------------------------------
# Traced against a live deployment: an attacker rotating roughly 120
# addresses per /24 abandons challenges (never attempts them, not failures)
# at a rate that is unmistakable in aggregate but invisible per IP. Reading
# these values from settings, not only the function's own parameter
# defaults, lets an operator tune the detector without calling it directly.
# From #75, every value here is resolved at call time like every other
# setting in this module: an override via override_settings or the pytest
# settings fixture is seen without any reload.


# Minimum challenged verdicts a single IP must accumulate within the
# detection window before it is considered a candidate. Unchanged from the
# pre-#84 function default: traced live, this threshold was not the
# bottleneck for the IPs that reached it (3 of 3 survivors passed every
# later check). The problem is that almost no individual IP reaches it at
# all when the attacker spreads across a /24.
def _DJANGO_WAF_UNSOLVED_MIN_CHALLENGED() -> int:
    return _get_setting("DJANGO_WAF_UNSOLVED_MIN_CHALLENGED", 3)


# Fraction of an IP's non-root requests that must carry an empty referer
# before the per-IP path flags it. Unchanged from the pre-#84 function
# default: traced live, this rejected nobody among the survivors, so it is
# not the current bottleneck (kept as a safety margin for when the
# candidate pool grows, per the issue's false-positive discipline).
def _DJANGO_WAF_UNSOLVED_REFERER_RATIO() -> float:
    return _get_setting("DJANGO_WAF_UNSOLVED_REFERER_RATIO", 0.8)


# How far back to look for a SOLVED ChallengeToken before granting an IP (or
# a subnet, see DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS below) permanent immunity
# from this detector. Before #84 the solved-challenge exemption had no time
# bound at all: a single solve at any point in an IP's history granted
# immunity forever. Traced live, this removed half the candidates in a
# 60-minute window. 24 hours is chosen to be comfortably longer than the
# detector's own 60-minute default window (a recent, deliberate solve still
# exempts the IP for a full day) while no longer letting a solve from weeks
# or months ago paper over current abandonment behaviour.
def _DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS() -> int:
    return _get_setting("DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS", 24)


# Minimum total challenged-verdict count across an entire /24 (IPv4) or /48
# (IPv6) subnet before the subnet itself becomes a candidate. Necessarily
# far higher than DJANGO_WAF_UNSOLVED_MIN_CHALLENGED: a /24 carries up to
# 256 addresses, and the measured attack produced up to 3,232 abandoned
# challenges from one /24 in a week. 30 is chosen so ten distributed IPs
# challenged 3 times each (the per-IP threshold) would already qualify,
# while a handful of genuine visitors sharing a /24 who each abandon one
# or two challenges does not.
def _DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED() -> int:
    return _get_setting("DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED", 30)


# Minimum number of DISTINCT contributing IPs within the subnet, required
# alongside DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED. This is the guard
# against one noisy host escalating its neighbours: without it, a single
# IP hammering the site could cross the total-count threshold alone and
# get an entire /24 challenged. Measured subnets in the traced attack
# carried 100+ distinct contributing IPs; 10 is set far below that so the
# detector catches a materially smaller, still-clearly-distributed pool
# rather than only the extreme case already seen.
def _DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS() -> int:
    return _get_setting("DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS", 10)


# Time window, in minutes, the subnet path of detect_unsolved_challenges
# aggregates over. Deliberately separate from the per-IP path's window
# (which stays on the function's own window_minutes parameter, default 60,
# and must not be widened: it is already producing correct per-IP BLOCK
# rules in production at that window). Issue #93 traced why the subnet path
# needed its own, wider window: DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED
# (30) and DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS (10) were calibrated in #84
# against a SEVEN DAY aggregate, but the subnet path only ever ran inside
# the per-IP detector's 60-minute window, so a deliberately slow-drip
# attacker never produced enough volume in any single hour to clear either
# threshold. Measured on the production deployment #93 was built for, same
# (30, 10) gate, varying only the window:
#
#   window  60m:  42 subnets seen,   0 qualify
#   window 180m: 116 subnets seen,   2 qualify
#   window 360m: 241 subnets seen,  10 qualify
#
# 360 (6 hours) is the smallest of the measured windows at which the
# existing thresholds catch every subnet clearing the distinct-IP floor,
# so it is the default rather than a threshold change: two variables were
# not moved at once. At a 360-minute window, all ten subnets that would
# have qualified carried zero allowed/passed rows, and nine of the ten had
# zero IPs that ever solved a challenge; the tenth was the known
# JS-executing bot cohort from #77. No legitimate user traffic was found in
# any of them. The wider scan is not a query-cost concern: on a table of
# 1.5M RequestLog rows, a 360-minute scan runs in 0.006s against the
# existing django_waf_rl_verdict_ts_idx index, indistinguishable in cost
# from the 60-minute scan.
def _DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES() -> int:
    return _get_setting("DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES", 360)


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
def _DJANGO_WAF_VERIFY_RATE_LIMIT_MAX() -> int:
    return _get_setting("DJANGO_WAF_VERIFY_RATE_LIMIT_MAX", 20)


def _DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS() -> int:
    return _get_setting("DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS", 300)


# ---------------------------------------------------------------------------
# detect_scraper_404_ratio: residential-proxy scraper detection by 404 rate
# ---------------------------------------------------------------------------
# Traced against a live deployment (VendablyCSS, shopping.vendably.com,
# django-waf 2.1.0, three-day window): a residential-proxy scraping botnet
# defeated every existing detector at once. 10,874 distinct IPs spread across
# roughly 9,700 distinct /24 subnets (about 1.1 IPs per /24, mean 1.42
# requests per IP) evaded detect_subnet_burst's >= 30 req/subnet floor and
# detect_unsolved_challenges's subnet path (>= 10 IPs/subnet). 15,426 distinct
# User-Agent strings, one per request, meant no shared-UA grouping key
# existed for detect_cloud_spray's UA path, and its subnet path needs >= 2
# suspicious IPs sharing a subnet, which this shape almost never produces.
# Every one of the botnet's 15,378 requests scored exactly 3.50
# (fingerprint-derived only, zero matched a suspicious path pattern), landing
# strictly between DJANGO_WAF_SCORE_THRESHOLD_LOG (2.5) and
# DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE (5.0), so every one was verdict=logged
# and passed straight through to the application.
#
# The signal that does separate them is the 404 ratio. Filtering the same
# window to IPs with >= 20 requests and >= 85% 404 responses yielded 14 IPs,
# all confirmed scrapers (e.g. 31.58.20.59 at 100% over 32 requests,
# 88.167.25.244 at 97% over 75, 103.59.160.242 at 92% over 115). A real
# browser does not sustain a ~100% 404 rate over dozens of requests: a human
# who hits a dead link navigates somewhere real, or gives up, long before
# reaching that volume. The requested paths were stale internal URLs (old
# category/merchant paths, with and without a trailing slash), i.e. a scrape
# working from an outdated link graph, not a vulnerability scan probing for
# known-bad paths (which DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS already covers).


# Minimum request count an IP must reach within the window before its 404
# ratio is considered at all. 20 is comfortably below the smallest confirmed
# scraper in the traced attack (32 requests) while high enough that a
# handful of genuinely broken links from a real visitor's session cannot
# alone qualify.
def _DJANGO_WAF_SCRAPER_404_MIN_REQUESTS() -> int:
    return _get_setting("DJANGO_WAF_SCRAPER_404_MIN_REQUESTS", 20)


# Fraction of an IP's (non-WAF-rejected) requests that must be 404 before it
# is flagged. 0.85 sits below every confirmed scraper measured (92-100%)
# with margin, while comfortably above what a real visitor following a few
# stale bookmarks or an old external link would ever sustain.
def _DJANGO_WAF_SCRAPER_404_RATIO() -> float:
    return _get_setting("DJANGO_WAF_SCRAPER_404_RATIO", 0.85)


# Time window, in minutes, the detector aggregates over. 1440 (24 hours) is
# deliberately wide, on the same precedent as
# DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES (360, #93): a detector whose
# attacker spreads volume thinly over time needs its own wider window, or
# the fixed count/ratio thresholds it compares against are never reachable
# regardless of how they are tuned. Simulated live against the traced
# deployment, sweeping window x DJANGO_WAF_SCRAPER_404_MIN_REQUESTS at the
# default 0.85 ratio, counting flagged IPs:
#
#   window   180m: minreq 10 ->  0, 15 ->  0, 20 ->  0, 30 ->  0
#   window   360m: minreq 10 ->  3, 15 ->  2, 20 ->  1, 30 ->  1
#   window   720m: minreq 10 ->  4, 15 ->  3, 20 ->  3, 30 ->  2
#   window  1440m: minreq 10 -> 13, 15 -> 10, 20 ->  8, 30 ->  7
#
# At 180 minutes the detector catches nothing at all: this cohort's mean of
# 1.42 requests per IP over the full 3-day trace means no individual IP
# accumulates enough volume inside 3 hours to clear even the lowest
# min_requests swept. 1440 (24 hours) is the smallest swept window at which
# the default DJANGO_WAF_SCRAPER_404_MIN_REQUESTS=20 catches a materially
# non-trivial, confirmed-scraper population (8 IPs), so it is the default
# rather than a threshold change: the window, not the count/ratio
# thresholds, was the wrong knob, exactly as it was for #93.
def _DJANGO_WAF_SCRAPER_404_WINDOW_MINUTES() -> int:
    return _get_setting("DJANGO_WAF_SCRAPER_404_WINDOW_MINUTES", 1440)


# Whether a qualifying IP is auto-created at RuleAction.BLOCK rather than
# RuleAction.CHALLENGE. Default False: a 404 ratio is a behavioural signal,
# not proof of malice on its own (a broken external link farm or a stale
# sitemap could theoretically produce the same shape), so this detector
# follows the same staging precedent as detect_cloud_spray's UA path
# (issue #82): a coarse aggregate signal is staged at CHALLENGE by default,
# and an operator who has built confidence in the signal opts into BLOCK.
def _DJANGO_WAF_SCRAPER_404_ACTION_BLOCK() -> bool:
    return _get_setting("DJANGO_WAF_SCRAPER_404_ACTION_BLOCK", False)


# ---------------------------------------------------------------------------
# PEP 562 module-level __getattr__ / __dir__: call-time resolution (#75)
# ---------------------------------------------------------------------------
# Every DJANGO_WAF_* name above is a private ``_NAME()`` resolver function,
# never a module-level constant, specifically so that ``conf.DJANGO_WAF_X``
# re-consults django.conf.settings on every access rather than freezing a
# value read once at import time. __getattr__ is only called by Python when
# normal attribute lookup fails (i.e. the name is not in this module's
# __dict__), which is exactly what a bare module-level function definition
# never populates for these names, so a test using
# unittest.mock.patch.object(django_waf.conf, "DJANGO_WAF_X", value) still
# works exactly as it would against a plain module attribute: entering the
# patch calls setattr (writing the name into this module's __dict__ for the
# duration), and exiting calls delattr (removing it again), which restores
# __getattr__ resolution rather than shadowing it. This module intentionally
# does NOT reassign __class__ to a custom ModuleType subclass with its own
# __setattr__/__delattr__: doing so cannot fix pytest's monkeypatch.setattr,
# whose restore-on-teardown path is itself a plain setattr call carrying the
# pre-patch value, indistinguishable from a fresh override by any override
# store this module could maintain. The ambiguity is inherent to Python
# attribute semantics, not a gap this module's mechanism leaves open. Do not
# use monkeypatch.setattr(conf, "NAME", ...) in a consumer's own tests for
# this reason; use unittest.mock.patch.object (as this package's own test
# suite does throughout) or override_settings instead.
_RESOLVERS: dict[str, Any] = {
    name[1:]: func for name, func in list(globals().items()) if name.startswith("_DJANGO_WAF_") and callable(func)
}


def __getattr__(name: str) -> Any:
    try:
        resolver = _RESOLVERS[name]
    except KeyError:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from None
    return resolver()


def __dir__() -> list[str]:
    return sorted({*globals().keys(), *_RESOLVERS.keys()})
