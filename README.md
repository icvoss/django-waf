<p align="center">
  <img src="https://raw.githubusercontent.com/icvoss/django-waf/main/.github/logo.svg" alt="" width="88">
</p>

# django-waf

Self-hosted request filtering, bot management, and WAF middleware for Django.

Provides two-layer defence (nginx + Django middleware) with rate limiting,
user-agent anomaly scoring, JS proof-of-work challenges, path-based threat
scoring, nginx blocklist generation, and collective threat feed integration,
all configurable without a reverse-proxy vendor.

## Features

- **Rate limiting**: sliding-window per-IP limits (burst, per-minute, per-5-min)
- **UA anomaly scoring**: heuristic detection of impossible OS/browser combos,
  ancient versions, scraper libraries
- **Path-based threat scoring**: suspicious path detection for credential probes
  (`.env`, `wp-config`, AWS/SSH config files) adds to the anomaly score
- **HTTP method filtering**: block non-standard methods (e.g. `HEAD`, `OPTIONS`,
  `PUT`, `PATCH`, `DELETE`) before rule evaluation
- **JS proof-of-work challenges**: hashcash-style SHA-256 challenges for
  suspicious clients (no CAPTCHAs, no third-party dependencies)
- **Challenge auto-escalation**: repeat offenders who exceed the unsolved-challenge
  threshold are automatically blocked for a configurable TTL
- **No-referer challenge trigger**: optionally challenge direct-navigation requests
  lacking a `Referer` header
- **GeoIP country code population**: attach ISO country codes to request log
  entries using a MaxMind GeoLite2 database
- **Composite rules**: block rules combining UA pattern with IP/CIDR
- **In-process rule cache**: version-checked in-memory cache avoids Redis round
  trips on every request; invalidated automatically when rules change
- **Hit count tracking**: block rules accumulate hit counts, flushed to the
  database periodically
- **Configurable anomaly score thresholds**: separate thresholds for log,
  challenge, and block verdicts
- **nginx blocklist generation**: exports `map`/`geo` blocks for C-level
  filtering at < 0.01 ms latency
- **Anomaly detection**: auto-creates expiring rules for UA rotation, subnet
  bursts, and challenge farms
- **Collective threat feed**: opt-in sync of anonymised threat intelligence
  across deployments
- **Staff dashboard**: HTMX-powered real-time analytics with anomaly management
- **Form protection**: defence-in-depth at the form layer: signed render
  tokens, honeypots, time-trap, UA-consistency, JS-touch, credential
  throttle (enumeration-safe), signup velocity, per-submission PoW.
  Mixin / decorator / template-tag entry points; per-form configuration;
  optional challenge-replay for false-positive rescue
- **Fail-open design**: Redis outage never breaks the site

## Requirements

- Python >= 3.11
- Django >= 5.2
- Redis (via `django-redis >= 5.4`)
- `httpx >= 0.27` (for threat feed sync)
- Optional: `celery >= 5.3` (for scheduled tasks)
- Optional: `maxminddb >= 2.4` (for GeoIP lookups)

## Installation

```bash
pip install django-waf
```

With optional extras:

```bash
pip install django-waf[geoip]    # adds maxminddb for GeoIP support
pip install django-waf[celery]   # adds celery for scheduled tasks
```

Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    "django_waf",
]
```

Add the middleware, placing it **after** `SecurityMiddleware` and **before**
other middleware so it can block requests early:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django_waf.middleware.WafMiddleware",        # <-- here
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    # ...
]
```

Include the URL routes for the challenge flow and staff dashboard:

```python
# urls.py
from django.urls import include, path

urlpatterns = [
    path("waf/", include("django_waf.urls")),
    # ...
]
```

Configure a Redis cache backend (required for rate limiting):

```python
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/0",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        },
    }
}
```

Run migrations:

```bash
python manage.py migrate django_waf
```

## Settings Reference

All settings are namespaced under `DJANGO_WAF_*` and have sensible defaults.

### Core

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_ENABLED` | `True` | Master switch: disable to pass all requests through |
| `DJANGO_WAF_EXEMPT_PATHS` | `["/static/", "/media/", "/health/", "/favicon.ico"]` | URL prefixes that bypass WAF evaluation entirely |
| `DJANGO_WAF_EXEMPT_HOSTS` | `[]` | Hostnames that bypass WAF evaluation entirely. Exact match, or a leading-dot entry (`.example.com`) matching the domain and any subdomain (mirrors Django's `ALLOWED_HOSTS`). Port is stripped before matching |
| `DJANGO_WAF_TRUST_X_FORWARDED_FOR` | `False` | Trust `X-Forwarded-For` header for client IP extraction |
| `DJANGO_WAF_REDIS_ALIAS` | `"default"` | Django cache alias for Redis connections |
| `DJANGO_WAF_ALLOWED_METHODS` | `None` | Allowed HTTP methods; requests with other methods receive 405 before rule evaluation. `None` allows all methods. |

### Rate Limiting

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_RATE_LIMIT_BURST` | `10` | Max requests per IP per second |
| `DJANGO_WAF_RATE_LIMIT_PER_MINUTE` | `120` | Max requests per IP per minute |
| `DJANGO_WAF_RATE_LIMIT_PER_5MIN` | `600` | Max requests per IP per 5 minutes |
| `DJANGO_WAF_RATE_LIMIT_PATHS` | `{}` | Per-path rate limits: `{path_prefix: (max_requests, window_seconds)}`. Checked before the global windows; the longest matching prefix wins |

### Challenges

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_CHALLENGE_DIFFICULTY` | `20` | Fallback proof-of-work leading zero **bits** when the desktop/mobile overrides are not set. Average work is `2 ** bits` SHA-256 hashes |
| `DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP` | `22` | PoW difficulty (bits) for non-mobile User-Agents. ~4M hashes, ~1 to 2s on a laptop |
| `DJANGO_WAF_CHALLENGE_DIFFICULTY_MOBILE` | `18` | PoW difficulty (bits) for mobile User-Agents. ~260k hashes, ~1 to 3s on a budget phone |
| `DJANGO_WAF_CHALLENGE_URL` | `""` | Optional literal path to the challenge view. Set this in projects using per-request urlconf routing (django-hosts and similar) where `reverse("django_waf:challenge")` cannot resolve. Empty = use `reverse()` |
| `DJANGO_WAF_VERIFY_URL` | `""` | Optional literal path to the verify view. Empty = use `reverse()` |
| `DJANGO_WAF_CHALLENGE_COOKIE_TTL` | `86400` | Seconds a solved-challenge cookie remains valid |
| `DJANGO_WAF_CHALLENGE_NO_REFERER` | `False` | Challenge requests that have no `Referer` header |
| `DJANGO_WAF_NO_REFERER_EXEMPT_PATHS` | `["/", "/search/", "/robots.txt", "/sitemap.xml", "/favicon.ico"]` | Paths exempt from the no-referer challenge (only evaluated when `DJANGO_WAF_CHALLENGE_NO_REFERER` is `True`) |
| `DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD` | `10` | Number of unsolved challenges before auto-escalating to a block |
| `DJANGO_WAF_ESCALATION_BLOCK_TTL` | `3600` | TTL in seconds for escalation blocks |

### Anomaly Scoring

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_SCORE_THRESHOLD_LOG` | `3.0` | Anomaly score at which a request is logged |
| `DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE` | `5.0` | Anomaly score at which a challenge is issued |
| `DJANGO_WAF_SCORE_THRESHOLD_BLOCK` | `7.0` | Anomaly score at which a request is blocked |
| `DJANGO_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS` | `20` | Distinct UAs per IP before triggering a UA-rotation anomaly |
| `DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS` | `24` | Hours before auto-generated rules expire |
| `DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS` | `[r"\.env", r"wp-config\.php", ...]` | Regex patterns for suspicious paths (credential probes, config files); matched paths add `DJANGO_WAF_SUSPICIOUS_PATH_SCORE` to the anomaly score |
| `DJANGO_WAF_SUSPICIOUS_PATH_SCORE` | `3.0` | Score added per suspicious path match |

### Logging

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_LOG_SAMPLE_RATE` | `0.01` | Fraction of allowed requests to log (0.0 to 1.0) |
| `DJANGO_WAF_LOG_RETENTION_DAYS` | `30` | Days to retain `RequestLog` entries |

### GeoIP

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_GEOIP_PATH` | `None` | Filesystem path to a MaxMind GeoLite2-Country `.mmdb` database. `None` disables GeoIP. |
| `DJANGO_WAF_BLOCKED_COUNTRIES` | `[]` | ISO 3166-1 alpha-2 country codes to block outright (e.g. `["CN", "RU"]`). Empty disables country blocking. Requires `DJANGO_WAF_GEOIP_PATH`; fails open when the lookup is unavailable. |

### nginx Integration

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_NGINX_BLOCKLIST_PATH` | `"/etc/nginx/conf.d/django-waf-blocklist.conf"` | Output path for the generated nginx blocklist |
| `DJANGO_WAF_ACCESS_LOG_PATH` | `"/var/log/nginx/access.log"` | nginx access log path for parsing |
| `DJANGO_WAF_NGINX_RELOAD_COMMAND` | `["nginx", "-s", "reload"]` | Command to reload nginx after blocklist generation |

### Collective Threat Feed

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_FEED_ENABLED` | `True` | Enable collective threat feed sync |
| `DJANGO_WAF_FEED_URL` | `"https://threats.drystane.com/v1/feed.json"` | Threat feed JSON endpoint |
| `DJANGO_WAF_FEED_MIN_CONFIDENCE` | `0.8` | Minimum confidence (0.0 to 1.0) to import a feed entry as a rule |
| `DJANGO_WAF_FEED_REPORT` | `False` | Report local detections back to the feed (opt-in). Setting this to `True` is the only setting a site needs to start reporting |
| `DJANGO_WAF_FEED_REPORT_URL` | `"https://threats.drystane.com/v1/report"` | Telemetry reporting endpoint |
| `DJANGO_WAF_FEED_API_KEY` | `""` | API key for feed authentication |

### Form protection (v0.11.0)

The form-protection subsystem is **opt-in per form**. Defaults are inert
until a form opts in via the mixin, decorator, or template tag.

| Setting | Default | Description |
|---------|---------|-------------|
| `DJANGO_WAF_SIGNING_KEY` | `""` | Package-wide HMAC secret. Separate from Django's `SECRET_KEY` so rotation lifecycles are independent. Empty → derives from `SECRET_KEY` and `django_waf.W003` warns at startup |
| `DJANGO_WAF_FORM_PROTECTION_ENABLED` | `True` | Master kill switch. `False` makes the mixin/decorator/tag short-circuit to pass without running defences |
| `DJANGO_WAF_FORM_FLAG_THRESHOLD` | `2.0` | Aggregate score crossing this triggers FLAGGED |
| `DJANGO_WAF_FORM_BLOCK_THRESHOLD` | `5.0` | Aggregate score crossing this triggers BLOCKED |
| `DJANGO_WAF_FORM_CHALLENGE_ON_FLAG` | `True` | Redirect FLAGGED submissions through `/waf/challenge/` (then replay the POST). `False` returns a generic rejection |
| `DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL` | `False` | Fire `form_submission_passed` on every PASS. Off by default: busy sites would burn cycles on the hot path; the structured log already records (sampled) passes |
| `DJANGO_WAF_FORM_TOKEN_TTL` | `3600` | Render-token lifetime in seconds; also the Redis marker TTL |
| `DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES` | `["url", "website", "homepage", "email_confirm"]` | Pool of names for the per-form rotating honeypot fields |
| `DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS` | `1.5` | Below this → flag; below 0.5 → block (hard floor) |
| `DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS` | `3600` | Above this → flag (stale form) |
| `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW` | `900` | Sliding window for credential-failure counters (seconds) |
| `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT` | `5` | Per-account threshold. Observation-only (drives `credential_attack_observed` signal); never user-visible |
| `DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT` | `20` | Per-IP threshold. **Drives the user-visible challenge**: same behaviour regardless of which accounts were tried (enumeration-safe) |
| `DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW` | `86400` | Window for completed-signup counter (24h) |
| `DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT` | `5` | Successful signups per IP before next attempt is flagged |
| `DJANGO_WAF_FORM_POW_DIFFICULTY` | `12` | Per-submission PoW difficulty (bits). 12 ≈ 4k SHA-256 hashes ≈ 50ms desktop / ~200ms mobile |
| `DJANGO_WAF_FORM_REPLAY_STORE` | `"session"` | Where to stash FLAGGED POST data for replay. Only `"session"` is implemented |
| `DJANGO_WAF_FORM_DEFENCE_WEIGHTS` | (see code) | Per-defence score weights; overridable per-form via `FormProtection(defence_weights={...})` |

**Usage**: Django Form mixin (recommended for new forms):

```python
from django import forms
from django_waf.forms import FormProtection, ProtectedForm

class ContactForm(ProtectedForm, forms.Form):
    name = forms.CharField()
    email = forms.EmailField()
    message = forms.CharField(widget=forms.Textarea)

    waf = FormProtection(
        form_id="contact",
        defences=("render_token", "honeypot", "time_trap", "ua_consistency"),
    )
```

In the view:

```python
def contact_view(request):
    form = ContactForm(request.POST or None, request=request)
    if request.method == "POST" and form.is_valid():
        # form.waf_result holds the FormEvaluationResult.
        ...
```

In the template:

```html
<form method="post">
  {% csrf_token %}
  {{ form.waf_fields }}
  {{ form.as_p }}
  <button type="submit">Send</button>
</form>
```

**Handwritten HTML** (forms that bypass Django's Form layer):

```python
# views.py
from django_waf.forms import waf_protect_post

@waf_protect_post(form_id="contact-handwritten",
                  defences=("honeypot", "time_trap"))
def contact_view(request):
    if request.method == "POST":
        ...
```

```html
<!-- contact.html -->
{% load waf_form_tags %}
<form method="post">
  {% csrf_token %}
  {% waf_protect form_id="contact-handwritten" %}
  <input type="email" name="email">
  <button type="submit">Send</button>
</form>
```

**HTMX compatibility**: the form-protection render token persists
across HTMX re-renders of the same form (a user fixing a validation
error keeps the same token). The Redis marker that backs replay
protection is consumed only on a PASS verdict, so submitting twice
in succession after a validation error works correctly. Operators
must ensure the HTMX target includes `{{ form.waf_fields }}` /
`{% waf_protect %}` in the swapped fragment.

**Authenticated forms**: set `skip_for_authenticated=True` on
`FormProtection` to drop the spam-style defences for logged-in users
while keeping `render_token` for integrity:

```python
waf = FormProtection(
    form_id="team-invite",
    defences=("render_token",),
    skip_for_authenticated=True,
)
```

## Structured Logging

`django_waf.logging.WafStructuredFormatter` renders each log record as one
JSON object per line, ready for a log aggregator (ELK, Loki, CloudWatch
Logs, etc.). It always includes `timestamp`, `level`, `logger`, and
`message`; it additionally includes `ip`, `verdict`, `rule_id`,
`anomaly_score`, `latency_ms`, `path`, `method`, and `user_agent` (truncated
to 200 characters) whenever those attributes are present on the log record
— fields that are absent are omitted entirely rather than emitted as
`null`.

Wire it into the `django_waf` logger via `LOGGING`:

```python
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "waf_json": {
            "()": "django_waf.logging.WafStructuredFormatter",
        },
    },
    "handlers": {
        "waf_json": {
            "class": "logging.StreamHandler",
            "formatter": "waf_json",
        },
    },
    "loggers": {
        "django_waf": {
            "handlers": ["waf_json"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
```

## Celery Beat Schedule

If using Celery, `django_waf.conf.DJANGO_WAF_CELERY_BEAT_SCHEDULE` provides a
ready-made schedule fragment covering every periodic django-waf task. Merge
it into your project's `CELERY_BEAT_SCHEDULE` rather than hand-transcribing
task names and cadences:

```python
from django_waf.conf import DJANGO_WAF_CELERY_BEAT_SCHEDULE

CELERY_BEAT_SCHEDULE = {
    **DJANGO_WAF_CELERY_BEAT_SCHEDULE,
    # ... your project's own periodic tasks
}
```

The `*/N minute` tasks (`generate_blocklist`, `flush_rule_hit_counts`,
`detect_anomalies`, `parse_access_log`, `expire_rules`,
`update_ip_reputation`) are expressed as plain second-interval schedules, so
they are always present regardless of whether `celery` is installed.

The wall-clock tasks (`prune_request_logs`, `prune_challenge_tokens`,
`sync_threat_feed`, `report_threat_telemetry`, `update_geoip_database`) need
`celery.schedules.crontab` to build their schedule. Because `django_waf.conf`
must stay importable even when `celery` is entirely absent from the
environment, the `crontab` import is guarded: if `celery` is not installed,
these five entries are simply omitted from the dict rather than
approximated. Install the `celery` extra (`pip install django-waf[celery]`)
to get the full schedule:

| Task | Cadence |
|------|---------|
| `generate_blocklist` | every 5 minutes |
| `flush_rule_hit_counts` | every 5 minutes |
| `detect_anomalies` | every 15 minutes |
| `parse_access_log` | every 10 minutes |
| `expire_rules` | every 30 minutes |
| `update_ip_reputation` | every 6 hours |
| `prune_request_logs` | daily 04:00 |
| `prune_challenge_tokens` | daily 04:15 |
| `sync_threat_feed` | daily 04:30 |
| `report_threat_telemetry` | daily 05:00 |
| `update_geoip_database` | weekly, Sunday 03:00 UTC |

You may of course still hand-write `CELERY_BEAT_SCHEDULE` entries yourself
(or override `DJANGO_WAF_CELERY_BEAT_SCHEDULE` via the setting of the same
name) if you need different cadences.

## Management Commands

| Command | Description |
|---------|-------------|
| `django_waf_generate_blocklist` | Generate the nginx blocklist file (`--dry-run` to preview) |
| `django_waf_detect_anomalies` | Run anomaly detectors and auto-create block rules (`--dry-run`) |
| `django_waf_prune_logs` | Delete `RequestLog` entries older than the retention period (`--dry-run`) |
| `django_waf_prune_challenges` | Delete pending/failed `ChallengeToken` entries older than N hours (`--hours`, `--dry-run`) |
| `django_waf_sync_feed` | Fetch and import rules from the collective threat feed (`--dry-run`) |
| `django_waf_export_rules` | Export `BlockRule`/`AllowRule` records to JSON (`--output`, `--source`, `--rule-type`) |
| `django_waf_import_rules` | Import `BlockRule`/`AllowRule` records from JSON produced by `django_waf_export_rules` (`--merge`, `--replace`, `--dry-run`) |

## Dashboard

The staff dashboard is available at `/waf/dashboard/` for authenticated staff
users. It provides:

- Real-time traffic counters (allowed, blocked, challenged, throttled)
- Top 10 blocked IPs
- Auto-detected anomalies awaiting review

Superusers can **confirm** auto-generated rules (promoting them to permanent) or
**reject** them (deactivating) directly from the anomalies panel.

## Architecture

```
Client → nginx (C-level blocklist, < 0.01 ms)
       → Django WafMiddleware (dynamic analysis, < 0.5 ms)
       → Application views
```

The middleware evaluates requests in this order:

1. **Exempt paths/hosts bypass**: static assets, health endpoints, and exempt hosts skip all evaluation
2. **HTTP method filtering**: disallowed methods receive 405 immediately
3. **Master switch check**: `DJANGO_WAF_ENABLED = False` passes all requests through
4. **Staff/superuser bypass**: authenticated staff skip rule evaluation
5. **Valid challenge cookie check**: previously-solved challenges are honoured
6. **Allow rules → Block rules → Rate limits**: explicit rule matching
7. **No-referer challenge**: optionally challenge requests with no `Referer` header
8. **Path scoring (always) + UA scoring (after 10 requests)**: anomaly score
   accumulates from suspicious paths and UA heuristics; score thresholds determine
   the verdict (log / challenge / block)
9. **Challenge escalation**: IPs exceeding the unsolved-challenge threshold are
   auto-blocked for `DJANGO_WAF_ESCALATION_BLOCK_TTL` seconds
10. **Verdict dispatch**: response rendered (allow / block / challenge / throttle),
    sampled logging written, and WAF signal emitted

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=term-missing

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

## Licence

MIT
