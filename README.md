# django-icv-waf

Self-hosted request filtering, bot management, and WAF middleware for Django.

Provides two-layer defence (nginx + Django middleware) with rate limiting,
user-agent anomaly scoring, JS proof-of-work challenges, nginx blocklist
generation, and collective threat feed integration — all configurable without
a reverse-proxy vendor.

## Features

- **Rate limiting** — sliding-window per-IP limits (burst, per-minute, per-5-min)
- **UA anomaly scoring** — heuristic detection of impossible OS/browser combos,
  ancient versions, scraper libraries
- **JS proof-of-work challenges** — hashcash-style SHA-256 challenges for
  suspicious clients (no CAPTCHAs, no third-party dependencies)
- **nginx blocklist generation** — exports `map`/`geo` blocks for C-level
  filtering at < 0.01 ms latency
- **Anomaly detection** — auto-creates expiring rules for UA rotation, subnet
  bursts, and challenge farms
- **Collective threat feed** — opt-in sync of anonymised threat intelligence
  across deployments
- **Staff dashboard** — HTMX-powered real-time analytics with anomaly management
- **Fail-open design** — Redis outage never breaks the site

## Requirements

- Python >= 3.11
- Django >= 4.2
- Redis (via `django-redis >= 5.4`)
- `django-icv-core`
- `httpx >= 0.27` (for threat feed sync)
- Optional: `celery >= 5.3` (for scheduled tasks)

## Installation

```bash
pip install django-icv-waf
```

Add to `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    # ...
    "icv_core",
    "icv_waf",
]
```

Add the middleware — place it **after** `SecurityMiddleware` and **before**
other middleware so it can block requests early:

```python
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "icv_waf.middleware.WafMiddleware",        # <-- here
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
    path("waf/", include("icv_waf.urls")),
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
python manage.py migrate icv_waf
```

## Settings Reference

All settings are namespaced under `ICV_WAF_*` and have sensible defaults.

| Setting | Default | Description |
|---------|---------|-------------|
| `ICV_WAF_ENABLED` | `True` | Master switch — disable to pass all requests through |
| `ICV_WAF_EXEMPT_PATHS` | `["/static/", "/media/", "/health/", "/favicon.ico"]` | URL prefixes that bypass WAF evaluation |
| `ICV_WAF_TRUST_X_FORWARDED_FOR` | `False` | Trust `X-Forwarded-For` header for client IP extraction |
| `ICV_WAF_REDIS_ALIAS` | `"default"` | Django cache alias for Redis connections |
| `ICV_WAF_RATE_LIMIT_BURST` | `10` | Max requests per IP per second |
| `ICV_WAF_RATE_LIMIT_PER_MINUTE` | `120` | Max requests per IP per minute |
| `ICV_WAF_RATE_LIMIT_PER_5MIN` | `600` | Max requests per IP per 5 minutes |
| `ICV_WAF_CHALLENGE_DIFFICULTY` | `4` | Proof-of-work leading zero bits |
| `ICV_WAF_CHALLENGE_COOKIE_TTL` | `86400` | Seconds a solved-challenge cookie remains valid |
| `ICV_WAF_LOG_SAMPLE_RATE` | `0.01` | Fraction of allowed requests to log (0.0–1.0) |
| `ICV_WAF_LOG_RETENTION_DAYS` | `30` | Days to retain RequestLog entries |
| `ICV_WAF_ANOMALY_THRESHOLD_DISTINCT_UAS` | `20` | Distinct UAs per IP before triggering anomaly |
| `ICV_WAF_AUTO_RULE_EXPIRY_HOURS` | `24` | Hours before auto-generated rules expire |
| `ICV_WAF_NGINX_BLOCKLIST_PATH` | `"/etc/nginx/conf.d/icv-waf-blocklist.conf"` | Output path for nginx blocklist |
| `ICV_WAF_ACCESS_LOG_PATH` | `"/var/log/nginx/access.log"` | nginx access log path for parsing |
| `ICV_WAF_FEED_ENABLED` | `True` | Enable collective threat feed sync |
| `ICV_WAF_FEED_URL` | `"https://threats.icv.dev/v1/feed.json"` | Threat feed JSON endpoint |
| `ICV_WAF_FEED_MIN_CONFIDENCE` | `0.8` | Minimum confidence to import feed rules |
| `ICV_WAF_FEED_REPORT` | `False` | Report local detections back to feed (opt-in) |
| `ICV_WAF_FEED_REPORT_URL` | `"https://threats.icv.dev/v1/report"` | Telemetry reporting endpoint |
| `ICV_WAF_FEED_API_KEY` | `""` | API key for feed authentication |

## Celery Beat Schedule

If using Celery, configure the beat schedule for automated tasks:

```python
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    "icv-waf-generate-blocklist": {
        "task": "icv_waf.tasks.generate_blocklist",
        "schedule": crontab(minute="*/5"),
    },
    "icv-waf-detect-anomalies": {
        "task": "icv_waf.tasks.detect_anomalies",
        "schedule": crontab(minute="*/15"),
    },
    "icv-waf-parse-access-log": {
        "task": "icv_waf.tasks.parse_access_log",
        "schedule": crontab(minute="*/10"),
    },
    "icv-waf-expire-rules": {
        "task": "icv_waf.tasks.expire_rules",
        "schedule": crontab(minute="*/30"),
    },
    "icv-waf-update-ip-reputation": {
        "task": "icv_waf.tasks.update_ip_reputation",
        "schedule": crontab(hour="*/6", minute=0),
    },
    "icv-waf-prune-request-logs": {
        "task": "icv_waf.tasks.prune_request_logs",
        "schedule": crontab(hour=4, minute=0),
    },
    "icv-waf-sync-threat-feed": {
        "task": "icv_waf.tasks.sync_threat_feed",
        "schedule": crontab(hour=4, minute=30),
    },
    "icv-waf-report-threat-telemetry": {
        "task": "icv_waf.tasks.report_threat_telemetry",
        "schedule": crontab(hour=5, minute=0),
    },
}
```

## Management Commands

| Command | Description |
|---------|-------------|
| `icv_waf_generate_blocklist` | Generate the nginx blocklist file (`--dry-run` to preview) |
| `icv_waf_detect_anomalies` | Run anomaly detectors and auto-create block rules (`--dry-run`) |
| `icv_waf_prune_logs` | Delete RequestLog entries older than retention period (`--dry-run`) |
| `icv_waf_sync_feed` | Fetch and import rules from the collective threat feed (`--dry-run`) |

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

1. Exempt paths bypass
2. Master switch check
3. Staff/superuser bypass
4. Valid challenge cookie check
5. Allow rules → Block rules → Rate limits → UA scoring
6. Verdict dispatch (allow / block / challenge / throttle)
7. Sampled logging + signal emission

## Development

```bash
# Run tests
cd packages/icv-waf && pytest

# Run tests with coverage
pytest --cov=src --cov-report=term-missing

# Lint
ruff check src/ tests/
ruff format src/ tests/

# Type check
mypy src/
```

## Specification

Full specification: [`docs/specs/APP-018-waf/`](../../docs/specs/APP-018-waf/)
