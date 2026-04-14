# Changelog

All notable changes to django-waf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.10.2] - 2026-04-14

### Fixed

- **`request_blocked` signal missing `verdict` kwarg**: the middleware's
  `_emit_request_blocked` sent `ip_address`, `user_agent`, `path`, and
  `rule`, but omitted `verdict`. The `on_request_blocked` handler in
  `handlers.py` declared `verdict: str` as a required parameter, so
  Django's signal dispatcher raised `TypeError` on every block event.
  The exception was swallowed by the bare `except Exception` in
  `_emit_request_blocked`, meaning the structured log entry was
  **silently never written** for any blocked request.

  **Fix**: the sender now passes `verdict=result.verdict`. The
  receiver's `verdict` parameter defaults to `""` for defensive
  backwards-compatibility with any external code that fires the signal
  without it.

- **`user_agent` now included in the structured log**: the sender was
  already passing `user_agent` but the receiver was dropping it into
  `**kwargs`. The structured log entry now includes `user_agent` for
  observability.

## [0.10.1] - 2026-04-14

### Fixed

- **`BlockRule.MultipleObjectsReturned` in `detect_anomalies`**: if
  duplicate `BlockRule` rows existed for the same
  `(rule_type, pattern, source, action)` key — created before the
  anomaly detector existed, or via a race condition —
  `_get_or_create_auto_rule()` would crash with
  `MultipleObjectsReturned`, causing `detect_anomalies` and all
  downstream anomaly detection tasks to fail silently. The fix catches
  `MultipleObjectsReturned`, deduplicates by keeping the newest row
  and deleting the rest, then retries `update_or_create`.

- **Same bug in `_create_escalation_rule` (rule_engine.py)**: the
  challenge-escalation path used the same `update_or_create` pattern
  and was vulnerable to the same crash. Previously masked by a bare
  `except Exception`, meaning escalation rules were silently never
  created when duplicates existed. Now deduplicates and retries.

### Upgrade

```bash
pip install -U django-waf
```

No migration required.

### Production workaround

If you hit this bug before upgrading, clean up existing duplicates:

```python
from django.db.models import Count
from icv_waf.models import BlockRule

dupes = (
    BlockRule.objects
    .values("rule_type", "pattern", "source", "action")
    .annotate(cnt=Count("id"))
    .filter(cnt__gt=1)
)
for d in dupes:
    qs = BlockRule.objects.filter(
        **{k: d[k] for k in ["rule_type", "pattern", "source", "action"]}
    )
    qs.exclude(pk=qs.order_by("-created_at").first().pk).delete()
```

After upgrading to 0.10.1 the package handles this automatically.

## [0.10.0] - 2026-04-11

### Added — GeoIP database installer

- **`manage.py icv_waf_install_geoip`**: downloads, verifies, and
  atomically installs the MaxMind GeoLite2-Country database for the
  middleware's `_lookup_country` helper. Flags:
  - `--license-key=XXX` — overrides the `ICV_WAF_MAXMIND_LICENSE_KEY`
    setting. Sign up at <https://www.maxmind.com/en/geolite2/signup>.
  - `--output-path=/path/to/file.mmdb` — overrides `ICV_WAF_GEOIP_PATH`.
    Defaults to `/var/lib/icv-waf/GeoLite2-Country.mmdb`.
  - `--if-older-than=DAYS` — skip the download if the existing file
    is younger than N days (cron-friendly).
  - `--quiet` — suppress progress output.

- **`update_geoip_database` Celery task** (`icv_waf.tasks.update_geoip_database`):
  wraps the service with a 6-day freshness check. Recommended schedule:
  weekly, Sunday 03:00 UTC. Example `CELERY_BEAT_SCHEDULE` entry:

  ```python
  from celery.schedules import crontab

  CELERY_BEAT_SCHEDULE = {
      "icv-waf-update-geoip": {
          "task": "icv_waf.tasks.update_geoip_database",
          "schedule": crontab(day_of_week=0, hour=3, minute=0),
      },
  }
  ```

- **`services.geoip`** module: `install_geoip_database()` is exposed as
  a reusable service function. Raises structured exceptions
  (`GeoIPNotInstalledError`, `GeoIPLicenseMissingError`,
  `GeoIPDownloadError`) for callers that need fine-grained error
  handling.

- **New setting `ICV_WAF_MAXMIND_LICENSE_KEY`**: MaxMind licence key
  for downloading GeoLite2 databases. Default `""`. Read the key from
  your environment in the consuming project's settings:

  ```python
  import os
  ICV_WAF_MAXMIND_LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")
  ```

### Installation

GeoIP support is an **optional** dependency. Install with:

```bash
pip install django-waf[geoip]
```

Then run once to install the database, or wire up the Celery task:

```bash
export MAXMIND_LICENSE_KEY=your-key-here
python manage.py icv_waf_install_geoip
```

### Behaviour notes

- Downloads are atomic: the archive is extracted to a temp directory,
  verified by opening it with `geoip2.database.Reader` and performing
  a smoke-test lookup, then `os.replace()`'d into the destination. An
  existing database is never clobbered if the replacement fails
  verification.
- **Running workers must be restarted to pick up a new database** —
  the MMDB file is mmap'd, so live processes keep their previous
  handle until restart. The command prints a reminder on success.
- Licence keys are never logged or echoed back on error.

## [0.9.0] - 2026-04-11

### Changed — defaults

- **Expanded default `ICV_WAF_SUSPICIOUS_PATH_PATTERNS`** from 18 to 45
  patterns, driven by production data from the 0.7 → 0.8.1 upgrade. New
  categories covered:
  - SSH key files (`id_rsa`, `id_dsa`, `.pem`, `.key`)
  - Shell history files (`.bash_history`, `.zsh_history`)
  - Additional VCS metadata (`.svn`, `.hg`)
  - Backup archives (`.sql.gz`, `.backup`, `dump.sql`, `backup.zip`, `db.sqlite`)
  - Named webshells (`alfa*.php`, `shell.php`, `r57.php`, `c99.php`,
    `filemanager.php`, `c99.php`, `webshell`, `cmd.php`, `eval.php`)
  - Information disclosure (`phpmyadmin`, `/server-status`, `/server-info`)
  - IoT/router exploits (`/onvif/`, `/boaform/`, `/HNAP1`, `/goform/`)

  **Omissions intentional:** `.ini`, `.conf`, `.asp`, `.aspx`, `.jsp`, and
  `/cgi-bin/` are **not** included because they collide with legitimate
  traffic on mixed-tech estates. Pattern additions are selected so that
  legitimate Django, WordPress, and SPA paths do not trigger scoring.

- **`ICV_WAF_SUSPICIOUS_PATH_SCORE` remains at 3.0**. A previous plan to
  raise it to 5.0 (pushing single probes from LOGGED → CHALLENGED) was
  dropped after production data showed ~44% of the challenge tier was
  already hitting real browsers. Raising this would have compounded the
  false-positive rate. Tune per consuming project via settings.

### Added

- **`RequestLog.matched_rule_type.help_text`**: documents the common
  misreading that `matched_rule_type="block"` means "the request was
  blocked". It does not — it means the matching rule came from the
  `BlockRule` table. A `BlockRule` with `action="challenge"` produces
  `matched_rule_type="block"` and `verdict="challenged"`. **Always use
  the `verdict` column for enforcement reporting.**

### Migration

- `0005_alter_requestlog_matched_rule_type` — schema-level no-op (only
  adds `help_text` to the field). Safe to apply on a running system; no
  table rewrite, no downtime. Run `manage.py migrate icv_waf` after
  upgrading.

### Notes for operators

The production data that drove this release revealed three ops-side
issues that are **not package bugs**:

1. **GeoIP database not installed** on some deployments →
   `country_code` is always empty. Install `geoip2` + the MaxMind
   GeoLite2-Country database and set `ICV_WAF_GEOIP_PATH`.
2. **Repeat-offender IPs keep returning** after rate-limit windows
   expire. Use `manage.py icv_waf_block <ip> --ttl 168 --reason "..."`
   to promote them to persistent `BlockRule` rows, or add the /24 to
   the upstream nginx blocklist so they never reach Django.
3. **Challenge tier firing on ~44% real browsers**: if you see this,
   lower `ICV_WAF_SCORE_THRESHOLD_CHALLENGE` sensitivity or add more
   patterns to `ICV_WAF_CHALLENGE_NO_REFERER_EXEMPT_PATHS`.

## [0.8.1] - 2026-04-11

### Fixed

- **`RequestLog` NOT NULL violation on unmatched requests**: `EvaluationResult`
  returned `matched_rule_type=None` for every no-match path (unmatched, throttled,
  challenged, anomaly-scored, Redis fast-path, escalation). The middleware passed
  this through to `RequestLog.objects.create(matched_rule_type=None)`, which
  bypasses the model's `default=""` and sends `NULL` to a `NOT NULL` column,
  producing an `IntegrityError` on every non-matching request. Audit log rows
  were silently dropped (the response to the client was unaffected). All
  `matched_rule_type=None` call sites in `services/rule_engine.py` now return
  `""`, and the `EvaluationResult.matched_rule_type` type hint is narrowed from
  `str | None` to `str`. Regression test added in `tests/test_services.py`.

## [0.8.0] - 2026-04-08

### Added

- **HTTP request fingerprinting** (`services/fingerprint.py`): deterministic bot
  detection via HTTP header analysis — identifies clients claiming to be
  browsers but missing expected headers (`Sec-CH-UA`, `Sec-Fetch-*`,
  `Accept-Language`, `Accept`).
  - `compute_fingerprint()` — SHA-256 hash of the normalised header tuple
  - `score_fingerprint_mismatch()` — 0.0–5.0 score for UA/header mismatch
  - `classify_fingerprint()` — `browser` / `bot` / `suspicious` / `unknown`
- **Dynamic known-good registry**: `VerifyView` registers fingerprints from
  solved challenges; known fingerprints bypass mismatch scoring; self-updating
  as new browser versions hit production; 30-day Redis TTL.
- **Rule engine integration**: fingerprint score combined with UA + path scores
  in step 10 of evaluation.
- **`RequestLog` fields**: `http_fingerprint` (SHA-256) and `fingerprint_verdict`,
  surfaced in admin `list_display` and `list_filter` (migration `0004`).

### Scoring signals

- `+2.0` Chrome 89+ UA without `Sec-CH-UA`
- `+1.5` Browser UA without any `Sec-Fetch-*` headers
- `+1.0` Browser UA without `Accept-Language`
- `+0.5` Browser UA with `Accept: */*` only

A `Go-http-client` or `python-requests` sending a Chrome UA now scores 5.0 from
fingerprinting alone — automatically challenged.

## [0.7.0] - 2026-04-08

### Added

- **Cloud spray detector** (`detect_cloud_spray`): detects coordinated low-and-slow
  scraping — many distinct IPs with identical UA, no referer, 1–3 requests each.
  Groups into `/24` subnets and auto-creates `CHALLENGE` rules. Tunable via
  `ICV_WAF_CLOUD_SPRAY_MIN_IPS` (default 20) and
  `ICV_WAF_CLOUD_SPRAY_MAX_REQUESTS_PER_IP` (default 3).
- **Management commands**: `icv_waf_block` and `icv_waf_unblock` for operator
  control.
  - `manage.py icv_waf_block 203.0.113.42 --reason "scanner" --ttl 24`
  - `manage.py icv_waf_unblock 203.0.113.42 [--delete]`

### Fixed

- **N+1 query in `detect_unsolved_challenges`**: replaced per-IP
  `ChallengeToken.exists()` + 2× `RequestLog.count()` with three prefetch
  queries. `O(3)` instead of `O(3n)` for `n` challenged IPs.

## [0.6.0] - 2026-04-08

### Added

- **Escalation block TTL**: `ICV_WAF_ESCALATION_BLOCK_TTL` setting (default 1 hour);
  creates a persistent auto BlockRule on escalation for use by the nginx blocklist
- **Path scoring**: always evaluated regardless of request count; `_score_path`
  accumulates all matching patterns, capped at 10.0
- **No-referer challenge**: moved into rule engine for proper RequestLog tracking
- **Access log parsing**: `parse_access_log` infers verdict from HTTP status code
  (403 → blocked, 429 → throttled, 302 → challenged)
- **Redis-first solved check**: challenge escalation counter uses Redis before
  hitting the database
- **In-process rule cache**: version check with a single Redis GET; skips JSON
  deserialisation when the rule set is unchanged
- **VerifyView**: resets escalation counter and sets `waf:solved:{ip}` flag on
  successful challenge completion

### Fixed

- Composite rules: pattern format corrected to `ua_pattern||ip_or_cidr`

## [0.5.0] - 2026-04-08

### Added

- **HTTP method filtering**: `ICV_WAF_ALLOWED_METHODS` setting
- **Path-based threat scoring**: `ICV_WAF_SUSPICIOUS_PATH_PATTERNS` with 18
  default patterns
- **Configurable anomaly score thresholds**: `ICV_WAF_SCORE_THRESHOLD_LOG`,
  `ICV_WAF_SCORE_THRESHOLD_CHALLENGE`, and `ICV_WAF_SCORE_THRESHOLD_BLOCK`
- **Auto-escalation**: `ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD` for repeat
  offenders
- **Hit count tracking**: `hit_count` on BlockRules via Redis counters and a
  `flush_rule_hit_counts` periodic task

### Fixed

- `ChallengeToken.ip_address` NULL constraint violation — `views._get_ip()` now
  falls back to `0.0.0.0`

## [0.4.1] - 2026-04-08

### Fixed

- Skip WAF evaluation when `ip_address` is empty (fail-open behaviour)

## [0.4.0] - 2026-04-07

### Added

- **No-referer challenge trigger**: `ICV_WAF_CHALLENGE_NO_REFERER` setting
- **GeoIP country code population**: `ICV_WAF_GEOIP_PATH` with optional
  `geoip2` dependency
- **Configurable nginx reload command**: `ICV_WAF_NGINX_RELOAD_COMMAND` setting
- **Duplicate auto-rule prevention**: `update_or_create` used when creating
  automatic BlockRules
- **Threat score formula**: revised with `unsolved_rate` at 0.35 weight, counts
  derived from `ChallengeToken` records
- **Version metadata**: reads from `importlib.metadata`

## [0.3.0] - 2026-04-07

### Added

- **Composite unsolved-challenge anomaly detector**: `detect_unsolved_challenges`
  service function
- **`UNSOLVED_CHALLENGE` anomaly type**

## [0.2.1] - 2026-04-07

### Fixed

- `views._get_ip()` now respects `ICV_WAF_TRUST_X_FORWARDED_FOR`

## [0.2.0] - 2026-04-07

### Added

- **`referer` field on `RequestLog`**: added via migration 0003
- **Middleware**: logs referer header automatically on every request
- **Admin**: `referer` added to `list_display`, `search_fields`, and
  `readonly_fields`

### Fixed

- Restored original 0001 migration for production compatibility
- Added 0002 migration for `BaseModel` transition (metadata only)

## [0.1.1] - 2026-04-07

### Fixed

- Restored original `0001_initial` migration for existing deployments
- Added `0002` migration for `BaseModel` transition

## [0.1.0] - 2026-03-23

### Added

- **Models**: BlockRule, AllowRule, RequestLog, IPReputation, ChallengeToken
  with custom managers and composite indexes
- **Enums**: RuleAction, RuleType, MatchType, RuleSource, Verdict,
  ChallengeStatus, AnomalyType (7 TextChoices enums)
- **Middleware**: WafMiddleware with fail-open design, exempt path bypass,
  staff bypass, cookie validation, and sampled request logging
- **Services**: rule engine, challenge service (hashcash PoW), rate limiter
  (sliding-window), UA analyser (heuristic scoring), anomaly detector
  (UA rotation, subnet burst, challenge farm), blocklist generator (nginx
  map/geo), threat feed sync and telemetry
- **Views**: ChallengeView and VerifyView (AllowAny, CSRF-exempt); staff
  dashboard with HTMX panels for stats, top-blocked IPs, and anomalies;
  superuser anomaly confirm/reject actions
- **Admin**: 5 ModelAdmin classes with list display, filters, search, actions,
  and read-only restrictions for log/reputation/challenge models
- **Templates**: proof-of-work challenge page (inline JS, Web Crypto API),
  HTMX dashboard shell with 4 partial panels
- **Celery tasks**: 8 periodic tasks for blocklist generation, anomaly
  detection, log parsing, log pruning, rule expiry, IP reputation updates,
  threat feed sync, and telemetry reporting
- **Signals**: 8 custom signals (rule_saved, anomaly_detected,
  challenge_issued/solved/failed, request_blocked, request_throttled,
  feed_synced) with cache invalidation and structured logging handlers
- **Management commands**: icv_waf_generate_blocklist, icv_waf_detect_anomalies,
  icv_waf_prune_logs, icv_waf_sync_feed (all with --dry-run support)
- **Configuration**: 21 namespaced ICV_WAF_* settings with sensible defaults
- **Testing utilities**: 5 factory-boy factories in icv_waf.testing
