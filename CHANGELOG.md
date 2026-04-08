# Changelog

All notable changes to django-waf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
