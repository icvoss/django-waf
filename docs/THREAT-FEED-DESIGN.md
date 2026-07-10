# Collective Threat Intelligence Feed: Design Document

**Package:** django-django-waf
**Service domain:** threats.icv.dev
**Status:** Design, not yet implemented
**Date:** April 2026
**Audience:** Developer implementing the central service

---

## Overview

django-django-waf installations already contain client-side code for syncing rules
from a central feed (`sync_feed`) and submitting anonymised telemetry
(`build_telemetry_payload` / `submit_telemetry`). The central service at
`threats.icv.dev` does not yet exist. This document specifies everything needed
to build it.

The system is a collective threat intelligence network: installations report
anonymised attack signals; the central service aggregates them into high-confidence
rules; rules are broadcast back to all participating installations. Every
installation benefits from threats seen by every other installation, with zero
exposure of user data.

---

## Table of Contents

1. [Data Flows](#1-data-flows)
2. [Central Service Architecture](#2-central-service-architecture)
3. [Confidence Scoring Algorithm](#3-confidence-scoring-algorithm)
4. [Privacy and Trust Model](#4-privacy-and-trust-model)
5. [API Design](#5-api-design)
6. [Client-Side Changes](#6-client-side-changes)
7. [Go-to-Market](#7-go-to-market)
8. [MVP Scope](#8-mvp-scope)

---

## 1. Data Flows

### 1.1 Inbound: installations → central service

The existing `build_telemetry_payload()` constructs the submission. The central
service must accept the following schema (extend, never shrink, across versions):

```json
{
  "schema_version": "1",
  "install_id": "a7f3c1d2-...",
  "period": "2026-04-06T05:00:00Z/2026-04-07T05:00:00Z",
  "summary": {
    "total_requests": 84201,
    "blocked": 1240,
    "challenged": 380,
    "throttled": 95
  },
  "subnets": [
    {
      "cidr": "185.220.101.0/24",
      "action": "blocked",
      "hits": 412
    }
  ],
  "ua_hashes": [
    {
      "sha256": "e3b0c44298fc1c149afb...",
      "action": "blocked",
      "hits": 87
    }
  ],
  "anomalies": [
    {
      "anomaly_type": "ua_rotation",
      "cidr": "185.220.101.0/24",
      "confidence": 0.92,
      "ttl_hours": 48
    }
  ],
  "country_distribution": {
    "RU": 512,
    "CN": 208,
    "US": 94
  },
  "referer_hashes": [
    {
      "sha256": "d8e8fca2dc0f896fd7cb...",
      "hits": 33
    }
  ]
}
```

**Field-by-field notes:**

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Always `"1"` for the initial release. Central service must version-gate parsing. |
| `install_id` | UUID string | Random UUID, generated once, persisted to filesystem. Never derived from domain, SECRET_KEY, or user data. Already implemented in `get_or_create_install_id()`. |
| `period` | ISO 8601 interval | UTC start/end of the reporting window (24 h). Used for deduplication. |
| `summary` | object | Aggregate verdict counts. No per-request detail. |
| `subnets[].cidr` | string | IPv4 or IPv6 /24 (or /48 for IPv6). **Never a full IP.** The existing client already truncates via `ipaddress.ip_network(f"{ip}/24", strict=False)`. |
| `subnets[].action` | string | The verdict applied: `blocked`, `challenged`, `throttled`. |
| `subnets[].hits` | integer | Count of events from this subnet in the period. |
| `ua_hashes[].sha256` | string | SHA-256 of the raw user-agent string. **Never the raw string.** Already implemented in `build_telemetry_payload()`. |
| `ua_hashes[].action` | string | `blocked`, `challenged`. |
| `ua_hashes[].hits` | integer | Hit count for this UA hash in the period. |
| `anomalies[].anomaly_type` | string | One of `ua_rotation`, `subnet_flood`, `challenge_farm`, `unsolved_challenge`, `path_hammering`, `burst`. Matches `AnomalyType` enum. |
| `anomalies[].cidr` | string | /24 subnet where the anomaly was detected. |
| `anomalies[].confidence` | float | Local confidence score from the reporting installation's detector. |
| `anomalies[].ttl_hours` | integer | Suggested TTL from the local detector. Central service may override. |
| `country_distribution` | object | ISO 3166-1 alpha-2 country → blocked hit count. Derived from GeoIP if `DJANGO_WAF_GEOIP_PATH` is configured. Omit key entirely if GeoIP is not available. |
| `referer_hashes[].sha256` | string | SHA-256 of the referer domain only (not full URL, not path, not query). E.g., `sha256("evil-botnet.ru")`. |
| `referer_hashes[].hits` | integer | Count of blocked/challenged requests with this referer domain. |

**What must never be submitted:**

- Full IP addresses (enforce /24 truncation at client before submission)
- Raw user-agent strings
- URL paths, query strings, or POST bodies
- Cookies or session identifiers
- User IDs, email addresses, or any user-identifiable field
- The site domain or hostname
- Django `SECRET_KEY` or any cryptographic secret
- `RequestLog.referer` raw values (only the hashed domain)
- Any field from `RequestLog.path`

The client code already enforces most of these. The central service must also
validate and reject payloads that contain obviously unsafe fields (e.g., any
field longer than 512 characters that is not a list).

---

### 1.2 Outbound: central service → installations

The existing `sync_feed()` function expects either a bare JSON array or an object
with a `"rules"` key. The v1 feed should always use the object envelope:

```json
{
  "schema_version": "1",
  "generated_at": "2026-04-07T04:30:00Z",
  "cursor": "2026-04-07T04:30:00Z",
  "total_rules": 1842,
  "rules": [
    {
      "rule_type": "cidr",
      "match_type": "cidr",
      "pattern": "185.220.101.0/24",
      "action": "block",
      "confidence": 0.94,
      "reporters": 47,
      "first_seen": "2026-03-15",
      "expires": "2026-05-07T04:30:00Z",
      "anomaly_types": ["ua_rotation", "subnet_flood"],
      "tags": ["tor-exit", "scanner"]
    }
  ]
}
```

| Field | Notes |
|---|---|
| `schema_version` | Clients must reject feeds with unknown schema versions. |
| `generated_at` | UTC timestamp when this feed snapshot was produced. |
| `cursor` | Opaque value for delta requests. For v1, use ISO 8601 timestamp string. |
| `total_rules` | Count of rules in this response (not total in database). Used by clients to detect truncation. |
| `rules[].rule_type` | `cidr`, `ip`, `ua`, `composite`. Matches client `RuleType` enum. |
| `rules[].match_type` | `cidr`, `exact`, `regex`, `contains`. Matches client `MatchType` enum. |
| `rules[].pattern` | The value to match: a CIDR, an IP, or a SHA-256 hash for UA rules. |
| `rules[].action` | `block`, `challenge`, `throttle`. Never `log_only` in the feed. |
| `rules[].confidence` | Float 0.0 to 1.0. The central service's computed confidence score. |
| `rules[].reporters` | Count of distinct installations that reported this threat. |
| `rules[].first_seen` | ISO 8601 date. When the central service first received a report for this pattern. |
| `rules[].expires` | ISO 8601 datetime. UTC expiry. Clients deactivate rules absent from the feed or past this timestamp. |
| `rules[].anomaly_types` | List of anomaly type strings that contributed to this rule. |
| `rules[].tags` | Optional human-readable labels (e.g., `tor-exit`, `scanner`, `credential-stuffer`). |

**Delta updates:**

```
GET /v1/feed.json?since=2026-04-06T04:30:00Z
```

The `since` parameter accepts an ISO 8601 datetime. The response contains only
rules created or modified after that timestamp, plus rules that have been
deactivated (include with `confidence: 0.0` so clients can expire them).
The `cursor` field in each response is the value to use as `since` in the next
call.

**Full snapshots vs deltas:**

- Full snapshot: no `since` parameter. Returns all active rules above the
  confidence threshold. Capped at 10,000 rules per response. Use `page` for
  pagination (see API section).
- Delta: `since` parameter present. Returns only changes since that timestamp.
  Suitable for frequent polling.

Clients should use the delta path after the first successful full sync, storing
the cursor in Django cache or a simple file.

---

## 2. Central Service Architecture

### 2.1 Tech Stack

**Recommendation: FastAPI + PostgreSQL + Redis + Celery**

| Component | Choice | Rationale |
|---|---|---|
| API framework | FastAPI | Async-native; Pydantic validation on every request; OpenAPI docs for free; faster cold path than Django for a high-read feed endpoint. |
| Database | PostgreSQL 16 | Full SQL; JSONB for flexible anomaly metadata; partial indexes for feed queries; strong consistency guarantees. |
| Cache / rate limiting | Redis 7 | Sliding window rate limiting; feed snapshot caching; install_id deduplication windows. |
| Background processing | Celery + Redis | Aggregation, confidence recalculation, feed regeneration, decay runs. |
| Feed delivery | Nginx + static JSON | The feed.json snapshot is regenerated by a Celery task and written to disk / object storage. Serving a static file is orders of magnitude cheaper than a live query at scale. |
| Object storage | S3-compatible (e.g. Hetzner Object Storage, Cloudflare R2) | Large feed snapshots served cheaply; CDN-cacheable. |
| Deployment | Single VPS (MVP) → Docker Compose → Kubernetes (scale) | See infrastructure section. |

**Why not Django for the central service?**
Django is appropriate for the client packages in this monorepo, where the ORM,
admin, and signals are load-bearing. The central service has different
characteristics: write-heavy ingest (report submissions), read-heavy feed
(thousands of installations polling daily), and CPU-bound aggregation jobs.
FastAPI's async request handling and Pydantic's validation speed are better
suited. The central service is a separate repository.

### 2.2 Data Model

```sql
-- Tracks each registered installation (created on first successful report)
CREATE TABLE installation (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    install_id      UUID UNIQUE NOT NULL,         -- from client payload
    api_key_hash    TEXT,                          -- SHA-256 of API key; NULL = anonymous reader
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report_count    INTEGER NOT NULL DEFAULT 0,
    is_trusted      BOOLEAN NOT NULL DEFAULT FALSE, -- manually elevated; higher weight
    is_banned       BOOLEAN NOT NULL DEFAULT FALSE, -- poisoning attempt; ignore all reports
    ban_reason      TEXT,
    schema_version  TEXT NOT NULL DEFAULT '1'
);

CREATE INDEX ON installation (install_id);
CREATE INDEX ON installation (last_seen_at);

-- One row per distinct (rule_type, pattern): the canonical threat record
CREATE TABLE threat_signal (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_type           TEXT NOT NULL,             -- cidr, ip, ua, composite
    match_type          TEXT NOT NULL,             -- cidr, exact, regex
    pattern             TEXT NOT NULL,             -- the CIDR, IP, or UA hash
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reported_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reporter_count      INTEGER NOT NULL DEFAULT 0,-- distinct installations reporting
    total_reports       INTEGER NOT NULL DEFAULT 0,-- cumulative reports (multiple periods)
    raw_blocked_hits    BIGINT NOT NULL DEFAULT 0, -- sum of blocked hits across all reports
    raw_challenged_hits BIGINT NOT NULL DEFAULT 0,
    raw_throttled_hits  BIGINT NOT NULL DEFAULT 0,
    anomaly_types       TEXT[] NOT NULL DEFAULT '{}',
    country_codes       TEXT[] NOT NULL DEFAULT '{}',
    tags                TEXT[] NOT NULL DEFAULT '{}',
    confidence          NUMERIC(4,3) NOT NULL DEFAULT 0.000,
    is_published        BOOLEAN NOT NULL DEFAULT FALSE, -- confidence >= publish_threshold
    published_action    TEXT,                       -- block, challenge, throttle
    expires_at          TIMESTAMPTZ,
    decay_starts_at     TIMESTAMPTZ,               -- when decay timer began
    UNIQUE (rule_type, pattern)
);

CREATE INDEX ON threat_signal (confidence) WHERE is_published = TRUE;
CREATE INDEX ON threat_signal (last_reported_at);
CREATE INDEX ON threat_signal (expires_at) WHERE is_published = TRUE;
CREATE INDEX ON threat_signal (rule_type, is_published);

-- Raw report rows: one per installation per period per signal
-- Kept for audit and reprocessing. Partitioned by reported_at.
CREATE TABLE threat_report (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id           UUID NOT NULL REFERENCES threat_signal(id) ON DELETE CASCADE,
    installation_id     UUID NOT NULL REFERENCES installation(id) ON DELETE CASCADE,
    reported_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    period_start        TIMESTAMPTZ NOT NULL,
    period_end          TIMESTAMPTZ NOT NULL,
    blocked_hits        INTEGER NOT NULL DEFAULT 0,
    challenged_hits     INTEGER NOT NULL DEFAULT 0,
    throttled_hits      INTEGER NOT NULL DEFAULT 0,
    anomaly_types       TEXT[] NOT NULL DEFAULT '{}',
    local_confidence    NUMERIC(4,3),              -- the installation's own confidence estimate
    ttl_hours           INTEGER
) PARTITION BY RANGE (reported_at);

CREATE INDEX ON threat_report (signal_id, reported_at);
CREATE INDEX ON threat_report (installation_id, reported_at);
-- Create monthly partitions; automate with pg_partman or a Celery task.

-- Stores API keys for reporting installations (hashed)
CREATE TABLE api_key (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    installation_id UUID NOT NULL REFERENCES installation(id) ON DELETE CASCADE,
    key_prefix      TEXT NOT NULL,                 -- first 8 chars of the key (for display)
    key_hash        TEXT NOT NULL UNIQUE,          -- SHA-256(full_key)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (installation_id)
);

-- Feed snapshots: the generated feed.json files
CREATE TABLE feed_snapshot (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_count      INTEGER NOT NULL,
    storage_path    TEXT NOT NULL,                 -- S3 key or filesystem path
    schema_version  TEXT NOT NULL DEFAULT '1',
    is_current      BOOLEAN NOT NULL DEFAULT FALSE -- only one row TRUE at a time
);

-- Outbound block list: denormalised, updated by the aggregation task
-- This is what the feed query reads; avoids live aggregation on every GET.
CREATE TABLE published_rule (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    signal_id       UUID NOT NULL UNIQUE REFERENCES threat_signal(id) ON DELETE CASCADE,
    rule_type       TEXT NOT NULL,
    match_type      TEXT NOT NULL,
    pattern         TEXT NOT NULL,
    action          TEXT NOT NULL,
    confidence      NUMERIC(4,3) NOT NULL,
    reporters       INTEGER NOT NULL,
    first_seen      DATE NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    anomaly_types   TEXT[] NOT NULL DEFAULT '{}',
    tags            TEXT[] NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX ON published_rule (confidence DESC);
CREATE INDEX ON published_rule (updated_at DESC);
CREATE INDEX ON published_rule (expires_at);
```

### 2.3 Aggregation Logic

The aggregation pipeline runs as a Celery task (`aggregate_threat_signals`) on
a 15-minute schedule.

```python
# Pseudocode: the actual implementation lives in the central service
def aggregate_threat_signals():
    """
    For every threat_signal, recompute confidence and decide whether to publish.
    """
    now = utcnow()
    signals = ThreatSignal.objects.filter(
        last_reported_at__gte=now - timedelta(days=30)
    ).select_related()

    for signal in signals:
        reports = ThreatReport.objects.filter(
            signal=signal,
            reported_at__gte=now - timedelta(days=14),  # rolling 14-day window
        ).exclude(
            installation__is_banned=True
        )

        if not reports.exists():
            # Begin decay if not already decaying
            if signal.decay_starts_at is None:
                signal.decay_starts_at = now
            signal.confidence = decay_confidence(
                base_confidence=signal.confidence,
                decay_start=signal.decay_starts_at,
                now=now,
            )
        else:
            # Recompute from reports
            signal.reporter_count = reports.values('installation_id').distinct().count()
            signal.total_reports = reports.count()
            signal.confidence = compute_confidence(signal, reports, now)
            signal.decay_starts_at = None  # reset decay
            signal.last_reported_at = reports.latest('reported_at').reported_at

        # Determine publication action
        signal.is_published = signal.confidence >= PUBLISH_THRESHOLD  # 0.80
        if signal.is_published:
            signal.published_action = choose_action(signal, reports)
            signal.expires_at = compute_expiry(signal, reports, now)
        else:
            signal.is_published = False

        signal.save()

    # Regenerate the published_rule table and feed snapshot
    rebuild_published_rules()
    generate_feed_snapshot()
```

### 2.4 Deduplication

Same threat reported by 50 sites vs one site:

- **By install_id + period:** The central service accepts at most one report
  per `(install_id, period_start, period_end, rule_type, pattern)` combination.
  Duplicate submissions for the same period are rejected with `409 Conflict`.
- **By installation uniqueness:** `reporter_count` counts distinct `installation_id`
  values in the rolling window, not total report rows. 50 identical reports from
  the same install count as 1 reporter.
- **Anti-sybil:** Multiple installations sharing the same public IP address
  are treated as a single "source cluster" for confidence scoring purposes. The
  service records the submitting IP (never stored beyond the session) and applies
  a cluster weight penalty if more than 3 distinct install_ids submit from the
  same /24 in a 24-hour window.

### 2.5 Decay

When a signal stops being reported:

```
decay_factor = e^(-λ * hours_since_last_report)
λ = 0.005   # half-life ≈ 6 days

decayed_confidence = current_confidence * decay_factor
```

At `confidence < 0.80` the rule is removed from the published feed (existing
clients will deactivate it at next sync per the existing `BR-FEED-005` logic).
At `confidence < 0.10` the signal row is archived (moved to `threat_signal_archive`).

The aggregation task runs every 15 minutes. Decay is computed on every run for
every signal that has not received a new report.

### 2.6 Abuse Prevention

| Threat | Mitigation |
|---|---|
| Malicious install submitting fake high-hit reports | Confidence scoring requires multiple distinct reporters. One reporter cannot push confidence above ~0.55 regardless of hit counts. |
| Sybil attack (many fake install_ids from one operator) | Cluster weight penalty for install_ids sharing a /24 source IP. API key required for submissions above free tier volume. |
| Poisoning legitimate IPs (submitting false blocks against, e.g., Google's crawlers) | Published rules are capped at `challenge` action until `reporter_count >= 10`. Only `reporter_count >= 25` unlocks `block` action for CIDR rules. UA rules require `reporter_count >= 5` for block. |
| Feed pollution with low-signal noise | Minimum publish threshold: `confidence >= 0.80`. Minimum `reporter_count >= 3` regardless of confidence. |
| Replay attacks (re-submitting old periods) | Period timestamps validated against submission time. Periods older than 48 hours are rejected. |
| Enumeration of known-bad CIDRs | The feed is public, so this is accepted. The API does not expose which installations reported which signals. |
| DoS on the report endpoint | Rate limiting: 1 report per install_id per 12 hours. API key required for higher frequency. Hard cap: 100 requests/minute per IP to the ingest endpoint. |

### 2.7 Infrastructure

**MVP (0 to 500 installations):**

```
Single VPS (Hetzner CX22: 2 vCPU, 4 GB RAM, ~€4/month)
├── Docker Compose
│   ├── fastapi (uvicorn, 2 workers)
│   ├── postgres:16
│   ├── redis:7
│   ├── celery worker (1 process)
│   └── nginx (TLS termination, static feed.json serving)
└── Hetzner Object Storage (S3-compatible, feed snapshots)
```

**Growth tier (500 to 10,000 installations):**

```
Hetzner CX32 (4 vCPU, 8 GB RAM) for API + Celery
Hetzner CCX13 (2 dedicated vCPU, 8 GB RAM) for Postgres
Redis: Hetzner managed or same VPS
Feed snapshots: Cloudflare R2 + Cloudflare CDN (zero egress cost)
```

At 10,000 installations polling once per day, each response ~500 KB:

- Bandwidth: 5 GB/day → well within CDN free tier
- Postgres: read load from aggregation only; feed reads hit the static file
- Redis: rate limiting + deduplication windows → <1 GB RAM

**Production (10,000+ installations):**
Kubernetes on Hetzner Cloud with separate API and worker deployments. Read replicas
for Postgres if aggregation queries become slow. Managed Postgres (Neon or
Supabase) optional.

---

## 3. Confidence Scoring Algorithm

### 3.1 Design Rationale

The scoring system must satisfy three properties:

1. **Slow ramp:** A single reporter cannot reach the publish threshold alone.
2. **Fast confirmation:** Five independent reporters with strong signals should
   cross the threshold quickly.
3. **Natural decay:** Threats that stop being reported fade out without manual
   intervention.

A Bayesian approach with a Beta distribution is appropriate:
- Prior: Beta(α=1, β=5), a sceptical prior, starting at ~0.17
- Each new reporter from a distinct installation updates α
- Signal weight varies by signal type (blocked > challenged > throttled)

### 3.2 Score Computation

```python
SIGNAL_WEIGHTS = {
    "blocked":    1.0,
    "challenged": 0.6,
    "throttled":  0.3,
    "unsolved":   0.8,   # challenged but never solved, a strong bot signal
}

# Publication thresholds
PUBLISH_THRESHOLD    = 0.80
MIN_REPORTERS        = 3       # absolute minimum before any publication
BLOCK_ACTION_MIN     = 25      # reporters needed to publish as 'block' for CIDRs
CHALLENGE_ACTION_MIN = 3       # reporters needed to publish as 'challenge'

ALPHA_PRIOR = 1.0
BETA_PRIOR  = 5.0


def compute_confidence(signal, reports, now):
    """
    Bayesian Beta confidence score for a threat_signal.

    Args:
        signal:  ThreatSignal ORM object
        reports: QuerySet of ThreatReport rows within the 14-day window
        now:     current UTC datetime

    Returns:
        float in [0.0, 1.0]
    """
    # Deduplicated reporters (distinct install_ids)
    distinct_installations = set()
    weighted_evidence = 0.0

    for report in reports:
        install_id = report.installation_id

        # Cluster penalty: installations from the same source /24 share weight
        cluster_weight = get_cluster_weight(install_id)  # 1.0 normally, <1.0 for clusters

        # Local signal strength from this installation
        signal_strength = (
            (report.blocked_hits * SIGNAL_WEIGHTS["blocked"])
            + (report.challenged_hits * SIGNAL_WEIGHTS["challenged"])
            + (report.throttled_hits * SIGNAL_WEIGHTS["throttled"])
        )
        # Cap contribution per reporter to prevent one site from dominating
        signal_strength = min(signal_strength, 500)

        # Recency weight: reports from last 24 h get full weight, older reports decay
        hours_old = (now - report.reported_at).total_seconds() / 3600
        recency = max(0.2, 1.0 - (hours_old / (14 * 24)))

        # Trusted installation bonus
        trust_multiplier = 1.3 if report.installation.is_trusted else 1.0

        contribution = (signal_strength / 500) * recency * cluster_weight * trust_multiplier
        weighted_evidence += contribution
        distinct_installations.add(install_id)

    reporter_count = len(distinct_installations)

    if reporter_count < MIN_REPORTERS:
        return 0.0  # Never publish below minimum reporters

    # Beta distribution: alpha = prior + evidence, beta = prior + absence
    # We treat weighted_evidence as pseudo-observations of "threat confirmed"
    alpha = ALPHA_PRIOR + weighted_evidence
    beta  = BETA_PRIOR + max(0, reporter_count - weighted_evidence)

    # Mean of Beta distribution: alpha / (alpha + beta)
    raw_score = alpha / (alpha + beta)

    # Apply a sigmoid-like reporter multiplier to make early reporters matter
    # (3 reporters → ~0.75× multiplier, 10 reporters → ~0.95× multiplier)
    reporter_multiplier = 1 - (1 / (1 + (reporter_count / 5)))
    score = raw_score * reporter_multiplier

    return min(round(score, 3), 1.0)


def choose_action(signal, reports):
    """
    Determine the published action based on reporter count.
    CIDRs default to 'challenge' until high confidence; UAs block earlier.
    """
    reporter_count = signal.reporter_count
    rule_type = signal.rule_type

    if rule_type == "cidr":
        if reporter_count >= BLOCK_ACTION_MIN and signal.confidence >= 0.92:
            return "block"
        return "challenge"

    if rule_type in ("ip", "ua"):
        if reporter_count >= 5 and signal.confidence >= 0.85:
            return "block"
        return "challenge"

    return "challenge"


def compute_expiry(signal, reports, now):
    """
    Expiry = last_reported_at + base_ttl, extended by reporter count.
    Base TTL: 7 days. +1 day per 5 reporters, capped at 30 days.
    """
    base_days = 7
    bonus_days = min(signal.reporter_count // 5, 23)
    return signal.last_reported_at + timedelta(days=base_days + bonus_days)


def decay_confidence(base_confidence, decay_start, now):
    """
    Exponential decay with half-life of ~6 days (λ=0.005 per hour).
    """
    import math
    hours_elapsed = (now - decay_start).total_seconds() / 3600
    lambda_ = 0.005
    return base_confidence * math.exp(-lambda_ * hours_elapsed)
```

### 3.3 Score Reference Table

The following illustrates expected confidence values at steady state:

| Reporters | Avg signal strength | Age | Approx. confidence | Published? | Action |
|---|---|---|---|---|---|
| 1 | High | 1 day | 0.38 | No | n/a |
| 2 | High | 1 day | 0.52 | No | n/a |
| 3 | High | 1 day | 0.67 | No | n/a |
| 5 | High | 1 day | 0.81 | Yes | challenge |
| 10 | Medium | 3 days | 0.85 | Yes | challenge |
| 25 | Mixed | 7 days | 0.91 | Yes | block (CIDR) |
| 50 | Mixed | 14 days | 0.95 | Yes | block |
| 5 | High | 10 days (no new reports) | 0.62 | No (decayed) | n/a |

### 3.4 Handling Disagreement

When some installations report a CIDR and others do not:

- Absence of a report is neutral, not evidence of absence. The score is computed
  only from reporting installations; non-reporters do not reduce confidence.
- If an installation explicitly submits a report with zero hits for a pattern
  (not currently in the client schema; see Section 6 for the addition needed),
  that counts as a weak negative signal (reduces β by 0.5 per such report).
- If the confidence stays below the publish threshold due to disagreement, the
  rule is simply not published; existing clients are unaffected.

---

## 4. Privacy and Trust Model

### 4.1 Guarantees

The following are unconditional guarantees, enforceable by inspecting the
open-source client code:

1. **No full IP addresses leave the installation.** The client truncates to /24
   before building the payload. Code: `django_waf/services/threat_feed.py`,
   `build_telemetry_payload()`, line using `ipaddress.ip_network(f"{ip}/24",
   strict=False)`.

2. **No raw user-agent strings leave the installation.** SHA-256 is applied
   before inclusion. The hash is one-way; the central service cannot recover
   the original string.

3. **No URL paths, query strings, cookies, or user identifiers are collected.**
   The payload schema does not include these fields. The central service rejects
   payloads with unexpected top-level keys.

4. **The install_id cannot identify the site.** It is a random UUID generated
   at install time with no relation to the domain, SECRET_KEY, or any user. A
   new UUID can be generated at any time by deleting the `.django_waf_install_id`
   file.

5. **Reporting is opt-in by default.** `DJANGO_WAF_FEED_REPORT` defaults to `False`.
   An operator must explicitly set it to `True` to submit telemetry.

6. **The central service does not store the submitting IP address** beyond the
   transient rate-limiting window (TTL: 1 hour in Redis).

### 4.2 GDPR Analysis

| Data point | GDPR classification | Justification |
|---|---|---|
| `/24 subnet` (e.g., `185.220.101.0/24`) | Likely not PII for most subnets | A /24 covers 256 addresses. ECJ case law (Breyer, C-582/14) requires "reasonable means" to re-identify. /24 alone does not identify a natural person; correlation with ISP data could in theory do so, but that requires external data the service does not hold. Treat as borderline; err on the side of caution in DPA communication. |
| `ua_hashes` (SHA-256 of UA string) | Not PII | One-way hash of a non-unique string. Cannot be reversed to identify an individual. |
| `install_id` | Not PII | Random UUID with no link to identity. |
| `country_distribution` | Not PII | Aggregate counts by country code. |
| `referer_hashes` | Not PII | One-way hash of a domain name. |

**Recommended DPA language:** The service processes aggregated, anonymised network
telemetry. No data capable of identifying a natural person is transmitted or
stored. The legal basis for any marginal processing is legitimate interest
(network security, Art. 6(1)(f) GDPR). A lightweight Privacy Notice covering
the central service should be published at `threats.icv.dev/privacy`.

### 4.3 Auditability

Every byte that leaves an installation can be inspected:

- The `build_telemetry_payload()` function is in `django_waf/services/threat_feed.py`
  in the open-source package.
- Operators can call `build_telemetry_payload(period_start, period_end)` directly
  in a Django shell and inspect the exact dict that would be submitted.
- The `submit_telemetry()` function logs the submission URL and the HTTP status
  code at INFO level. Operators can set `DJANGO_WAF_FEED_REPORT = False` at any
  time and submissions stop immediately.
- A `--dry-run` flag on the management command equivalent should be added (see
  Section 6).

### 4.4 Feed Integrity

**Problem:** A compromised central service could serve malicious rules (e.g.,
blocking legitimate IPs).

**Mitigation (MVP):** HTTPS from a trusted CA. Clients already use `httpx.get`
with default CA verification. This is sufficient for MVP.

**Mitigation (v2):** Ed25519-signed feeds. The central service signs each feed
snapshot with a private key. The public key is pinned in the client package.
Clients verify the signature before applying any rules.

```python
# Feed envelope with signature (v2 design, not MVP)
{
  "schema_version": "2",
  "generated_at": "...",
  "signature": "base64-encoded Ed25519 signature over sha256(rules_json)",
  "public_key_id": "feed-2026-04",
  "rules": [...]
}
```

The public key rotation mechanism (and key pinning update) requires a minor
version bump in the client package. Design this properly before implementing:
key management mistakes are worse than no signing.

---

## 5. API Design

Base URL: `https://threats.icv.dev`

### 5.1 Authentication Model

| Endpoint | Auth required |
|---|---|
| `GET /v1/feed.json` | None (anonymous public read) |
| `GET /v1/stats` | None |
| `POST /v1/report` | API key (Bearer token) for regular use; anonymous allowed with rate limit |
| `GET /v1/install/register` | None (returns an API key) |
| `GET /health` | None |

**API key format:** `waf_live_<base62(24 random bytes)>`, e.g.
`waf_live_4Xk9mNpQ2rLsT7vYeAzBcDwF`

Key prefix `waf_live_` is stored in `api_key.key_prefix` for display.
The full key is shown once on registration; only `sha256(full_key)` is stored.

### 5.2 Endpoints

---

#### `POST /v1/report`

Submit anonymised telemetry from an installation.

**Request headers:**
```
Authorization: Bearer waf_live_<key>
Content-Type: application/json
```

**Request body:** The telemetry payload schema from Section 1.1.

**Rate limits:**
- Anonymous (no API key): 1 request per install_id per 24 hours
- Authenticated: 1 request per install_id per 12 hours
- Hard cap: 100 requests/minute per source IP (enforced in Redis)

**Responses:**

```
201 Created
{
  "accepted": true,
  "signals_received": 12,
  "signals_deduplicated": 0,
  "message": "Telemetry accepted. Thank you for contributing."
}

409 Conflict
{
  "detail": "A report for this install_id and period has already been accepted."
}

422 Unprocessable Entity
{
  "detail": "Payload validation error: subnets[2].cidr must be a /24 prefix."
}

429 Too Many Requests
{
  "detail": "Rate limit exceeded. Retry after 3600 seconds.",
  "retry_after": 3600
}
```

**Pydantic request schema (FastAPI):**

```python
from pydantic import BaseModel, field_validator
import ipaddress
import re

SHA256_RE = re.compile(r'^[a-f0-9]{64}$')

class SubnetReport(BaseModel):
    cidr: str
    action: str  # "blocked" | "challenged" | "throttled"
    hits: int

    @field_validator('cidr')
    @classmethod
    def validate_cidr(cls, v):
        net = ipaddress.ip_network(v, strict=False)
        # Only accept /24 for IPv4, /48 for IPv6
        if net.version == 4 and net.prefixlen != 24:
            raise ValueError("IPv4 subnets must be /24")
        if net.version == 6 and net.prefixlen != 48:
            raise ValueError("IPv6 subnets must be /48")
        return v

    @field_validator('action')
    @classmethod
    def validate_action(cls, v):
        if v not in ('blocked', 'challenged', 'throttled'):
            raise ValueError("action must be blocked, challenged, or throttled")
        return v

    @field_validator('hits')
    @classmethod
    def validate_hits(cls, v):
        if v < 1 or v > 10_000_000:
            raise ValueError("hits must be between 1 and 10,000,000")
        return v


class UAHashReport(BaseModel):
    sha256: str
    action: str
    hits: int

    @field_validator('sha256')
    @classmethod
    def validate_hash(cls, v):
        if not SHA256_RE.match(v):
            raise ValueError("sha256 must be a 64-char hex string")
        return v


class AnomalyReport(BaseModel):
    anomaly_type: str
    cidr: str
    confidence: float
    ttl_hours: int = 48

    @field_validator('anomaly_type')
    @classmethod
    def validate_type(cls, v):
        valid = {
            'ua_rotation', 'subnet_flood', 'challenge_farm',
            'unsolved_challenge', 'path_hammering', 'burst'
        }
        if v not in valid:
            raise ValueError(f"Unknown anomaly_type: {v}")
        return v


class TelemetryPayload(BaseModel):
    schema_version: str = "1"
    install_id: str           # UUID string, validated as UUID
    period: str               # ISO 8601 interval
    summary: dict
    subnets: list[SubnetReport] = []
    ua_hashes: list[UAHashReport] = []
    anomalies: list[AnomalyReport] = []
    country_distribution: dict[str, int] = {}
    referer_hashes: list[dict] = []

    @field_validator('schema_version')
    @classmethod
    def validate_version(cls, v):
        if v not in ('1',):
            raise ValueError(f"Unsupported schema_version: {v}")
        return v

    @field_validator('subnets')
    @classmethod
    def limit_subnets(cls, v):
        if len(v) > 500:
            raise ValueError("subnets list exceeds maximum of 500 entries")
        return v

    @field_validator('ua_hashes')
    @classmethod
    def limit_ua_hashes(cls, v):
        if len(v) > 200:
            raise ValueError("ua_hashes list exceeds maximum of 200 entries")
        return v
```

---

#### `GET /v1/feed.json`

Fetch the curated threat feed. Served as a static file from Nginx/CDN in
production. The dynamic endpoint is used only for delta queries.

**Query parameters:**

| Parameter | Type | Description |
|---|---|---|
| `since` | ISO 8601 datetime | Return only rules modified after this timestamp (delta mode). |
| `page` | integer | Page number for full snapshots (default: 1). |
| `per_page` | integer | Rules per page (default: 500, max: 2000). |
| `min_confidence` | float | Server-side confidence filter (default: 0.80). |

**Response (200):** The feed envelope from Section 1.2.

**Cache headers (full snapshot):**
```
Cache-Control: public, max-age=3600, s-maxage=3600
ETag: "sha256-of-feed-content"
Last-Modified: <generated_at>
```

**Implementation note:** The full snapshot endpoint returns a static file.
The delta endpoint (`?since=...`) is a live query against `published_rule`
filtered by `updated_at > since`. Keep the delta query fast with the
`updated_at DESC` index.

---

#### `GET /v1/stats`

Public statistics. No authentication. Cached aggressively (1 hour).

**Response:**
```json
{
  "schema_version": "1",
  "as_of": "2026-04-07T04:30:00Z",
  "active_rules": 1842,
  "total_installations": 312,
  "reporting_installations_7d": 187,
  "threats_blocked_7d": 2480912,
  "top_anomaly_types": [
    {"type": "ua_rotation", "count": 841},
    {"type": "subnet_flood", "count": 623}
  ]
}
```

---

#### `POST /v1/install/register`

Register a new installation and obtain an API key. Called once by the client
(not yet implemented on the client side; see Section 6).

**Request body:**
```json
{
  "install_id": "a7f3c1d2-...",
  "schema_version": "1"
}
```

**Response (201):**
```json
{
  "api_key": "waf_live_4Xk9mNpQ2rLsT7vYeAzBcDwF",
  "message": "Store this key securely. It will not be shown again. Set DJANGO_WAF_FEED_API_KEY in your Django settings."
}
```

The API key is shown exactly once. The central service stores only
`sha256(api_key)`. If the key is lost, the operator registers again (a new
`install_id` is generated and the old one is orphaned after 90 days of inactivity).

---

#### `GET /health`

Health check. Returns 200 if the service is operational.

```json
{"status": "ok", "version": "1.0.0"}
```

---

## 6. Client-Side Changes Needed in django-waf

### 6.1 Current State

The existing client code is largely correct. The following changes are needed:

### 6.2 Required Changes

**`conf.py`: new settings:**

```python
# How often to submit telemetry (hours between submissions).
DJANGO_WAF_FEED_REPORT_INTERVAL_HOURS: int = getattr(
    settings, "DJANGO_WAF_FEED_REPORT_INTERVAL_HOURS", 24
)

# Maximum retries for telemetry submission before giving up.
DJANGO_WAF_FEED_REPORT_MAX_RETRIES: int = getattr(
    settings, "DJANGO_WAF_FEED_REPORT_MAX_RETRIES", 3
)

# Base backoff in seconds for retry logic.
DJANGO_WAF_FEED_REPORT_BACKOFF_BASE: int = getattr(
    settings, "DJANGO_WAF_FEED_REPORT_BACKOFF_BASE", 60
)

# How often to sync the feed (hours between syncs).
DJANGO_WAF_FEED_SYNC_INTERVAL_HOURS: int = getattr(
    settings, "DJANGO_WAF_FEED_SYNC_INTERVAL_HOURS", 24
)

# Store the cursor from the last successful feed sync for delta updates.
# Stored in Django cache; this setting controls the cache key prefix.
DJANGO_WAF_FEED_CURSOR_CACHE_KEY: str = getattr(
    settings, "DJANGO_WAF_FEED_CURSOR_CACHE_KEY", "django_waf:feed_cursor"
)
```

**`services/threat_feed.py`, `submit_telemetry()`: add retry with backoff:**

```python
def submit_telemetry(payload: dict, report_url: str | None = None) -> bool:
    """POST telemetry with exponential backoff retry."""
    import time
    import httpx
    from django_waf import conf

    url = report_url or conf.DJANGO_WAF_FEED_REPORT_URL
    api_key = conf.DJANGO_WAF_FEED_API_KEY
    max_retries = conf.DJANGO_WAF_FEED_REPORT_MAX_RETRIES
    backoff_base = conf.DJANGO_WAF_FEED_REPORT_BACKOFF_BASE

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    for attempt in range(max_retries):
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=30)
            if response.is_success:
                logger.info("django-waf: telemetry submitted (attempt %d)", attempt + 1)
                return True
            if response.status_code == 409:
                # Already accepted for this period, treat as success
                logger.info("django-waf: telemetry already accepted for this period")
                return True
            if response.status_code == 422:
                # Validation error, retrying won't help
                logger.warning("django-waf: telemetry rejected (422): %s", response.text[:200])
                return False
            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", backoff_base * (2 ** attempt)))
                logger.warning("django-waf: rate limited; waiting %ds", retry_after)
                time.sleep(retry_after)
                continue
        except Exception as exc:
            wait = backoff_base * (2 ** attempt)
            logger.warning("django-waf: telemetry error (attempt %d): %s; retrying in %ds", attempt + 1, exc, wait)
            if attempt < max_retries - 1:
                time.sleep(wait)

    logger.warning("django-waf: telemetry submission failed after %d attempts", max_retries)
    return False
```

**`services/threat_feed.py`, `sync_feed()`: add delta update support:**

```python
def sync_feed(feed_url=None, min_confidence=None, use_delta=True):
    """
    Fetch the threat feed, using delta updates when a cursor is available.
    """
    from django.core.cache import cache
    from django_waf import conf

    url = feed_url or conf.DJANGO_WAF_FEED_URL
    cursor = cache.get(conf.DJANGO_WAF_FEED_CURSOR_CACHE_KEY) if use_delta else None

    if cursor:
        fetch_url = f"{url}?since={cursor}"
        logger.info("django-waf: fetching delta feed since %s", cursor)
    else:
        fetch_url = url
        logger.info("django-waf: fetching full feed snapshot")

    # ... existing fetch and apply logic ...

    # Store the cursor from the response for next delta
    if "cursor" in feed_data:
        cache.set(conf.DJANGO_WAF_FEED_CURSOR_CACHE_KEY, feed_data["cursor"], timeout=None)
```

**`build_telemetry_payload()`: add `country_distribution` and `referer_hashes`:**

The current implementation does not populate `country_distribution` (even when
GeoIP is configured) or `referer_hashes`. Both should be added:

```python
# country_distribution from RequestLog.country_code
from django.db.models import Count
country_dist = (
    logs_in_period
    .filter(verdict__in=["blocked", "challenged"])
    .exclude(country_code="")
    .values("country_code")
    .annotate(count=Count("id"))
)
country_distribution = {row["country_code"]: row["count"] for row in country_dist}

# referer_hashes: hash the domain component only
import urllib.parse
referer_domain_counts: dict[str, int] = {}
for log in logs_in_period.filter(verdict__in=["blocked", "challenged"]).exclude(referer="").values("referer"):
    try:
        domain = urllib.parse.urlparse(log["referer"]).netloc.lower()
        if domain:
            h = hashlib.sha256(domain.encode()).hexdigest()
            referer_domain_counts[h] = referer_domain_counts.get(h, 0) + 1
    except Exception:
        continue
referer_hashes = [
    {"sha256": h, "hits": count}
    for h, count in referer_domain_counts.items()
    if count >= 3  # suppress single-occurrence referers
]
```

**`tasks.py`, `report_threat_telemetry`: respect the reporting interval:**

The task should check the last submission timestamp in cache and skip if the
configured interval has not elapsed:

```python
@shared_task
def report_threat_telemetry() -> dict:
    from django.core.cache import cache
    from django_waf import conf

    if not conf.DJANGO_WAF_FEED_REPORT:
        return {"skipped": True, "reason": "reporting disabled"}

    # Idempotency guard: skip if submitted within the reporting interval
    last_submitted_key = "django_waf:last_telemetry_submitted"
    last_submitted = cache.get(last_submitted_key)
    if last_submitted:
        hours_since = (timezone.now() - last_submitted).total_seconds() / 3600
        if hours_since < conf.DJANGO_WAF_FEED_REPORT_INTERVAL_HOURS:
            return {"skipped": True, "reason": f"submitted {hours_since:.1f}h ago"}

    # ... existing build + submit logic ...

    if submitted:
        cache.set(last_submitted_key, timezone.now(), timeout=60 * 60 * 48)
```

**Management command `django_waf_report_telemetry` (new):**

Add a management command mirroring `django_waf_sync_feed` for manual telemetry
submission and audit (includes `--dry-run` to print the payload without submitting):

```
python manage.py django_waf_report_telemetry --dry-run
```

### 6.3 Offline Resilience

If the central service is unreachable:

- `submit_telemetry()` never raises (existing behaviour; `BR-TEL-004`).
- Failed submissions are logged as WARNING. No local queueing of failed payloads:
  the next scheduled run will produce a fresh payload for the new period.
- `sync_feed()` returns `{"error": "..."}` on network failure. The existing
  rules remain active. No rules are expired due to a failed sync; expiry only
  occurs when a rule is explicitly absent from a *successful* feed response.

No additional resilience infrastructure is needed for the MVP. The impact of
missing one daily submission is a ~1-day data gap in the central service, which is
acceptable.

### 6.4 Reporting Frequency

| Setting | Default | Notes |
|---|---|---|
| `report_threat_telemetry` Celery task | Daily at 05:00 | One 24-hour window of data per submission. |
| `sync_threat_feed` Celery task | Daily at 04:30 | Full sync first; delta sync once cursor is established. |
| Minimum API-enforced interval | 12 hours (keyed) | Prevents accidental double-submission from misconfigured cron. |

For installations with Celery Beat, no changes to the schedule are needed. The
idempotency guard (cache check) in the task handles accidental double-runs.

---

## 7. Go-to-Market

### 7.1 Tiers

| Tier | Price | Feed access | Reporting | API key |
|---|---|---|---|---|
| Consumer (read-only) | Free | Full feed, 24h refresh | No | Not required |
| Contributor | Free | Full feed, 1h refresh | Yes (opt-in) | Required |
| Pro | $29/month | Full feed, 15-min delta | Yes | Required; higher rate limits |
| Enterprise | Custom | Real-time delta + private rules | Yes | Dedicated key; SLA |

**Value prop for contributing:**

- Faster feed refresh (1h vs 24h)
- Your threats reach other installations within hours
- Access to `stats` endpoint breakdown by industry/vertical (v2)
- Contributor badge in README (vanity, but developers respond to it)

The core value exchange is explicit and fair: contribute data → get fresher
and more comprehensive protection. The free tier reader gets stale but usable
data; contributors get near-real-time coverage.

### 7.2 Critical Mass

The feed is meaningless until it has enough reporters to generate confident
signals. Minimum viable network effects:

| Metric | Target | Rationale |
|---|---|---|
| Active contributors | 50 | Below this, reporter_count rarely reaches 5 for any signal. Rules are not published. |
| Active contributors | 200 | Sufficient to publish CIDR rules with confidence > 0.80 within 48h of a coordinated attack. |
| Active contributors | 1,000 | Feed covers most botnets active against Django deployments. Comparable to AbuseIPDB at this scale. |

**Bootstrapping strategy:**

1. Pre-seed the feed with ~200 high-confidence CIDR rules from public threat
   intel sources (Spamhaus, emerging-threats, Tor exit node lists). These are
   tagged `source:external` and do not count toward reporter_count, but they
   give early adopters immediate value before the network has critical mass.
2. Announce on Django forums, r/django, Django Chat podcast. The open-source WAF
   itself is the distribution channel.
3. First 500 contributors get Contributor tier free forever (grandfathered).

### 7.3 Comparison to Existing Threat Feeds

| Feed | Data type | Coverage | Cost | Django integration |
|---|---|---|---|---|
| AbuseIPDB | Full IPs, reports | General | Free/paid API | Manual |
| Spamhaus | CIDR blocklists | Spam, botnets | Licence required | Manual |
| Emerging Threats | Suricata/Snort rules | General | Free/paid | Manual |
| Cloudflare Radar | CIDR, ASN | General | API, read-only | Manual |
| **threats.icv.dev** | /24 CIDRs, UA hashes | Django-specific bots | Free/paid | Native, automatic |

The differentiation is Django-specific: the signal is generated by Django WAF
middleware, filtered to threats that successfully hit Django applications, and
delivered natively to Django WAF middleware with zero operator effort. General
feeds require manual integration and produce high false-positive rates when
applied to Django applications.

### 7.4 Revenue Potential

Assumptions: 2,000 total installations at 24-month mark; 15% Pro conversion.

| Metric | Value |
|---|---|
| Pro subscribers (Y2) | 300 |
| ARPU | $29/month |
| MRR (Y2) | $8,700 |
| ARR (Y2) | $104,400 |

Infrastructure cost at this scale: <$200/month. Margin >97% before any support
overhead. The feed is a natural upsell to a SaaS dashboard offering (the
commercialisation analysis at `project_icvwaf_saas_analysis.md` covers this in
detail).

---

## 8. MVP Scope

### 8.1 What the MVP Must Include

The absolute minimum to ship a working collective threat feed:

**Central service:**

| Component | Included in MVP |
|---|---|
| `POST /v1/report` endpoint | Yes |
| `GET /v1/feed.json` (static file) | Yes |
| `GET /v1/feed.json?since=` (delta) | No, v1.1 |
| `GET /v1/stats` | Yes (simple counts) |
| `POST /v1/install/register` | Yes |
| `GET /health` | Yes |
| Confidence scoring | Yes (full algorithm) |
| Aggregation Celery task (15-min) | Yes |
| Feed snapshot generation | Yes |
| Feed signing (Ed25519) | No, v2 |
| Private rules per Enterprise customer | No, v2 |
| Pre-seeded external threat intel | Yes (manual import script) |

**Client package:**

| Change | Included in MVP |
|---|---|
| New settings (`INTERVAL_HOURS`, `MAX_RETRIES`, `BACKOFF_BASE`) | Yes |
| Retry with backoff in `submit_telemetry()` | Yes |
| `country_distribution` in payload | Yes (requires GeoIP configured) |
| `referer_hashes` in payload | Yes |
| Delta sync (`?since=` with cursor) | No, v1.1 |
| `django_waf_report_telemetry` management command | Yes |
| Auto-registration (`/v1/install/register`) | No, v1.1; manual key copy is acceptable for MVP |

### 8.2 Data Model: MVP Tables

For the MVP, the minimum required tables are:

1. `installation`: track reporters
2. `threat_signal`: canonical signals
3. `threat_report`: raw inbound data (without partitioning for MVP; add later)
4. `api_key`: authentication
5. `published_rule`: denormalised feed output
6. `feed_snapshot`: audit trail of generated feeds

The `feed_snapshot` table is optional for MVP but trivially cheap to add.

### 8.3 Infrastructure: MVP

```
Hetzner CX22 VPS (€4/month)
├── nginx (TLS via Let's Encrypt, serves static feed.json)
├── Docker Compose
│   ├── fastapi:uvicorn (2 workers)
│   ├── postgres:16 (500 MB disk for MVP)
│   ├── redis:7 (rate limiting, deduplication)
│   └── celery:worker (1 process, aggregation + feed generation)
└── Backups: daily Postgres dump to Hetzner Object Storage
```

Total infrastructure cost: ~$10/month including storage.

### 8.4 Estimated Effort

| Task | Estimate |
|---|---|
| FastAPI project scaffold, Postgres schema, Alembic migrations | 2 days |
| `POST /v1/report` endpoint + Pydantic validation | 1 day |
| Confidence scoring algorithm + aggregation task | 2 days |
| Feed snapshot generation + static file serving | 1 day |
| `GET /v1/feed.json` + `GET /v1/stats` | 0.5 days |
| `POST /v1/install/register` + API key management | 0.5 days |
| Rate limiting (Redis sliding window) | 0.5 days |
| Docker Compose + nginx + Let's Encrypt setup | 0.5 days |
| Client-side changes (retry, new settings, management command) | 1 day |
| Pre-seed import script (Tor exits, Spamhaus, emerging-threats) | 0.5 days |
| Testing (pytest, hypothesis for scoring algorithm) | 2 days |
| **Total** | **~11 developer-days** |

### 8.5 Definition of Done for MVP

- [ ] A real installation can set `DJANGO_WAF_FEED_REPORT = True` and
  `DJANGO_WAF_FEED_API_KEY`, run `report_threat_telemetry`, and see a 201 response
  from `threats.icv.dev/v1/report`
- [ ] After 5 distinct installations report the same /24 subnet with sufficient
  hits, the aggregation task publishes it to `published_rule` with confidence >= 0.80
- [ ] `GET https://threats.icv.dev/v1/feed.json` returns a valid JSON feed with
  at least the pre-seeded rules
- [ ] A new installation can `sync_feed()` and have the feed rules applied as
  `BlockRule` objects in its local database
- [ ] The feed correctly deactivates rules absent from the next feed response
  (existing `BR-FEED-005` behaviour)
- [ ] `GET /v1/stats` returns non-zero `active_rules` and `total_installations`
- [ ] All endpoints return 429 when rate limits are exceeded
- [ ] Payloads containing full IPs (non-/24 CIDRs) are rejected with 422

---

## Appendix A: File Locations in django-waf

| File | Role |
|---|---|
| `src/django_waf/services/threat_feed.py` | `sync_feed()`, `build_telemetry_payload()`, `submit_telemetry()`, `get_or_create_install_id()` |
| `src/django_waf/tasks.py` | `sync_threat_feed`, `report_threat_telemetry` Celery tasks |
| `src/django_waf/conf.py` | All `DJANGO_WAF_*` settings with defaults |
| `src/django_waf/management/commands/django_waf_sync_feed.py` | Manual feed sync command |
| `src/django_waf/enums.py` | `AnomalyType`, `RuleType`, `RuleAction`, `Verdict` |
| `src/django_waf/models.py` | `BlockRule` (`feed_reporters`, `feed_first_seen`, `confidence` fields) |
| `src/django_waf/signals.py` | `feed_synced` signal |

## Appendix B: Central Service Repository Structure

Suggested layout for the new `threats-feed` repository:

```
threats-feed/
├── pyproject.toml
├── docker-compose.yml
├── nginx/
│   └── default.conf
├── src/
│   └── feed/
│       ├── main.py               # FastAPI app
│       ├── models.py             # SQLAlchemy models
│       ├── schemas.py            # Pydantic request/response schemas
│       ├── api/
│       │   ├── report.py         # POST /v1/report
│       │   ├── feed.py           # GET /v1/feed.json
│       │   ├── stats.py          # GET /v1/stats
│       │   └── install.py        # POST /v1/install/register
│       ├── services/
│       │   ├── aggregation.py    # compute_confidence, aggregate_threat_signals
│       │   ├── rate_limiting.py  # Redis sliding window
│       │   └── snapshot.py       # Feed JSON generation + storage
│       └── tasks/
│           ├── celery.py         # Celery app
│           └── aggregate.py      # Scheduled tasks
├── alembic/
│   └── versions/
├── tests/
│   ├── test_report.py
│   ├── test_scoring.py
│   └── test_feed.py
└── scripts/
    └── seed_external_intel.py    # One-time pre-seed import
```
