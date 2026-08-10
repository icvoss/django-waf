# django-waf: Threat Model and Operator Safety Controls

Status: current as of the `Unreleased` branch (post-1.8.0). Issue: #36.

Every claim below is checked against source (`file:line` or module name) as
of this pass. Where a control does not exist yet, this document says so
plainly rather than describing an aspiration as shipped: per ADR-021, this
document describes the in-process, MIT-licensed package only, and must not
promise operated-service or roadmap features that are not built.

---

## 1. What this document is for

django-waf is marketed and packaged as a WAF. Read literally, "web
application firewall" implies payload inspection: SQL injection, XSS,
command injection, the OWASP Core Rule Set class of coverage. django-waf
does not do any of that. What it does is bot detection, rate limiting,
proof-of-work challenges, IP/UA reputation, and a form-submission defence
chain: an anti-abuse and bot-management system, not a payload-inspecting
firewall. This document exists so an operator (or a prospective one reading
marketing copy) can see the real capability matrix and trust boundary
before deploying it as their only defence layer, and so any future
commercial claim about this package is checked against what section 2 says
is actually built, per the verified-claims discipline in
`docs/research/competitors/django-waf/market-strategy.md` (umbrella repo).

---

## 2. Capability matrix

### In scope (built, verified against source)

| Capability | Module | Notes |
|---|---|---|
| Bot / scraper detection | `services/ua_analyser.py`, `services/fingerprint.py` | Heuristic UA scoring plus HTTP fingerprint mismatch scoring (claimed browser UA missing the headers a real browser sends) |
| Rate limiting | `services/rate_limiter.py` | Redis sliding-window, per-IP and optionally per-path |
| Proof-of-work challenges | `services/challenge_service.py`, `views.ChallengeView`/`VerifyView` | Hashcash-style; solved client-side, verified server-side |
| IP / CIDR / UA block and allow rules | `services/rule_engine.py`, `models.BlockRule`/`AllowRule` | Priority-ordered; rDNS-gated allow rules for verified crawlers |
| IP reputation scoring | `services/anomaly_detector.py` (`update_ip_reputation`), `models.IPReputation` | Rebuilt from `RequestLog` on a schedule; a composite threat score, not a payload verdict |
| Anomaly detection (auto rule creation) | `services/anomaly_detector.py` | UA rotation, cloud spray, challenge farms, subnet bursts; see section 4 for the safety gaps this document exists to surface |
| Collective threat feed (opt-in) | `services/threat_feed.py`, `06-threat-feed-api.md` | Client only; see section 3 |
| Form-submission defence chain | `forms/` (eight defences) | Honeypot, timing, render-token replay protection, UA consistency, JS touch, credential/signup throttling, form-level PoW |
| Site-password gate (opt-in) | `services/site_password_service.py` | Whole-site shared-password wall, independent of rule evaluation |
| nginx blocklist export | `services/blocklist_generator.py` | Generates `map`/`geo` config from active rules; enforcement is operator-wired (BR-BL-007) |

### Out of scope (not built; do not claim)

| Not covered | Why this matters |
|---|---|
| Application payload inspection (SQLi, XSS, command injection, OWASP CRS-class signatures) | `RuleType` has exactly four values (`ua`, `ip`, `cidr`, `composite`, `enums.py`); none inspects a request body or query string against attack signatures. `request.body` is read in exactly one place in the whole package (`views.py:247`), to parse the challenge-solution JSON on `POST /waf/verify/`, not to scan a payload. The closest existing capability is reconnaissance-path scoring (`DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS`, matched against the path only), which is not payload inspection |
| File upload scanning | No upload-handling code exists in the package |
| Volumetric / network-layer DDoS mitigation | The package is in-process Django middleware plus an nginx export; it has no edge network, no anycast, no capacity beyond the host it runs on. A large enough flood exhausts the host before the WAF's own logic runs |
| TLS termination, certificate management | Out of scope by design; a consumer's existing web server owns this |
| GeoIP database lifecycle beyond `django_waf_install_geoip` | The package ships a download command; it does not operate or update a hosted GeoIP service |
| Central threat feed service | `threats.drystane.com` is a separate, closed commercial implementation of the public wire contract (`06-threat-feed-api.md`); this package is the client only |

If a page or a customer conversation ever needs the phrase "web application
firewall" without qualification, that claim is false against this matrix.
The honest framing, consistent with the market-strategy document's
positioning lines, is anti-abuse and bot-management, in-process, with WAF
used as a category label buyers search for rather than a literal capability
promise.

---

## 3. Trust boundaries

- **The package trusts Redis.** Rule evaluation, rate limiting, and
  challenge state have no safe fallback on a non-Redis cache backend (see
  `django_waf.services.redis_client`, issue #44); a misconfigured or
  unreachable Redis makes the WAF evaluate nothing for the duration
  (fail-open, BR-EVAL-007). This is a deliberate choice, not an oversight:
  the alternative (fail closed on every Redis hiccup) would make the WAF
  itself the site's biggest availability risk. An operator who needs
  fail-closed behaviour for a specific route must build that at the
  reverse-proxy layer, not expect it from this package.
- **The package trusts the operator's Redis and database, not any third
  party, for anything except the opt-in threat feed and telemetry.** No
  request data leaves the process unless `DJANGO_WAF_FEED_REPORT` (default
  `False`) is explicitly turned on, and even then only hashed UAs and
  truncated IP subnets are sent (BR-TEL-002), never full IPs, paths,
  headers, cookies, or user identifiers.
- **The package trusts `AuthenticationMiddleware` ordering, with an opt-in
  escape hatch.** The staff/superuser bypass (BR-RATE-003) reads
  `request.user` by default, which requires `WafMiddleware` to run after
  auth; `django_waf.W004` warns when it does not. From 1.8.0, the
  trusted-user cookie (`DJANGO_WAF_TRUSTED_COOKIE_ENABLED`) removes this
  dependency for sites that opt in, at the cost of a new signed,
  short-TTL, IP-bound cookie the WAF issues and trusts itself.
- **A feed-sourced allow rule is trusted only after forward-confirmed rDNS
  and, by default, operator review.** Feed-sourced `AllowRule`s require
  `verify_rdns=True` and are created `is_active=False` (quarantined) unless
  `DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES` is explicitly disabled
  (BR-FEED-008). This is the one place the package already implements
  approval-before-enforcement; section 4 covers where it does not.
- **Feed responses are not cryptographically signed.** A compromised or
  on-path-tampered feed (mitigated for HTTP by `django_waf.W005`, which
  warns when the feed URL is not HTTPS, but not eliminated) can inject or
  suppress `BlockRule`s up to the confidence and validation checks in
  BR-FEED-002/007. Signing is deferred to a separate service-side decision
  (tracked at `drystane/drystane.com#6`), out of this package's control.

---

## 4. Operator safety controls: what exists, what does not

The acceptance criteria for this issue ask whether automatic enforcement
retains evidence, confidence, TTL, and provenance, whether detectors
support observe-only rollout, and whether outcomes are exposed. As of the
approve-before-enforce cluster (#45/#46/#47/#48), checked against
`services/anomaly_detector.py`, `tasks.py`, and `views.py`, the schema and
the detectors are now aligned: every gap this document previously
identified is closed, gated behind two settings that default to the
pre-#45 behaviour for existing deployments.

### What exists today

- **The schema carries provenance, confidence, TTL, and review fields.**
  `BlockRule` has `source` (`admin`/`auto`/`feed`), `confidence`
  (`DecimalField`), `expires_at`, `hit_count`, `last_hit_at`, `notes`, and
  now `review_status`/`reviewed_at` (`models.py`, BR-ANOM-010). An
  auto-generated rule is tagged `source=auto` and expires after
  `DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS` (or the escalation-specific TTL for
  challenge-escalation blocks), so nothing an automatic detector creates is
  permanent by default (BR-LIFE-001).
- **A standing per-detector observe-only mode exists, distinct from
  dry-run.** `DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS` (BR-ANOM-008)
  names detector functions that always create a quarantined rule
  (`is_active=False`, `review_status=pending`) regardless of the
  package-wide quarantine setting, so an operator can build trust in one
  detector's output without quarantining every detector's rules. An
  unrecognised name is caught at boot by `django_waf.W008`, validated
  against `anomaly_detector.DETECTOR_NAMES`, the single source of truth
  also read by the quarantine decision itself, so a detector rename cannot
  silently desync the setting from the functions it names.
- **A package-wide quarantine setting exists.**
  `DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES` (BR-ANOM-007), default
  `False`, quarantines every newly-created auto-generated rule when set.
  The default is deliberately not a mirror of BR-FEED-008's equivalent
  (default `True`): every existing deployment already relies on an
  auto-generated rule enforcing immediately, and flipping this default
  would silently stop enforcement on upgrade with no code change on the
  consumer's side.
- **Auto-generated rules carry the evidence that triggered them.**
  `_get_or_create_auto_rule` now accepts `confidence` and `evidence`
  keyword arguments (BR-ANOM-009); every one of the five detectors passes
  its own per-detector confidence (computed by the shared
  `_scaled_confidence` helper from how far the observed value clears its
  threshold, floored at 0.50 and capped below 0.99) and the same evidence
  dict already built for the `anomaly_detected` signal, rendered into
  `notes` as one `key: value` line per entry. A reviewer on the dashboard's
  Anomalies panel sees the request counts, score, and window that
  triggered detection without cross-referencing logs.
- **Approve-before-enforce is a real queue, not enforce-then-review.**
  When quarantine or observe-only applies, a newly-created rule is
  `is_active=False` from the moment it is written: the rule engine's
  `active()` queryset excludes it, so it never challenges or blocks real
  traffic until a superuser confirms it via `DashboardAnomalyConfirmView`
  (which also activates it and sets `review_status=confirmed`) or rejects
  it via `DashboardAnomalyRejectView` (`review_status=rejected`). A later
  detector run matching the same rule can never silently undo either
  decision: the re-detection guard in `_get_or_create_auto_rule` omits
  `is_active`/`review_status` from the write once a rule is `confirmed` or
  `rejected`, refreshing only `expires_at`.
- **An outcome metric exists.** `anomaly_detector.auto_rule_review_outcomes`
  is a live `GROUP BY review_status` query over auto-generated rules in a
  configurable window (default 7 days), zero-filled across every
  `ReviewStatus` bucket, surfaced on the dashboard's Anomalies panel. A
  quarantined rule nobody reviews before it expires is caught by
  `expire_rules`' independent `review_status=pending` sweep (BR-ANOM-010),
  which does not rely on `BlockRuleManager.expired()`'s `is_active=True`
  filter, so it also catches a rule that was never activated.
- **A dry-run mode exists for manual detector invocation, unconditional
  and taking precedence over the two settings above.** From 1.7.0,
  `run_all_detectors(dry_run=True)` and the `django_waf_detect_anomalies
  --dry-run` command flag genuinely suppress every write (BR-ANOM-006).
  Per BR-ANOM-008, dry-run's no-writes contract is unconditional: it
  suppresses writes regardless of quarantine or observe-only status.
- **Log-only exists as an enum value the rule engine honours.**
  `RuleAction.LOG_ONLY` (`enums.py:13`) is a real, evaluated action for
  manually-authored `BlockRule`s (BR-BL-005 excludes it from the nginx
  export; the middleware still applies it at the application layer). This
  is distinct from observe-only: a `LOG_ONLY` rule is active and evaluated
  on every request; an observe-only detector's rule is not active at all.
- **The challenge solve rate remains a secondary proxy for false
  positives.** `IPReputationAdmin` (`admin.py`) computes
  `challenge_success_rate` (passes over total challenges) per IP. It still
  conflates "solved the PoW" with "was not a false positive", and a
  `BlockRule` block is never challenged at all, so `auto_rule_review_outcomes`
  above is the more direct signal for auto-generated rules specifically.

### What operators must still opt into

Both `DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES` and
`DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS` default to the pre-#45
enforce-then-review behaviour: an existing deployment sees no change in
enforcement until it sets one of them. Approve-before-enforce is available,
not automatic.

---

## 5. Summary position

django-waf is an in-process Django anti-abuse and bot-management system:
rate limiting, PoW challenges, IP/UA/CIDR rules, reputation scoring, an
opt-in collective threat feed, and a form-defence chain, all built and
verified against source. It is not a payload-inspecting firewall and has
no DDoS mitigation. Its automatic-enforcement detectors enforce
immediately by default, matching every deployment's behaviour before this
document's follow-on work, but an operator can now opt a detector, or every
detector, into approve-before-enforce (quarantine on creation, review via
the dashboard, an outcome metric, and per-detector observe-only), closing
the gap this document originally identified. Any positioning or sales
conversation should lead with what section 2 lists as built, describe the
approve-before-enforce controls in section 4 as opt-in rather than
standing behaviour, and treat "WAF" as the category label the market
searches for, not a literal capability claim this document cannot back up.
