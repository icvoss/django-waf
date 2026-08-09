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
support observe-only rollout, and whether outcomes are exposed. The honest
answer, checked against `services/anomaly_detector.py` as of this pass, is
partial: the schema already has the right shape, but the detectors that
populate it do not use most of it.

### What exists today

- **The schema already carries provenance, confidence, and TTL fields.**
  `BlockRule` has `source` (`admin`/`auto`/`feed`), `confidence`
  (`DecimalField`), `expires_at`, `hit_count`, `last_hit_at`, and `notes`
  (`models.py`). An auto-generated rule is tagged `source=auto` and expires
  after `DJANGO_WAF_AUTO_RULE_EXPIRY_HOURS` (or the escalation-specific TTL
  for challenge-escalation blocks), so nothing an automatic detector
  creates is permanent by default (BR-LIFE-001).
- **A review path exists, after the fact.** The staff dashboard's
  "Anomalies" panel (`views.DashboardAnomalyPanel`) lists auto-generated
  `BlockRule`s created in the last 48 hours; a superuser can confirm
  (promote to a permanent `source=admin` rule) or reject (deactivate) via
  `DashboardAnomalyConfirmView`/`DashboardAnomalyRejectView`
  (`views.py:611-656`). This is enforce-then-review, not
  approve-before-enforcement: the rule is already live (challenging or
  blocking real traffic) by the time a human sees it.
- **Log-only exists as an enum value the rule engine honours.**
  `RuleAction.LOG_ONLY` (`enums.py:13`) is a real, evaluated action for
  manually-authored `BlockRule`s (BR-BL-005 excludes it from the nginx
  export; the middleware still applies it at the application layer).
- **A dry-run mode exists for manual detector invocation.** From 1.7.0,
  `run_all_detectors(dry_run=True)` and the `django_waf_detect_anomalies
  --dry-run` command flag genuinely suppress every write (BR-ANOM-006).
  This is a per-invocation safety valve for an operator testing detector
  behaviour, not a standing configuration a detector runs under
  continuously.
- **The closest existing proxy for a false-positive signal is the
  challenge solve rate.** `IPReputationAdmin` (`admin.py:424-425`) computes
  `challenge_success_rate` (passes over total challenges) per IP. It is a
  proxy, not a purpose-built false-positive metric: it conflates "solved
  the PoW" with "was not a false positive", which are not the same claim
  for every verdict type (a `BlockRule` block, for instance, is never
  challenged at all, so it never contributes to this rate).

### What does not exist today (gaps this document surfaces, not fixes)

- **No detector runs in a standing observe-only mode.** Every anomaly
  detector hardcodes its action: `detect_ua_rotation`, `detect_subnet_burst`,
  and `detect_cloud_spray` create `action=RuleAction.CHALLENGE`
  (`anomaly_detector.py:76, 142, 455`); `detect_challenge_farms` and
  `detect_unsolved_challenges` create `action=RuleAction.BLOCK`
  (`anomaly_detector.py:196, 336`). Every one of these is created
  `is_active=True` (`anomaly_detector.py:614`), so
  it enforces from the moment it is written, before any human sees it. The
  `dry_run` flag above is the only way to run a detector without writing
  anything, and it is an all-or-nothing per-invocation switch, not a
  per-detector "log only, do not enforce" standing policy.
- **Auto-generated rules carry none of the evidence fields the schema
  already has room for.** `_get_or_create_auto_rule`'s `defaults` dict
  sets `name`, `match_type`, `is_active`, and `expires_at` only
  (`anomaly_detector.py:611-616`); it never sets `confidence` (so every
  auto rule silently inherits the model default, `1.00`, the same value a
  hand-authored admin rule would carry) and never sets `notes` (so the
  only human-readable evidence for why a rule fired lives in the rule's
  `name` string and a transient `anomaly_detected` signal payload that is
  not persisted anywhere a later reviewer can read). A reviewer looking at
  the dashboard's Anomalies panel sees a rule and a creation timestamp,
  not the request counts, score, or window that triggered it.
- **No aggregate outcome metric is exposed anywhere.** The dashboard shows
  today's verdict counts (`DashboardStatsPanel`) and top-blocked IPs
  (`DashboardTopBlockedPanel`), but nothing answers "of the rules an
  automatic detector created this week, how many were confirmed versus
  rejected versus left un-reviewed and simply expired". That number would
  be the honest false-positive proxy this package is missing.

### Follow-on work (tracked separately, not part of this documentation pass)

Per the triage plan for #36, closing the gaps above is implementation
work, scoped here and filed as separate issues so this documentation pass
does not silently expand into a feature build:

1. Give each detector an independent `dry_run`-equivalent standing mode
   (observe-only per detector, not only per manual invocation), so an
   operator can run detection with zero enforcement until they trust it.
2. Populate `confidence` and `notes` on every auto-generated rule with the
   evidence that triggered it (request counts, score, window), using the
   fields the schema already has.
3. Turn the dashboard's Anomalies panel into an approval queue for a
   configurable subset of detectors (quarantined like feed-sourced allow
   rules, BR-FEED-008, rather than enforce-then-review by default).
4. Add a confirmed/rejected/expired-unreviewed outcome metric, surfaced on
   the dashboard, as the real false-positive proxy this document
   identifies as missing.

---

## 5. Summary position

django-waf is an in-process Django anti-abuse and bot-management system:
rate limiting, PoW challenges, IP/UA/CIDR rules, reputation scoring, an
opt-in collective threat feed, and a form-defence chain, all built and
verified against source. It is not a payload-inspecting firewall, has no
DDoS mitigation, and its automatic-enforcement detectors currently act
before any human reviews them, with the review path itself running
after enforcement rather than before it. Any positioning or sales
conversation should lead with what section 2 lists as built, name the
gaps in section 4 rather than let a prospective buyer discover them, and
treat "WAF" as the category label the market searches for, not a literal
capability claim this document cannot back up.
