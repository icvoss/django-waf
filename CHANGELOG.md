# Changelog

All notable changes to django-waf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **A liveness probe for the Redis hit-count flush path** (#100, BR-LIFE-005).
  The companion to the detector probe shipped in 2.2.0, covering the
  subsystem that one cannot reach. `flush_rule_hit_counts` called Redis
  `GETDEL`, which needs 6.2+; production ran 6.0.16, every call raised into
  a bare except, and 40,936 scheduled task runs reported success while
  flushing nothing. The defect survived tests, review and release because
  `{"flushed": 0, "keys_seen": 0, "errors": 0}` is simultaneously the
  healthy result on a quiet site, the Redis-unreachable result, and what
  the bug produced. Zero against unknown traffic is ambiguous; zero against
  a counter the probe just wrote itself is not.

  `run_flush_probe()` (`services/flush_probe.py`) drives one hit end to end
  through the real producer (`rule_engine._record_rule_hit`) and the real
  consumer (`flush_rule_hit_counts`), then asserts it reached
  `BlockRule.hit_count`. It calls the real producer deliberately: the key
  literal `waf:rule_hits:` is duplicated with no shared constant between
  producer and consumer, so a probe hardcoding a third copy could not
  detect the two drifting apart. Ships with an hourly `probe_flush_path`
  task and beat entry, plus a `django_waf_probe_flush_path` management
  command that exits non-zero on a dead path, for a cron or k8s wrapper.

  Safe to run against a live site, which took work rather than luck.
  `flush_rule_hit_counts` scans `waf:rule_hits:*` and flushes every key it
  finds, so the probe's own run also sweeps up real counters, whose
  database updates would land inside the probe's rolled-back transaction
  while their Redis keys were deleted regardless. The probe therefore
  snapshots every other key first and restores each one afterwards, to
  Redis only and never to the row, leaving the count pending for the next
  scheduled flush. Restoring both double-counts, which an implementation of
  this probe did before review caught it: a real counter of 5 reached
  `hit_count = 10` after one probe run plus one flush.

- **A PEP 561 `py.typed` marker** (#108). The package has always been
  annotated but never advertised it, so a consumer type-checking its own
  code saw `Any` for everything imported from `django_waf`. Verified on the
  built wheel rather than the source tree: against the published 2.4.0
  wheel a consumer's mypy reports `import-untyped` and `Revealed type is
  "Any"`, and against this build it resolves the real signature.

- **A `typecheck` CI job** (#111), with mypy and django-stubs pinned
  exactly, as the `lint` job already pins ruff. mypy was configured with
  the django-stubs plugin and documented in the README, but no workflow ran
  it, so a type regression could reach `main` with every check green. The
  job asserts mypy analysed 80+ source files before trusting its exit
  status: without `PYTHONPATH=.` the plugin cannot resolve
  `django_settings_module = "tests.settings"` and mypy exits 2 having
  checked nothing at all, a no-op that reads as a pass when scripted.

### Fixed

- **`_deduplicate_block_rules` could raise `AttributeError` on a
  concurrent delete** (#111). It called `.pk` on the result of
  `qs.first()`, which is `None` if the queryset empties between the
  `qs.count() <= 1` guard and the fetch. Found by the mypy pass rather than
  in production; it now fetches once and returns early.

- **`verify_challenge_solution` accepted a `None` difficulty** (#111),
  passing it into the proof-of-work check rather than rejecting it. It now
  raises `ChallengeInvalidError`, since a difficulty that was never issued
  cannot be verified against.

### Changed

- mypy now reports zero errors across 86 source files, down from 31 in 19
  (#111). Third-party stub noise (`rest_framework.*`, `celery.*`,
  `django_redis.*`) is suppressed with a per-module override rather than a
  blanket `ignore_missing_imports`, which would also silence genuine
  missing-import findings in this package's own code.

## [2.4.0] - 2026-09-02

### Added

- **A sixth anomaly detector, `detect_scraper_404_ratio`, catches a
  residential-proxy scraping botnet that defeated every existing detector
  at once** (BR-ANOM-014). Traced against a live deployment (VendablyCSS,
  shopping.vendably.com, django-waf 2.1.0, three-day window): 10,874
  distinct IPs spread across roughly 9,700 distinct /24 subnets (about 1.1
  IPs per /24, mean 1.42 requests per IP) evaded `detect_subnet_burst`'s
  absolute floor (needs >= 30 requests per subnet) and
  `detect_unsolved_challenges`'s subnet path (needs >= 10 IPs per subnet).
  15,426 distinct User-Agent strings, one per request, meant no shared UA
  existed for `detect_cloud_spray` to group on, and its subnet path also
  needed at least 2 suspicious IPs sharing a subnet, which this shape
  almost never produced. All 15,378 of the botnet's requests scored
  exactly 3.50 (fingerprint-derived only; zero matched a suspicious path
  pattern), landing strictly between `DJANGO_WAF_SCORE_THRESHOLD_LOG`
  (2.5) and `DJANGO_WAF_SCORE_THRESHOLD_CHALLENGE` (5.0), so every request
  was `verdict=logged`, passed straight through to the application.

  The one signal that does separate the botnet from real traffic is the
  404 ratio. Filtering the same window to IPs with >= 20 requests and
  >= 85% of them 404 yielded 14 IPs, all confirmed scrapers, for example
  31.58.20.59 at 100% over 32 requests, 88.167.25.244 at 97% over 75, and
  103.59.160.242 at 92% over 115. A real browser does not sustain a
  ~100% 404 rate over dozens of requests: a human who hits a dead link
  navigates somewhere real, or gives up, long before reaching that
  volume. The requested paths were stale internal URLs (old
  category/merchant paths, with and without a trailing slash), i.e. a
  scrape working from an outdated link graph, not a vulnerability scan
  (which `DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS` already covers).

  Every IP the detector would flag against the production trace at its
  final defaults (window 1440 minutes, 20 requests, 0.85 ratio, verdicts
  `allowed`/`logged`) was individually verified by UA and requested paths:
  precision was 100%, with no legitimate user among them, across four
  shapes the other five detectors structurally miss:

  1. Webshell/backdoor hunters sending an EMPTY User-Agent string, for
     example 4.205.62.107 (446 requests, 100% 404, requesting `/agg.php`,
     `/cp2.php`, `/ebahvhhh.php`) and 158.23.18.78 (138 requests, 100%
     404, requesting `/inx.php`, `/file1221.php`, `/adminner.php`). These
     filenames are random per host, so no static path-pattern list
     (`DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS`) can ever enumerate them; the
     404 ratio catches them precisely because the filenames are guesses
     that, by definition, do not exist.
  2. A self-identifying exploit scanner, 103.59.160.242 (123 requests,
     96% 404), whose User-Agent is literally `xploit_probe`, requesting
     `/wp-admin/*` paths.
  3. Distributed scrapers hitting dead product URLs with a shared mobile
     UA, 114.119.148.27 (83 requests, 94% 404) and 114.119.137.80 (56
     requests, 100% 404), both classified `fingerprint_verdict=suspicious`
     on every row.
  4. A spoofed Googlebot, 45.45.237.69 (27 requests, 89% 404), sending the
     genuine Googlebot User-Agent string
     (`Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)`)
     and classified `fingerprint_verdict=browser` on every row. This IP is
     outside Google's published ranges, so it fails the forward-confirmed
     reverse-DNS (FCrDNS) check the seeded Googlebot `AllowRule` requires
     (`verify_rdns=True`, `rule_engine._check_allow_rules` /
     `_verify_rdns`); it therefore never matches the AllowRule and never
     gets `verdict=passed`, unlike the genuine Googlebot IPs (66.249.x)
     in the same trace. This is the sharpest argument for excluding
     `passed` on AllowRule grounds rather than on UA or IP shape: a UA
     match cannot distinguish this impostor from the real crawler (the
     UA string is identical), an IP/CIDR rule cannot either (the
     impostor's address is not stable across a botnet), and the
     fingerprint scorer does not catch it (it presents as a browser on
     every row). Only "did this client actually earn an AllowRule match"
     separates them, which is exactly what excluding non-`passed`
     traffic tests. The empty-UA cases in point 1 show the same property
     from the other direction: this detector still catches a scraper
     when every UA-derived signal (`detect_cloud_spray`'s UA path,
     `detect_ua_rotation`) is entirely absent, because it never looks at
     the UA at all.

  Verdict scoping is the correctness-critical part of this detector, and
  it was proven, not assumed: a request the WAF itself blocked,
  challenged, or throttled never reaches a view (`middleware.py`'s
  `_handle_verdict` returns a `HttpResponseForbidden`/429/redirect for
  those verdicts without ever calling `_get_response`), so its
  `response_code` reflects what the WAF returned, not a genuine 404 the
  application produced; production data confirms this, blocked,
  challenged, and throttled rows show exactly 0.0% 404 in the trace,
  because none of them ever reached a view. Only rows whose verdict shows
  the request reached the application (`allowed`, `logged`) are counted,
  in both the numerator and the denominator; a WAF-produced verdict can
  never dilute or inflate an IP's ratio.

  `passed` (an AllowRule match) is excluded, and this was measured, not
  assumed: over an identical 180-minute window at the default
  20-request/85%-ratio gate, excluding `passed` traffic flagged zero IPs;
  including it flagged 10, every one a verified Bingbot IP, for example
  40.77.167.132 (34 requests, 100% 404) and 207.46.13.156 (25 requests,
  100% 404), re-crawling roughly 14,897 dead URLs still present in its own
  historical index (one URL was hit 478 times in three days), a
  stale-sitemap/HTTP 410 gap on the site's side, not malicious behaviour.
  Including `passed` would have made this detector auto-challenge (or,
  with `DJANGO_WAF_SCRAPER_404_ACTION_BLOCK=True`, auto-block) Bingbot,
  risking delisting. The exclusion is applied on exactly the same
  "AllowRules win" precedence the rule engine already applies at its step
  4, ahead of every BlockRule: this detector only ever creates a new
  `(rule_type=ip, source=auto)` BlockRule and can neither touch nor take
  precedence over an existing AllowRule, so excluding `passed` traffic
  from the count is what keeps a verified crawler out of this detector's
  results entirely, rather than relying on a rule that would never fire
  anyway. Point 4 above (the spoofed Googlebot) is the same property from
  the other direction: excluding `passed` protects the real crawler
  without also protecting an impostor presenting the identical UA string
  but never earning the AllowRule match.

  A qualifying IP is created at `RuleAction.CHALLENGE` by default,
  promoted to `RuleAction.BLOCK` only when
  `DJANGO_WAF_SCRAPER_404_ACTION_BLOCK` is `True`. A 404 ratio is
  behavioural, not proof of malice on its own (a broken external link
  farm or a stale sitemap could in principle produce a similar shape),
  so this follows the same staging precedent as `detect_cloud_spray`'s
  UA path (issue #82): a coarse aggregate signal stages at CHALLENGE by
  default.

- `DJANGO_WAF_SCRAPER_404_MIN_REQUESTS` (default `20`). Minimum request
  count an IP must reach within the window before its 404 ratio is
  considered at all.

- `DJANGO_WAF_SCRAPER_404_RATIO` (default `0.85`). Fraction of an IP's
  application-reaching requests that must be 404 before it is flagged.

- `DJANGO_WAF_SCRAPER_404_WINDOW_MINUTES` (default `1440`, 24 hours).
  Deliberately wide, on the same precedent as
  `DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES` (360, #93): a detector whose
  attacker spreads volume thinly over time needs its own wider window, or
  the count/ratio thresholds are never reachable regardless of tuning.
  Simulated live against the traced deployment, sweeping window x
  `DJANGO_WAF_SCRAPER_404_MIN_REQUESTS` at the default 0.85 ratio,
  counting flagged IPs:

  ```
  window   180m: minreq 10 ->  0, 15 ->  0, 20 ->  0, 30 ->  0
  window   360m: minreq 10 ->  3, 15 ->  2, 20 ->  1, 30 ->  1
  window   720m: minreq 10 ->  4, 15 ->  3, 20 ->  3, 30 ->  2
  window  1440m: minreq 10 -> 13, 15 -> 10, 20 ->  8, 30 ->  7
  ```

  At 180 minutes the detector caught nothing at all: this cohort's mean of
  1.42 requests per IP over the full three-day trace means no individual
  IP accumulates enough volume inside 3 hours to clear even the lowest
  swept `min_requests`. 1440 minutes is the smallest swept window at
  which the default `DJANGO_WAF_SCRAPER_404_MIN_REQUESTS=20` catches a
  materially non-trivial, confirmed-scraper population (8 IPs), so it is
  the default rather than a threshold change: the window, not the
  count/ratio thresholds, was the wrong knob, exactly as it was for #93.

- `DJANGO_WAF_SCRAPER_404_ACTION_BLOCK` (default `False`). When `True`,
  a qualifying IP is created at `RuleAction.BLOCK` instead of
  `RuleAction.CHALLENGE`.

  **Upgrading**: no change to existing detection behaviour. This is a new,
  additive detector; `run_all_detectors` and the `detect_anomalies` Celery
  task now also run it, and their result dict gains a `scraper_404_rules`
  key alongside the five existing ones.

## [2.3.0] - 2026-09-01

### Fixed

- **`BlockRule.detectors` field default restored to match its own migration**
  (#105, #107, closes #115). The `v2.2.0` tag was cut roughly 76 minutes
  before #107 merged to `main`, so the published 2.2.0 wheel still carried
  the pre-fix `models.py`: the `detectors` field had no `default=""` while
  migration `0006_blockrule_detectors.py` already recorded one. Every
  consumer who installed `django-waf==2.2.0` and ran
  `manage.py makemigrations --check --dry-run`, a standard merge-blocking CI
  gate, got a spurious `AlterField` diff for a field inside an installed
  package, with no local remedy: the migration that would settle it has to
  live in the package. Fixed on the model side rather than with a new
  `AlterField` migration, since the migration graph already records
  `default=""` and only `deconstruct()`, never DDL, differed between the two.

  **Upgrading from 2.2.0**: the `makemigrations --check` drift disappears on
  upgrade to this release; no new migration runs and no data is affected.
  If you added a local workaround (an `AlterField` migration of your own, or
  an exclusion for `django_waf` in your CI's drift check), it can be
  removed.

### Added

- **The test suite now runs against real PostgreSQL in CI** (#72). Every
  one of the 1245 tests ran on sqlite in-memory, which is materially more
  permissive than the PostgreSQL consumers deploy on: it does not
  validate `GenericIPAddressField` values on write, and it differs on
  constraint and transaction behaviour. Any `bulk_create` or
  field-validation claim was therefore unverifiable against a real
  deployment, and a regression test for that class of defect would pass
  whether or not the defect was fixed.

  A dedicated `test-postgres` CI leg now runs the full suite against
  PostgreSQL 16. `tests/settings.py` selects the backend from
  `DJANGO_WAF_TEST_DB`, defaulting to sqlite so a local run needs no
  database server and nothing changes for existing contributors.

  This immediately surfaced two tests that had passed on sqlite for their
  whole life by inserting `999.999.999.999` into `RequestLog.ip_address`
  to exercise a `ValueError` guard. PostgreSQL's `inet` type rejects that
  at insert, so both the precondition and the guard it was proving are
  unreachable there via that column. The guards are kept, since a sqlite
  deployment can still reach them, and both tests are now skipped on any
  backend that cannot construct their precondition rather than passing
  against a state production cannot produce.


- **Cloud-spray detection catches diffuse residential-proxy botnets**
  (#68, #69, BR-ANOM-002b). `detect_cloud_spray` grouped on two keys the
  attacker controls, which left the detector purpose-built for
  distributed spray largely inert against it. It groups by exact
  user-agent string, so rotating a pool of UAs divides each bucket's
  distinct-IP count; and its subnet aggregation required at least 2
  suspicious IPs per /24, which assumes cloud-contiguous allocation.
  Measured live: one UA shared by 217 distinct IPs occupied 216 distinct
  subnets, so 215 of 216 were discarded and the detector created zero
  rules against the flood it exists to catch. Raising the log sample rate
  was investigated and ruled out as the cause; the signal is present in
  the retained rows and the grouping discards it.

  A second, opt-in rule path now keys on the user agent itself once it
  alone clears `DJANGO_WAF_CLOUD_SPRAY_MIN_IPS` distinct suspicious IPs,
  independent of how those IPs distribute across subnets. The subnet path
  and its 2-IP floor are unchanged.

- `DJANGO_WAF_CLOUD_SPRAY_UA_RULE` (default `False`). Enables the UA path
  above. Off by default: a user agent shared by many IPs has legitimate
  causes (a corporate NAT, a carrier CGNAT range, a popular app's
  embedded webview), so no existing consumer's enforcement behaviour
  changes on upgrade. Rules from this path are created with
  `action=challenge` and never `block`, because a shared UA is a coarse
  signal: a production measurement over 1,544,473 requests put the
  false-positive floor for acting on it at no less than 35.6% real users,
  including genuine Bingbot and Applebot. CHALLENGE rules are excluded
  from `for_nginx()`, so these rules are enforced by `WafMiddleware`
  only and the matched user-agent string never reaches a rendered nginx
  configuration.

- `DJANGO_WAF_CLOUD_SPRAY_TOP_N` (default 5). Replaces a hardcoded cap on
  how many spray user agents a single run inspects. The previous
  hardcoded limit silently discarded the long tail of exactly the
  rotated-UA pool the detector is meant to catch.

  **Upgrading from 2.2.0**: no change to detection behaviour unless you set
  `DJANGO_WAF_CLOUD_SPRAY_UA_RULE = True`, since it defaults off. If you do
  enable it, `detect_cloud_spray` gains a second, independent rule path
  that can create CHALLENGE (never BLOCK) rules keyed on a shared user
  agent alone; the existing subnet-based path and its behaviour are
  unchanged. `DJANGO_WAF_CLOUD_SPRAY_TOP_N` (default 5) now governs how
  many spray user agents a run inspects, replacing a previous hardcoded
  cap of the same value, so a default deployment sees no change there
  either.

## [2.2.0] - 2026-08-29

### Added

- **Detector liveness probe** (BR-ANOM-012). Three defects this cycle (a
  `getdel` call reporting success 40,936 times while doing nothing, the
  2.0.0 subnet detector producing 0 rules for 13 hours, and #97's staging
  skip) all passed tests, review and release. A scheduled probe asserting
  the detectors still produce rules would have caught each within the
  hour. `services.detector_probe.run_detector_probe()` builds synthetic
  fixture traffic, shaped to provably cross every anomaly detector's own
  configured threshold using RFC 5737 TEST-NET IP ranges, and reports
  which detectors did (and did not) produce a rule against it. Real
  recent traffic cannot be used for this: `run_all_detectors` returning
  zero is the normal, healthy result on a quiet site, indistinguishable
  from a dead detector. Everything runs inside a transaction that is
  unconditionally rolled back, so no synthetic row is ever committed. New
  `probe_detectors` Celery task (hourly) and `django_waf_probe_detectors`
  management command (`--exercise-writes` for the opt-in real-write mode;
  exits non-zero on a silent detector, for cron wrappers and k8s liveness
  probes). No environment guard gates this probe, on the same principle
  as #97's fix: a check silently inert in one environment is the next
  regression, not a safety net for it. A dead Celery Beat entry for this
  task produces no log line at all; consumers must alert on the absence
  of the hourly log line, not only on its content, since this package
  stays stateless and does not persist a last-run timestamp.

- `django_waf.E006`: a new system check that errors when
  `DJANGO_WAF_ENABLED = True` but `WafMiddleware` (or a subclass of it,
  matched by class name) is absent from `MIDDLEWARE` entirely (#101).
  `django_waf.W004` only ever warns about ordering once `WafMiddleware`
  is found in `MIDDLEWARE`; nothing previously checked for its outright
  absence. A brickworkui.com production deployment had `django_waf`
  installed and `DJANGO_WAF_ENABLED = True` with no `WafMiddleware` in
  `MIDDLEWARE` for its entire deployed life, and `manage.py check` passed
  throughout: the WAF inspected no traffic at all while reporting a clean
  bill of health. This is an Error, matching `django_waf.E004`'s
  rationale: a security control that reports healthy while blocking
  nothing is worse than one that refuses to start.


### Fixed

- **`django_waf.conf` now resolves every `DJANGO_WAF_*` setting at call
  time instead of freezing it at import time** (closes #75). Every one of
  the 92 settings was previously a module-level constant computed once
  from `getattr(settings, "DJANGO_WAF_X", default)` when `conf.py` first
  imported, despite the module's own docstring promising call-time
  resolution. In practice this meant `override_settings` and the pytest
  `settings` fixture silently had no effect on WAF behaviour, and any
  consuming project whose own settings module touched `django_waf.conf`
  during settings execution froze every constant at the package default
  for the rest of the process. This was observed live: a site whose
  `settings.DJANGO_WAF_ENABLED` was `False` still ran with the WAF
  enabled, against the wrong Redis alias, because `conf.py` had imported
  earlier in the settings module with the package defaults still in
  effect. Every `DJANGO_WAF_*` name is now a private resolver function
  behind a PEP 562 module `__getattr__`, so `conf.DJANGO_WAF_X` always
  reflects the current `django.conf.settings` value.

  **This is consumer-visible if your test suite relied on the WAF
  ignoring `override_settings` or the pytest `settings` fixture.** A test
  that sets `DJANGO_WAF_ENABLED = False` (by either mechanism) expecting
  the WAF to keep running regardless will now see it actually disabled;
  the same applies to every other `DJANGO_WAF_*` setting. If your suite
  worked around the old defect with `importlib.reload(django_waf.conf)`,
  that reload is now a harmless no-op and can be removed.

  `DJANGO_WAF_SITE_PASSWORD_ENABLED`'s derived default (`bool(DJANGO_WAF_SITE_PASSWORD)`,
  the one intra-conf cross-reference among all 92 settings) now recurses
  through the resolver for `DJANGO_WAF_SITE_PASSWORD` rather than reading
  a value frozen at import time, so BR-SP-002's fail-closed guarantee
  (gate enabled, no password, deny every request) holds correctly when
  the password is set or cleared after the process started.

  `DJANGO_WAF_CELERY_BEAT_SCHEDULE` (and every other setting) resolves to
  its documented default rather than raising `ImproperlyConfigured` when
  `django.conf.settings` is not yet configured, which is what keeps the
  README's documented consumer pattern, importing it directly from
  inside a consuming project's own `settings.py` before that module has
  finished running, safe.

  `django_waf.services.blocklist_generator._activate_candidate` and
  `_validate_nginx_config` now read `DJANGO_WAF_NGINX_VALIDATE` and
  `DJANGO_WAF_NGINX_TEST_COMMAND` from `django_waf.conf` instead of
  duplicating their own `getattr(django.conf.settings, ...)` reads and
  defaults. `django_waf.urls` now reads `DJANGO_WAF_API_ENABLED` from
  `django_waf.conf` instead of `django.conf.settings` directly; the
  urlconf-import-time caveat this read carried (the mount decision is
  still made once, at first URL dispatch for the whole process, not
  re-evaluated per request) is unchanged and still documented in the
  module docstring.

- **`disable_waf` (the public `django_waf.testing.fixtures` pytest
  fixture) no longer patches `django_waf.conf` directly.** It now sets
  `settings.DJANGO_WAF_ENABLED = False` via the pytest `settings`
  fixture. **Consumer-visible**: the fixture's signature changed from
  `disable_waf(monkeypatch)` to `disable_waf(settings)`; a project that
  depended on the exact patched object (rather than only on the WAF being
  disabled for the duration of the test) should review its own tests.
  This also removes a genuine hazard the old implementation carried:
  `monkeypatch.setattr` restores a patched module attribute by calling
  `setattr` with the pre-patch value on teardown, which, unlike
  `unittest.mock.patch.object`'s `delattr`-based restore, would have
  permanently shadowed live resolution in `django_waf.conf` for the rest
  of the process once that module stopped freezing values at import
  time.

- `django_waf.E003` (the site-password gate, BR-SP-002), `django_waf.E001`,
  `django_waf.E002`, `django_waf.W001`, `django_waf.W002` (challenge
  difficulty), and `django_waf.W004` (middleware ordering) no longer fire
  when `DJANGO_WAF_ENABLED = False` (#95). Every feature these checks
  protect is dead at runtime when the master switch is off, so a
  misconfiguration behind it was never a live lockout, only a boot-time
  false positive. E003 mattered most: as an Error it aborted
  `manage.py check` outright, and consumers personal-site and JOBU hit
  this exact failure under a `LocMemCache` settings profile. This closes
  the same class of defect `django_waf.E004` was fixed for in 2.0.0 (#67,
  #92), for the checks that fix missed.
  `django_waf.W006` (trusted-cookie trust level) is unchanged, and
  deliberately not gated: it warns behind its own explicit opt-in flag
  (`DJANGO_WAF_TRUSTED_COOKIE_ENABLED`) and, as a Warning, cannot abort
  `manage.py check`. `django_waf.W005`, `django_waf.W007`, and
  `django_waf.W008` are also unchanged: the features they cover (threat-feed
  sync, the anomaly detectors) run on independent Celery schedules, not the
  request path the master switch gates.

- **`detect_unsolved_challenges`'s subnet staging could not reach its own
  CHALLENGE stage on a default deployment** (closes #97). The detector's
  two-stage promotion (a first crossing of a subnet creates a CHALLENGE
  rule; only a repeat crossing promotes to BLOCK) checked for a prior
  active CHALLENGE rule by rule shape alone, not by which detector created
  it. `detect_subnet_burst` and `detect_cloud_spray` both run by default
  and both create AUTO/CIDR/CHALLENGE rules for the same subnet pattern,
  so their rules were counted as `detect_unsolved_challenges`'s own prior
  crossing: measured live, 9 of 10 subnet rules from this detector were
  promoted straight to BLOCK instead of staging through CHALLENGE first.
  This defeated the staging that exists specifically as a false-positive
  control: issue #82 measured that blocking on this signal without
  staging would have caught at least 35.6% real users, including genuine
  Bingbot and Applebot, on the deployment it was measured against. A
  subnet's two-stage promotion now recognises only a CHALLENGE rule
  `detect_unsolved_challenges` itself created; another detector reaching
  the same conclusion about a subnet no longer accelerates this
  detector's own promotion to BLOCK.

  **Migration note**: this fix adds a new field, `BlockRule.detectors`
  (migration `0006_blockrule_detectors`), recording which detector(s)
  created or refreshed an auto-generated rule. It is a set, not a single
  value: several detectors can independently target the same rule (most
  commonly a shared subnet pattern), and a rule created by one detector
  and later touched by another carries both names, never overwriting one
  with the other. This is what lets `detect_unsolved_challenges`
  recognise its own prior CHALLENGE rule even after a different detector
  has since refreshed the same row. Existing rows backfill to blank.
  Practical effect: for a subnet whose CHALLENGE rule already existed
  before you upgrade, `detect_unsolved_challenges`'s next run against
  that subnet will not recognise its own prior rule (since the backfilled
  value cannot say who created it) and will create or refresh a CHALLENGE
  rule again rather than promoting to BLOCK. This costs at most one extra
  CHALLENGE stage per pre-existing subnet rule, once, and is intentional:
  it fails safe toward the less disruptive action, consistent with the
  discipline this fix restores.

### Removed

- `tests/conftest.py`'s `_reset_conf_module` autouse fixture and every
  `importlib.reload(django_waf.conf)` call across the test suite (55
  sites): both were workarounds for the import-time-snapshot defect
  above and are no longer needed now that `conf.py` resolves live.

## [2.1.0] - 2026-08-29

No breaking API changes and no migration in this release, unlike 2.0.0. If
you are upgrading from 2.0.0, read the first two Fixed entries before
anything else: the subnet detection 2.0.0 shipped did not run, and a
settings profile with the WAF switched off may currently fail to boot.

### Added

- `DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT` setting (default
  30): the absolute minimum request count a /24 (or /48 for IPv6) subnet
  must reach within the detection window before `detect_subnet_burst` can
  flag it, in addition to the existing 3x-ratio check (now against the
  median rather than the mean; see Security below). An operator who has
  not tuned this detector sees the same behaviour as before for any
  subnet whose burst was already a clear outlier against a small,
  mostly-uniform population; the change in outcome is specifically for
  the self-inflating-mean pattern this fixes, which the old threshold
  could never have caught.
- **`detect_unsolved_challenges` was starved of candidates by an attacker
  spreading traffic across a subnet** (closes #84). Traced against a live
  deployment: an attacker rotating roughly 120 addresses per /24 leaves
  almost no individual IP reaching the challenge-count threshold within
  the detection window, even though the subnet in aggregate abandoned
  3,232 challenges from 120 distinct IPs in one hour, and 15,667 over
  seven days (1,616 solved, zero failed: the counted signal is
  abandonment, not failure). The detector now runs a parallel
  subnet-grain aggregation alongside the existing per-IP one: a /24 (or
  /48 for IPv6) whose total challenged-verdict count and number of
  distinct contributing IPs both clear a configurable threshold is
  treated as a candidate even when no individual IP within it ever
  reaches the per-IP threshold (only 6 IPs reached it in the traced hour,
  and 3 of those were exempted by a past solve). The distinct-IP
  requirement is independent of the total count, so one noisy host can
  never escalate its neighbours by itself. A first subnet-level crossing
  creates a CHALLENGE rule; only a repeat crossing of the same subnet,
  detected against an already-active auto-generated CHALLENGE rule,
  promotes it to BLOCK. Abandonment has legitimate causes (a real user
  closing the tab or blocking JavaScript looks identical to a bot at this
  signal), so a subnet is never blocked on a single crossing. Five new
  settings, listed below, cover both the per-IP and subnet thresholds.
- **The solved-challenge exemption had no time bound.** `solved_ips`
  exempted an IP from this detector permanently after a single solved
  challenge at any point in its history. Traced live, this removed half
  of the candidates that otherwise met every other signal. The exemption
  is now scoped to `DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS`
  (default 24 hours); the same bound applies to the new subnet path, so an
  occasional solve from a rotating pool of addresses cannot grant a whole
  subnet permanent immunity either.
- `DJANGO_WAF_UNSOLVED_MIN_CHALLENGED`, `DJANGO_WAF_UNSOLVED_REFERER_RATIO`,
  `DJANGO_WAF_UNSOLVED_SOLVE_EXEMPTION_WINDOW_HOURS`,
  `DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED`, and
  `DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS` settings for tuning
  `detect_unsolved_challenges`, matching every other detector threshold in
  the package. The two existing thresholds were previously only reachable
  as function-parameter defaults; an operator can now tune all five
  without calling the detector directly. `min_challenged` and
  `referer_ratio` remain accepted keyword arguments on
  `detect_unsolved_challenges` and default to the new settings, so
  existing callers and the dry-run management command are unaffected.
- `DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES` setting (default 360): the
  time window, in minutes, the subnet path of `detect_unsolved_challenges`
  aggregates over, independent of the per-IP path's `window_minutes`. See
  the first Fixed entry below for why this exists. `detect_unsolved_challenges`
  also accepts a new `subnet_window_minutes` keyword argument, defaulting
  to this setting, matching how the other five subnet-tuning settings
  above are already exposed as overridable parameters.
- **`POST /waf/verify/` had no rate limit of its own** (closes #81). Each
  solve attempt costs a signature check and Redis work, so it was a cheap
  way to consume server resources at any submission rate a client could
  sustain. `DJANGO_WAF_RATE_LIMIT_PATHS` cannot cover this endpoint: the
  challenge and verify paths are typically listed in
  `DJANGO_WAF_EXEMPT_PATHS` so a challenged user can always reach them,
  and the middleware returns on that exempt-path match before its rate
  limiter ever runs. `VerifyView` now checks a dedicated, independent
  limit before doing any signature or proof-of-work verification work. A
  breach returns 429 with an accurate `Retry-After`, matching the
  existing throttle response shape, rather than blocking: the default
  (20 solves per 5 minutes per IP, via `DJANGO_WAF_VERIFY_RATE_LIMIT_MAX`
  and `DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS`) sits comfortably
  above the 2 to 3 round trips a real client needs and above a NAT
  gateway or corporate proxy serving several simultaneous solvers.
  Fail-open is unchanged (BR-EVAL-007): a rate-limiter Redis error never
  blocks a legitimate user from clearing a challenge.
- `DJANGO_WAF_VERIFY_RATE_LIMIT_MAX` (default 20) and
  `DJANGO_WAF_VERIFY_RATE_LIMIT_WINDOW_SECONDS` (default 300) settings
  governing the new `POST /waf/verify/` rate limit above.

### Fixed

- **On 2.0.0, the subnet detection added to `detect_unsolved_challenges`
  above produced zero rules in 13 hours in production, because its window
  and thresholds were calibrated against different timescales** (closes
  #93). The subnet path shared the per-IP path's hardcoded 60-minute
  window, but the subnet thresholds
  (`DJANGO_WAF_UNSOLVED_SUBNET_MIN_CHALLENGED` and
  `DJANGO_WAF_UNSOLVED_SUBNET_MIN_IPS`) were calibrated against a
  seven-day aggregate, so a deliberately slow-drip attacker never
  produced enough volume in any single hour to clear either threshold.
  Measured live, holding the thresholds constant and varying only the
  window: 60 minutes catches 0 qualifying subnets, 180 minutes catches 2,
  360 minutes catches 10. The subnet path now runs on its own,
  independently configurable window
  (`DJANGO_WAF_UNSOLVED_SUBNET_WINDOW_MINUTES`, default 360), decoupled
  from the per-IP path's `window_minutes`, which stays at 60 minutes,
  unchanged, and keeps producing correct BLOCK rules in production. The
  thresholds themselves are unchanged; at a 360-minute window they already
  catch every subnet clearing the distinct-IP floor. **Without this fix,
  the subnet detection 2.0.0 shipped does nothing**, which is why this
  release matters most to anyone upgrading from 2.0.0.
- **`django_waf.E004` no longer fires when the WAF is switched off**
  (closes #67). The check errored whenever `DJANGO_WAF_REDIS_ALIAS` was
  not a django-redis backend, regardless of `DJANGO_WAF_ENABLED`, so any
  settings profile that disables the WAF and uses a plain cache (a test
  or CI profile on LocMemCache, typically) could not run `manage.py
  check` at all: the Error aborts the command. A project that has
  switched the feature off is not misconfigured for it. `django_waf.E005`
  already guarded this way, and its own test cited #67 as the mistake not
  to repeat, but E004 itself had no test of any kind, which is why the
  defect survived. It now has three, including one that fails without the
  guard. This may currently be blocking a settings profile you have not
  tried yet, and affects any consumer upgrading from before 1.8.1, where
  E004 was introduced.
- **`ChallengeTokenFactory` could produce a solved token with no solve
  timestamp, a state production never writes.** `challenge_service.py`
  unconditionally sets `solved_at` on the solve path, so every genuinely
  solved token has one, but the factory hardcoded `solved_at = None`
  regardless of the `status` passed in (closes #86). This is shipped
  package API (`django_waf.testing.factories`), so a consuming project's
  tests inherit it: a consuming project's own tests that build a solved
  `ChallengeToken` via `ChallengeTokenFactory` will now get a realistic
  `solved_at` timestamp derived from `status` without having to pass one
  explicitly. A consumer test that (incorrectly) relied on a solved
  token's `solved_at` being `None` will start failing, correctly: fix the
  assertion to match what production actually writes, or pass
  `solved_at=None` explicitly if the inconsistent object is genuinely
  what the test needs, which still overrides the derived value.
  `PENDING`, `EXPIRED`, and `FAILED` were already correct (`solved_at`
  stays `None` on every path but the solve path) and are unchanged. Two
  tests in `tests/test_services.py` (added by #87) pass an explicit
  `solved_at=now` that duplicates what the factory now derives on its own;
  left as-is rather than churned, since they are otherwise unaffected by
  this fix.
- **`_invalidate_rule_cache` could never distinguish a django-redis
  connection from the plain Django cache API, so the fallback path it
  guarded against was dead code.** It chose its code path with
  `hasattr(conn, "incr")`, but every Django cache backend implements
  `incr`, so the probe could never tell a django-redis connection (whose
  native `INCR` auto-creates a missing key) apart from the plain Django
  cache API (whose `incr()` raises on a missing key). On any non-Redis
  deployment, the first cache-version bump silently failed. It now
  branches on provenance instead.

### Security

- **`detect_subnet_burst`'s threshold was raised by the very botnet it
  measures** (closes #80). The burst threshold was 3x the arithmetic mean
  of the window's own per-subnet request counts. A botnet spread across
  several adjacent /24s at a similar low volume raised that mean with
  every additional prefix it occupied, so the wider the spread, the safer
  every subnet in it became. Traced in production: a cohort sustaining
  roughly 1.2 requests/hour per prefix across several adjacent /24 and
  /25 blocks was never flagged for a month. The ratio now compares
  against the MEDIAN, which a large low-volume cohort cannot move nearly
  as easily, and a new absolute floor,
  `DJANGO_WAF_ANOMALY_THRESHOLD_SUBNET_BURST_MIN_COUNT` (default 30),
  gates detection independently of the window's own population: adding
  more attacker-controlled subnets at the same volume can no longer
  reduce detection for any of them. Either condition alone flags, and the
  floor is the actual guarantee, because it is read from settings and
  never derived from the measured population. `detect_subnet_burst`
  continues to create CHALLENGE rules on first detection, never BLOCK,
  unchanged.

## [2.0.0] - 2026-08-28

### Security

- **Challenge escalation never fired against a JS-executing botnet that
  solves its own proof-of-work.** `_get_unsolved_challenge_count` cleared
  the `waf:challenged:{ip}` counter to 0 whenever `waf:solved:{ip}` was
  set, with no check on whether the solve came from a genuine browser.
  Verified in production: a rotating-UA datacentre botnet (~37,700
  events, ~3,044 CHALLENGED verdicts) produced zero blocks, because it
  solved SHA-256 hashcash at negligible cost on datacentre CPUs and every
  solve reset its counter before the escalation threshold was ever
  reached. The counter now clears on a solve only when the request's HTTP
  fingerprint (BR-FP-001) does not classify as "bot"; a bot-classified
  fingerprint's challenges count towards
  `DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD` regardless of solve status.
  Fail-open is unchanged (BR-EVAL-007): a Redis failure still passes the
  request through, now logged as before.

- **Escalation could silently resurrect a rule an operator had rejected.**
  `_create_escalation_rule` called `BlockRule.objects.update_or_create`
  directly, bypassing the read-before-write CONFIRMED/REJECTED guard
  (`anomaly_detector._update_or_create_auto_rule`, BR-ANOM-007) every
  other auto-rule creation path already goes through. An operator who
  rejected an auto-generated rule for a given `(rule_type, pattern,
  source=AUTO, action)` key could see escalation recreate it as an active
  BLOCK the next time the same IP crossed the challenge threshold.
  Escalation now calls the same guarded `_get_or_create_auto_rule` path
  the anomaly detectors use, so a CONFIRMED or REJECTED review decision is
  never overwritten.

### Changed

- **BREAKING: auto-detected rules now escalate to an enforced nginx
  block on repeat detection, where they previously stayed
  challenge-only forever.** `detect_ua_rotation`, `detect_subnet_burst`,
  and `detect_cloud_spray` still create CHALLENGE rules on first
  detection, unchanged; that trigger stays deliberately weak (a
  mean-times-3 threshold) and challenge-only is still the right first
  response. What changes is what happens next: because the escalation
  fix above makes `DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD` reachable
  for a bot-classified IP for the first time, an IP that keeps getting
  challenged by one of these detectors' rules and keeps presenting a
  bot fingerprint will now cross the threshold and be promoted to a
  persistent auto BLOCK rule, exactly as `DJANGO_WAF_ESCALATION_BLOCK_TTL`
  and BR-CHAL-010 always specified. BlockRule.objects.for_nginx() already
  exports BLOCK rules, so **on upgrade, an existing deployment will begin
  auto-blocking, at the nginx edge, repeat offenders that previously only
  ever received a JS challenge and were never blocked.** This is an
  enforcement change on upgrade, not an opt-in: there is no flag to
  restore the previous (permanently challenge-only) behaviour, only the
  pre-existing `DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES` /
  `DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS` review knobs (BR-ANOM-007,
  BR-ANOM-008), which apply exactly as they already did to every other
  auto-generated rule. `for_nginx()`'s own docstring and
  `blocklist_generator.py`'s module docstring now document that a
  CHALLENGE rule is middleware-only and never reaches nginx, since nginx
  cannot serve or verify a JS proof-of-work; this was previously
  undocumented.

### Added

- **Django 6.1 added to the CI test matrix** and declared via the
  `Framework :: Django :: 6.1` classifier.

- **`django_waf.E005`: a boot-time check for the connected Redis server's
  version.** `django_waf.services.redis_client.MIN_REDIS_VERSION` (6.0) is
  now the package's single declared floor, read via `INFO` and compared at
  `manage.py check` time. Guarded exactly like `django_waf.E004`: silent
  when the WAF is disabled, when the configured cache alias is not even a
  django-redis backend, or when a live version cannot be read, so it never
  repeats the mistake `django_waf.E004` made in #67 (firing under
  `DJANGO_WAF_ENABLED = False`). Only a reachable, correctly configured
  server reporting an unsupported version raises an Error.

### Fixed

- **`flush_rule_hit_counts` silently flushed nothing on Redis older than
  6.2 (#78).** The task called `redis_client.getdel(key)`, which requires
  Redis 6.2+; on a 6.0/6.1 server every call raised `ResponseError`,
  caught by a bare `except Exception: continue`, so every `BlockRule`'s
  `hit_count` stayed permanently 0 and `last_hit_at` stayed `None` while
  the task logged `"flushed hit counts for 0 rules"` at INFO on every run,
  identical to a genuinely idle site. Confirmed in production against a
  Redis 6.0.16 server: 40,936 runs, all reporting success, none flushing
  anything. `getdel` was the only command anywhere in the package needing
  newer than Redis 6.0, so the fix is a `GET`+`DEL` pipeline in its place,
  not a raised floor: the pipeline is not atomic against a concurrent
  `INCR` landing between the two commands, an acceptable trade for a
  coarse hit counter flushed every five minutes rather than a balance.
  `BlockRule.objects.filter(...).update()` failures in the same loop
  (previously caught by the same bare `except: continue`, so a DB error
  read identically to a Redis error) now increment a distinct `errors`
  count and log at ERROR rather than vanishing silently.

- **Redis failures that fail open silently, with no log at any level, now
  log a WARNING naming the consequence.** Fail-open behaviour is
  unchanged in every case (BR-EVAL-007): only observability changes.
  - `rule_engine._record_rule_hit`, the producer half of the same hit
    counter `flush_rule_hit_counts` reads: a silent failure here means
    every read of that rule's hit count reads as zero forever,
    indistinguishable from the rule never matching, inviting an operator
    to delete a rule that is actively blocking traffic.
  - `rule_engine._get_unsolved_challenge_count`, the escalation counter:
    returning 0 on failure is indistinguishable from "never challenged",
    which silently disables challenge escalation. A bot farm failing
    every challenge would never escalate to a block. The middleware's
    matching write path (`waf:challenged:{ip}`, incremented on every
    CHALLENGED verdict) gets the same treatment, since a silent failure
    there has the identical effect from the other side of the counter.
  - `fingerprint.register_known_fingerprint`: kills the dynamic
    known-fingerprint allowlist, so a real user who just solved a
    challenge is challenged again on every subsequent visit, a
    false-positive amplifier rather than a neutral fail-open. The
    `VerifyView` call site's own wrapping `except` (which also covered
    the unrelated solved-flag write) is split so each failure logs its
    own consequence.

- **`_invalidate_rule_cache_redis` now logs when it falls back to the
  per-process Django cache.** The Redis increment this function normally
  performs (`waf:rules:version`) is how a newly expired or created rule
  reaches every already-running `WafMiddleware` worker without a restart;
  the Django cache fallback is per-process, so it does not actually
  invalidate other workers' caches, only this one's next read. Previously
  this fell back silently, indistinguishable from the caller's side as a
  successful shared invalidation, so an operator watching Redis come back
  up after an outage had no way to see that a chunk of rule changes only
  ever reached one worker.

- **`parse_access_log` and `update_ip_reputation` no longer report a
  silent zero indistinguishable from an idle site.** A misconfigured
  `DJANGO_WAF_ACCESS_LOG_PATH` (file does not exist) previously logged at
  DEBUG, invisible in production, and returned the same
  `{"parsed_lines": 0}` as a genuinely quiet site forever; it now logs a
  WARNING (an unset path, the expected "feature not configured" case,
  stays at DEBUG). `update_ip_reputation` now reports `ips_seen` alongside
  `updated_count`/`created_count` and logs a WARNING when no `RequestLog`
  rows landed in the 24-hour window at all, since `detect_challenge_farms`
  reads `IPReputation` directly and a silent zero here means that detector
  runs blind for the window with no signal that anything is wrong.

- **Ruff `S110` (try-except-pass) and `S112` (try-except-continue) are
  re-enabled** (previously ignored in `pyproject.toml`); these are
  precisely the two rules that would have flagged the `flush_rule_hit_counts`
  and `_record_rule_hit` defects above. All resulting violations in `src/`
  are fixed by the logging changes in this release; none required a
  per-line `noqa`.

## [1.10.0] - 2026-08-11

### Fixed

- **Trusted-proxy client IP resolution now supports unix-socket WSGI binds
  (#62).** `DJANGO_WAF_TRUSTED_UNIX_SOCKET`, default `False`, explicitly
  treats an empty `REMOTE_ADDR` as the trusted direct hop and applies the
  existing right-to-left, validated `X-Forwarded-For` walk. It must be enabled
  only when the unix socket is accessible exclusively to the reverse proxy;
  non-empty peers remain subject to `DJANGO_WAF_TRUSTED_PROXIES` CIDR checks.

- Removed the default `ordering = ["-created_at"]` from the bundled
  abstract `BaseModel` (ADR-066): a default ordering on a shared abstract
  base defeats `values()`/`values_list()` combined with `distinct()` in
  every inheriting model. Every concrete model in this package
  (`BlockRule`, `AllowRule`, `RequestLog`, `IPReputation`,
  `ChallengeToken`) already declares its own explicit `ordering`, so this
  is a no-op for effective query behaviour and generates no migration.
  (#60)

## [1.9.1] - 2026-08-10

### Fixed

- **The confirmed/rejected outcome metric no longer empties its own
  `confirmed` bucket (#56).** `auto_rule_review_outcomes` filtered on
  `source=auto`, but confirming a rule promotes it to `source=admin` (which
  is what stops it reappearing in the review queue and stops the detector
  re-matching it on its `source=auto` lookup key), so every rule left the
  metric at the exact moment it was confirmed. The `confirmed` bucket was
  therefore permanently zero, and the metric reported only the outcomes
  nobody approved: precisely inverting what BR-ANOM-010 exists to show. The
  window now matches a rule that is either still `source=auto` or carries
  any review status other than `not_applicable`. Widening on review status
  rather than source is precise rather than loose, since `review_status`
  only ever leaves `not_applicable` for a rule an anomaly detector created,
  so no hand-authored or feed-sourced rule can enter the count.

### Removed

- **`AnomalyType.BURST` and `AnomalyType.PATH_HAMMERING` (#53).** Neither
  was emitted by any detector, so both advertised a category that could
  never have members: in a security tool that reads as "the detector exists
  and is quiet" rather than "it was never built", and any per-anomaly-type
  breakdown carried two permanently empty rows. Both behaviours are already
  covered elsewhere and were never detector-shaped: per-second burst by
  `DJANGO_WAF_RATE_LIMIT_BURST` in the rate limiter, and path hammering by
  `DJANGO_WAF_SUSPICIOUS_PATH_PATTERNS` scoring. No data migration is
  needed, because no model field stores an `AnomalyType`: the enum travels
  only as an `anomaly_detected` signal kwarg. This is technically breaking
  for any consumer that references either constant by name, which is why it
  is called out here rather than folded into a patch.

## [1.9.0] - 2026-08-10

### Added

- **A standing per-detector observe-only mode, distinct from dry-run
  (#45).** `DJANGO_WAF_ANOMALY_OBSERVE_ONLY_DETECTORS` names anomaly
  detector functions (e.g. `["detect_cloud_spray"]`) that must always
  create a quarantined `BlockRule` (inactive, pending review) regardless of
  the package-wide quarantine setting, so an operator can build trust in
  one detector's output without quarantining every detector's rules. This
  is a standing configuration, unlike the existing per-invocation
  `dry_run` flag, which suppresses every write unconditionally and takes
  precedence over this setting. An unrecognised detector name is caught at
  boot by the new `django_waf.W008` system check, validated against a
  single source of truth also used by the quarantine decision itself, so a
  detector rename cannot silently desync the setting from the functions it
  names.
- **Auto-generated rules now carry the evidence that triggered them
  (#46).** Every anomaly detector computes a per-detector confidence score
  (via a new shared `_scaled_confidence` helper, scaling from how far the
  observed value clears its threshold, floored at 0.50 and capped strictly
  below the hand-authored/feed default of 1.00) and renders the same
  evidence dict already sent with the `anomaly_detected` signal into the
  rule's `notes` field as human-readable `key: value` lines. A reviewer on
  the dashboard's Anomalies panel can now see the request counts, score,
  and window that triggered detection without cross-referencing logs.
- **Auto-generated rules can be quarantined pending review before they
  enforce (#47).** `DJANGO_WAF_ANOMALY_QUARANTINE_AUTO_RULES`, default
  `False`, creates a newly-detected auto-generated `BlockRule` inactive and
  pending review rather than enforcing immediately. The default is
  deliberately not a mirror of the equivalent threat-feed setting (default
  `True`): every existing deployment already relies on an auto-generated
  rule enforcing immediately, and flipping the default would silently stop
  enforcement on upgrade with no code change required. Confirming a
  quarantined rule via the dashboard now also activates it (previously
  confirmation only promoted the rule's source and cleared its expiry,
  which had no effect if the rule was never deactivated in the first
  place); rejecting one records the rejection. A re-detection of the same
  rule by a later detector run can never silently undo either decision:
  once a rule is confirmed or rejected, the detector's write path refreshes
  only its expiry.
- **Auto-generated rule outcomes are now tracked and surfaced (#48).**
  `BlockRule` gains `review_status` (not applicable, pending, confirmed,
  rejected, or expired unreviewed) and `reviewed_at`. A new
  `anomaly_detector.auto_rule_review_outcomes` service function returns a
  live, zero-filled count per status over a configurable window, surfaced
  on the dashboard's Anomalies panel as the honest false-positive proxy
  the previous challenge-solve-rate metric could not provide. `expire_rules`
  now also sweeps auto-generated rules still pending review whose expiry
  has passed, independently of whether they were ever activated, so a
  quarantined rule nobody reviews is marked expired unreviewed rather than
  sitting pending forever.

### Fixed

- **The `anomaly_detected` signal's documented payload now matches what the
  code actually sends (#52).** `signals.py` described the signal as
  providing `ip_address`, `anomaly_type`, `score`, and `details`, but the
  only call site sends `rule`, `anomaly_type`, and `details`: a receiver
  written against the documented payload raised `KeyError` on `ip_address`
  or `score`. The comment is corrected to describe the real payload rather
  than the code changed to match the comment, since the sent payload is the
  one any existing receiver is already written against. The offending IP or
  CIDR is available as the rule's own `pattern`.

### Changed

- The dashboard's Anomalies panel now orders pending-review rules first,
  shows each rule's confidence and review status, surfaces its evidence
  (`notes`) as a title attribute, and only offers Confirm/Reject on rules
  that are actually reviewable (pending, or not-applicable rules created
  under the pre-#47 enforce-then-review default).

## [1.8.1] - 2026-08-09

### Documentation

- **New `docs/THREAT-MODEL.md` (#36).** django-waf is marketed and packaged
  as a WAF; read literally that implies payload inspection (SQLi, XSS,
  OWASP Core Rule Set-class coverage), which this package does not do. The
  new document is a verified capability matrix (in scope: bot detection,
  rate limiting, PoW challenges, reputation scoring, the form-defence
  chain; out of scope: payload inspection, upload scanning, volumetric
  DDoS), the trust boundaries (Redis, the opt-in threat feed, middleware
  ordering), and an honest accounting of the automatic-enforcement safety
  controls: what the schema already supports (provenance, confidence, TTL
  fields; a post-hoc dashboard review path; a per-invocation dry-run mode)
  against what it does not (no detector runs observe-only by default,
  auto-generated rules carry no evidence in their `confidence`/`notes`
  fields, review happens after enforcement rather than before it, no
  aggregate false-positive-proxy metric exists). Four follow-on
  implementation issues (#45, #46, #47, #48) are filed for the gaps this
  document identifies rather than folded into this documentation pass. The
  README now links to it and states the payload-inspection boundary
  up front.

### Fixed

- **The non-Redis cache fallback was broken: six Redis-only calls raised on
  `LocMemCache` and the WAF silently failed open (#44).** Three
  near-identical `_get_redis_client()`/`_default_redis_factory()`
  implementations (`middleware.py`, `views.py`,
  `forms/protection.py`) caught `django_redis.get_redis_connection()`
  raising `NotImplementedError` (the configured cache alias is not a
  django-redis backend, the common case for `LocMemCache` under
  `DEBUG=True`) and fell back to returning `django.core.cache.cache`
  itself. That object has no `setex`, no incr-with-init, no pipeline, and
  no sorted-set support, so Redis-only calls in `rule_engine.py`,
  `rate_limiter.py`, and elsewhere raised `AttributeError` several frames
  later, caught by the middleware's outermost handler, which failed the
  whole WAF open per BR-EVAL-007: it evaluated no rules at all, on any
  project whose cache backend was not Redis, while looking from a plain
  200 response exactly like a healthy pass. New
  `django_waf.services.redis_client.get_redis_client()` is now the single
  resolution point: it returns a real Redis client or `None`, never a
  non-Redis object standing in for one. BR-EVAL-007's existing fail-open
  policy for a genuine runtime Redis outage is unchanged and still applies;
  what changes is that a *misconfigured* backend (the wrong kind of cache
  configured, not a working Redis that is merely unreachable right now) is
  now surfaced.
- New system check **`django_waf.E004`** (Error): fires at boot when
  `DJANGO_WAF_REDIS_ALIAS` is not configured as a `django_redis.cache.RedisCache`
  backend, since rule evaluation, rate limiting, and challenge state have
  no safe equivalent on a generic Django cache backend. A security control
  that reports healthy while blocking nothing is worse than one that
  refuses to start; this check exists so an operator catches the
  misconfiguration at `manage.py check` rather than only discovering it
  from a stream of per-request log lines.

### Added

- New system check **`django_waf.W007`** (#42): warns at boot when
  `DJANGO_WAF_TRUST_X_FORWARDED_FOR` is enabled and
  `DJANGO_WAF_TRUSTED_PROXIES` is empty, the configuration under which
  `client_ip.resolve_client_ip` (BR-EVAL-008) falls back to trusting the
  leftmost `X-Forwarded-For` entry unconditionally: exactly the hop a
  client controls, and therefore spoofable by design. The resolver already
  logged a warning on every such request; this surfaces the same risk once,
  at boot.

## [1.8.0] - 2026-08-01

A single opt-in feature closing the last item from the 2026-08-01 triage: the
WAF can now recognise staff without depending on `AuthenticationMiddleware`
order, dissolving the W004 tension. Off by default, so existing sites are
unaffected. All 1058 tests pass.

### Added

- **Signed trusted-user cookie so the staff bypass works before
  `AuthenticationMiddleware` (#23).** The staff/superuser rate-limit bypass
  (BR-RATE-003) read `request.user`, which is only populated once
  `AuthenticationMiddleware` has run, so the bypass silently failed on any
  deployment that (correctly, for security-first ordering) placed
  `WafMiddleware` before auth, and `django_waf.W004` warned about the
  ordering with no fix beyond moving the WAF later, which trades away its
  early-rejection value. New opt-in setting
  `DJANGO_WAF_TRUSTED_COOKIE_ENABLED` (default `False`) turns on a
  WAF-owned, IP-bound, short-TTL signed cookie
  (`django_waf.services.trusted_user_service`, mirroring the existing
  site-password cookie's `TimestampSigner` pattern) set on login via a new
  opt-in `user_logged_in` receiver
  (`django_waf.receivers.set_trusted_cookie_flag_on_login`, wired from
  `DjangoWafConfig.ready()`). `_is_staff_user` now checks this cookie
  first, falling back to `request.user` unchanged. When the feature is
  enabled, `django_waf.W004` is no longer raised: the bypass no longer
  depends on middleware order. The cookie is bound to the client IP via the
  hardened `resolve_client_ip` resolver (#29) and carries a short TTL, so a
  stolen cookie grants the bypass only briefly and only from the same
  address.
- `DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL` (default `"staff"`, or
  `"authenticated"`): which logged-in users receive the cookie. An invalid
  value is warned about by the new `django_waf.W006` system check and falls
  back to `"staff"`.
- `DJANGO_WAF_TRUSTED_COOKIE_TTL` (default `3600` seconds) and
  `DJANGO_WAF_TRUSTED_COOKIE_DOMAIN` (default `None`, falling back to
  `SESSION_COOKIE_DOMAIN`): the cookie's lifetime and cross-subdomain scope,
  mirroring the site-password settings.

### Changed

- `django_waf.W004` (middleware ordering) is suppressed when
  `DJANGO_WAF_TRUSTED_COOKIE_ENABLED` is `True`, and still raised as before
  when the feature is off and the WAF sits before auth.

## [1.7.0] - 2026-08-01

The P2/P3 hardening pass from the 2026-08-01 issue triage: six defects and
hardening items across client-IP resolution, rule matching, log ingestion,
the threat feed, and the nginx export path. All 1028 tests pass.

### Fixed

- **Client IP was resolved from an unverified `X-Forwarded-For`, and three
  subsystems disagreed on the client IP (#29).** With
  `DJANGO_WAF_TRUST_X_FORWARDED_FOR` on, the middleware took the leftmost
  (fully client-controlled) `X-Forwarded-For` value without confirming the
  direct peer was a trusted proxy, so a client could choose its own
  block/rate-limit identity; separately, the middleware, the views, and the
  form defences each resolved the IP differently, so behind a proxy every
  form submission bound to the proxy IP. A single resolver
  (`django_waf.services.client_ip.resolve_client_ip`) now backs all three.
  It honours `X-Forwarded-For` only when `REMOTE_ADDR` is inside a configured
  `DJANGO_WAF_TRUSTED_PROXIES` CIDR, walking the header right-to-left and
  returning the first hop that is not itself a trusted proxy, and validates
  every candidate with `ipaddress`. The legacy leftmost behaviour survives
  only when no trusted proxies are configured, and now logs a warning on
  every use.
- **Rule matching recompiled regexes per request and never used its own
  compiled cache, and no entry point validated patterns (#28).** The UA regex
  path re-ran `re.search` on the raw pattern string on every request while the
  precompiled `ua_regex_set` cache went unused. Matching now uses a
  process-lifetime compiled cache. Patterns are validated at write time by
  `django_waf.services.pattern_validation.validate_ua_regex_pattern`, which
  rejects empty, over-length, non-compiling, and catastrophic-backtracking
  (nested-quantifier) patterns; it is called from the admin forms, the
  threat-feed importer (#33), and now `BlockRule.clean()`/`AllowRule.clean()`
  so a ReDoS-prone pattern is rejected regardless of how the rule is created.
  The validator is a static heuristic, not a formal safety proof (no RE2
  dependency added).
- **WAF decision events and parsed nginx access-log lines shared `RequestLog`
  with no way to tell them apart, double-counting and losing data (#32).**
  `RequestLog` gains a `source` field (`middleware` by default, so existing
  and middleware-written rows are correctly tagged without a middleware
  change) and a `source_event_id`; a partial unique constraint on
  `(source, source_event_id)` for `nginx_log` rows makes re-ingestion
  idempotent, so `bulk_create(ignore_conflicts=True)` finally deduplicates.
  The log parser now stores the real log-line timestamp instead of discarding
  it and stamping `now()`, and detects file rotation/truncation (size below
  the stored offset resets to zero) with a warning when no offset is cached.
  `detect_unsolved_challenges` scopes its verdict count to middleware rows so
  status-code-inferred nginx rows no longer distort it. (Offset storage
  remains cache-backed; a cache eviction triggers a safe, deduplicated
  re-read rather than lost or double-counted rows.)
- **`django_waf_detect_anomalies --dry-run` actually created and activated
  rules (#38).** The command dropped the flag and always ran the real
  detectors. `run_all_detectors` and every detector now accept `dry_run`;
  in dry-run the auto-rule path performs no database writes and emits no
  signal, and the command prints what it would have created.
- **Threat-feed entries were minimally validated, letting a bad or compromised
  feed corrupt local rules (#33).** `sync_feed()` now validates each entry
  before importing it, and skips (logs + counts) rather than acting on a bad
  one: a non-numeric `confidence` no longer aborts the whole sync with an
  uncaught `ValueError`; `rule_type`, `match_type`, and `action` must be in a
  known whitelist, so an unrecognised `action` is skipped rather than
  silently falling through to the rule engine's default-BLOCKED behaviour;
  regex/UA patterns are checked against
  `django_waf.services.pattern_validation.validate_ua_regex_pattern` (#28)
  where available, with a defensive local fallback otherwise. A feed-sourced
  `kind: "allow"` entry must now carry `verify_rdns: true` with a non-empty
  `rdns_pattern` or it is skipped outright (a compromised feed can no longer
  strip the rDNS safeguard off its own allow rules), and a newly-created
  feed allow rule is quarantined (`is_active=False`) pending operator review
  by default (`DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES=True`); an operator's
  manual approval survives later syncs.
- **The nginx blocklist generator was repositioned as an export utility with
  a complete enforcement contract (#31).** Previously the generated file
  declared `map`/`geo` variables that nothing consumed, block and throttle
  rules wrote identical output, and a syntactically broken candidate file
  could be activated and survive on disk as a reload timebomb. The generator
  now writes block and throttle rules to distinct variables
  (`$waf_block_ip`/`$waf_block_ua` vs `$waf_throttle_ip`/`$waf_throttle_ua`),
  ships a reference `http{}`-scope include and per-`location{}` enforcement
  snippet as package data under `django_waf/conf/nginx/` (based on the config
  shape proven in production), and validates the candidate with `nginx -t`
  (or `DJANGO_WAF_NGINX_TEST_COMMAND`) before leaving it active. A failed
  validation restores the previous file automatically
  (`DJANGO_WAF_NGINX_VALIDATE`, default `True`; skips gracefully when no
  local nginx binary is available). README.md's nginx Integration section is
  rewritten to state plainly that django-waf generates configuration and
  reloads nginx, but the operator wires enforcement.

### Added

- `DJANGO_WAF_TRUSTED_PROXIES` (list of CIDR strings, default empty): the
  hardened replacement for `DJANGO_WAF_TRUST_X_FORWARDED_FOR` (#29).
- `DJANGO_WAF_FEED_QUARANTINE_ALLOW_RULES` (bool, default `True`): import
  feed-sourced allow rules inactive, pending operator review (#33).
- `DJANGO_WAF_NGINX_VALIDATE` (bool, default `True`) and
  `DJANGO_WAF_NGINX_TEST_COMMAND` (list, default `["nginx", "-t"]`):
  validate a generated blocklist before activating it, with automatic
  rollback on failure (#31).
- Reference nginx configuration shipped as package data under
  `django_waf/conf/nginx/` (the `http{}` include and the enforcement
  snippet) (#31).

### Changed

- `RequestLog` gains `source` and `source_event_id` fields and a partial
  unique constraint for deduplicating ingested nginx-log rows (migration
  `0004`) (#32).
- `run_all_detectors` and every anomaly detector accept a `dry_run` keyword
  (#38).

## [1.6.0] - 2026-08-01

A defect wave from the 2026-08-01 issue triage. Each of these was latent since
the feature that introduced it, not a regression: the fixes below correct
behaviour that was wrong from first release (the one exception is noted under
rule expiry). All 929 tests pass.

### Fixed

- **Cloud-spray detection was blind to botnets that spoof a referer (#24).**
  `detect_cloud_spray` only counted requests with an empty or missing referer,
  so a botnet that stamped every request with a static referer was invisible.
  Observed in production (2026-08-01): a distributed click-fraud flood of
  131,293 distinct IPs in one day, a rotated pool of plausible Chrome/Edge user
  agents, every request carrying a bare-origin `Referer` header, reported as
  zero cloud-spray while roughly 95% of the flood was allowed. A referer that
  is a bare origin with no path (matching `^https?://[^/]+$`) is now treated
  the same as a missing referer in both detector queries, because genuine
  browser navigation always serialises at least a trailing slash after the host
  (including `Referrer-Policy: origin`), so a path-less referer cannot come from
  real traffic. Referers with a real path, and trailing-slash origins, are
  unaffected.
- **Proof-of-work pass cookies could not round-trip an IPv6 address (#26).** The
  cookie payload was colon-joined (`token:ip:expiry:signature`) and validation
  split on colons, so an IPv6 client's address (which contains colons)
  mis-parsed and every solved IPv6 client was re-challenged on every request.
  The payload is now a versioned, pipe-delimited format (`v2|token|ip|expiry|
  signature`) and IPs are normalised through the `ipaddress` module, so
  compressed and expanded IPv6 forms validate interchangeably. Cookies in the
  old format are rejected without special-casing: a client holding one is
  re-challenged once after upgrade, then behaves normally. Cookie name, TTL, and
  IP binding are unchanged.
- **Rule expiry was not enforced during evaluation, and AllowRules never
  expired (#25).** Active-rule queries filtered only on `is_active`, so the
  cache could serve a rule past its `expires_at` until the housekeeping task
  ran, and that task deactivated only BlockRules. An expired feed or crawler
  AllowRule therefore bypassed every WAF check indefinitely. (The AllowRule half
  became possible in 1.4.0, which first gave AllowRules an `expires_at`.) Both
  `active()` querysets now exclude passed expiry, the rule cache carries
  `expires_at` per entry and rejects expired entries at match time, and the
  `expire_rules` task deactivates expired AllowRules as well as BlockRules and
  invalidates the cache when either model had an expired row.
- **Unsolved-challenge escalation was unreachable (#27).** The escalation check
  sat after the rule-driven, no-referer, and score-driven challenge verdicts had
  already returned, so an IP that repeatedly ignored challenges never reached
  auto-block. Escalation is now gated before every challenge-verdict return
  point: once the unsolved-challenge count reaches the threshold, the request is
  blocked with a single TTL-bound auto rule instead of challenged again. A
  successful solve resets the counter, as before.
- **Rate limiting returned an inaccurate `Retry-After` (#30).** The retry
  calculation always collapsed to one second and the value was then dropped
  because `EvaluationResult` carried no rate-limit metadata, so the middleware
  sent a fixed 60 seconds. The sliding-window limiter now returns the true
  seconds until the oldest event ages out (computed atomically in the same Redis
  pipeline), `EvaluationResult` carries `retry_after`, and both the main WAF
  throttle and the site-password guess-throttle emit accurate headers.
- **Verified-crawler allow rules trusted an unconfirmed PTR record (#34).**
  Crawler verification accepted a reverse-DNS hostname whose suffix matched an
  approved pattern without forward-resolving it, so anyone controlling the PTR
  record for their own IP (any cloud host with settable reverse DNS) could pass
  as Googlebot or Bingbot. Verification now performs forward-confirmed reverse
  DNS: after the PTR suffix matches, the hostname is forward-resolved and the
  original IP must appear among the results. Any DNS failure fails closed.

### Added

- `DJANGO_WAF_RDNS_FAILURE_CACHE_TTL` (default 300): negative reverse-DNS
  verdicts are now cached briefly, rather than for the 24 hours a positive
  verdict is cached, so a transient resolver outage no longer suppresses a
  crawler allow rule for a full day.

### Changed

- `EvaluationResult` gained a `retry_after` field (keyword default `None`);
  positional 5-argument constructions are unaffected.
- The `expire_rules` task result gained `expired_block_count` and
  `expired_allow_count` alongside the existing `expired_count`.

## [1.5.2] - 2026-07-19

### Fixed

- **Site-password gate leaked a template comment into the page.** The gate's
  CSRF-rationale note was written as a multi-line `{# ... #}` comment, but Django
  template `{# #}` comments are single-line only, so the note rendered verbatim
  as visible body text on the password prompt. Switched to a
  `{% comment %}...{% endcomment %}` block, the correct multi-line construct.

### Changed

- `Development Status` classifier corrected from `3 - Alpha` to `4 - Beta` —
  the package has shipped to a production consumer (vendablyv3) since
  v1.3.0 and no longer reflects an alpha maturity level.

### Docs

- `check_middleware_ordering` (W004) docstring records the outcome of
  investigating #18 (self-sufficient staff bypass for early placement):
  rejected, because `django.contrib.auth.get_user(request)` reads
  `request.session`, which does not exist before `SessionMiddleware` runs —
  the same class of defect fixed in v1.5.1 for the site-password gate.

## [1.5.1] - 2026-07-18

### Fixed

- **Site password gate 500 on password submit.** The gate stored its verified
  flag in `request.session`, but `WafMiddleware` runs before `SessionMiddleware`
  (the WAF gates early), so `request.session` did not exist when the gate ran and
  a correct password raised `AttributeError`. The gate now stores its flag in its
  own signed cookie (`django.core.signing.TimestampSigner`, the package's own
  signing key), independent of Django's session, so the WAF keeps running early.
  The cookie is `httponly`, `secure` (when the request is), `samesite=Lax`, TTL
  enforced live; it inherits `SESSION_COOKIE_DOMAIN` (or the new
  `DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN`) for subdomain coverage. A regression
  test reproduces the exact shipped condition (no SessionMiddleware in the stack).


## [1.5.0] - 2026-07-18

### Added

- **Site password gate.** `DJANGO_WAF_SITE_PASSWORD` walls an entire site (and
  every subdomain it serves) behind a single shared password, enforced in the
  WAF middleware before any application view runs. For staging sites, private
  betas, holding pages, and internal tools that must be live but not public.
  Off by default (additive, no change to existing sites). An un-verified request
  gets a noindex 401 password prompt; a correct password sets a signed session
  flag valid for `DJANGO_WAF_SITE_PASSWORD_TTL` (default 12h). Fail-closed when
  enabled with an empty password (system check `django_waf.E003`). Exempt paths
  (`DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS`, default health / `.well-known/` /
  `robots.txt` / the WAF's own interstitials) bypass the gate so liveness and
  ACME keep working. Guess attempts are throttled via the existing rate limiter;
  the `next` redirect is validated against open-redirect. Password comparison is
  constant-time and the password never appears in a response, log, or template.
  Subdomain coverage: set `SESSION_COOKIE_DOMAIN` to the parent domain.
  Security-reviewed. New settings: `DJANGO_WAF_SITE_PASSWORD`,
  `_ENABLED`, `_TTL`, `_EXEMPT_PATHS`, `_VERIFY_PATH`.

## [1.4.0] - 2026-07-18

### Added

- Verified-crawler allowlist (ADR-035). `DJANGO_WAF_ALLOW_VERIFIED_CRAWLERS`
  (default `True`) seeds rDNS-gated `AllowRule` rows for Googlebot and Bingbot
  on migrate, so a verified search crawler is never served the `noindex`
  proof-of-work challenge that a non-JavaScript client cannot solve. Each seed
  requires reverse-DNS verification, so a spoofed `Googlebot` user-agent from an
  unverified IP is still scored and challenged (not a user-agent bypass). Set
  the setting to `False`, or deactivate the seeded rows, to opt out. See the
  README "Search engine crawlers" section.
- Threat-feed contract extension (06-threat-feed-api.md section 2.8): a feed
  entry may carry `kind: "allow"` with `verify_rdns` / `rdns_pattern`, so an
  operated feed can deliver curated `AllowRule` rows (for example an
  always-current crawler allowlist) alongside block rules. `AllowRule` gains a
  `source` field for feed attribution and lifecycle. Fully backward compatible:
  a feed with no `kind` field imports as block-only exactly as before.

### Fixed

- Verified search crawlers are no longer challenged out of the box. Previously
  the package recognised crawler user-agents for analytics only and never
  exempted them, so a real Googlebot scored into the challenge band, could not
  solve the JavaScript proof-of-work, and was served an `X-Robots-Tag: noindex`
  interstitial on every path, silently de-indexing sites that put a public
  marketing surface behind the WAF. This closes a spec-vs-code gap:
  BR-CHAL-001's guarantee ("search engine crawlers are never challenged") now
  holds by default rather than only when an operator hand-seeded an `AllowRule`.

## [1.3.0] - 2026-07-14

### Added

- Dashboard time-range selector: `DashboardStatsPanel` and
  `DashboardTopBlockedPanel` accept `?range=today|7d|30d` (default
  `today`). The stats panel aggregates `RequestLog` verdict counts directly
  from the database for `7d`/`30d` (the Redis snapshot only covers "today");
  the top-blocked panel filters `IPReputation` by `last_seen_at`. The
  selector lives inside `stats_panel.html` so its active state survives each
  HTMX swap; the dashboard shell's 30 s auto-refresh always requests the
  default `today` range.
- Rule-effectiveness dashboard panel (`/waf/dashboard/rule-effectiveness/`,
  `DashboardRuleEffectivenessPanel`): lists the top 10 active `BlockRule`
  records by `hit_count` and flags active rules with `hit_count=0` as
  removal candidates.
- Optional DRF API under `waf/api/`: `BlockRuleViewSet` and `AllowRuleViewSet`
  (full CRUD, restricted to superusers or staff with `django_waf.change_blockrule`
  via the new `IsWafAdmin` permission), and read-only `RequestLogViewSet`
  (`?verdict=`, `?ip_address=`, `?from_ts=` filters) and `IPReputationViewSet`
  (`?min_threat_score=` filter), both restricted to Django admin users. Off by
  default, set `DJANGO_WAF_API_ENABLED = True` to mount the routes, and every
  endpoint returns `503` while disabled. Requires the new `django-waf[api]`
  extra (`djangorestframework>=3.14`); `djangorestframework` stays fully
  optional otherwise, the package imports and every existing test passes
  with it absent from the environment.
- System check `django_waf.W005`: warns when `DJANGO_WAF_FEED_ENABLED` is
  true but `DJANGO_WAF_FEED_URL` is not `https://`. Feed responses become
  `BlockRule` records, so a plaintext feed is a rule-injection vector. The
  check inspects the URL scheme only and issues no request; fix by using an
  HTTPS feed URL or setting `DJANGO_WAF_FEED_ENABLED = False`.
- Celery task `prune_challenge_tokens` and management command
  `django_waf_prune_challenges`: delete pending/failed `ChallengeToken`
  records older than a configurable age (default 24 hours). Scheduled
  daily at 04:15 alongside the existing `prune_request_logs` task.
- `django_waf.conf.DJANGO_WAF_CELERY_BEAT_SCHEDULE`: a ready-made
  `CELERY_BEAT_SCHEDULE` fragment covering every periodic django-waf task,
  merged into a project's own schedule with `{**DJANGO_WAF_CELERY_BEAT_SCHEDULE, ...}`
  instead of hand-transcribing task names and cadences. Stays importable
  even when `celery` is not installed: the interval-based entries
  (`*/N minute` tasks) are always present, and the wall-clock entries that
  need `celery.schedules.crontab` are omitted rather than approximated.
- System check `django_waf.W004`: warns when `WafMiddleware` is placed
  before `AuthenticationMiddleware` in `MIDDLEWARE` (or when
  `AuthenticationMiddleware` is missing). `request.user` is not available
  yet in that ordering, so the staff/superuser bypass silently fails and
  staff accounts get blocked/challenged like anonymous traffic.
- `django_waf.testing.fixtures`: pytest fixtures for consuming-project test
  suites, `disable_waf`, `waf_redis_mock` (requires `fakeredis`),
  `block_rule`, `allow_rule`, `challenge_token`. Re-exported from
  `django_waf.testing`.
- `django_waf.testing.helpers`: `create_blocked_request()` and
  `create_challenged_request()` test helpers that create the matching
  `BlockRule` and issue a request through the Django test client.
  Re-exported from `django_waf.testing`.
- `django_waf.logging.WafStructuredFormatter`: a JSON logging formatter for
  the `django_waf` logger hierarchy, one object per line with timestamp,
  level, logger, message, and (when present on the record) ip, verdict,
  rule_id, anomaly_score, latency_ms, path, method, and user_agent
  (truncated to 200 characters).
- `DJANGO_WAF_RATE_LIMIT_PATHS`: per-path rate limiting. A dict of
  `{path_prefix: (max_requests, window_seconds)}` checked before the global
  IP rate-limit windows; the longest matching prefix wins. Lets a site set a
  tight limit on `/api/login/` without touching the general request budget.
- `DJANGO_WAF_BLOCKED_COUNTRIES`: country blocking. A list of ISO 3166-1
  alpha-2 codes (e.g. `["CN", "RU"]`) rejected outright with a 403, checked
  after IP extraction and before the staff bypass. Requires a GeoIP database
  (`django_waf_install_geoip`); fails open when the lookup is unavailable so
  a missing/broken database never blocks traffic.
- Management commands `django_waf_export_rules` and `django_waf_import_rules`:
  serialise `BlockRule`/`AllowRule` records to JSON and load them back on
  another site. Import supports `--merge` (default, skips rules that already
  exist by `rule_type`/`match_type`/`pattern`) and `--replace` (deletes
  existing `source=admin` rules first), plus `--dry-run`. Imported rules are
  always tagged `source=admin`, never re-tagged as feed/auto.

### Fixed

- Challenge/pow_gate solvers now use a synchronous SHA-256 batch loop
  instead of awaiting `crypto.subtle.digest` once per nonce, raising client
  hash throughput by orders of magnitude so challenges resolve in the
  expected time.
- `DJANGO_WAF_CHALLENGE_DIFFICULTY_DESKTOP` / `_MOBILE` now default to
  `None`, so setting the single `DJANGO_WAF_CHALLENGE_DIFFICULTY` value
  takes effect as documented instead of being silently overridden by the
  per-band defaults. Single-value default lowered from `20` to `16`.
- Both solvers now bound their attempt count at 64x the expected mean and
  fail visibly rather than grinding indefinitely if difficulty is
  misconfigured.

## [1.2.0] - 2026-07-11

Minor because the feed URL defaults change consumer-visible behaviour: a
site that never set `DJANGO_WAF_FEED_URL` now pulls from
`threats.drystane.com` rather than the (never-resolving) `threats.icv.dev`
placeholder. Telemetry stays opt-in, so nothing is transmitted without
`DJANGO_WAF_FEED_REPORT = True`.

### Changed

- Feed URL defaults now point at `threats.drystane.com` (the operated feed
  server) instead of the retired `threats.icv.dev` placeholder. Telemetry
  remains opt-in (`DJANGO_WAF_FEED_REPORT` defaults `False`), so setting
  `DJANGO_WAF_FEED_REPORT = True` is now the only setting a site needs to
  start reporting.

### Fixed

- Challenge and verify interstitials now send `X-Robots-Tag: noindex,
  nofollow, noarchive` and carry a robots meta tag, so search engines do not
  index the security-check pages or follow their `next` URLs.

## [1.1.0] - 2026-07-10

Minor rather than patch because two changes are consumer-visible behaviour:
IPv6 sources now produce /48 rule patterns and telemetry keys (previously
an IPv4-style /24 of IPv6 space), so anything consuming auto-created rule
patterns or telemetry payloads will see new shapes; and
`run_all_detectors()` gained an optional `window_minutes` parameter (new
public API).

### Fixed

- `detect_subnet_burst`, `detect_cloud_spray`, and `build_telemetry_payload`
  now aggregate IPv6 addresses to their /48 network instead of naively
  applying an IPv4-style /24, which for IPv6 produced an absurdly wide (and
  meaningless) network and, for telemetry, was one step away from leaking
  full IPv6 addresses. All three call sites now share a
  `_get_subnet_prefix()` helper in `anomaly_detector.py` (IPv4 stays /24,
  IPv6 is /48).
- `load_rule_cache` now guards its database rebuild with a short-lived Redis
  lock (`waf:rule_cache:lock`, 5s TTL) so that concurrent worker processes
  racing on a cache miss (typically right after the rule version bumps) no
  longer all hit the database simultaneously. Retries acquiring the lock up
  to 3 times with a 100ms delay, then proceeds without it (fail-open) rather
  than blocking the request.
- `DashboardTopBlockedPanel` and `DashboardAnomalyPanel` now catch database
  errors in `get_context_data` and degrade to an empty panel (`ips=[]` /
  `rules=[]`), matching the fallback already in place on
  `DashboardStatsPanel`. Previously a DB or Redis error on either panel
  raised and broke the whole dashboard fragment.
- `django_waf_detect_anomalies --window-minutes` was broken since the flag
  was added: the command forwarded `window_minutes` to
  `anomaly_detector.run_all_detectors()`, but that function accepted no
  parameters, so passing the flag always raised `TypeError` (surfaced as a
  `CommandError`). `run_all_detectors` now takes `window_minutes: int | None
  = None` and forwards it to all five detectors (converted to hours for
  `detect_challenge_farms`, which takes its window in hours); omitting the
  flag is unchanged and leaves each detector on its own default window.

### Changed

- Publishing is now triggered by pushing a `v<semver>` tag instead of creating
  a GitHub release. The publish workflow gained test, build, and CHANGELOG-gate
  jobs, and creates the GitHub release itself. See the new `RELEASING.md`.

## [1.0.1] - 2026-06-30

### Fixed

- Shorten three `BlockRule` index names that exceeded Django's 30-character
  limit (`models.E034`): `..._source_active_idx` → `..._src_active_idx`,
  `..._priority_active_idx` → `..._prio_active_idx`, and
  `..._expires_active_idx` → `..._exp_active_idx`. Renamed in both the model
  `Meta.indexes` and `0001_initial`.

## [1.0.0] - 2026-06-27

### Changed (BREAKING): package renamed `icv_waf` → `django_waf`

The package is now consistently named `django_waf` throughout, matching the
`django-waf` distribution name. Every public surface that carried the old
`icv_waf` / `ICV_WAF_` name moved:

- **Import package:** `import icv_waf` → `import django_waf`
  (e.g. `from django_waf.forms import ProtectedForm`).
- **Installed app:** put `"django_waf"` in `INSTALLED_APPS` (was `"icv_waf"`).
- **App label & database tables:** the app label is now `django_waf` and tables
  are `django_waf_*` (were `icv_waf_*`). Migration history was squashed to a
  fresh `0001_initial` under the new label.
- **Settings prefix:** `ICV_WAF_*` → `DJANGO_WAF_*`
  (e.g. `ICV_WAF_ENABLED` → `DJANGO_WAF_ENABLED`). No alias is kept.
- **Management commands:** `icv_waf_*` → `django_waf_*`
  (e.g. `manage.py django_waf_block`).
- **Templates:** the template namespace is now `django_waf/` (was `icv_waf/`).

A deprecation shim keeps `import icv_waf` (and `from icv_waf.<sub> import ...`)
working with a `DeprecationWarning`, Python imports only. It does **not** make
`"icv_waf"` usable in `INSTALLED_APPS`, and does **not** alias the settings
prefix or management commands. The shim will be removed in a future major release.

The threat-feed service domain (`threats.icv.dev`) is unchanged: it is the
operated endpoint, not a naming artifact, and remains overridable via
`DJANGO_WAF_FEED_URL` / `DJANGO_WAF_FEED_REPORT_URL`.

#### Upgrade guide

1. Rename the app in `INSTALLED_APPS`: `"icv_waf"` → `"django_waf"`.
2. Rename every `ICV_WAF_*` setting in your `settings.py` to `DJANGO_WAF_*`.
3. Update imports: `icv_waf` → `django_waf` (the shim warns until you do).
4. Update any management-command invocations / cron / Celery beat entries:
   `icv_waf_*` → `django_waf_*`.
5. **Database:** existing tables are named `icv_waf_*`. Because the migration
   history was squashed under the new label, the recommended path for an
   existing install is to rename the tables in a one-off operation and fake the
   new initial migration:

   ```sql
   ALTER TABLE icv_waf_allow_rule        RENAME TO django_waf_allow_rule;
   ALTER TABLE icv_waf_block_rule        RENAME TO django_waf_block_rule;
   ALTER TABLE icv_waf_challenge_token   RENAME TO django_waf_challenge_token;
   ALTER TABLE icv_waf_ip_reputation     RENAME TO django_waf_ip_reputation;
   ALTER TABLE icv_waf_request_log       RENAME TO django_waf_request_log;
   ```

   Then mark the new migration applied without re-running it:
   `python manage.py migrate django_waf 0001 --fake`. (Indexes are recreated by
   name under the new prefix; adjust index names too if your tooling is strict.)
   A fresh install needs none of this: `migrate` creates the new tables
   directly.

## [0.12.0] - 2026-05-28

### Added

- **Host exclusions** via `ICV_WAF_EXEMPT_HOSTS`. Requests to a listed
  host bypass WAF evaluation entirely, complementing the existing
  `ICV_WAF_EXEMPT_PATHS`. The check runs at the same early stage
  (BR-EVAL-001), immediately after the exempt-paths check. Matching
  mirrors Django's `ALLOWED_HOSTS`: an exact host match, or a
  leading-dot entry (`.example.com`) matching the domain and any
  subdomain. The port is stripped before matching, and IPv6 literals
  are handled. Empty by default (no host exempt).
- **Django 6.0 support.** Added to the CI matrix (on Python 3.12+) and
  trove classifiers.

### Changed

- **Dropped Django 4.2, 5.0, and 5.1 support.** The supported range is
  now Django 5.2 (LTS) and 6.0, the only series with upstream support.
  Python floor stays at 3.11; Django 6.0 requires Python 3.12+.
- `FormVerdict` now subclasses `enum.StrEnum` instead of `(str, Enum)`.
  Behaviour is unchanged: `.value` and string equality are identical.

## [0.11.2] - 2026-05-27

### Fixed

- **`dict(QueryDict)` produced list-valued entries that crashed the
  defence chain on every real submission.** Critical bug in v0.11.0
  and v0.11.1. The mixin's `clean()` (`mixin.py:157`) and the
  decorator's POST handler (`decorators.py:114`) both called
  `dict(self.data)` / `dict(request.POST)`, but Django's `QueryDict`
  stores values as lists internally, and `dict(querydict)` iterates
  the underlying storage producing entries like `{"waf_token":
  ["Y29udGFjdHx..."]}`. The defences then crashed (`TypeError: can
  only concatenate list (not "str") to list` at
  `base64.urlsafe_b64decode`) or silently mis-evaluated (honeypot
  saw `[""]`, treating empty fields as filled).

  Production effect: every real-browser POST through a protected
  form returned a 500 with the TypeError above. Production-affecting
  for anyone running v0.11.0 or v0.11.1 with form protection
  enabled.

  Reported by Vendably during the v0.11.1 production rollout:
  same form, second-consecutive-day breakage. The previous release
  (v0.11.1) had fixed the render-side bug; this one fixes the
  submit-side bug. Both bugs passed every unit test in their
  respective releases because the tests built POST payloads as
  plain Python dicts, never as actual `QueryDict` instances.

  **Fix**: added `icv_waf.forms.protection.scalarise_submitted_data()`,
  a single seam between the entry points (mixin, decorator,
  replay-store) and the orchestrator that calls
  `QueryDict.dict()` for last-value-per-key string semantics, or
  falls through to `dict(...)` for plain mappings. Wired into all
  three call sites. No public-API change.

### Added

- **`tests/forms/test_querydict_round_trip.py`**: regression suite
  that exercises the mixin and decorator with **real Django
  `QueryDict` instances**, going through `RequestFactory.post()` and
  `Client.post()`. Verified to fail loudly without the fix and pass
  with it. Covers:

    1. `scalarise_submitted_data` contract: `QueryDict` →
       last-value-per-key strings, plain dicts pass through, `None`
       → `{}`.
    2. Mixin path: `Form(request.POST, request=request)` where
       `request.POST` is a real `QueryDict`.
    3. Decorator path: `RequestFactory.post()` + Django test
       `Client.post()`.

  The test suite that would have caught both the v0.11.0 and v0.11.1
  bugs before either release.

### Upgrade

Anyone running v0.11.0 or v0.11.1 with form protection enabled has
500s on every real form submission:

```bash
pip install -U django-waf
```

No settings or migration changes. The operator-side workaround if
upgrade is blocked is `ICV_WAF_FORM_PROTECTION_ENABLED=False`, but
that disables protection entirely; the proper fix is to upgrade.

## [0.11.1] - 2026-05-27

### Fixed

- **`RenderTokenDefence.render_fields` shipped the raw token string
  instead of a hidden `<input>` tag**: a critical bug in v0.11.0 that
  made every protected form unusable for real users. The orchestrator
  concatenated the raw token into the DOM as visible page text; no
  `<input name="waf_token">` ever rendered, so browsers never
  submitted a `waf_token` field, and every real-user POST was rejected
  with `render_token:missing`.

  The unit tests in v0.11.0 missed this because they constructed POST
  payloads directly; none ever parsed the rendered HTML and submitted
  what a browser would actually submit. The strengthened tests in this
  release (see "Added" below) close that gap.

  **Fix**: `RenderTokenDefence.render_fields` now returns
  `format_html('<input type="hidden" name="{}" value="{}">', ...)`.
  The orchestrator extracts the nonce back out of the rendered `<input>`
  via a `value="..."` regex when threading it to subsequent defences
  (honeypot, js_touch, pow_gate). No public-API change.

### Added

- **DOM round-trip test suite** (`tests/forms/test_dom_round_trip.py`).
  Renders a protected form, parses the HTML the way a browser would
  (via `html.parser`), builds a POST from the discovered `<input>`
  values, and verifies `PASSED`. This is the test class that would
  have caught the v0.11.0 bug before release; future render-side
  regressions across any defence are now covered.

### Upgrade

Anyone who shipped v0.11.0 with form protection enabled has broken
forms; upgrade immediately:

```bash
pip install -U django-waf
```

No settings or migration changes.

## [0.11.0] - 2026-05-27

### Added

- **Form-protection subsystem.** Defence-in-depth at the form layer,
  composing eight defences into a single chain per protected form. See
  README "Form protection" for the operator guide. Highlights:

    - **Eight defences**: `render_token` (signed payload + Redis
      one-shot marker), `honeypot` (rotating hidden fields per form_id),
      `time_trap` (too-fast / too-slow / expired), `ua_consistency`
      (UA hash captured at render vs. submit), `js_touch` (sentinel
      cleared by JS to detect headless clients), `credential_throttle`
      (per-IP + per-account login-failure counters, enumeration-safe),
      `signup_velocity` (per-IP completed-signup throttle), `pow_gate`
      (per-submission proof-of-work, ~50ms desktop / ~200ms mobile).

    - **Three entry points**: `ProtectedForm` Django Form mixin (the
      recommended path), `@waf_protect_post` view decorator (for views
      that bypass Django's Form layer), `{% waf_protect %}` template
      tag (pairs with the decorator on handwritten HTML forms). All
      three route to the same `FormProtection` orchestrator.

    - **HTMX-aware token lifecycle**: the render-token Redis marker is
      consumed only on a PASS verdict. Failed validations preserve the
      marker so re-submitting the corrected form works without
      re-tokening.

    - **Challenge-replay** (opt-in via
      `ICV_WAF_FORM_CHALLENGE_ON_FLAG=True`, default): FLAGGED
      submissions stash their POST data in `request.session`, redirect
      the user through `/waf/challenge/?form_replay=<token>`, and
      automatically re-issue the original POST after the challenge
      passes. Sensitive fields (password / secret / csrf / api_key /
      token) are stripped before storage, so operators see "please
      re-enter your password" on login replays. Replay token is signed,
      IP-bound, 60s TTL, one-shot.

    - **Per-form configuration** via `FormProtection(...)` kwargs:
      `defences=`, `defence_weights=`, `skip_for_authenticated=`, plus
      any per-defence override (e.g. `min_fill_seconds=0.8` for short
      newsletter forms).

    - **Four signals**: `form_submission_passed` (opt-in via
      `ICV_WAF_FORM_EMIT_PASSED_SIGNAL`, off by default, hot path),
      `form_submission_flagged`, `form_submission_blocked`, and
      `credential_attack_observed` (observation-only, never affects
      user-visible response; operators wire up email-to-owner
      handlers here).

    - **Structured logging**: one `waf.form_submission` log entry per
      submission with verdict, total score, per-defence outcomes and
      reasons. PASSED entries sampled at `ICV_WAF_LOG_SAMPLE_RATE`;
      FLAGGED + BLOCKED always logged. `X-WAF-Form-Verdict` debug
      header attached in `DEBUG=True` only.

- **`ICV_WAF_SIGNING_KEY`**: package-wide HMAC secret, separate from
  Django's `SECRET_KEY`. Used by every signed artefact the WAF issues
  (currently form render tokens + replay tokens). Defaults to a
  `SECRET_KEY`-derived value with a new `icv_waf.W003` system check
  warning so v0.10.x → v0.11.0 upgrades are seamless. Set to a
  dedicated key in production to rotate WAF signatures independently
  of Django sessions.

- **`icv_waf.W003`** system check: warns when `ICV_WAF_SIGNING_KEY`
  is unset and the package is falling back to a `SECRET_KEY`-derived
  value.

### Internal

- Defence-chain canonical ordering ensures `render_token` always runs
  first, with its verified payload threaded onto subsequent defences'
  `EvaluateContext` so `time_trap`, `ua_consistency`, `js_touch`, and
  `pow_gate` can read it without re-verifying.

- A defence exception is caught + logged + treated as a silent pass.
  A bug in any one defence cannot lock legitimate users out.

- `pow_gate` reuses `_digest_has_leading_zero_bits` from v0.10.5 (the
  page-level challenge's bit-counting helper) rather than maintaining
  a parallel implementation, so there is no drift risk between the two PoWs.

### Documentation

- README gains a "Form protection" section under Settings Reference
  with usage examples for all three entry points, plus per-form
  configuration patterns and HTMX integration notes.

- PRD lives at `docs/specs/forms/PRD.md` (the design that drove this
  release).

### Backwards compatibility

- **No DB migrations.** All state is in Redis (counters, token markers)
  or in signed tokens (no server-side state for the token itself).

- **Opt-in per form.** Adding `ProtectedForm` to a form is one line.
  Upgrading django-waf to v0.11.0 changes nothing until a form opts
  in via the mixin / decorator / template tag.

- **No changes to existing settings.** All new settings are additive.

- **Existing signals unchanged.** The four new signals
  (`form_submission_passed/_flagged/_blocked`, `credential_attack_observed`)
  are additions; existing `request_blocked`, `challenge_failed`, etc.
  are untouched.

## [0.10.6] - 2026-05-27

### Fixed

- **Challenge tokens stuck PENDING under per-request urlconf routing.**
  `ChallengeView` rendered the challenge page with `post_url =
  reverse("icv_waf:verify")`, a sibling of the middleware bug fixed in
  v0.10.5, but on the other side of the flow. Under django-hosts (or
  any other per-request urlconf setup) the page rendered fine, the
  browser solved the PoW, but the form POSTed to a path on the wrong
  host's urlconf, so `VerifyView` never ran. Tokens accumulated in the
  `PENDING` state forever, `solved_at` was never set, and the
  challenge counter never reset.

  **Fix**: `ChallengeView.get` now honours `ICV_WAF_VERIFY_URL` (the
  literal-path override added in v0.10.5) before falling back to
  `reverse()`. Operators with multi-host setups can pin the verify
  path explicitly the same way they already pin the challenge path.

- **`BlockRule.hit_count` not incrementing for repeat blocks.** The
  Redis blocked-IP fast-path (step 5 of `evaluate_request`) blocked
  cached IPs without identifying the matching rule, so subsequent
  hits to the same blocked IP never reached
  `_check_block_rules`, which is where `_record_rule_hit` runs. Once
  an IP was in the cache, its rule's hit counter froze at whatever
  value the first match recorded.

  **Fix**: `record_block_verdict` now stores the matched rule's UUID
  as the cache value (was a literal `"1"`). The fast-path decodes it
  on read, calls `_record_rule_hit`, and threads the rule id into the
  `EvaluationResult` so downstream signals and logs carry proper
  attribution too. Legacy `"1"` cache entries are tolerated and block
  anonymously until they roll over (5-minute TTL by default).

### Added

- **Richer `IPReputation` admin list view.** New columns: `country`
  (via GeoIP, when database installed), `challenge_passes`,
  `challenge_failures`, plus derived `block_rate` and
  `challenge_success_rate` percentages. New list filters for triage:
  threat tier (high/medium/low), recent activity window
  (hour/day/week), and "has unsolved challenges". Old fields stay; no
  data changes.

### Changed

- **`icv_waf.services.geoip.lookup_country`** is now the public entry
  point for IP-to-country lookups (was a private
  `_lookup_country` helper inside the middleware). The middleware
  still exposes a `_lookup_country` shim for backwards compatibility,
  so any external callers continue to work.

## [0.10.5] - 2026-05-23

### Fixed

- **Proof-of-work difficulty counted in bytes instead of bits** (lockout
  regression). `verify_challenge_solution` and the JS solver both required
  `difficulty` leading zero **bytes** in the SHA-256 digest, while the
  README and inline comments documented the field as leading zero **bits**.
  At the default of 4, average work was `256^4 ≈ 4.3 billion` hashes,
  unsolvable in a browser. Combined with `ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD=10`,
  legitimate users challenged by the WAF were auto-blocked within seconds.

  **Fix**: server verifier and JS solver now count leading zero **bits**,
  matching the documented semantics. Difficulty selection is now
  device-aware: desktop UAs get `ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP`
  (default 22, ~1 to 2s on a laptop), mobile UAs get `..._MOBILE` (default 18,
  ~1 to 3s on a budget phone). The legacy `ICV_WAF_CHALLENGE_DIFFICULTY`
  remains as a single-value fallback (default 20). The token's stored
  difficulty drives the solver, so it never drifts from the verifier.

- **Per-request urlconf routing broke challenge redirects**
  (django-hosts and similar). The middleware called
  `reverse("icv_waf:challenge")` with no `urlconf` argument and cached the
  result on the middleware instance. With per-request urlconf routing the
  first host to trigger a challenge froze its resolved path for every
  subsequent request on every host, until the process restarted.

  **Fix**: the resolved paths are no longer cached: `_get_challenge_paths`
  consults the active urlconf on every call. Two new settings,
  `ICV_WAF_CHALLENGE_URL` and `ICV_WAF_VERIFY_URL`, let operators bypass
  `reverse()` entirely with literal paths when the icv_waf URLs are not
  mounted on every host.

### Added

- **Device-aware challenge difficulty**: `ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP`
  and `ICV_WAF_CHALLENGE_DIFFICULTY_MOBILE` (set either to `None` to fall
  back to the single-value setting).
- **Challenge URL overrides**: `ICV_WAF_CHALLENGE_URL` /
  `ICV_WAF_VERIFY_URL` for projects with per-request urlconf routing.
- **Challenge UI progress bar + ETA**, so slow devices see legible progress
  rather than a stalled spinner.
- **Django system check** (`icv_waf.E002` / `W001` / `W002` / `E001` /
  `icv_waf.checks.check_challenge_difficulty`) that refuses to start with a
  PoW difficulty that would lock users out, and warns on values that are
  too high for low-end phones or too low to deter bots.

### Changed

- **Default difficulty raised** from `4` to `20` bits. With the previous
  byte-counting bug fixed, 4 bits ≈ 16 hashes, effectively no PoW. The
  new default targets ~1 to 2s of work, visible as a "verifying" signal
  without being painful.

## [0.10.4] - 2026-05-22

### Fixed

- **`varchar(10)` overflow on overlong HTTP methods**: `parse_access_log`
  truncated `path` and `user_agent` before insert but passed the HTTP method
  through unmodified into `RequestLog.method` (`max_length=10`). Scanners
  routinely send junk methods longer than 10 characters, causing a database
  overflow on insert and dropping the log line.

  **Fix**: `RequestLog.method` is widened to `max_length=16` (migration
  `0006`), which fits the longest IANA-registered method
  (`BASELINE-CONTROL`), and `parse_access_log` now clips the parsed method to
  16 characters before constructing the record.

### Added

- **`make_migrations.py`**: committed helper for authoring migrations against
  the bundled test settings (this package ships no `manage.py`). See
  CONTRIBUTING.

## [0.10.3] - 2026-04-14

### Fixed

- **Challenge redirect loop**: the challenge view could redirect a client back
  to a WAF-protected URL that re-triggered the challenge. WAF URLs are now
  resolved via `reverse()` and excluded from the challenge flow.

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
  `(rule_type, pattern, source, action)` key (created before the
  anomaly detector existed, or via a race condition),
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

### Added: GeoIP database installer

- **`manage.py icv_waf_install_geoip`**: downloads, verifies, and
  atomically installs the MaxMind GeoLite2-Country database for the
  middleware's `_lookup_country` helper. Flags:
  - `--license-key=XXX`: overrides the `ICV_WAF_MAXMIND_LICENSE_KEY`
    setting. Sign up at <https://www.maxmind.com/en/geolite2/signup>.
  - `--output-path=/path/to/file.mmdb`: overrides `ICV_WAF_GEOIP_PATH`.
    Defaults to `/var/lib/icv-waf/GeoLite2-Country.mmdb`.
  - `--if-older-than=DAYS`: skip the download if the existing file
    is younger than N days (cron-friendly).
  - `--quiet`: suppress progress output.

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
- **Running workers must be restarted to pick up a new database**:
  the MMDB file is mmap'd, so live processes keep their previous
  handle until restart. The command prints a reminder on success.
- Licence keys are never logged or echoed back on error.

## [0.9.0] - 2026-04-11

### Changed: defaults

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
  blocked". It does not: it means the matching rule came from the
  `BlockRule` table. A `BlockRule` with `action="challenge"` produces
  `matched_rule_type="block"` and `verdict="challenged"`. **Always use
  the `verdict` column for enforcement reporting.**

### Migration

- `0005_alter_requestlog_matched_rule_type`: schema-level no-op (only
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
  detection via HTTP header analysis; it identifies clients claiming to be
  browsers but missing expected headers (`Sec-CH-UA`, `Sec-Fetch-*`,
  `Accept-Language`, `Accept`).
  - `compute_fingerprint()`: SHA-256 hash of the normalised header tuple
  - `score_fingerprint_mismatch()`: 0.0 to 5.0 score for UA/header mismatch
  - `classify_fingerprint()`: `browser` / `bot` / `suspicious` / `unknown`
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
fingerprinting alone, and is automatically challenged.

## [0.7.0] - 2026-04-08

### Added

- **Cloud spray detector** (`detect_cloud_spray`): detects coordinated low-and-slow
  scraping: many distinct IPs with identical UA, no referer, 1 to 3 requests each.
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

- `ChallengeToken.ip_address` NULL constraint violation: `views._get_ip()` now
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
