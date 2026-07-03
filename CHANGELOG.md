# Changelog

All notable changes to django-waf will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

### Changed (BREAKING) — package renamed `icv_waf` → `django_waf`

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
working with a `DeprecationWarning` — Python imports only. It does **not** make
`"icv_waf"` usable in `INSTALLED_APPS`, and does **not** alias the settings
prefix or management commands. The shim will be removed in a future major release.

The threat-feed service domain (`threats.icv.dev`) is unchanged — it is the
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
   A fresh install needs none of this — `migrate` creates the new tables
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
  now Django 5.2 (LTS) and 6.0 — the only series with upstream support.
  Python floor stays at 3.11; Django 6.0 requires Python 3.12+.
- `FormVerdict` now subclasses `enum.StrEnum` instead of `(str, Enum)`.
  Behaviour is unchanged — `.value` and string equality are identical.

## [0.11.2] - 2026-05-27

### Fixed

- **`dict(QueryDict)` produced list-valued entries that crashed the
  defence chain on every real submission.** Critical bug in v0.11.0
  and v0.11.1. The mixin's `clean()` (`mixin.py:157`) and the
  decorator's POST handler (`decorators.py:114`) both called
  `dict(self.data)` / `dict(request.POST)` — but Django's `QueryDict`
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

  Reported by Vendably during the v0.11.1 production rollout —
  same form, second-consecutive-day breakage. The previous release
  (v0.11.1) had fixed the render-side bug; this one fixes the
  submit-side bug. Both bugs passed every unit test in their
  respective releases because the tests built POST payloads as
  plain Python dicts, never as actual `QueryDict` instances.

  **Fix**: added `icv_waf.forms.protection.scalarise_submitted_data()`
  — a single seam between the entry points (mixin, decorator,
  replay-store) and the orchestrator that calls
  `QueryDict.dict()` for last-value-per-key string semantics, or
  falls through to `dict(...)` for plain mappings. Wired into all
  three call sites. No public-API change.

### Added

- **`tests/forms/test_querydict_round_trip.py`** — regression suite
  that exercises the mixin and decorator with **real Django
  `QueryDict` instances**, going through `RequestFactory.post()` and
  `Client.post()`. Verified to fail loudly without the fix and pass
  with it. Covers:

    1. `scalarise_submitted_data` contract — `QueryDict` →
       last-value-per-key strings, plain dicts pass through, `None`
       → `{}`.
    2. Mixin path — `Form(request.POST, request=request)` where
       `request.POST` is a real `QueryDict`.
    3. Decorator path — `RequestFactory.post()` + Django test
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
that disables protection entirely — the proper fix is to upgrade.

## [0.11.1] - 2026-05-27

### Fixed

- **`RenderTokenDefence.render_fields` shipped the raw token string
  instead of a hidden `<input>` tag** — a critical bug in v0.11.0 that
  made every protected form unusable for real users. The orchestrator
  concatenated the raw token into the DOM as visible page text; no
  `<input name="waf_token">` ever rendered, so browsers never
  submitted a `waf_token` field, and every real-user POST was rejected
  with `render_token:missing`.

  The unit tests in v0.11.0 missed this because they constructed POST
  payloads directly — none ever parsed the rendered HTML and submitted
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
forms — upgrade immediately:

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
      (per-IP + per-account login-failure counters — enumeration-safe),
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
      token) are stripped before storage — operators see "please
      re-enter your password" on login replays. Replay token is signed,
      IP-bound, 60s TTL, one-shot.

    - **Per-form configuration** via `FormProtection(...)` kwargs:
      `defences=`, `defence_weights=`, `skip_for_authenticated=`, plus
      any per-defence override (e.g. `min_fill_seconds=0.8` for short
      newsletter forms).

    - **Four signals**: `form_submission_passed` (opt-in via
      `ICV_WAF_FORM_EMIT_PASSED_SIGNAL`, off by default — hot path),
      `form_submission_flagged`, `form_submission_blocked`, and
      `credential_attack_observed` (observation-only, never affects
      user-visible response — operators wire up email-to-owner
      handlers here).

    - **Structured logging**: one `waf.form_submission` log entry per
      submission with verdict, total score, per-defence outcomes and
      reasons. PASSED entries sampled at `ICV_WAF_LOG_SAMPLE_RATE`;
      FLAGGED + BLOCKED always logged. `X-WAF-Form-Verdict` debug
      header attached in `DEBUG=True` only.

- **`ICV_WAF_SIGNING_KEY`** — package-wide HMAC secret, separate from
  Django's `SECRET_KEY`. Used by every signed artefact the WAF issues
  (currently form render tokens + replay tokens). Defaults to a
  `SECRET_KEY`-derived value with a new `icv_waf.W003` system check
  warning so v0.10.x → v0.11.0 upgrades are seamless. Set to a
  dedicated key in production to rotate WAF signatures independently
  of Django sessions.

- **`icv_waf.W003`** system check — warns when `ICV_WAF_SIGNING_KEY`
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
  a parallel implementation — no drift risk between the two PoWs.

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
  reverse("icv_waf:verify")` — sibling of the middleware bug fixed in
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
  cached IPs without identifying the matching rule — so subsequent
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
  At the default of 4, average work was `256^4 ≈ 4.3 billion` hashes —
  unsolvable in a browser. Combined with `ICV_WAF_CHALLENGE_ESCALATION_THRESHOLD=10`,
  legitimate users challenged by the WAF were auto-blocked within seconds.

  **Fix**: server verifier and JS solver now count leading zero **bits**,
  matching the documented semantics. Difficulty selection is now
  device-aware: desktop UAs get `ICV_WAF_CHALLENGE_DIFFICULTY_DESKTOP`
  (default 22, ~1–2s on a laptop), mobile UAs get `..._MOBILE` (default 18,
  ~1–3s on a budget phone). The legacy `ICV_WAF_CHALLENGE_DIFFICULTY`
  remains as a single-value fallback (default 20). The token's stored
  difficulty drives the solver, so it never drifts from the verifier.

- **Per-request urlconf routing broke challenge redirects**
  (django-hosts and similar). The middleware called
  `reverse("icv_waf:challenge")` with no `urlconf` argument and cached the
  result on the middleware instance. With per-request urlconf routing the
  first host to trigger a challenge froze its resolved path for every
  subsequent request on every host, until the process restarted.

  **Fix**: the resolved paths are no longer cached — `_get_challenge_paths`
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
  byte-counting bug fixed, 4 bits ≈ 16 hashes — effectively no PoW. The
  new default targets ~1–2s of work, visible as a "verifying" signal
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
