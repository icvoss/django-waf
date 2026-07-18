# PRD: Site Password Gate

Status: proposed, 2026-07-18. A middleware-level password wall that gates an
entire site (and every subdomain it serves) behind a shared password, before any
application view runs. For staging sites, private betas, holding pages, and
internal tools that must not be publicly reachable or indexed.

## 1. Context and goals

Sites frequently need to be live (real TLS, real host, real app) but not public:
a staging deploy, a private beta, an internal integration ground. Today that is
done outside the app (nginx basic auth, a VPN), which is fine but not portable,
not app-aware, and not part of the security surface django-waf already owns.
django-waf already gates requests (block/challenge/throttle) in one middleware
and already ships a noindex interstitial pattern (`ChallengeView` +
`NoIndexResponseMixin`). A site-password gate is the same shape: intercept early,
show an interstitial, verify, let verified visitors through.

**Goal:** a single setting turns a site into a password-gated site. Every request
to every host the middleware serves is intercepted until the visitor submits the
correct password; after that, a signed cookie lets them through for a
configurable duration. Gated responses are noindex. It covers subdomains because
it is middleware, not per-host config.

### 1.1 In scope
- A shared-password wall over the whole site, all hosts/subdomains the app serves.
- An interstitial password prompt (noindex), a verify endpoint, a signed
  verified-flag cookie on success with a TTL.
- Exempt paths (health checks, ACME, robots.txt) configurable so the gate does
  not break liveness probes or cert renewal.
- Fail-closed: if the gate is enabled and the password is unset/misconfigured,
  deny (do not silently open).

### 1.2 Out of scope
- Per-user accounts or roles (this is a single shared password, not auth). A site
  needing real accounts uses Django auth; this is a coarse pre-app wall.
- Per-path or per-host different passwords in v1 (one password for the whole
  site). A later increment could scope passwords per host if demand appears.
- Replacing nginx basic auth everywhere; this is the app-portable equivalent for
  sites that want it in django-waf rather than in the edge.

### 1.3 Non-goals
- Not a substitute for the WAF's threat defences; it runs alongside them.
- Not brute-force-proof by itself; it reuses the WAF's existing rate-limit/
  throttle surface to bound password-guess attempts (see 3.4).

## 2. Architecture

### 2.1 One check in the existing middleware

The gate is a single check in `WafMiddleware.__call__`, placed AFTER the
enabled/exempt/health short-circuits and BEFORE the threat evaluation (a locked
site should prompt for the password before spending threat-scoring effort, and
the prompt itself must be reachable). Mirrors the existing `_check_country_block`
hook: a method returns an `HttpResponse` (the prompt or a redirect) to
short-circuit, or `None` to continue.

Flow per request when `DJANGO_WAF_SITE_PASSWORD` is set:
1. If the request path is an exempt path (gate-exempt list), continue (no gate).
2. If the request carries a valid, unexpired verified-flag cookie, continue.
3. If this is a POST to the gate's verify path, check the submitted password;
   on success set the verified-flag cookie on the redirect response and
   redirect to the originally-requested URL (or `next`); on failure re-render
   the prompt with an error (and record a throttle hit).
4. Otherwise, render the password prompt interstitial (noindex, 401), preserving
   the originally-requested URL as `next`.

### 2.2 The verified-flag cookie

`WafMiddleware` is documented to sit before `SessionMiddleware` in the
middleware stack (so it can block requests as early as possible), which means
`request.session` does not exist when the gate runs. The verified flag is
therefore the gate's own signed cookie (`waf_site_password`), not Django's
session — a dependency on `request.session` here is a defect, not a design
choice (see `django_waf.services.site_password_service` module docstring).

On correct password, the gate signs a marker with
`django.core.signing.TimestampSigner`, keyed with the package's own signing key
(`DJANGO_WAF_SIGNING_KEY`, falling back to a `SECRET_KEY`-derived value — the
same convention every other signed artefact in this package uses) and sets it
as a cookie on the redirect response, valid for `DJANGO_WAF_SITE_PASSWORD_TTL`
seconds. The TTL is enforced live via the `max_age` passed to
`TimestampSigner.unsign()` on every request, so a TTL change in settings takes
effect for existing cookies on their next request. The cookie is
`httponly=True`, `samesite="Lax"`, and `secure` matching whether the request is
served over HTTPS.

To cover subdomains, `DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN` (default `None`)
falls back to `settings.SESSION_COOKIE_DOMAIN` at call time — a site that
already sets `SESSION_COOKIE_DOMAIN=".example.com"` gets the same subdomain
coverage on the gate's cookie without configuring it twice; set the gate
setting explicitly only when its scope must differ from the session cookie's.

Comparison of the submitted password uses `hmac.compare_digest`
(constant-time); `django.core.signing`'s HMAC verification is inherently
constant-time for the cookie signature itself. The stored password is read
from settings (an env var in production), never rendered, never logged.

### 2.3 The interstitial

A `SitePasswordView` mirroring `ChallengeView`: `NoIndexResponseMixin` (so the
prompt is never indexed), a minimal template (`django_waf/site_password.html`)
with a password field and a hidden `next`, posting to the verify path. Status 401
on the prompt (unauthorised), so bots and scanners see a locked door, not content.

## 3. Behaviour rules

- **BR-SP-001 Gate is off by default.** `DJANGO_WAF_SITE_PASSWORD` unset/empty
  means no gate (backwards compatible; existing sites are unaffected).
- **BR-SP-002 Fail-closed on misconfiguration.** If the gate is enabled by a
  truthy `DJANGO_WAF_SITE_PASSWORD_ENABLED` but the password is empty, every
  gated request is denied (a system check E-warns at boot; runtime denies rather
  than opens).
- **BR-SP-003 Exempt paths always pass.** `DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS`
  (default: health check, `/.well-known/`, `/robots.txt`, the WAF challenge/verify
  paths) bypass the gate so liveness, ACME, and the WAF's own interstitials keep
  working.
- **BR-SP-004 Verified cookie passes for its TTL.** A correct password sets a
  signed verified-flag cookie valid for `DJANGO_WAF_SITE_PASSWORD_TTL` (default
  12h); requests within the TTL are not re-prompted. The cookie is the gate's
  own (`waf_site_password`), independent of Django's session, because
  `WafMiddleware` runs before `SessionMiddleware`.
- **BR-SP-005 Constant-time comparison; no leakage.** Password compared with
  `hmac.compare_digest`; never rendered, never logged, never in an error message.
- **BR-SP-006 Prompt is noindex and 401.** The interstitial carries
  `X-Robots-Tag: noindex, nofollow, noarchive` and HTTP 401.
- **BR-SP-007 Guess throttling reuses the WAF limiter.** Repeated failed
  submissions from an IP are throttled via the existing rate-limit surface
  (bounded attempts per window), so the gate is not a brute-force oracle.
- **BR-SP-008 Runs before threat scoring, after the enabled/exempt/health
  short-circuits.** A locked site prompts for the password before spending
  block/challenge effort; the prompt and verify paths are themselves reachable.

## 4. Settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `DJANGO_WAF_SITE_PASSWORD` | `""` | The shared password. Unset = gate off. |
| `DJANGO_WAF_SITE_PASSWORD_ENABLED` | `bool(DJANGO_WAF_SITE_PASSWORD)` | Explicit on/off; enabling with an empty password fails closed (BR-SP-002). |
| `DJANGO_WAF_SITE_PASSWORD_TTL` | `43200` (12h) | Verified-cookie lifetime, seconds. |
| `DJANGO_WAF_SITE_PASSWORD_EXEMPT_PATHS` | health, `/.well-known/`, `/robots.txt`, WAF interstitials | Paths that bypass the gate. |
| `DJANGO_WAF_SITE_PASSWORD_VERIFY_PATH` | `/waf/site-password/` | Where the prompt posts. |
| `DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN` | `None` (falls back to `SESSION_COOKIE_DOMAIN`) | Domain scope of the gate's own verified-flag cookie. |

Subdomain coverage is achieved by the operator setting Django's
`SESSION_COOKIE_DOMAIN` to the parent domain (documented) — the gate's own
cookie inherits it by default via `DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN`; the
gate itself is host-agnostic (middleware runs on every host).

## 5. Acceptance criteria

- AC: with `DJANGO_WAF_SITE_PASSWORD` unset, no gate (every request proceeds; a
  regression guard that existing WAF behaviour is unchanged).
- AC: with it set, an un-verified request to any path (except exempt) gets the
  401 noindex prompt, not the app.
- AC: a correct password POST sets the verified-flag cookie and redirects to
  `next`; subsequent requests within the TTL proceed without a prompt.
- AC: the gate works with no `SessionMiddleware` in the stack at all (it never
  touches `request.session`) -- regression guard for the defect that shipped
  in 1.5.0.
- AC: an incorrect password re-prompts with an error and records a throttle hit;
  after the throttle limit, further attempts from that IP are rate-limited.
- AC: exempt paths (health, `/.well-known/`, robots.txt, the WAF challenge/verify)
  bypass the gate even when locked.
- AC: enabling the gate with an empty password fails closed (denies) and emits a
  system-check warning at boot.
- AC: the prompt response is 401 with `X-Robots-Tag: noindex, nofollow, noarchive`.
- AC: the password never appears in any log line, error, or rendered response.
- AC: comparison is constant-time (`hmac.compare_digest`).

## 6. Rollout

Additive and off by default, so it ships in a minor version (1.5.0). The
vendablyconnect integration ground is the first consumer: its interim nginx basic
auth is replaced by this gate (set `DJANGO_WAF_SITE_PASSWORD` from env,
`SESSION_COOKIE_DOMAIN=.vendablyconnect.com`), keeping the lock inside django-waf
where it is portable and app-aware.
