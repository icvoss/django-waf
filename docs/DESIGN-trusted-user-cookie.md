# Design proposal: signed trusted-user cookie so the WAF recognises staff without AuthenticationMiddleware

Status: proposed (2026-07-29). Owner-requested from an icvlocal/vendablyconnect
integration finding. This is the durable brief; file it as an issue with the
`gh` command at the bottom.

## Problem

`WafMiddleware.process_request` has a staff/superuser bypass (BR-RATE-003,
`middleware.py:111` -> `_is_staff_user`, `middleware.py:508`) that reads
`request.user`. `request.user` is only populated by
`django.contrib.auth.middleware.AuthenticationMiddleware`. So the bypass only
works if the WAF runs AFTER auth middleware, and system check `django_waf.W004`
(`checks.py:168`) warns when it does not.

But the WAF is deliberately placed EARLY (after SecurityMiddleware, before
session/auth) on every real deployment, because a WAF's whole value is cheap
rejection of hostile traffic BEFORE the site pays for session decode, user
resolution, and DB work. Running the WAF after auth to satisfy the staff bypass
inverts that: every request, including a flood of malicious ones, runs
session + auth first. That is the wrong security ordering.

Result: a genuine three-way tension. On vendablyconnect (2026-07-29) the WAF sits
before auth (security-first), so W004 fires and staff are WAF-evaluated like
anonymous traffic. It FAILS SAFE (`_is_staff_user` guards with
`hasattr(request, "user")`, so no crash, the bypass just does not fire), but it
is a real operability bug: a staff member can be PoW-challenged or rate-limited.

## Key observation: the WAF already solved this everywhere ELSE

The staff bypass is the ONLY part of the WAF that reaches for `request.user`.
Everything else that needs per-request trust state is carried in a signed cookie
the WAF verifies ITSELF, no session, no auth, no DB:

- `waf_pass` (HMAC-signed `{token}:{ip}:{expiry}:{signature}`,
  `challenge_service.py:276`), read at `middleware.py:123`.
- The site-password gate: `site_password_service.py` uses
  `django.core.signing.TimestampSigner` (keyed with
  `django_waf.forms.services.tokens.get_signing_key`, salt
  `"django_waf.site_password"`), with `set_verified_cookie(response, request)` /
  `has_valid_cookie(request)` and a TTL via `max_age`. Its docstring
  (`middleware.py:249`) explicitly states it NEVER touches `request.session`
  because the WAF runs before SessionMiddleware.

So the codebase already knows it must not depend on session/auth at WAF-time,
and has a clean, reusable signed-cookie pattern. The staff bypass is simply the
one place that was not aligned to it.

## Proposed fix

Carry "this request is from a trusted (staff) user" in a WAF-owned signed
cookie, exactly mirroring `site_password_service`:

1. **New service `trusted_user_service.py`** (mirror `site_password_service`):
   `TimestampSigner` with the same `get_signing_key`, a distinct salt
   (`"django_waf.trusted_user"`) and cookie name (e.g. `waf_trusted`).
   - `set_trusted_cookie(response, request)`: signs a minimal claim (a marker
     plus, to limit theft value, a binding such as the client IP the way
     `waf_pass` binds IP) and sets the cookie with a SHORT `max_age`.
   - `has_valid_trusted_cookie(request)`: unsigns with `max_age=TTL`, checks the
     IP binding, returns bool. No DB, no session, no auth.
2. **Set the cookie on login.** A receiver on Django's `user_logged_in` signal
   (django-waf already has `signals.py`), gated so it only fires for staff/
   superusers (or a configurable trust level, see Open questions), sets the
   cookie on the login response. Because the cookie is set on the RESPONSE after
   auth ran, the WAF recognises the user from the NEXT request onward, which is
   correct: the login request itself already passed through auth successfully.
   This is exactly how `waf_pass` and the site-password cookie already behave.
   Provide the receiver as opt-in wiring (connect it in the consumer, or an
   AppConfig `ready()` gated by a setting) so sites that do not want it are
   unaffected.
3. **`_is_staff_user` prefers the cookie, falls back to `request.user`.** Change
   it to: return True if `has_valid_trusted_cookie(request)` OR (the existing
   `request.user` check, preserved so it still works when the WAF IS placed
   after auth). Now the bypass works in BOTH orderings.
4. **W004 stops warning when the cookie mechanism is enabled.** Update the
   `checks.py:168` check: if the trusted-user-cookie feature is enabled
   (its setting is on), the WAF no longer depends on auth-middleware order, so
   W004 is not raised. Keep raising it when the feature is off and the order is
   wrong (unchanged behaviour for existing users).

## Why this is the right shape

- WAF stays EARLY (security-first ordering preserved); no per-request session/
  auth cost forced by the bypass.
- The staff bypass no longer depends on middleware order, so W004 dissolves for
  sites that enable the feature.
- It reuses an already-shipped, already-trusted in-package pattern
  (`TimestampSigner`, the site-password service) rather than inventing a
  mechanism.
- It is a PACKAGE improvement: every consuming site benefits, not just icvlocal.
  (Per the workspace issue-placement rule, this lives on django-waf because the
  files that change are all here; the icvlocal middleware order is downstream and
  needs no change once this ships.)

## Honest caveats to spec, not blockers

- **Stolen-cookie risk.** A signed cookie is unforgeable but a stolen one grants
  the bypass until TTL expiry. Mitigate with a SHORT TTL and the IP binding
  `waf_pass` already uses. Document the tradeoff; do not make the TTL long.
- **First-request-after-login gap.** The WAF cannot recognise the user on the
  request that sets the cookie (only afterwards). Acceptable and consistent with
  the existing cookie mechanisms; that request already cleared auth.
- **Cookie domain / multi-host.** Reuse the site-password cookie-domain handling
  (`DJANGO_WAF_SITE_PASSWORD_COOKIE_DOMAIN` -> `SESSION_COOKIE_DOMAIN` fallback)
  so the cookie works across subdomains on multi-host sites like icvlocal.

## Open questions for the implementer

- **Staff-only or any authenticated user?** Current bypass is staff/superuser
  only. "Logged-in users too" broadens the bypass and weakens the WAF; recommend
  staff-only by default with a setting (e.g.
  `DJANGO_WAF_TRUSTED_COOKIE_TRUST_LEVEL = "staff" | "authenticated"`).
- **Feature flag default.** Ship OFF by default (opt-in), so existing sites see
  no behaviour change until they wire the login receiver and enable it.
- **Setting names** follow the existing `DJANGO_WAF_*` conf convention
  (`conf.py`); mirror the site-password settings (enable flag, TTL, cookie
  domain, cookie name).

## Acceptance criteria

- With the feature ON and the login receiver wired: a staff user logs in, and on
  subsequent requests the WAF bypass fires via the signed cookie WHILE
  `WafMiddleware` sits BEFORE `AuthenticationMiddleware`. `django_waf.W004` is not
  raised. Tampering with or expiring the cookie removes the bypass.
- With the feature OFF: behaviour is byte-identical to today, including W004
  warning when the WAF is before auth.
- A non-staff (or any excluded) user never gets the cookie and is evaluated
  normally.
- Tests cover: cookie set on staff login, WAF-before-auth bypass via cookie,
  tamper/expiry/IP-mismatch rejection, feature-off no-op, W004 suppressed when
  on.

## Files that change (all in django-waf)

- `src/django_waf/services/trusted_user_service.py` (new; mirror
  `site_password_service.py`).
- `src/django_waf/middleware.py` (`_is_staff_user` prefers cookie, falls back to
  `request.user`).
- `src/django_waf/signals.py` + an opt-in `user_logged_in` receiver / AppConfig
  wiring.
- `src/django_waf/conf.py` (new `DJANGO_WAF_TRUSTED_*` settings).
- `src/django_waf/checks.py` (W004 suppressed when the feature is enabled).
- Spec under `docs/specs/` + CHANGELOG; a released version once done.

---

To file:

    gh issue create --repo icvoss/django-waf \
      --title "Signed trusted-user cookie so the WAF recognises staff without AuthenticationMiddleware (fixes W004 ordering tension)" \
      --body-file docs/DESIGN-trusted-user-cookie.md
