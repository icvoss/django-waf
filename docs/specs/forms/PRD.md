# PRD — Form Protection (v0.11.0)

**Status:** Draft for review
**Target release:** django-waf v0.11.0
**Author:** Nigel Copley
**Reviewers needed:** consumer project leads (Vendably first)
**Implementation branch:** `feat/v0.11.0-form-protection`

---

## 1. Context and goals

django-waf currently protects at the request layer: rate limiting, anomaly
scoring, challenges, and rule-based blocking. The middleware sees every
request but has no semantic knowledge of forms — it can't distinguish a
contact-form spam attempt from a login brute-force from a paginated GET on
a list view.

This PRD specifies a **form-protection subsystem** that runs at the form
layer, between Django's `Form.is_valid()` and the view's normal handling.
It complements the WAF rather than duplicating it: form defences feed
their findings back into the same per-IP escalation counter the WAF
already uses, so a bot that abuses both layers gets blocked sooner.

### 1.1 In scope (threats this subsystem defends against)

1. **Spam submissions** on public forms (contact, signup, comment,
   newsletter): bots filling fields with junk.
2. **Credential stuffing / brute force** on auth forms: per-account and
   per-IP attempt tracking with challenge escalation.
3. **Mass automated signup**: per-IP velocity throttling on registration.
4. **Bot-driven form submissions**: headless browsers and scripted POSTs
   against any protected form.

### 1.2 Explicitly out of scope

- **CAPTCHA fallback**. The subsystem uses honeypots + PoW + behavioural
  signals. Adding image/audio CAPTCHA is a separate decision with its
  own privacy and accessibility implications. Deferred to a later
  release if PoW proves insufficient.
- **File-upload replay through challenge**. Multipart bodies are too
  large to round-trip via session. Forms with file fields that get
  flagged for challenge show a "please resubmit after verification"
  page rather than re-POSTing the data.
- **Async / Channels forms**. v0.11.0 targets sync Django views.
  WebSocket form handling is uncommon and would benefit from a separate
  design.
- **IP allow/deny override of defences**. Operators who need to bypass
  defences for an IP do so via the existing WAF exempt-path mechanism
  or by setting `skip_for_authenticated=True` on per-form
  `FormProtection`. There is intentionally no per-IP-allowlist API on
  the form-protection layer — that lives at the WAF layer.

### 1.3 Non-goals (deliberately weaker than they could be)

- **Defences are not exact rejections**. They emit scored verdicts that
  aggregate. A single defence rarely blocks alone; the orchestrator
  decides based on cumulative score. This keeps false-positive damage
  bounded.
- **No new database tables**. All defence state lives in Redis
  (counters, token markers) and signed tokens (no server state for
  tokens themselves). Operators upgrading to v0.11.0 do not run a
  migration.

---

## 2. Architecture

### 2.1 Three entry points, one orchestrator

```
┌─────────────────────────────────────────────────────────────┐
│                    Consumer integration                      │
│                                                              │
│  Option A: Django Form mixin                                 │
│     class ContactForm(ProtectedForm, forms.Form):            │
│         waf = FormProtection(form_id="contact", ...)         │
│                                                              │
│  Option B: View decorator (for non-Form views)               │
│     @waf_protect_post(form_id="contact-handwritten",         │
│                       defences=("honeypot", "time_trap"))    │
│     def contact_view(request): ...                           │
│                                                              │
│  Option C: Template tag (for handwritten HTML forms)         │
│     <form method="post">                                     │
│       {% csrf_token %}                                       │
│       {% waf_protect form_id="contact-handwritten" %}        │
│       ...inputs...                                           │
│     </form>                                                  │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   FormProtection     │
              │      (per-form)      │
              │                      │
              │  - Holds defence     │
              │    config + weights  │
              │  - render_fields()   │
              │  - evaluate()        │
              │  - resolve_verdict() │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Defence chain      │
              │                      │
              │  HoneypotDefence     │
              │  TimeTrapDefence     │
              │  RenderTokenDefence  │
              │  UaConsistencyDefenc │
              │  JsTouchDefence      │
              │  CredentialThrottle  │
              │  SignupVelocity      │
              │  PowGateDefence      │
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Outcome aggregator │
              │                      │
              │  - sum scores        │
              │  - cross thresholds  │
              │  - emit signals      │
              │  - log structured    │
              │  - bump WAF counter  │
              └──────────────────────┘
```

The three integration points (mixin, decorator, template tag) all
construct or reference the same `FormProtection` object. The mixin is
the recommended path for new Django Form subclasses; the decorator and
template tag together cover handwritten HTML forms that don't go
through Django's Form layer (which Vendably's `contact.html` is an
example of).

### 2.2 Why three entry points

| Entry point | When to use | Pros | Cons |
|---|---|---|---|
| `ProtectedForm` mixin | Standard Django Forms | Cleanest API; runs in `clean()`; no view changes | Requires `forms.Form` subclass |
| `@waf_protect_post` decorator | Handwritten POST handlers | Works without Form; explicit at the view | Has to manually pull fields from `request.POST` |
| `{% waf_protect %}` template tag | Handwritten HTML forms | Pairs with the decorator for HTML-only forms | Template-side only — must combine with decorator |

The template tag *renders* the protected fields (honeypot, token,
JsTouch); the decorator *validates* them on POST. Used together they
cover any form, including those bypassing Django's Form layer.

### 2.3 Module layout

```
src/django_waf/forms/
    __init__.py              — re-exports ProtectedForm, FormProtection,
                               waf_protect_post
    protection.py            — FormProtection orchestrator class
    fields.py                — HoneypotField, RenderTokenField, JsTouchField
    mixin.py                 — ProtectedForm mixin
    decorators.py            — waf_protect_post
    templatetags/
        __init__.py
        waf_form_tags.py     — {% waf_protect %}
    defences/
        __init__.py
        base.py              — Defence ABC, Outcome dataclass, contexts
        honeypot.py
        time_trap.py
        render_token.py
        ua_consistency.py
        js_touch.py
        credential_throttle.py
        signup_velocity.py
        pow_gate.py
    services/
        tokens.py            — issue/verify signed form tokens (HMAC)
        markers.py           — Redis one-shot markers for replay protection
        counters.py          — per-IP / per-account / per-form counters
        replay.py            — challenge-replay session/store handling
    signals.py               — form_submission_passed / _flagged / _blocked
                               + credential_attack_observed
```

Tests mirror the structure under `tests/forms/`.

---

## 3. The defences

Each defence implements:

```python
class Defence(Protocol):
    name: str  # stable identifier (snake_case)

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """Hidden inputs (or empty dict) to inject into the rendered form.

        Called once per render. Receives the request, the form_id, and
        the per-defence config from FormProtection.
        """

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        """Inspect submitted data + request. Return a single Outcome."""
```

```python
@dataclass(frozen=True)
class Outcome:
    verdict: Literal["pass", "flag", "block"]
    score: float = 0.0
    reason: str = ""           # logged + emitted in structured event
    public_message: str = ""   # shown to user if this defence blocks (rare)
```

### 3.1 HoneypotDefence

**Threat:** Spam, scraping

**Mechanism:** Renders one or more hidden inputs with names drawn from
`DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES` (default `["url", "website",
"homepage", "email_confirm"]`). The set rotates per-form by hashing
`form_id` — same form always gets the same honeypot names (so caching
works) but different forms get different names (so bots can't learn
one set globally).

**Accessibility:**
- Visually hidden via `position: absolute; left: -9999px;` (not
  `display: none`, which most modern bots detect).
- `autocomplete="off"` to defeat password manager autofill.
- `tabindex="-1"` to skip in keyboard navigation.
- Visible screen-reader-only label: "Leave this field empty — anti-spam".
- `aria-hidden="false"` (deliberately not hidden from AT — we *want*
  screen-reader users to be told to skip, not for the field to be
  invisible to them).

**Verdict:** Any honeypot field with a non-empty value → `block`
verdict, score `5.0`, reason `"honeypot:<field_name>"`.

**Settings:**
- `DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES` — pool of names to draw from.

**False-positive considerations:** Aggressive password managers
auto-fill these. The accessibility properties above mitigate; if
operators see false positives, they can downweight via
`defence_weights`.

### 3.2 TimeTrapDefence

**Threat:** Spam

**Mechanism:** The render token records `render_time` (server time, not
client). On submit, defence checks `now - render_time` against
`DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS` (default `1.5`) and
`DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS` (default `3600`).

**Verdict:**
- `delta < 0.5s` → `block`, score `5.0`, reason `"time_trap:too_fast"`.
- `0.5s ≤ delta < min` → `flag`, score `2.0`, reason
  `"time_trap:fast"`.
- `delta > max` → `flag`, score `2.0`, reason `"time_trap:expired"`.
- Otherwise → `pass`.

**Settings:**
- `DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS` (default `1.5`)
- `DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS` (default `3600`)

**False-positive considerations:** Power users on simple forms (1-2
fields) can submit in under 1.5s. The `0.5s` hard block is for clearly
non-human speeds; the flag tier between 0.5 and 1.5 is the noisier
band.

**Per-form override is the recommended pattern** for short forms.
Newsletter signup (one email field) might set `min_fill_seconds=0.8`;
a long contact form can leave the default. The setting is exposed
both globally (`DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS`) and per-form
(`FormProtection(min_fill_seconds=...)`), with the per-form value
taking precedence.

**HTMX interaction:** `render_time` is from the *original* render, not
the most recent HTMX re-render. A user with multiple validation errors
isn't penalised. See §4.3.

### 3.3 RenderTokenDefence

**Threat:** All — this is the foundation defence

**Mechanism:** A signed token in a hidden field carries the form
identifier, IP, optional user id, render time, and a nonce. A Redis
marker keyed on the nonce is set at render time with TTL
`DJANGO_WAF_FORM_TOKEN_TTL`. On `pass` verdict from the overall chain,
the marker is deleted; on any other verdict it persists, so the user
can resubmit (e.g. after fixing a validation error).

**Token format:** HMAC-SHA256 over:
```
form_id | ip | user_id_or_empty | render_time_iso | nonce_hex
```

**Signing key:** Reads `DJANGO_WAF_SIGNING_KEY` (new in v0.11.0, package-wide;
see §7.5). This is **separate from Django's `SECRET_KEY`** so that
rotating one doesn't force rotating the other. If
`DJANGO_WAF_SIGNING_KEY` is empty, the package falls back to a
`SECRET_KEY`-derived value and a Django system check emits a Warning
recommending an explicit key. Operators are expected to set a
dedicated key in production.

**Verdict:**
- Missing/malformed/wrong-signature → `block`, score `5.0`, reason
  `"render_token:invalid"`.
- Signature OK but Redis marker absent and `delta > 5s` → `block`,
  reason `"render_token:replayed"`. (5s grace allows for re-submits
  during the marker-delete race window after a successful pass.)
- Signature OK, marker present, `expires_at < now` → `block`, reason
  `"render_token:expired"`.
- IP changed since render → `flag`, score `3.0`, reason
  `"render_token:ip_changed"`. (Mobile networks change IP; reduces
  false positives vs. blocking.)

**Settings:**
- `DJANGO_WAF_FORM_TOKEN_TTL` (default `3600`)
- `DJANGO_WAF_SIGNING_KEY` (package-wide; see §7.5)

**HTMX interaction:** See §4.3 — token persists across re-renders;
marker only deleted on successful `pass`.

### 3.4 UaConsistencyDefence

**Threat:** Scraping

**Mechanism:** The render token also carries a SHA-256 hash of the
User-Agent at render time. On submit, compare to the current UA hash.

**Verdict:**
- Hashes differ → `flag`, score `2.0`, reason
  `"ua_consistency:changed"`.
- Match → `pass`.

**False-positive considerations:** Browser updates mid-session
(extremely rare in practice — happens on restart, not mid-form). At
`2.0` it cannot block alone; only contributes alongside another flag.

### 3.5 JsTouchDefence

**Threat:** Headless bots without JS

**Mechanism:** A hidden field `waf_js_touch` rendered with value
`unset`. Inline `<script>` runs on DOM ready and sets it to a
short-lived signed value derived from the render token. Bots without
JS submit the field still containing `unset`.

**Verdict:**
- Field contains `unset` → `flag`, score `1.5`, reason
  `"js_touch:not_set"`.
- Field contains a value that doesn't match the expected derivation →
  `flag`, score `1.5`, reason `"js_touch:invalid"`.
- Correct value → `pass`.

**Accessibility:** `aria-hidden="true"`, `tabindex="-1"`, hidden via
the same CSS as honeypots. Some assistive tools clear hidden field
values; the `1.5` weight ensures this can't single-handedly block.

### 3.6 CredentialThrottleDefence

**Threat:** Credential stuffing, brute force

**Mechanism:** Two counters in Redis:
- `waf:form:cred_fail:account:<sha256(identifier)>` — per-account
  failure count, identifier hashed for privacy. Increments on every
  failed login regardless of whether the account exists (see §3.6.1).
- `waf:form:cred_fail:ip:<ip>` — per-IP failure count across all
  accounts.

Both have window TTL `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW` (default
`900` seconds, 15 min).

**Hooking into login flow:** This defence runs in `evaluate()` *after*
the form's `is_valid()` returns `False` (i.e. authentication failed).
The mixin handles this; for the decorator, the consumer calls
`waf_record_credential_failure(request, identifier)` explicitly when
auth fails.

**Verdict on submit:**
- Per-IP count ≥ `DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT` (default `20`)
  → `flag`, score `5.0`, reason `"credential_throttle:ip"`. Triggers
  challenge redirect.
- Per-account count ≥ `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT`
  (default `5`) → does **not** affect form verdict; emits
  `credential_attack_observed` signal only (see §3.6.1).
- Otherwise → `pass`.

#### 3.6.1 Account enumeration safety

**Critical constraint:** The form's user-visible behaviour must not
reveal whether an account exists. Three implications baked into the
design:

1. **The per-account counter increments on every failed login**, not
   only when the account exists. A bot trying `admin / wrongpass` and
   `nonexistent / wrongpass` both increment counters under their
   respective typed identifiers. The counter operates on the hashed
   identifier string, not on a database lookup.

2. **User-visible escalation fires on the per-IP counter, not the
   per-account.** If per-account triggered a visible challenge, it
   would leak: "your account is being attacked" tells the attacker
   the username was right. The per-account counter is
   observation-only.

3. **Constant-time defence evaluation.** All defences run before the
   form's password check. The defence chain takes the same wall-clock
   regardless of which fields were typed. Django's
   `AuthenticationForm` already runs `bcrypt` against a dummy hash
   when the user doesn't exist, so the auth check itself doesn't leak
   timing.

**The `credential_attack_observed` signal** is emitted when a
per-account counter crosses its threshold. Consumer projects connect a
handler to email the legitimate account holder (if the account exists),
notify ops, or both. The signal does not affect the response to the
attacker.

**Settings:**
- `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW` (default `900`)
- `DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT` (default `5`)
- `DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT` (default `20`)

### 3.7 SignupVelocityDefence

**Threat:** Mass automated signup

**Mechanism:** Counter `waf:form:signup:<ip>` increments on each
*successful* form pass (so it counts completed registrations, not
attempts). Window TTL
`DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW` (default `86400`, 24h).

**Verdict:**
- Count ≥ `DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT` (default `5`) → `flag`,
  score `5.0`, reason `"signup_velocity:ip"`. Challenge required for
  the next submission.
- Otherwise → `pass`. The increment happens after the form passes, so
  the user that crosses the threshold sees their challenge on the
  *next* signup, not the current one.

**Settings:**
- `DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW` (default `86400`)
- `DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT` (default `5`)

### 3.8 PowGateDefence

**Threat:** All — adds a constant CPU cost per submission

**Mechanism:** Reuses the existing WAF PoW infrastructure rather than
duplicating it. Specifically:

- **Server verification** calls
  `django_waf.services.challenge_service._digest_has_leading_zero_bits`
  — the same helper the page-level challenge uses (introduced in
  v0.10.5). One source of bit-counting logic, no risk of drift.
- **JS solver** is the same `hasLeadingZeroBits` function shipped in
  `templates/django_waf/challenge.html`. The form's protected-fields
  partial includes a minimal solver script that imports the same
  function shape; we extract it into a static asset so both the
  page-level challenge template and the form partial reference the
  same code (refactor done as part of this work).
- **Difficulty source:** form-level PoW is *lighter* than the page
  challenge by default — `DJANGO_WAF_FORM_POW_DIFFICULTY` (default
  `12` bits, ~4k hashes, ~50ms on desktop, ~200ms on mobile). The
  page-level challenge defaults are 22 (desktop) / 18 (mobile);
  form-level is intentionally lower because it runs on *every*
  submission while the page challenge fires once per session.

The token shape (digest of `form_token + nonce`) and the verifier
contract are identical to the page-level PoW, so any future
improvements to the PoW (e.g. argon2-based instead of SHA-256) land
once and benefit both.

**Solver runs on render**, not on submit. Submit reads the nonce
from the hidden field — submit itself is instant. If operators want
a guarantee the PoW is done before submit, they set
`data-waf-pow-block-submit="true"` on the form element; this disables
the submit button until the solver writes the nonce.

**Verdict:**
- Nonce missing or doesn't satisfy bit difficulty → `block`, score
  `5.0`, reason `"pow_gate:invalid"`.
- Valid → `pass`.

**Settings:**
- `DJANGO_WAF_FORM_POW_DIFFICULTY` (default `12` bits)

**Why a separate form-level PoW at all (vs. just relying on the page
challenge)?** The page challenge runs once per session and grants a
cookie; after that, every submission from that session is free. A
form-level PoW costs the bot per-submission, which is what slows
high-volume spam. The two PoWs are complementary, not redundant.

---

## 4. Token lifecycle (deep dive)

### 4.1 Issuance

On render (form GET, or any HTMX re-render that hits
`render_fields()`):

```
nonce        = secrets.token_hex(16)
render_time  = timezone.now()
ua_hash      = sha256(request.META["HTTP_USER_AGENT"])
payload      = f"{form_id}|{ip}|{user_id_or_empty}|{render_time.isoformat()}|{nonce}|{ua_hash}"
signature    = hmac.new(signing_key, payload.encode(), sha256).hexdigest()
token        = base64url(payload + "|" + signature)

redis.setex(f"waf:form:token:{nonce}", token_ttl, "1")
```

The token is the hidden field's value. The Redis marker (`"1"`) is
the one-shot indicator — its presence means "this token has not yet
been spent on a successful submission."

### 4.2 Verification (in `evaluate()`)

```
token = request.POST["waf_token"]
payload, sig = decode(token)
expected_sig = hmac(...)
if not constant_time_eq(sig, expected_sig):
    return Outcome(block, "render_token:invalid")

form_id, ip_at_render, user_at_render, render_time, nonce, ua_hash = parse(payload)

if render_time + token_ttl < now:
    return Outcome(block, "render_token:expired")

marker_exists = redis.exists(f"waf:form:token:{nonce}")
if not marker_exists:
    delta = now - render_time
    if delta > 5:  # grace window for marker-delete race
        return Outcome(block, "render_token:replayed")

if ip_at_render != current_ip:
    return Outcome(flag, score=3.0, "render_token:ip_changed")

return Outcome(pass)
```

### 4.3 HTMX re-render semantics

Vendably (and others) re-render forms via HTMX after validation
errors. The semantics must be: **the same token survives all
re-renders of the same form session.**

Rule: **the Redis marker is only deleted when the orchestrator's
overall verdict is `pass`.** On `flag`, `block`, or form-level
`is_valid() == False`, the marker stays. So:

| Scenario | Marker after submit |
|---|---|
| Form passed validation + defences | Deleted |
| Form failed Django validation (e.g. missing field) | Kept |
| Form passed validation, defence flagged | Kept (challenge replay) |
| Form passed validation, defence blocked | Kept (no replay benefit but no harm) |

When the user fixes the form and re-submits with the same token, the
marker is still there. Token TTL still bounds the window: a user with
50 validation errors over an hour eventually hits expiry and gets a
new token on the next render.

**Constraint for consumers:** When using HTMX, the protected fields
must be in the swapped fragment. If `hx-target` excludes them, the
form loses its token on re-render and the next submit will fail.
Document this in the operator runbook.

### 4.4 Token replay window analysis

- Between issuance and first submit: marker present → replay impossible.
- Between successful submit and marker delete: ~5ms in normal Redis,
  bounded by the 5s grace window. An attacker would need to intercept
  the response and replay the token in under 5s; in practice, the
  CSRF token rotates on session updates so this is doubly bounded.
- After successful submit + marker delete: marker absent + delta > 5s
  → block. Replay closed.
- After TTL: token expired regardless of marker. Replay closed.

---

## 5. Challenge replay flow

When the orchestrator's verdict is `flag` and
`DJANGO_WAF_FORM_CHALLENGE_ON_FLAG=True` (default), the user is
redirected to the existing WAF challenge view, then the form is
re-POSTed automatically after the challenge passes.

### 5.1 Sequence

```
1. User submits form.
2. FormProtection.evaluate() returns Outcome(flag, score=3.5,
   defences=["time_trap", "ua_consistency"]).
3. FormProtection persists submitted POST data to
   request.session["waf_form_replay"]:
     {
       "form_id": "contact",
       "post_url": "/contact/",
       "data": {sanitized_post_data},
       "files": [<list of file fields excluded from replay>],
       "csrf_token": <new CSRF token bound to session>,
       "expires_at": now + 60s,
     }
   Password fields and file fields are EXCLUDED from replay data.
4. Bump waf:challenged:<ip> counter (cross-layer escalation).
5. Emit form_submission_flagged signal.
6. Return HttpResponseRedirect to
     /waf/challenge/?next=/contact/&form_replay=<token>
   where <token> is a short-lived signed reference to the
   session-stored replay data.
7. User solves the challenge.
8. WAF VerifyView, on success, checks for form_replay parameter.
9. If present, validate the replay token, fetch the data from session,
   re-construct the POST, and dispatch the original view with the
   restored data.
10. The view sees a normal POST. The form's defences run again — but
    this time the user has a valid waf_pass cookie, so the
    UaConsistencyDefence sees a fresh UA (it does — first submit was
    pre-challenge, second is post-challenge with same UA) and the
    RenderToken has been refreshed... actually this needs care.
```

### 5.2 Token state on replay

The challenge passes do **not** automatically re-issue a form token.
The original render token is still in the replay data and gets POSTed
along. The RenderTokenDefence re-evaluates it; on the replay POST, the
flags that triggered the challenge (time_trap, ua_consistency) might
re-fire. To prevent an infinite loop:

**Rule:** When the VerifyView replays a POST, it adds a header
`X-WAF-Challenge-Passed: <signed marker>` and the FormProtection
orchestrator treats this as "skip behavioural defences this submit"
(but **not** integrity defences like render_token and honeypot — those
still run, because the data is the same as the original submit and
those didn't fire then anyway).

Defences are classified:
- **Integrity** (always run): RenderToken, Honeypot, PowGate.
- **Behavioural** (skipped on challenge replay): TimeTrap, UaConsistency,
  JsTouch.
- **Throttle** (always run): CredentialThrottle, SignupVelocity.

### 5.3 Sensitive data omission

Replay data **must not** contain:
- Password fields (any field name matching `/pass(word)?/i`).
- File upload fields (multipart bodies; oversized for session
  storage).
- Any field marked `sensitive=True` in the form definition (custom
  marker for operators who want to exclude additional fields).

For login forms: the password field is omitted, so on challenge
replay the user is shown a "please re-enter your password" page
rather than auto-replayed. Acceptable UX cost for the security
benefit.

For forms with file uploads: the user is shown "verification
successful, please resubmit your form" with the form data
pre-filled from session except the file fields.

### 5.4 CSRF rotation

A fresh CSRF token is generated when the challenge passes and bound
to the replayed POST. This prevents CSRF attacks that exploit the
challenge as a CSRF bypass.

### 5.5 Failure modes

| Failure | Behaviour |
|---|---|
| Session storage unavailable | Fall back to form-level rejection (no replay) |
| Replay token expired (60s TTL) | Show form pre-filled, ask user to resubmit |
| Form fields changed between original POST and replay | Show form pre-filled, ask user to resubmit |
| User navigates away during challenge | Session expires; form data lost |

The replay flow is best-effort UX. Failing back to "please resubmit"
is always safe.

---

## 6. Score aggregation and verdict resolution

After all defences run, the orchestrator computes a final verdict.

```python
def resolve_verdict(outcomes: list[Outcome]) -> FormVerdict:
    if any(o.verdict == "block" for o in outcomes):
        return FormVerdict.BLOCKED

    total = sum(o.score for o in outcomes if o.verdict == "flag")

    if total >= DJANGO_WAF_FORM_BLOCK_THRESHOLD:  # default 5.0
        return FormVerdict.BLOCKED
    if total >= DJANGO_WAF_FORM_FLAG_THRESHOLD:   # default 2.0
        return FormVerdict.FLAGGED
    return FormVerdict.PASSED
```

### 6.1 Verdict actions

| Verdict | Form behaviour | Logging | Counter | Signal |
|---|---|---|---|---|
| `PASSED` | Form validates normally | Sampled (`DJANGO_WAF_LOG_SAMPLE_RATE`) | — | `form_submission_passed` |
| `FLAGGED` | Challenge redirect (or generic error if challenge disabled) | Always logged | Bump `waf:challenged:<ip>` | `form_submission_flagged` |
| `BLOCKED` | `forms.ValidationError("submission rejected")` | Always logged | Bump `waf:challenged:<ip>` | `form_submission_blocked` |

The challenge counter bump on FLAGGED is the cross-layer integration:
form defences and WAF request defences share the same escalation
threshold (`DJANGO_WAF_CHALLENGE_ESCALATION_THRESHOLD`), so a bot abusing
both layers gets auto-blocked sooner.

---

## 7. Configuration

### 7.1 Top-level settings

```python
DJANGO_WAF_FORM_PROTECTION_ENABLED          = True
DJANGO_WAF_FORM_FLAG_THRESHOLD              = 2.0
DJANGO_WAF_FORM_BLOCK_THRESHOLD             = 5.0
DJANGO_WAF_FORM_CHALLENGE_ON_FLAG           = True
DJANGO_WAF_FORM_REPLAY_STORE                = "session"  # "session" | "redis"
DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL          = False      # opt-in; busy sites
                                                      # don't want the hot
                                                      # path firing signals
```

Plus the **package-wide signing key** (see §7.4):

```python
DJANGO_WAF_SIGNING_KEY                      = ""         # dedicated WAF HMAC
                                                      # secret; falls back to
                                                      # SECRET_KEY-derived
                                                      # value with W003
                                                      # warning if unset
```

### 7.2 Per-defence settings

```python
DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES        = ["url", "website", "homepage", "email_confirm"]
DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS       = 1.5
DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS       = 3600
DJANGO_WAF_FORM_TOKEN_TTL                   = 3600
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW  = 900
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT   = 5
DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT         = 20
DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW      = 86400
DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT       = 5
DJANGO_WAF_FORM_POW_DIFFICULTY              = 12
```

### 7.3 Global score weights (overridable per-form)

```python
DJANGO_WAF_FORM_DEFENCE_WEIGHTS = {
    "honeypot": 5.0,
    "time_trap": 2.0,
    "render_token": 5.0,
    "ua_consistency": 2.0,
    "js_touch": 1.5,
    "credential_throttle": 5.0,
    "signup_velocity": 5.0,
    "pow_gate": 5.0,
}
```

### 7.4 Package-wide signing key

```python
DJANGO_WAF_SIGNING_KEY = os.environ.get("DJANGO_WAF_SIGNING_KEY", "")
```

**New in v0.11.0.** A dedicated signing secret for any HMAC the WAF
issues — form render tokens, future signed verdicts, and challenge
tokens (which currently derive from `SECRET_KEY`; the v0.11.0 work
migrates them onto this key so all WAF-issued signatures share one
rotation lifecycle).

**Why separate from `SECRET_KEY`:** rotating `SECRET_KEY` invalidates
all Django sessions; coupling the WAF's signed tokens to it means
rotating one forces rotating the other and vice versa. A dedicated
key lets operators rotate WAF signatures on a security-driven cadence
without logging users out.

**Defaults and fallback:** if `DJANGO_WAF_SIGNING_KEY` is empty, the
package derives a key from `SECRET_KEY` (so v0.10.x → v0.11.0
upgrades don't break) and a Django system check (`django_waf.W003`)
emits a warning at startup recommending an explicit key. The fallback
is not silently failing; it's documented and surfaced.

**Operational guidance:** generate with
`python -c "import secrets; print(secrets.token_urlsafe(64))"` and
load from environment, the same pattern as `SECRET_KEY`.

### 7.5 Per-form override

```python
class ContactForm(ProtectedForm, forms.Form):
    waf = FormProtection(
        form_id="contact",
        defences=("honeypot", "time_trap", "render_token", "ua_consistency"),
        defence_weights={"time_trap": 4.0},  # this form's bots are faster
        min_fill_seconds=1.0,                 # this form is short, allow 1s
        skip_for_authenticated=False,         # public form
        challenge_on_flag=True,               # explicit
    )
```

---

## 8. Signals

```python
# Emitted on PASSED submissions only when
# DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL=True (default False). Busy sites can
# have 1000× more passed submissions than flagged/blocked; firing a
# signal on every one is a hidden cost in the hot path. Operators who
# want pass-event analytics opt in; everyone else pulls from the
# structured log (which already records passed submissions, sampled).
form_submission_passed = Signal()
# kwargs: form_id, ip, user_agent, user_id (or None)

# Emitted when score crosses DJANGO_WAF_FORM_FLAG_THRESHOLD.
form_submission_flagged = Signal()
# kwargs: form_id, ip, user_agent, user_id, total_score, defences (list of Outcome)

# Emitted on BLOCKED verdict (defence block OR score >= block threshold).
form_submission_blocked = Signal()
# kwargs: form_id, ip, user_agent, user_id, total_score, defences, reason

# Emitted when per-account credential failure counter crosses threshold.
# Consumer-side handler decides what to do (email user, alert ops, etc.).
credential_attack_observed = Signal()
# kwargs: identifier_hash, attempt_count, window_seconds, ip
```

All signals emitted from a non-atomic context. Receivers must not
raise; failures are logged but never propagate to the caller.

---

## 9. Logging

Every submission produces one structured log line at `INFO`:

```python
logger.info(
    "waf.form_submission",
    extra={
        "event": "waf.form_submission",
        "form_id": "contact",
        "verdict": "flagged",         # passed | flagged | blocked
        "ip": "1.2.3.4",
        "user_agent": "...",
        "user_id": None,
        "total_score": 3.5,
        "defences": [
            {"name": "honeypot", "verdict": "pass", "score": 0.0},
            {"name": "time_trap", "verdict": "flag", "score": 2.0,
             "reason": "time_trap:fast"},
            {"name": "ua_consistency", "verdict": "flag", "score": 1.5,
             "reason": "ua_consistency:changed"},
        ],
    },
)
```

Goes to the existing `django_waf` logger.

### 9.1 Sampling

- `passed` submissions: sampled at `DJANGO_WAF_LOG_SAMPLE_RATE` (same
  setting that drives request-level log sampling).
- `flagged` and `blocked`: always logged, never sampled.

### 9.2 Debug header (DEBUG=True only)

In development, the response includes:

```
X-WAF-Form-Verdict: flagged; score=3.5; defences=time_trap,ua_consistency
```

Off in production (`DEBUG=False`). Lets developers reproduce blocking
without grepping logs.

---

## 10. Operator runbook

### 10.1 "Why did legitimate user X get blocked?"

1. Grep logs for the user's IP and form_id:
   ```
   grep 'waf.form_submission' app.log | jq 'select(.ip == "1.2.3.4")'
   ```
2. Look at the `defences` array. Each entry has `name`, `verdict`,
   `score`, and `reason`. The reasons are structured strings —
   `time_trap:fast`, `ua_consistency:changed`, etc.
3. If the user reproduces the block in a dev environment, the
   `X-WAF-Form-Verdict` header surfaces the same info inline.
4. Common fixes:
   - User is a password-manager user → downweight `honeypot` or use
     fewer field names.
   - User is on mobile with frequent IP changes → downweight
     `render_token` IP-changed flag (`ip_changed_score=0.5`).
   - User fills forms very fast → lower the form's `min_fill_seconds`.

### 10.2 "Bots are still getting through"

1. Check the log for `verdict: passed` entries on the form_id. Look
   at the defences array — which ones are running, which aren't?
2. If the bot has a valid render token, it's solving the PoW and
   honeypot. Consider enabling PoW (`defences=(..., "pow_gate")`).
3. Check `total_score` distribution. If passing submissions are
   scoring 1.0–1.9 (just under the flag threshold), the threshold
   may need lowering for that form.

### 10.3 "Challenge-replay flow isn't working"

1. Check `request.session` is configured and writable.
2. Check the replay token in the redirect URL hasn't expired (60s
   TTL).
3. Check the form fields haven't changed between original POST and
   replay (e.g. dynamic field generation based on user state).
4. Disable with `DJANGO_WAF_FORM_CHALLENGE_ON_FLAG=False` as a workaround
   while investigating; flagged submissions get a generic rejection.

---

## 11. Backwards compatibility

- **No DB migrations.** All defence state in Redis or signed tokens.
- **Opt-in per form.** Adding `ProtectedForm` to a base class is one
  line per form. Upgrading django-waf to v0.11.0 changes nothing
  until a form opts in.
- **No changes to existing settings** (no defaults shifted, no
  semantics changed). All new settings are additive.
- **Existing signals unchanged.** New signals are added; existing
  ones (`request_blocked`, `challenge_failed`, etc.) are untouched.
- **Public API surface added:**
  - `django_waf.forms.ProtectedForm`
  - `django_waf.forms.FormProtection`
  - `django_waf.forms.waf_protect_post` (decorator)
  - `{% load waf_form_tags %}` and `{% waf_protect %}` (template tag)
  - 4 new signals

The version bump to v0.11.0 reflects the new public API. No breaking
changes to v0.10.x callers.

---

## 12. Test plan

Target ≥90% coverage on the new modules, matching existing project
standard.

### 12.1 Per-defence tests

One module per defence under `tests/forms/`:

- `test_honeypot.py` — empty field passes, non-empty blocks, rotating
  field names per form_id, accessibility attributes rendered.
- `test_time_trap.py` — fast submission blocks (<0.5s), slow flag
  band (0.5–min), expiry flag (>max), passes between min and max.
- `test_render_token.py` — issue, verify, replay protection, IP
  binding, UA binding, signature verification, expiry, marker
  lifecycle.
- `test_ua_consistency.py` — match passes, mismatch flags.
- `test_js_touch.py` — sentinel unchanged flags, correct value
  passes, invalid value flags.
- `test_credential_throttle.py` — per-account counter increments on
  failure, per-IP counter crosses threshold, account enumeration
  safety (same behaviour whether account exists), window expiry.
- `test_signup_velocity.py` — increments on pass, blocks when
  threshold crossed, window expiry.
- `test_pow_gate.py` — missing nonce blocks, invalid nonce blocks,
  valid nonce passes, bit-counting parity with verifier.

### 12.2 Integration tests

- `test_orchestrator.py` — score aggregation, threshold crossing,
  block precedence over flag.
- `test_mixin.py` — field injection, clean() flow, signal emission,
  skip_for_authenticated behaviour.
- `test_decorator.py` — POST handling, defence chain runs, signal
  emission.
- `test_template_tag.py` — renders correct fields, integrates with
  decorator.
- `test_challenge_replay.py` — full flow: flag → session store →
  redirect → challenge pass → replay → form succeeds. Plus failure
  modes (expired token, missing session, file upload).
- `test_htmx_re_render.py` — same token survives re-render with
  validation errors, marker not deleted until successful pass.
- `test_signals.py` — all 4 signals fire on appropriate verdicts.
- `test_cross_layer_escalation.py` — form flag bumps
  `waf:challenged:<ip>`, subsequent WAF challenge failure escalates
  to block.
- `test_enumeration_timing.py` — measure response time for existing
  vs. nonexistent accounts on a protected login form; assert delta
  under threshold.

### 12.3 What we deliberately don't test

- The exact PoW solve time on a real browser (CI is too variable).
- Cross-browser JS solver compatibility (manual smoke test pre-release).
- Real-world false-positive rate (only measurable in production).

---

## 13. Estimated work

| Block | Code | Tests | Days |
|---|---|---|---|
| Token + marker services | ~150 | ~250 | 0.5 |
| 8 defences (~80 LOC each) | ~640 | ~1100 | 3.0 |
| Orchestrator + mixin | ~250 | ~400 | 1.0 |
| Decorator + template tag | ~120 | ~200 | 0.5 |
| Challenge-replay flow | ~200 | ~400 | 1.0 |
| Signals + logging | ~80 | ~150 | 0.5 |
| Docs (README, CHANGELOG, runbook) | ~500 | — | 0.5 |
| **Total** | **~1940** | **~2500** | **~7 days** |

About one focused week. Commits land defence-by-defence within the
branch — each defence is independently testable and reviewable.

---

## 14. Resolved design decisions

The six questions originally posed during PRD review, with the
decisions taken. Resolved 2026-05-27.

1. **Challenge replay scope** — **In v0.11.0 behind a setting.**
   `DJANGO_WAF_FORM_CHALLENGE_ON_FLAG` defaults to `True`. If it lands
   buggy in production, operators flip it to `False` and flagged
   submissions get a generic rejection. Implementation lands last in
   the branch so the simpler defences are stable first.

2. **Token signing key** — **Separate, package-wide
   `DJANGO_WAF_SIGNING_KEY`.** Coupling WAF signatures to `SECRET_KEY`
   means rotating one forces rotating the other (and logs every user
   out). The new setting is package-wide because future signed-token
   uses (challenge tokens, signed verdicts) should share one key, not
   per-feature ones. See §7.4. Falls back to a `SECRET_KEY`-derived
   value with a Django system check (`django_waf.W003`) warning if
   unset, so v0.10 → v0.11 upgrades don't break.

3. **Default `time_trap` min** — **1.5s, with per-form override
   prominently documented.** Newsletter-signup-style short forms set
   `min_fill_seconds=0.8` (or lower) on their `FormProtection`.
   1.5s is the right default for a typical 3–5 field form.

4. **PoW default difficulty** — **Reuse the existing PoW
   infrastructure** rather than building a parallel implementation.
   Calls the same `_digest_has_leading_zero_bits` helper introduced
   in v0.10.5 server-side and the same `hasLeadingZeroBits` JS
   helper from the page challenge. Form-level default is `12` bits
   (~50ms desktop, ~200ms mobile) — lighter than the page challenge
   (22/18) because it runs on every submission, not once per session.
   See §3.8.

5. **HTMX documentation** — **Framework-agnostic.** Single "HTMX
   integration" subsection in the operator guide describing the
   token-survives-re-render rule (§4.3) and the
   protected-fields-must-be-in-swap constraint. No project-specific
   examples in the package; consumer projects document their own
   patterns.

6. **`form_submission_passed` default** — **Off by default**
   (`DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL = False`). Busy sites have 1000×
   more passed submissions than flagged/blocked, so firing the signal
   on every one is a hidden cost in the hot path. The structured log
   already records passed submissions (sampled at
   `DJANGO_WAF_LOG_SAMPLE_RATE`). Operators who want pass-event analytics
   opt in explicitly. `form_submission_flagged` and `_blocked` always
   fire regardless of this setting.

---

## 15. Explicitly deferred

- **CAPTCHA fallback** for when PoW proves insufficient against
  determined adversaries.
- **Async / Channels forms.** v0.11.0 is sync-only.
- **File upload replay** through challenge. Multipart bodies aren't
  round-tripped; user resubmits.
- **Per-IP allowlists** at the form-protection layer. Use the WAF
  exempt-path mechanism.
- **Machine learning** for defence weighting. Static weights; tune
  via configuration.
- **Distributed counter coordination** across multiple Redis
  instances. Single-instance Redis is the assumption (same as the
  rest of django-waf).

---

## Appendix A — Glossary

- **Defence**: a single check (honeypot, time_trap, ...) that
  produces one `Outcome`.
- **Outcome**: a defence's result — verdict (pass/flag/block) plus
  score and reason.
- **Verdict**: the orchestrator's aggregate decision — `PASSED`,
  `FLAGGED`, or `BLOCKED`.
- **Render token**: HMAC-signed payload embedded in the form at render
  time, verified on submit.
- **Marker**: short-lived Redis key indicating a token hasn't been
  spent on a successful submission yet.
- **Form ID**: stable string identifier for a form, used as a
  counter-bucket key and to namespace per-form settings.

---

## Appendix B — Settings cheat sheet

```python
# Package-wide
DJANGO_WAF_SIGNING_KEY                      = ""     # dedicated HMAC secret;
                                                  # falls back to
                                                  # SECRET_KEY-derived value
                                                  # with W003 warning if unset

# Top-level
DJANGO_WAF_FORM_PROTECTION_ENABLED          = True
DJANGO_WAF_FORM_FLAG_THRESHOLD              = 2.0
DJANGO_WAF_FORM_BLOCK_THRESHOLD             = 5.0
DJANGO_WAF_FORM_CHALLENGE_ON_FLAG           = True
DJANGO_WAF_FORM_REPLAY_STORE                = "session"
DJANGO_WAF_FORM_EMIT_PASSED_SIGNAL          = False  # opt-in; off by default

# Tokens (uses package-wide DJANGO_WAF_SIGNING_KEY for signature)
DJANGO_WAF_FORM_TOKEN_TTL                   = 3600

# Honeypot
DJANGO_WAF_FORM_HONEYPOT_FIELD_NAMES        = ["url", "website", "homepage", "email_confirm"]

# Time trap
DJANGO_WAF_FORM_TIME_TRAP_MIN_SECONDS       = 1.5
DJANGO_WAF_FORM_TIME_TRAP_MAX_SECONDS       = 3600

# Credential throttle
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_WINDOW  = 900
DJANGO_WAF_FORM_CREDENTIAL_THROTTLE_LIMIT   = 5
DJANGO_WAF_FORM_CREDENTIAL_IP_LIMIT         = 20

# Signup velocity
DJANGO_WAF_FORM_SIGNUP_VELOCITY_WINDOW      = 86400
DJANGO_WAF_FORM_SIGNUP_VELOCITY_LIMIT       = 5

# PoW
DJANGO_WAF_FORM_POW_DIFFICULTY              = 12

# Score weights (overridable per-form via defence_weights kwarg)
DJANGO_WAF_FORM_DEFENCE_WEIGHTS = {
    "honeypot": 5.0, "time_trap": 2.0, "render_token": 5.0,
    "ua_consistency": 2.0, "js_touch": 1.5,
    "credential_throttle": 5.0, "signup_velocity": 5.0,
    "pow_gate": 5.0,
}
```
