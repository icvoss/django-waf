"""FormProtection orchestrator — composes defences into a chain.

A ``FormProtection`` instance lives on a form class (or a decorated
view) and holds the configured defence chain. It's responsible for:

* constructing defence instances from a name tuple,
* injecting per-defence config (weights + form-specific overrides),
* threading the verified token payload from RenderTokenDefence onto
  subsequent defences' EvaluateContexts,
* running the chain in deterministic order,
* aggregating Outcomes into a final ``FormVerdict``,
* consuming the Redis marker on a PASS verdict (the
  delete-on-pass-only rule that makes HTMX re-renders work).

The orchestrator is intentionally separate from the entry-point
mechanisms (mixin / decorator / template tag) — those each construct
a FormProtection and call into it, but the composition logic lives
here.

Per PRD §2.1, §3 (per-defence sections), and §6 (score aggregation).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from django_waf.forms.defences.base import (
    Defence,
    EvaluateContext,
    Outcome,
    RenderContext,
)

logger = logging.getLogger("django_waf.forms")


# ---------------------------------------------------------------------------
# FormVerdict — the orchestrator's aggregate decision
# ---------------------------------------------------------------------------


class FormVerdict(StrEnum):
    """Final verdict after all defences have run.

    String values so logs / signals carry stable identifiers without
    having to remember whether to log .name or .value.
    """

    PASSED = "passed"
    FLAGGED = "flagged"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class FormEvaluationResult:
    """What ``FormProtection.evaluate()`` returns.

    Carries the verdict plus the per-defence outcomes so callers can
    log them, fire the right signal, and assemble the
    ``X-WAF-Form-Verdict`` debug header.
    """

    verdict: FormVerdict
    total_score: float
    outcomes: list[Outcome] = field(default_factory=list)
    # The verified token payload, if RenderTokenDefence produced one.
    # Held so the orchestrator can consume the Redis marker on PASS.
    token_payload: Any = None


# ---------------------------------------------------------------------------
# Defence registry
# ---------------------------------------------------------------------------


def _build_defence(name: str, redis_factory: Callable[[], Any] | None) -> Defence:
    """Construct a defence instance by name.

    Centralised so the orchestrator (and tests) have one place to go.
    Defences that need a Redis client get the factory injected; the
    rest ignore it.
    """
    if name == "render_token":
        from django_waf.forms.defences.render_token import RenderTokenDefence

        if redis_factory is None:
            raise ValueError("render_token defence requires a redis_client_factory")
        return RenderTokenDefence(redis_client_factory=redis_factory)

    if name == "honeypot":
        from django_waf.forms.defences.honeypot import HoneypotDefence

        return HoneypotDefence()

    if name == "time_trap":
        from django_waf.forms.defences.time_trap import TimeTrapDefence

        return TimeTrapDefence()

    if name == "ua_consistency":
        from django_waf.forms.defences.ua_consistency import UaConsistencyDefence

        return UaConsistencyDefence()

    if name == "js_touch":
        from django_waf.forms.defences.js_touch import JsTouchDefence

        return JsTouchDefence()

    if name == "credential_throttle":
        from django_waf.forms.defences.credential_throttle import CredentialThrottleDefence

        if redis_factory is None:
            raise ValueError("credential_throttle defence requires a redis_client_factory")
        return CredentialThrottleDefence(redis_client_factory=redis_factory)

    if name == "signup_velocity":
        from django_waf.forms.defences.signup_velocity import SignupVelocityDefence

        if redis_factory is None:
            raise ValueError("signup_velocity defence requires a redis_client_factory")
        return SignupVelocityDefence(redis_client_factory=redis_factory)

    if name == "pow_gate":
        from django_waf.forms.defences.pow_gate import PowGateDefence

        return PowGateDefence()

    raise ValueError(f"unknown defence: {name!r}")


# Order in which defences run. Foundation first (render_token), then
# behaviour signals that depend on its payload, then unconditional
# checks, then per-form-specific ones.
_CANONICAL_ORDER = (
    "render_token",
    "honeypot",
    "time_trap",
    "ua_consistency",
    "js_touch",
    "credential_throttle",
    "signup_velocity",
    "pow_gate",
)


def scalarise_submitted_data(data) -> dict[str, str]:
    """Return a single-value-per-key dict from form-submission data.

    Defences read their hidden fields as scalar strings —
    ``ctx.submitted_data.get("waf_token")`` is expected to return the
    token, not ``[token]``. Django's ``QueryDict`` stores values as
    lists internally; ``dict(querydict)`` iterates the underlying
    storage and produces list-valued entries, which silently passes
    the truthy ``or ""`` check in defences and then crashes when the
    defence tries to ``base64.urlsafe_b64decode`` a list (v0.11.0 +
    v0.11.1 bug found in production).

    The fix: call ``.dict()`` on a ``QueryDict`` (last-value-per-key
    string semantics), else just ``dict(data)`` for plain mappings
    that tests sometimes pass.

    This function is the single seam between the entry points
    (mixin, decorator, replay) and the orchestrator. Adding it once
    here closes the class of bug: every defence-facing path goes
    through this.
    """
    # ``QueryDict.dict()`` is the scalarising accessor; we duck-type
    # against any other MultiValueDict-shaped input that exposes it.
    if hasattr(data, "dict") and callable(data.dict):
        return data.dict()
    return dict(data) if data else {}


_TOKEN_VALUE_RE = None  # lazy-compiled on first call


def _extract_token_value(fragment: str) -> str:
    """Return the contents of ``value="..."`` from a rendered <input> fragment.

    The orchestrator uses this to read back the token nonce after
    ``RenderTokenDefence.render_fields`` returns its hidden-input
    HTML. Returns the empty string if no value attribute is found
    (treated as 'no token available', and the orchestrator falls
    through without threading a nonce to later defences).
    """
    import re

    global _TOKEN_VALUE_RE  # noqa: PLW0603 — single-shot lazy compile is fine
    if _TOKEN_VALUE_RE is None:
        _TOKEN_VALUE_RE = re.compile(r'value="([^"]*)"')
    match = _TOKEN_VALUE_RE.search(fragment)
    return match.group(1) if match else ""


def _order_defences(names: tuple[str, ...]) -> tuple[str, ...]:
    """Return the configured names in canonical order.

    Operators can pass defences in any order; we re-sort so the chain
    runs deterministically and so render_token always runs first (its
    payload feeds later defences).
    """
    name_set = set(names)
    return tuple(n for n in _CANONICAL_ORDER if n in name_set)


# ---------------------------------------------------------------------------
# Default redis factory — used when the consumer doesn't supply one
# ---------------------------------------------------------------------------


def _default_redis_factory():
    """Return the package-wide Redis client (or None on failure).

    The factory shape (callable returning client) matches what
    individual defences expect, so we can swap it for tests without
    monkey-patching the conf module.
    """
    from django_waf import conf

    try:
        from django_redis import get_redis_connection

        return get_redis_connection(conf.DJANGO_WAF_REDIS_ALIAS)
    except Exception:
        try:
            from django.core.cache import cache

            return cache
        except Exception:
            return None


# ---------------------------------------------------------------------------
# FormProtection — the orchestrator
# ---------------------------------------------------------------------------


class FormProtection:
    """Composes a defence chain for one protected form.

    Construct one per form class (or per decorated view). Reused
    across requests — the orchestrator is stateless apart from its
    config; the defences themselves only hold the redis factory.

    Usage in a form mixin (block 5):

        class ContactForm(ProtectedForm, forms.Form):
            waf = FormProtection(
                form_id="contact",
                defences=("honeypot", "time_trap", "render_token"),
                defence_weights={"time_trap": 4.0},  # tighter than default
                token_ttl=1800,                       # 30 min instead of 1h
            )
    """

    def __init__(
        self,
        *,
        form_id: str,
        defences: tuple[str, ...] = ("render_token", "honeypot", "time_trap"),
        defence_weights: dict[str, float] | None = None,
        redis_client_factory: Callable[[], Any] | None = None,
        skip_for_authenticated: bool = False,
        **per_form_config: Any,
    ) -> None:
        """Construct the chain.

        * ``form_id`` — stable identifier used in counter keys, the
          honeypot's name rotation, the structured log, and the
          ``X-WAF-Form-Verdict`` header.
        * ``defences`` — names of defences to run. Re-sorted into
          canonical order so render_token always runs first.
        * ``defence_weights`` — per-defence score overrides; merged
          over ``DJANGO_WAF_FORM_DEFENCE_WEIGHTS``. Unknown names are
          accepted silently (operators may upweight future defences
          without breaking the current chain).
        * ``redis_client_factory`` — callable returning a Redis
          client; defaults to the package-wide resolver. Tests inject
          a MagicMock factory directly.
        * ``skip_for_authenticated`` — when True, only render_token
          runs for authenticated users; spam/timing defences are
          skipped on in-product forms.
        * ``per_form_config`` — any other kwarg becomes a per-defence
          config entry. e.g. ``min_fill_seconds=0.8`` reaches
          ``TimeTrapDefence`` via ``ctx.config['min_fill_seconds']``.
        """
        # Validate every name *before* re-ordering so unknown defences
        # surface at construction (app-startup) rather than silently
        # disappearing because _order_defences filters by the canonical
        # set.
        unknown = [n for n in defences if n not in _CANONICAL_ORDER]
        if unknown:
            raise ValueError(f"unknown defence(s): {', '.join(repr(n) for n in unknown)}")

        self.form_id = form_id
        self._raw_defence_names = defences
        self._defence_names = _order_defences(defences)
        self._weights = defence_weights or {}
        self._redis_factory = redis_client_factory or _default_redis_factory
        self.skip_for_authenticated = skip_for_authenticated
        self._per_form_config = per_form_config

        # Instantiate defences eagerly so construction-time errors
        # (missing redis factory for redis-using defence) surface at
        # app-startup rather than first-render.
        self._defences: dict[str, Defence] = {
            name: _build_defence(name, self._redis_factory) for name in self._defence_names
        }

    # ----- internal -------------------------------------------------------

    def _config_for(self, defence_name: str, token_nonce: str | None = None) -> dict:
        """Build the config dict passed to a defence at render/evaluate time.

        Merges, in order:
          1. ``per_form_config`` — what the operator passed to
             ``FormProtection(...)``.
          2. ``token_nonce`` if known — read by HoneypotDefence /
             JsTouchDefence / PowGateDefence to bind their rendered
             values to the active render.

        Defence-specific keys read from this dict include:
          * render_token : ``token_ttl``
          * honeypot     : ``field_names``
          * time_trap    : ``min_fill_seconds`` / ``max_fill_seconds``
          * cred_throttle: ``ip_limit``
          * signup_vel.  : ``limit``
          * pow_gate     : ``difficulty`` / ``token_nonce``
        """
        cfg = dict(self._per_form_config)
        if token_nonce is not None:
            cfg["token_nonce"] = token_nonce
        return cfg

    def _is_authenticated(self, request) -> bool:
        user = getattr(request, "user", None)
        return bool(user is not None and getattr(user, "is_authenticated", False))

    # ----- public ---------------------------------------------------------

    @property
    def defence_names(self) -> tuple[str, ...]:
        """The defences configured for this form, in run order.

        Public so the mixin/decorator/template tag can introspect
        without reaching into the private attribute.
        """
        return self._defence_names

    def render_fields(self, request) -> dict[str, str]:
        """Collect hidden inputs from every defence for this request.

        Returns a dict of ``synthetic_key → html_fragment``. Callers
        concatenate the values into the form's template. The keys
        are only used for de-duplication when multiple defences emit
        fragments under the same key.
        """
        from django_waf import conf

        if not conf.DJANGO_WAF_FORM_PROTECTION_ENABLED:
            return {}

        # In skip_for_authenticated mode, still render render_token
        # (it's the integrity check that survives across all user
        # types) but skip everything else.
        names = self._defence_names
        if self.skip_for_authenticated and self._is_authenticated(request):
            names = tuple(n for n in names if n == "render_token")

        all_fields: dict[str, str] = {}
        # First pass: render_token to learn the nonce (so we can pass
        # it to honeypot / js_touch / pow_gate).
        token_nonce: str | None = None
        if "render_token" in names:
            defence = self._defences["render_token"]
            ctx = RenderContext(
                form_id=self.form_id,
                request=request,
                config=self._config_for("render_token"),
            )
            try:
                fragments = defence.render_fields(ctx)
                all_fields.update(fragments)
                # The token rides inside the rendered <input>'s
                # ``value`` attribute. Extract it back out so the
                # nonce can be threaded onto subsequent defences'
                # ctx.config — they need it to bind their hidden
                # fields to this render (PowGateDefence + JsTouchDefence).
                #
                # We could ask the defence to expose the payload via
                # a side channel, but parsing what we just rendered
                # keeps the contract uniform: every defence's
                # ``render_fields`` returns a name → HTML mapping,
                # and the orchestrator's only structural assumption
                # is that the token sits in a ``value="..."`` attr —
                # which is also the assumption browsers will make.
                from django_waf.forms.defences.render_token import (
                    TOKEN_FIELD_NAME,
                    parse_submitted_payload,
                )

                fragment = fragments.get(TOKEN_FIELD_NAME, "")
                token_str = _extract_token_value(fragment)
                if token_str:
                    payload = parse_submitted_payload({TOKEN_FIELD_NAME: token_str})
                    if payload is not None:
                        token_nonce = payload.nonce
            except Exception:
                # Per fail-open policy: render_token failure must not
                # break form rendering. The form just renders without
                # protection fields, and submission will fail open.
                logger.exception("django-waf: render_token render_fields failed")

        # Second pass: every other defence, with token_nonce threaded in.
        for name in names:
            if name == "render_token":
                continue
            defence = self._defences[name]
            ctx = RenderContext(
                form_id=self.form_id,
                request=request,
                config=self._config_for(name, token_nonce=token_nonce),
            )
            try:
                fragments = defence.render_fields(ctx)
                all_fields.update(fragments)
            except Exception:
                logger.exception("django-waf: %s render_fields failed", name)

        return all_fields

    def evaluate(self, request, submitted_data: dict) -> FormEvaluationResult:
        """Run the defence chain against a submission, return the verdict.

        Each defence's ``evaluate`` runs in canonical order. After
        render_token verifies, its payload is threaded onto subsequent
        defences' EvaluateContexts (time_trap, ua_consistency, js_touch,
        pow_gate all read from it).

        A defence returning ``block`` short-circuits the chain — no
        further defences run, and the final verdict is BLOCKED.
        Otherwise scores accumulate; crossing
        ``DJANGO_WAF_FORM_BLOCK_THRESHOLD`` upgrades the verdict to
        BLOCKED, crossing ``DJANGO_WAF_FORM_FLAG_THRESHOLD`` to FLAGGED.
        """
        from django_waf import conf

        if not conf.DJANGO_WAF_FORM_PROTECTION_ENABLED:
            return FormEvaluationResult(verdict=FormVerdict.PASSED, total_score=0.0)

        names = self._defence_names
        if self.skip_for_authenticated and self._is_authenticated(request):
            names = tuple(n for n in names if n == "render_token")

        outcomes: list[Outcome] = []
        token_payload: Any = None

        for name in names:
            defence = self._defences[name]
            ctx = EvaluateContext(
                form_id=self.form_id,
                request=request,
                submitted_data=submitted_data,
                config=self._config_for(name, token_nonce=token_payload.nonce if token_payload else None),
                token_payload=token_payload,
            )
            try:
                outcome = defence.evaluate(ctx)
            except Exception:
                # Defence raised — log and treat as a silent pass so a
                # bug in one defence can't block legitimate users.
                logger.exception("django-waf: defence %s raised; treating as pass", name)
                outcome = Outcome(verdict="pass")
            outcomes.append(outcome)

            # Short-circuit on a hard block — no later defence's
            # verdict can revert this.
            if outcome.verdict == "block":
                total = self._aggregate_score(outcomes)
                return FormEvaluationResult(
                    verdict=FormVerdict.BLOCKED,
                    total_score=total,
                    outcomes=outcomes,
                    token_payload=token_payload,
                )

            # After render_token returns pass-or-flag, parse the
            # payload so subsequent defences can use it.
            if name == "render_token" and token_payload is None:
                from django_waf.forms.defences.render_token import parse_submitted_payload

                token_payload = parse_submitted_payload(submitted_data)

        total = self._aggregate_score(outcomes)
        verdict = self._resolve_verdict(total)
        return FormEvaluationResult(
            verdict=verdict,
            total_score=total,
            outcomes=outcomes,
            token_payload=token_payload,
        )

    def consume_token_marker(self, token_payload) -> None:
        """Delete the Redis one-shot marker after a PASS verdict.

        Called by the mixin / decorator after evaluate() returns
        PASSED. The delete-on-PASS-only rule is what makes HTMX
        re-renders work (PRD §4.3) — failed validations preserve the
        marker so the same token can be re-submitted with the same
        Redis state.
        """
        if token_payload is None:
            return
        try:
            from django_waf.forms.services.markers import consume_marker

            consume_marker(self._redis_factory(), token_payload.nonce)
        except Exception:
            logger.exception("django-waf: failed to consume token marker")

    # ----- internal verdict resolution -----------------------------------

    def _aggregate_score(self, outcomes: list[Outcome]) -> float:
        """Sum flag scores, applying per-defence weight overrides.

        Block outcomes contribute their own ``score`` field (which is
        usually 0 since the verdict short-circuits) so the total in
        the log reflects what the bot scored before the block landed.
        """
        from django_waf import conf

        weights = dict(conf.DJANGO_WAF_FORM_DEFENCE_WEIGHTS)
        weights.update(self._weights)

        total = 0.0
        for outcome, name in zip(outcomes, self._defence_names, strict=False):
            if outcome.verdict == "pass":
                continue
            # Block + flag both contribute their score field. Each
            # defence already returns its canonical score; weights
            # override on a per-defence basis.
            score = outcome.score
            if name in weights:
                # If the operator supplied a weight, treat the
                # defence's intrinsic score as a *unit* signal and
                # scale by the weight. When weight equals the
                # defence's canonical score this is a no-op.
                score = weights[name] if outcome.verdict != "pass" else 0.0
            total += score
        return total

    def _resolve_verdict(self, total_score: float) -> FormVerdict:
        from django_waf import conf

        if total_score >= conf.DJANGO_WAF_FORM_BLOCK_THRESHOLD:
            return FormVerdict.BLOCKED
        if total_score >= conf.DJANGO_WAF_FORM_FLAG_THRESHOLD:
            return FormVerdict.FLAGGED
        return FormVerdict.PASSED
