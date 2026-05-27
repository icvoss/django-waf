"""Defence contract for the form-protection subsystem.

A defence is one focused check (honeypot, time-trap, render-token, ...)
that produces a single ``Outcome``. The orchestrator
(``FormProtection``) composes defences into a chain and aggregates
their outcomes into a final verdict.

Defences are intentionally small and independently testable. A
defence:

* Reads its config from per-call ``RenderContext`` / ``EvaluateContext``
  rather than reaching into ``conf`` directly — keeps tests
  deterministic and avoids module-level state.
* Returns a single ``Outcome`` per evaluation; never raises through.
  Any internal failure should produce a ``flag`` or ``pass`` outcome
  with a reason rather than blowing up the form.
* Renders zero or more hidden inputs at form render time
  (``render_fields``). Defences that don't need browser cooperation
  (e.g. ``CredentialThrottleDefence``) return an empty dict.

Per PRD §3 (the per-defence contract subsection).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from django.utils.safestring import SafeString

Verdict = Literal["pass", "flag", "block"]
"""The three states a single defence can return."""


# ---------------------------------------------------------------------------
# Outcome — a defence's single-call result
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Outcome:
    """A single defence's verdict on a submission.

    Frozen so a defence can't accidentally mutate its outcome after
    returning; the orchestrator only reads.

    * ``verdict`` — pass / flag / block. ``block`` is reserved for
      defences with deterministic certainty (honeypot non-empty,
      invalid signature). ``flag`` adds to the orchestrator's
      cumulative score and may cross the block threshold once enough
      defences agree.
    * ``score`` — added to the form's total only when the verdict is
      ``flag``. A ``pass`` always contributes 0; a ``block`` short-
      circuits the chain.
    * ``reason`` — short structured string (``defence_name:detail``,
      e.g. ``time_trap:too_fast``) for logs and the
      ``X-WAF-Form-Verdict`` debug header. Must not contain
      PII — the IP is logged separately at the orchestrator level.
    * ``public_message`` — rarely populated. Only used when a defence
      surfaces a user-facing error (e.g. \"please complete the
      challenge\"). Empty by default so the orchestrator can show a
      generic message.
    """

    verdict: Verdict
    score: float = 0.0
    reason: str = ""
    public_message: str = ""


# Convenience factories — defences read more clearly as
# ``return passed()`` than ``return Outcome(verdict="pass")``.
def passed() -> Outcome:
    """Outcome shorthand for a clean pass."""
    return Outcome(verdict="pass")


def flagged(score: float, reason: str, public_message: str = "") -> Outcome:
    """Outcome shorthand for a non-decisive flag."""
    return Outcome(verdict="flag", score=score, reason=reason, public_message=public_message)


def blocked(reason: str, score: float = 0.0, public_message: str = "") -> Outcome:
    """Outcome shorthand for a hard block.

    ``score`` is optional — most blocks short-circuit the chain and
    the score is unused, but recording one lets the orchestrator log
    the score that *would* have accrued if the chain had continued.
    """
    return Outcome(verdict="block", score=score, reason=reason, public_message=public_message)


# ---------------------------------------------------------------------------
# Render and evaluate contexts
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RenderContext:
    """Inputs available to a defence at form render time.

    ``form_id`` and ``request`` are always present. The defence reads
    whatever else it needs from ``request`` (IP, user, UA) — kept
    flexible so adding a new piece of context later doesn't force
    every defence to update its signature.

    ``config`` is the per-defence config dict, lifted out of the
    ``FormProtection`` instance. Defences read settings from here, not
    from the global ``conf`` module, so per-form overrides flow
    through naturally and tests can construct contexts directly.
    """

    form_id: str
    request: Any  # Django HttpRequest; typed as Any to keep imports light
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvaluateContext:
    """Inputs available to a defence at submit time.

    Mirrors ``RenderContext`` plus the parsed token payload (when the
    render-token defence has already verified one — defences run in a
    fixed order so later defences can rely on earlier ones having
    populated this). ``token_payload`` is None when the render-token
    defence isn't in the chain or hasn't yet been called.

    ``submitted_data`` is the POST data the orchestrator received,
    passed through so defences can read their own hidden fields
    without each one re-parsing ``request.POST``.
    """

    form_id: str
    request: Any
    submitted_data: dict[str, Any]
    config: dict[str, Any] = field(default_factory=dict)
    token_payload: Any = None  # TokenPayload | None; deferred import to avoid cycles


# ---------------------------------------------------------------------------
# Defence protocol
# ---------------------------------------------------------------------------


class Defence(Protocol):
    """Structural type that every defence implements.

    Protocol (not ABC) because defences are usually short stateless
    classes — duck-typing keeps the boilerplate down and makes test
    doubles trivial to construct.

    ``name`` is the stable snake_case identifier used in reasons,
    log fields, the score-weights config, and the X-WAF-Form-Verdict
    header. Don't change it casually — it's effectively public API.
    """

    name: str

    def render_fields(self, ctx: RenderContext) -> dict[str, SafeString]:
        """Return hidden inputs to inject into the rendered form.

        Map of field name → already-safe HTML string. Empty dict if
        this defence doesn't need browser cooperation.
        """
        ...

    def evaluate(self, ctx: EvaluateContext) -> Outcome:
        """Inspect the submitted data + request. Return a single Outcome."""
        ...
