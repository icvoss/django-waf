"""Write-time validation for user-agent regex patterns (#28).

Python's ``re`` module has no execution timeout: a pathological pattern
(nested quantifiers, alternation with overlapping branches inside a
quantified group) can exhibit catastrophic backtracking and pin a worker
process at 100% CPU on an adversarially-crafted User-Agent string, entirely
independent of whether the pattern was ever meant to match anything.
django-waf runs UA regex rules against every request's User-Agent header, so
a single bad pattern saved through the admin becomes a live ReDoS surface.

This module is the single place that decides whether a UA regex pattern is
safe to store. It is deliberately dependency-free: no ``google-re2`` or
similar RE2-backed engine is a hard dependency of this package (see the
package's ``pyproject.toml``), and adding one solely to police pattern
input would be a mandatory heavy dependency for what is fundamentally an
input-validation problem. The residual risk this leaves is documented in
:func:`validate_ua_regex_pattern`'s docstring.

Consumers: ``django_waf.admin`` (``BlockRuleAdminForm.clean_pattern`` /
``AllowRuleAdminForm.clean_pattern``). ``django_waf.models`` (model-level
``clean()``) and ``django_waf.services.threat_feed`` (import-time
validation of feed-sourced patterns) are expected to call the same
function so a catastrophic pattern is rejected regardless of entry point;
those two call sites are not wired up by this change because this module
does not own ``models.py`` or ``threat_feed.py`` — see the implementation
report for this follow-up.
"""

from __future__ import annotations

import re

__all__ = ["PatternValidationError", "validate_ua_regex_pattern"]

# Patterns longer than this are rejected outright regardless of content.
# A legitimate UA-matching pattern (even a fairly elaborate one covering
# several bot variants via alternation) fits comfortably under this; a
# pattern this long is far more likely to be adversarial or a mistake than
# a genuine rule.
MAX_PATTERN_LENGTH = 512

# Nested-quantifier shapes that are the classic catastrophic-backtracking
# trigger: a quantified group containing another quantified (sub-)expression,
# so the regex engine can partition a failing match across the outer and
# inner repetition in exponentially many ways. Examples this catches:
# (a+)+, (a*)*, (a+)*, (a*)+, (.*)*, (.+)+, and the same shapes with a
# non-capturing group `(?:...)`.
_NESTED_QUANTIFIER_RE = re.compile(
    r"""
    \(              # opening paren (capturing or non-capturing)
    (?:\?:)?        # optional non-capturing marker "?:"
    [^()]*          # inner content with no nested groups of its own
    [+*]            # inner quantifier: the group's content is itself repeated
    [^()]*
    \)              # close the group
    [+*]            # outer quantifier: the whole group is repeated again
    """,
    re.VERBOSE,
)

# Alternation inside a quantified group with overlapping branches is the
# other classic shape: (a|a)+, (a|ab)+, and similar. Detecting genuine
# branch overlap in general is undecidable in the general case; this catches
# the common textbook shape of a quantified alternation group, which is a
# strong enough signal to warrant rejection — legitimate UA patterns rarely
# need a quantified alternation group at all.
_QUANTIFIED_ALTERNATION_RE = re.compile(
    r"""
    \(
    (?:\?:)?
    [^()]*\|[^()]*  # at least one alternation inside the group
    \)
    [+*]            # the whole alternation group is then repeated
    """,
    re.VERBOSE,
)


class PatternValidationError(ValueError):
    """Raised when a UA regex pattern fails validation.

    ``str(exc)`` is a human-readable reason suitable for surfacing directly
    in a form error or a raised ``django.core.exceptions.ValidationError``.
    """


def validate_ua_regex_pattern(pattern: str) -> None:
    """Validate a UA regex pattern for write-time storage.

    Raises :class:`PatternValidationError` if the pattern:

    * is empty,
    * exceeds :data:`MAX_PATTERN_LENGTH` characters,
    * does not compile as a valid Python regex,
    * matches a known catastrophic-backtracking shape (nested quantifiers
      or a quantified alternation group).

    This is a static, syntactic check, not a proof of safety: it catches
    the well-known textbook ReDoS shapes, but Python's ``re`` engine has no
    execution timeout, so a pattern that passes this check can still, in
    principle, be adversarially slow against a sufficiently crafted input
    that this heuristic does not recognise. Operators running
    latency-sensitive deployments who need a hard guarantee should evaluate
    an RE2-backed engine (which cannot backtrack catastrophically by
    construction) rather than relying on this heuristic alone; that is a
    larger dependency decision (see this module's docstring) and is out of
    scope for the write-time guard implemented here.

    Returns ``None`` on success.
    """
    if not pattern:
        raise PatternValidationError("Pattern must not be empty.")

    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PatternValidationError(f"Pattern exceeds the maximum length of {MAX_PATTERN_LENGTH} characters.")

    try:
        re.compile(pattern)
    except re.error as exc:
        raise PatternValidationError(f"Pattern is not a valid regular expression: {exc}") from exc

    if _NESTED_QUANTIFIER_RE.search(pattern):
        raise PatternValidationError(
            "Pattern contains a nested quantifier (e.g. (a+)+ or (.*)*), which "
            "can cause catastrophic backtracking and pin a worker process at "
            "100% CPU on an adversarial User-Agent string. Rewrite the pattern "
            "to avoid repeating a group that is itself repeated."
        )

    if _QUANTIFIED_ALTERNATION_RE.search(pattern):
        raise PatternValidationError(
            "Pattern contains a quantified alternation group (e.g. (a|ab)+), "
            "which can cause catastrophic backtracking on an adversarial "
            "User-Agent string. Rewrite the pattern to avoid repeating an "
            "alternation group."
        )
