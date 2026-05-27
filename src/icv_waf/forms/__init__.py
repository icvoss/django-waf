"""Public API for the icv_waf form-protection subsystem.

The flat surface is small on purpose — consumers integrate via one of
three entry points:

* ``ProtectedForm`` — Django Form mixin (block 5).
* ``waf_protect_post`` — view decorator (block 6).
* ``{% waf_protect %}`` — template tag (block 6).

Plus the orchestrator and signals for advanced use.
"""

from __future__ import annotations

from icv_waf.forms.mixin import ProtectedForm
from icv_waf.forms.protection import (
    FormEvaluationResult,
    FormProtection,
    FormVerdict,
)
from icv_waf.forms.signals import (
    credential_attack_observed,
    form_submission_blocked,
    form_submission_flagged,
    form_submission_passed,
)

__all__ = [
    "FormEvaluationResult",
    "FormProtection",
    "FormVerdict",
    "ProtectedForm",
    "credential_attack_observed",
    "form_submission_blocked",
    "form_submission_flagged",
    "form_submission_passed",
]
