"""Produce an Authorization record suggestion from parser output.

The resolver never *grants* authorization; it only reflects what the human
stated, and policy defaults to the most restrictive mode.
"""

from __future__ import annotations

from traceatlas.core.authorization import Authorization
from traceatlas.core.enums import AuthorizationMode
from traceatlas.core.objective_spec import ObjectiveSpec


def suggested_authorization(case_id: str, spec: ObjectiveSpec) -> Authorization:
    return Authorization(
        case_id=case_id,
        mode=spec.authorization_mode,
        granted_by="",  # must be filled by a human before enforcement
        evidence_reference="" if spec.authorization_mode == AuthorizationMode.PUBLIC_ONLY else "MISSING",
    )
