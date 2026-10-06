"""Transform: Email → mail domain (deterministic, no network)."""

from __future__ import annotations

from traceatlas.core.validation import is_valid_email
from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult


class EmailToDomainTransform(Transform):
    id = "transform.email_to_domain"
    name = "Email to Domain"
    input_kind = "email"
    output_kinds = ("domain",)
    requires_network = False

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=False)
        email = ti.value.lower().strip()
        if not is_valid_email(email):
            res.errors.append(f"invalid email: {email!r}")
            return res
        domain = email.split("@", 1)[1]
        ekey = f"email:{email}"
        dkey = f"domain:{domain}"
        res.entities.append(EntityDraft("email", ekey, email))
        res.entities.append(EntityDraft("domain", dkey, domain))
        res.relationships.append(RelationshipDraft(
            ekey, "related_to", dkey, confidence=1.0))
        res.ok = True
        return res
