"""Transform: URL → registrable domain (deterministic, no network)."""

from __future__ import annotations

from urllib.parse import urlparse

from traceatlas.core.validation import is_valid_domain
from traceatlas.transforms.base import EntityDraft, RelationshipDraft, Transform, TransformInput, TransformResult

_TWO_LEVEL_TLDS = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.jp", "co.in",
                   "com.br", "co.za", "com.cn", "com.mx", "co.nz", "com.sg", "com.tr"}


def registrable_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _TWO_LEVEL_TLDS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


class UrlToDomainTransform(Transform):
    id = "transform.url_to_domain"
    name = "URL to Domain"
    input_kind = "url"
    output_kinds = ("domain",)
    requires_network = False

    def run(self, ti: TransformInput) -> TransformResult:
        res = self._result(ti, ok=False)
        parsed = urlparse(ti.value)
        host = (parsed.hostname or "").lower()
        if not host:
            res.errors.append(f"url has no host: {ti.value!r}")
            return res
        ukey = f"url:{ti.value}"
        res.entities.append(EntityDraft("url", ukey, ti.value,
                                        {"scheme": parsed.scheme, "path": parsed.path}))
        d = registrable_domain(host)
        if is_valid_domain(d):
            dkey = f"domain:{d}"
            res.entities.append(EntityDraft("domain", dkey, d))
            res.relationships.append(RelationshipDraft(
                ukey, "related_to", dkey, evidence_ids=[], confidence=1.0))
            res.ok = True
        else:
            res.errors.append(f"host {host!r} yields no valid registrable domain")
        return res
