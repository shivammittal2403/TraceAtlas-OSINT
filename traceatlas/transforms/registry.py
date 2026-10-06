"""Transform registry + router: select transforms by input/output kind."""

from __future__ import annotations

from traceatlas.transforms.base import Transform


class TransformRegistry:
    def __init__(self) -> None:
        self._transforms: dict[str, Transform] = {}

    def register(self, transform: Transform) -> None:
        if transform.id in self._transforms:
            raise ValueError(f"duplicate transform id {transform.id}")
        self._transforms[transform.id] = transform

    def get(self, transform_id: str) -> Transform:
        if transform_id not in self._transforms:
            raise KeyError(f"unknown transform {transform_id!r}")
        return self._transforms[transform_id]

    def for_input(self, kind: str) -> list[Transform]:
        return [t for t in self._transforms.values() if t.input_kind == kind]

    def path(self, from_kind: str, to_kind: str, max_hops: int = 3) -> list[Transform]:
        """BFS shortest transform chain from_kind -> ... producing to_kind output."""
        from collections import deque
        q = deque([(k, [v]) for k, v in self._transforms.items()])
        seen_ids = set()
        while q:
            chain_key, chain = q.popleft()
            last = chain[-1]
            if last.id in seen_ids:
                continue
            seen_ids.add(last.id)
            for out in last.output_kinds:
                if out == to_kind:
                    return chain
                if len(chain) >= max_hops:
                    continue
                for nxt in self.for_input(out):
                    if nxt.id not in seen_ids:
                        q.append((f"{chain_key}>{nxt.id}", chain + [nxt]))
        return []

    def ids(self) -> list[str]:
        return sorted(self._transforms)


def default_registry(capture=None) -> TransformRegistry:
    """The production transform set wired to real connectors."""
    from traceatlas.transforms.certificate.from_ct import DomainToCertificateTransform
    from traceatlas.transforms.dns.to_dns import DomainToDnsTransform
    from traceatlas.transforms.domain.to_rdap import DomainToRdapTransform
    from traceatlas.transforms.ip.to_asn import IpToAsnTransform
    from traceatlas.transforms.url.derive import UrlToDomainTransform
    from traceatlas.transforms.email.derive import EmailToDomainTransform

    reg = TransformRegistry()
    for t in (DomainToDnsTransform(capture=capture),
              DomainToRdapTransform(capture=capture),
              DomainToCertificateTransform(capture=capture),
              IpToAsnTransform(capture=capture),
              UrlToDomainTransform(),
              EmailToDomainTransform()):
        reg.register(t)
    return reg
