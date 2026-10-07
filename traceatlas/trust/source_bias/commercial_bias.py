"""Commercial/vendor bias detector (e.g. vendor blogs selling a product)."""
from __future__ import annotations

from traceatlas.trust.model import BiasType, SourceRecord
from traceatlas.trust.source_bias.model import BiasFlags

_COMMERCIAL_HINTS = ("blog", "press release", "product", "solution", "webinar", "vendor")


def detect(source: SourceRecord, flags: BiasFlags) -> BiasFlags:
    text = f"{source.title} {source.publisher} {source.url}".lower()
    if source.author_type == "commercial" or any(h in text for h in _COMMERCIAL_HINTS):
        flags.add(
            BiasType.COMMERCIAL,
            incentive="revenue/marketing interest: claims may sell a product or threat narrative",
            limitation="commercial framing; verify against primary data",
        )
    return flags
