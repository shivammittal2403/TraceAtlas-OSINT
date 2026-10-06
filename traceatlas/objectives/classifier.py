"""Determine investigation type from objective wording (keyword rules)."""

from __future__ import annotations

_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("infrastructure", ("ip", "asn", "domain", "dns", "hosting", "certificate", "subnet")),
    ("company", ("company", "corporation", "llc", "ltd", "registry", "procurement", "filing")),
    ("person", ("person", "individual", "who is", "identify the")),
    ("username", ("username", "handle", "nickname", "alias")),
    ("social", ("social media", "twitter", "linkedin", "facebook", "instagram", "telegram")),
    ("cti", ("malware", "ioc", "threat actor", "cve", "ransomware", "botnet")),
    ("media", ("image", "photo", "video", "audio", "exif")),
    ("leak", ("breach", "leak", "exposed", "dump")),
]


def classify_investigation_type(text: str) -> str:
    lowered = text.lower()
    scores = {
        kind: sum(1 for kw in keywords if kw in lowered) for kind, keywords in _RULES
    }
    best = max(scores, key=lambda k: (scores[k], -list(scores).index(k)))
    return best if scores[best] > 0 else "general"
