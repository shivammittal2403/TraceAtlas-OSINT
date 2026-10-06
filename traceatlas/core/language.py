"""Language tag helpers (BCP-47 subset)."""

from __future__ import annotations

KNOWN_LANGUAGES = {
    "en": "English",
    "hi": "Hindi",
    "mr": "Marathi",
    "ta": "Tamil",
    "te": "Telugu",
    "bn": "Bengali",
    "zh": "Chinese",
    "es": "Spanish",
    "fr": "French",
    "ar": "Arabic",
    "ru": "Russian",
    "pt": "Portuguese",
}


def normalize_language(tag: str) -> str:
    base = tag.lower().split("-")[0]
    return base if base in KNOWN_LANGUAGES else "und"
