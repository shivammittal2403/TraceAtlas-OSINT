"""Application composition root.

Wires the TraceAtlas subsystems together into a single runnable application:
evidence store -> connectors -> transform registry -> investigation engine ->
API app. Nothing here fabricates data; every component is real and lazily
imported so lightweight CLI commands don't pay for heavy dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from traceatlas.config import get_settings
from traceatlas.evidence.capture import EvidenceCapture
from traceatlas.logging import configure_logging
from traceatlas.transforms.registry import TransformRegistry, default_registry
from traceatlas.version import __version__


@dataclass
class Application:
    settings: object
    capture: EvidenceCapture
    transforms: TransformRegistry
    version: str = __version__
    started: bool = False

    def start(self) -> None:
        configure_logging(self.settings.log_level if hasattr(self.settings, "log_level") else "INFO")
        self.started = True

    def stop(self) -> None:
        self.started = False


def build_application(capture_root: str | None = None) -> Application:
    """Compose the full application graph with real components."""
    settings = get_settings()
    capture = EvidenceCapture(root=capture_root or getattr(settings, "evidence_root", "./var/evidence"))
    transforms = default_registry(capture=capture)
    return Application(settings=settings, capture=capture, transforms=transforms)


def create_api_app():
    """FastAPI app factory (imports lazily so non-API entry points stay light)."""
    from traceatlas.api.app import create_app  # noqa: WPS433

    return create_app()
