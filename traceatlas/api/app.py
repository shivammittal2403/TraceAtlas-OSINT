"""FastAPI application factory.

NOTE: FastAPI is an optional dependency (`pip install 'traceatlas-api[api]'`).
If it is not installed, importing this module raises a clear error instead of
silently degrading. The API exposes read-only status plus case/objective
drafting endpoints; it does NOT run investigations yet.
"""

from __future__ import annotations


def create_app():  # pragma: no cover - exercised only when FastAPI is installed
    try:
        from fastapi import FastAPI
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "FastAPI is not installed. Install the api extra to run the web API."
        ) from exc

    from traceatlas.api.routes import cases, health, objectives
    from traceatlas.bootstrap import build_application
    from traceatlas.version import __version__

    app = FastAPI(title="TraceAtlas-Automator API", version=__version__)
    app.state.application = build_application()
    app.include_router(health.router)
    app.include_router(cases.router)
    app.include_router(objectives.router)
    return app
