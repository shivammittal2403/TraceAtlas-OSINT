"""TraceAtlas CLI (stdlib argparse).

Commands are deliberately limited to what actually works: doctor, parse
(objective), plan, and catalog inspection. There is no `run` command because
live investigation execution is not implemented.
"""

from __future__ import annotations

import argparse
import json
import sys

from traceatlas.bootstrap import build_application
from traceatlas.version import __version__


def cmd_doctor(argv: list[str]) -> int:
    app = build_application()
    print(json.dumps({"version": app.version, **app.capabilities}, indent=2))
    return 0


def cmd_parse(argv: list[str]) -> int:
    from traceatlas.core.objective import Objective
    from traceatlas.objectives.parser import parse_objective
    from traceatlas.objectives.validator import validate_spec

    text = " ".join(argv).strip()
    if not text:
        print("usage: traceatlas parse <objective text>", file=sys.stderr)
        return 2
    obj = Objective(case_id="cli", text=text)
    spec = parse_objective(obj)
    out = spec.to_dict()
    out["validation_problems"] = validate_spec(spec)
    print(json.dumps(out, indent=2))
    return 0


def cmd_plan(argv: list[str]) -> int:
    from traceatlas.core.objective import Objective
    from traceatlas.objectives.parser import parse_objective
    from traceatlas.planning.planner import build_plan

    text = " ".join(argv).strip()
    obj = Objective(case_id="cli", text=text or "general investigation")
    spec = parse_objective(obj)
    plan = build_plan(spec)
    print(json.dumps(plan.to_dict(), indent=2))
    return 0


def cmd_catalog(argv: list[str]) -> int:
    from traceatlas.sources.registry import catalog_summary, list_catalog_files

    print(json.dumps({"files": list_catalog_files(), "entry_counts": catalog_summary()}, indent=2))
    return 0


_COMMANDS = {
    "doctor": cmd_doctor,
    "parse": cmd_parse,
    "plan": cmd_plan,
    "catalog": cmd_catalog,
}


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="traceatlas", description=__doc__)
    parser.add_argument("--version", action="version", version=f"traceatlas {__version__}")
    parser.add_argument("command", nargs="?", choices=sorted(_COMMANDS), default="doctor")
    args, rest = parser.parse_known_args(argv)
    return _COMMANDS[args.command](rest)
