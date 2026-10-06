"""Allow `python -m traceatlas ...` by delegating to the CLI."""

from traceatlas.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
