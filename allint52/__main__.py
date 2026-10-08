"""Run with python -m allint52 --list or python -m allint52 osint."""
import argparse
import importlib
from pathlib import Path
import sys

from . import PANELS


def main(argv=None):
    parser = argparse.ArgumentParser(description='TraceAtlas standalone desktop intelligence panels')
    parser.add_argument('panel', nargs='?', choices=sorted(PANELS))
    parser.add_argument('--list', action='store_true', help='List implemented panels without requiring Tk')
    args = parser.parse_args(argv)
    if args.list or not args.panel:
        for name, (module, _) in PANELS.items():
            print(f'{name}: {module}.py — standalone panel')
        empty = sum(p.stat().st_size == 0 for p in Path(__file__).parent.glob('*.py'))
        print(f'{empty} empty domain placeholders are not runnable employees.')
        return 0
    try:
        module, class_name = PANELS[args.panel]
        app = getattr(importlib.import_module('.' + module, __package__), class_name)()
        app.mainloop()
    except ImportError as exc:
        print(f'Panel dependency unavailable: {exc}. Install Python with Tkinter support.', file=sys.stderr)
        return 1
    except Exception as exc:
        if type(exc).__name__ != 'TclError':
            raise
        print('Desktop display unavailable. Run this panel in a local graphical session.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
