from __future__ import annotations

import sys


def main(argv=None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in ("cli", "--cli"):
        from .cli import main as cli_main

        return cli_main(args[1:])
    from .app import main as gui_main

    return gui_main([sys.argv[0], *args])


if __name__ == "__main__":
    raise SystemExit(main())
