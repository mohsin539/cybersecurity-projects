"""Entry point: GUI by default, CLI --selftest mode for CI/frozen-exe smoke test."""

import sys

from src import cli, gui


def main():
    if len(sys.argv) > 1:
        sys.exit(cli.main())
    gui.main()


if __name__ == "__main__":
    main()