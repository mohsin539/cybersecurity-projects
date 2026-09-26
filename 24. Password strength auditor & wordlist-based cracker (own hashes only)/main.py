import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--cli":
        from src import cli

        raise SystemExit(cli.main(argv[1:]))
    from src.gui.app import main as gui_main

    gui_main()


if __name__ == "__main__":
    main()