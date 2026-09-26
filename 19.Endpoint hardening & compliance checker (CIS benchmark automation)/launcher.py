"""PyInstaller entrypoint: GUI by default; `--cli` for headless; `--demo` offline mode."""
import multiprocessing
import sys


def main():
    multiprocessing.freeze_support()  # required for spawn on frozen Windows
    argv = sys.argv[1:]
    if "--cli" in argv:
        rest = argv[argv.index("--cli") + 1:]
        from cisguard.cli import main as cli_main

        raise SystemExit(cli_main(rest))
    from cisguard.app import main as app_main

    # forward --demo through app.main
    sys.argv = [sys.argv[0]] + argv
    raise SystemExit(app_main())


if __name__ == "__main__":
    main()
