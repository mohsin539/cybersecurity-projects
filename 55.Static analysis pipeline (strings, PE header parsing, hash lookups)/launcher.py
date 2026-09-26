"""PyInstaller entrypoint (project 46 / launcher pattern).

Routes to the GUI by default; forwards known CLI commands to the headless CLI
so `SAP-cli.exe scan ...` stays scriptable (same Analysis, two EXE targets).
"""
import sys

_KNOWN_CLI = {
    "scan", "verify", "seal", "info", "doctor", "ioc", "run-gui",
    "help", "--help", "-h", "--version",
}


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] in _KNOWN_CLI:
        from sap.cli import main as cli_main
        return cli_main(sys.argv[1:])
    from sap.gui import main as gui_main
    return gui_main()


if __name__ == "__main__":
    sys.exit(main())