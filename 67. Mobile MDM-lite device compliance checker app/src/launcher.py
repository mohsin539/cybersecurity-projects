"""PyInstaller entry point that imports the finished package."""
import sys

from mdmcheck.main import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        sys.stderr.write(f"FATAL: {e!r}\n")
        sys.exit(1)