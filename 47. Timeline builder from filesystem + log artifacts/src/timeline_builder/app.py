from __future__ import annotations

import sys

from . import __version__


def _extract_case(argv: list[str]) -> tuple[list[str], str | None]:
    case = None
    cleaned: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--case" and index + 1 < len(argv):
            case = argv[index + 1]
            index += 2
            continue
        if token.startswith("--case="):
            case = token.split("=", 1)[1]
            index += 1
            continue
        cleaned.append(token)
        index += 1
    return cleaned, case


def main(argv=None) -> int:
    raw = list(sys.argv if argv is None else argv)
    qt_argv, case = _extract_case(raw[1:])
    try:
        from PySide6.QtWidgets import QApplication
    except Exception:
        print("PySide6 is required for the GUI.")
        print("Install it with:  pip install -r requirements.txt")
        print("Or use the CLI:   python -m timeline_builder cli --help")
        return 1

    from .config import AppSettings
    from .ui.main_window import MainWindow
    from .ui.theme import apply_theme

    app = QApplication([raw[0], *qt_argv])
    app.setApplicationName("TimelineBuilder")
    app.setApplicationVersion(__version__)
    app.setOrganizationName("DFIR Engineering")
    settings = AppSettings()
    apply_theme(app, settings.theme)
    window = MainWindow(settings=settings, case_path=case)
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
