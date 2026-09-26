PEM-CAT: Persistence Mechanism Catalog & Matching Detection Engine
GUI-based portable desktop application implementing architecture.md.

Structure:
    main.py            entry point (also PyInstaller target)
    pemcat/
        __init__.py    package banner / version
        collect.py     host enumerators (registry, services, cron/sched tasks,
                       startup folders, WMI)
        catalog.py     canonical record, fingerprinting, SQLite storage
        rules.py       detection rule engine + embedded rule store
        report.py      report exporters (.xlsx / .csv / .html)
        audit.py       audit ledger
        ui.py          Tkinter GUI (Dashboard/Catalog/Detections/Rules/Reports/Audit)
    build.bat          onefile --windowed build for portable .exe