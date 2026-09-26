import argparse
import os
import sys

from pemcat import audit, collect, report, rules
from pemcat.catalog import Storage, canonical_fingerprint, db_path_for, default_data_dir
from pemcat.__init__ import APP_NAME, APP_VERSION


def run_headless(data_dir):
    storage = Storage(db_path_for(data_dir))
    storage.seed_rules(rules.BUILTIN_RULES)
    host = collect.host_id()
    records, last = collect.enumerate_all()
    for rec in records:
        rec["host_id"] = host
        rec["fingerprint_sha256"] = canonical_fingerprint(rec)
        storage.upsert_artifact(rec)
    storage.refresh_baselines()
    matches = rules.run_matching(storage)
    summary = rules.summarize(matches)
    data = report.build_report_data(storage, APP_VERSION, host)
    out = sys.stdout
    log_path = None
    if out is None:
        log_path = os.path.join(data_dir, "pemcat_headless.log")
        out = open(log_path, "w", encoding="utf-8")
    out.write("=" * 60 + "\n")
    out.write("PEM-CAT headless scan\n")
    out.write("=" * 60 + "\n")
    out.write("Host:                   {0}\n".format(host))
    out.write("Cataloged artifacts:    {0}\n".format(data["stats"]["total"]))
    out.write("By type:                {0}\n".format(data["stats"].get("by_type", {})))
    out.write("Baselined:              {0}\n".format(data["stats"]["baselined"]))
    out.write("Detection matches:      {0}\n".format(len(matches)))
    out.write("By severity:            {0}\n".format(summary["by_severity"]))
    out.write("By technique:           {0}\n".format(summary["by_technique"]))
    out.write("Last collector bundle:  {0}\n".format(last))
    out.write("Database:               {0}\n".format(storage.db_path))
    if log_path:
        out.write("Log file:               {0}\n".format(log_path))
    out.close()
    storage.close()
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Persistence Mechanism Catalog & Matching Detection Engine")
    parser.add_argument("--data-dir", help="alternative catalog database directory")
    parser.add_argument("--headless", action="store_true",
                        help="run a scan + rule matching and exit (no GUI)")
    args = parser.parse_args()

    override = args.data_dir or os.environ.get("PEMCAT_DATA_DIR")
    data_dir = override or default_data_dir()

    if args.headless:
        return run_headless(data_dir)

    try:
        from pemcat.ui import main as gui_main

        gui_main(data_dir=data_dir)
        return 0
    except Exception as exc:
        msg = "GUI launch failed: {0}".format(exc)
        if sys.stdout is not None:
            print(msg, file=sys.stderr)
        else:
            try:
                with open(os.path.join(data_dir, "pemcat_gui_error.log"), "w") as fh:
                    fh.write(msg)
            except OSError:
                pass
        if args.data_dir or "--headless" in sys.argv:
            raise
        return 1


if __name__ == "__main__":
    sys.exit(main())