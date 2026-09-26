import time

ACTOR = "analyst"

EVENT_SCAN_START = "scan-start"
EVENT_SCAN_DONE = "scan-done"
EVENT_MATCH_RUN = "matching-run"
EVENT_REPORT_XLSX = "report-xlsx"
EVENT_REPORT_CSV = "report-csv"
EVENT_REPORT_HTML = "report-html"
EVENT_EXPORT_BUNDLE = "export-bundle"


def log(storage, action, object_id=None, detail=None):
    storage.audit(ACTOR, action, object_id, detail)


def stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%S")