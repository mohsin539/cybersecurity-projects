import { useEffect, useState } from "react";
import type { Report } from "../types";
import { api, getToken } from "../api";

const fmtLabel: Record<string, string> = {
  xlsx: "Excel (charts + 4 sheets)",
  csv: "CSV (UTF-8 BOM, Excel-safe)",
  html: "Self-contained HTML report",
};

export default function Reports() {
  const [reports, setReports] = useState<Report[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  function refresh() {
    api.reports().then(setReports).catch((e) => setErr((e as Error).message));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function generate(fmt: string) {
    setErr("");
    setMsg("");
    try {
      const r = await api.createReport(fmt);
      setMsg("Report ready: " + r.name);
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  function download(report: Report) {
    const token = getToken();
    fetch(api.reportUrl(report.url_token), {
      headers: token ? { Authorization: "Bearer " + token } : {},
    })
      .then((res) => {
        if (!res.ok) throw new Error(res.statusText);
        return res.blob();
      })
      .then((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = report.name;
        a.click();
        URL.revokeObjectURL(url);
      })
      .catch((e) => setErr((e as Error).message));
  }

  return (
    <div>
      <div className="card">
        <div className="row spread">
          <h3>Security Metrics Exports</h3>
          <div className="row">
            <button className="btn primary" onClick={() => generate("xlsx")}>Generate .xlsx</button>
            <button className="btn primary" onClick={() => generate("csv")}>Generate .csv</button>
            <button className="btn primary" onClick={() => generate("html")}>Generate .html</button>
          </div>
        </div>
        <p className="hint">
          Reports are produced server-side from live campaign data, wrapped with an HMAC-signed download
          token (expires in 15 minutes) and an immutable hash entry appended to the audit chain.
        </p>
        {msg && <div className="note">{msg}</div>}
        {err && <div className="err">{err}</div>}
      </div>

      <div className="card">
        <h3>Generated Report Bundles</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Format</th><th>Size</th><th>Status</th><th>Created</th><th>Download</th></tr>
          </thead>
          <tbody>
            {reports.map((r) => (
              <tr key={r.id}>
                <td>{r.name}</td>
                <td>{fmtLabel[r.fmt] || r.fmt}</td>
                <td>{r.size} bytes</td>
                <td>{r.status === "ready" ? <span className="pill green">ready</span> : <span className="pill amber">{r.status}</span>}</td>
                <td className="muted">{r.created_at ? r.created_at.slice(0, 16) : "—"}</td>
                <td>
                  <button className="btn ghost" onClick={() => download(r)}>Download</button>
                </td>
              </tr>
            ))}
            {reports.length === 0 && <tr><td colSpan={6} className="muted">No reports generated yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}