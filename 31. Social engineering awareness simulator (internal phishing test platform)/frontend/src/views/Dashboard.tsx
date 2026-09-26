import { useEffect, useState } from "react";
import type { Dashboard } from "../types";
import { api } from "../api";

function Pill({ s }: { s: string }) {
  const cls =
    s === "running" || s === "approved" || s === "completed"
      ? "green"
      : s === "review" || s === "draft"
      ? "amber"
      : s === "rejected" || s === "failed"
      ? "red"
      : "slate";
  return <span className={"pill " + cls}>{s}</span>;
}

function seLevel(score: number): "low" | "medium" | "high" | "critical" {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 15) return "medium";
  return "low";
}

function SeGauge({ score }: { score: number }) {
  return (
    <span className="se-gauge">
      <span className={"dot " + seLevel(score)} />
      <b>{score.toFixed(1)}</b>
    </span>
  );
}

export default function Dashboard() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => setError((e as Error).message));
  }, []);

  if (error) return <div className="card"><div className="err">{error}</div></div>;
  if (!data) return <div className="card">Loading dashboard…</div>;

  return (
    <div>
      <div className="kpis">
        <div className="kpi"><div className="v">{data.total_employees}</div><div className="l">Employees</div></div>
        <div className="kpi alt1"><div className="v">{data.total_campaigns}</div><div className="l">Campaigns</div></div>
        <div className="kpi alt2"><div className="v">{data.total_sent}</div><div className="l">Lures Delivered</div></div>
        <div className="kpi alt3"><div className="v">{data.total_clicked}</div><div className="l">Clicked</div></div>
        <div className="kpi"><div className="v">{data.total_submitted}</div><div className="l">Credential Drop</div></div>
        <div className="kpi alt4"><div className="v">{data.total_reported}</div><div className="l">Reported by Staff</div></div>
        <div className="kpi alt1"><div className="v">{data.avg_se_index.toFixed(1)}</div><div className="l">Avg SE-Index (0–100)</div></div>
      </div>

      <div className="card">
        <h3>Campaign Overview</h3>
        <table>
          <thead>
            <tr><th>Campaign</th><th>Vector</th><th>Status</th><th>Funnel</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Reported</th></tr>
          </thead>
          <tbody>
            {data.campaigns.map((c) => {
              const pct = c.sent ? Math.round((c.clicked / c.sent) * 100) : 0;
              const heat = pct >= 40 ? "hot" : pct >= 20 ? "warm" : "";
              return (
                <tr key={c.id}>
                  <td>{c.name}</td>
                  <td>{c.vector}</td>
                  <td><Pill s={c.status} /></td>
                  <td>
                    <span className="funnel">
                      <span className="bar"><i className={heat} style={{ width: pct + "%" }} /></span>
                      <span className="muted">{pct}% click</span>
                    </span>
                  </td>
                  <td>{c.sent}</td>
                  <td>{c.opened}</td>
                  <td>{c.clicked}</td>
                  <td>{c.submitted}</td>
                  <td>{c.reported}</td>
                </tr>
              );
            })}
            {data.campaigns.length === 0 && (
              <tr><td colSpan={9} className="muted">No campaigns yet — create one from the Campaigns tab.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Top Risk Employees</h3>
        <table>
          <thead>
            <tr><th>Employee</th><th>Branch</th><th>SE-Index</th><th>Risk</th><th>Clicks</th><th>Credential Drops</th><th>Training OK</th></tr>
          </thead>
          <tbody>
            {data.top_risk.map((r) => (
              <tr key={r.employee_code}>
                <td>{r.full_name} <span className="muted">({r.employee_code})</span></td>
                <td>{r.branch}</td>
                <td><SeGauge score={r.se_index} /></td>
                <td><span className={"pill " + (r.se_index >= 70 ? "red" : r.se_index >= 40 ? "amber" : r.se_index >= 15 ? "violet" : "green")}>{seLevel(r.se_index)}</span></td>
                <td>{r.clicks}</td>
                <td>{r.submissions}</td>
                <td>{r.trainings_ok ? <span className="ok-badge">Yes</span> : <span className="pill amber">Needs training</span>}</td>
              </tr>
            ))}
            {data.top_risk.length === 0 && <tr><td colSpan={7} className="muted">Awaiting campaign data.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}