import { useEffect, useState } from "react";
import type { Campaign } from "../types";
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

export default function Campaigns({ role }: { role: string }) {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [name, setName] = useState("Q3 Phishing Drill - Motijheel");
  const [vector, setVector] = useState("email");
  const [templates, setTemplates] = useState<{ id: number; name: string }[]>([]);
  const [lands, setLands] = useState<{ id: number; name: string }[]>([]);
  const [templateId, setTemplateId] = useState<number | undefined>();
  const [landId, setLandId] = useState<number | undefined>();
  const [branch, setBranch] = useState("Motijheel");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  function refresh() {
    api.campaigns().then(setCampaigns).catch((e) => setErr((e as Error).message));
  }

  useEffect(() => {
    refresh();
    api.templates().then((t) => {
      setTemplates(t);
      if (t[0]) {
        setTemplateId(t[0].id);
      }
    }).catch(() => undefined);
    api.landingPages().then((l) => {
      setLands(l);
      if (l[0]) {
        setLandId(l[0].id);
      }
    }).catch(() => undefined);
  }, []);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api.createCampaign({
        name,
        vector,
        templates: templateId ? [templateId] : [],
        landing_pages: landId ? [landId] : [],
        branches: [branch],
        divisions: [],
      });
      setMsg("Campaign created (draft). It needs admin + security approval before launch.");
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function approve(id: number) {
    try {
      await api.approveCampaign(id);
      setMsg("Approval step submitted.");
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function launch(id: number) {
    try {
      await api.launchCampaign(id);
      setMsg("Campaign launched — lures are being delivered in the simulator.");
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div>
      <div className="card">
        <h3>Create Phishing Campaign</h3>
        <form className="form-grid" onSubmit={create}>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Campaign name" />
          <select value={vector} onChange={(e) => setVector(e.target.value)}>
            <option value="email">Email + Landing Page</option>
            <option value="sms">SMS Smishing</option>
            <option value="voice">Vishing (voice)</option>
          </select>
          <select value={templateId ?? ""} onChange={(e) => setTemplateId(Number(e.target.value) || undefined)}>
            {templates.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <select value={landId ?? ""} onChange={(e) => setLandId(Number(e.target.value) || undefined)}>
            {lands.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="Branch filter" />
          <button className="btn primary" type="submit">Create Draft</button>
        </form>
        {msg && <div className="note">{msg}</div>}
        {err && <div className="err">{err}</div>}
      </div>

      <div className="card">
        <h3>Campaign Lifecycle</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Vector</th><th>Status</th><th>Funnel</th><th>Sent</th><th>Opened</th><th>Clicked</th><th>Submitted</th><th>Reported</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {campaigns.map((c) => {
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
                      <span className="muted">{pct}%</span>
                    </span>
                  </td>
                  <td>{c.sent}</td>
                  <td>{c.opened}</td>
                  <td>{c.clicked}</td>
                  <td>{c.submitted}</td>
                  <td>{c.reported}</td>
                  <td className="row">
                    {c.status === "draft" || c.status === "review" ? (
                      <button className="btn gold" onClick={() => approve(c.id)}>Approve</button>
                    ) : null}
                    {c.status === "approved" ? (
                      <button className="btn primary" onClick={() => launch(c.id)}>Launch</button>
                    ) : null}
                    <span className="muted">{role}</span>
                  </td>
                </tr>
              );
            })}
            {campaigns.length === 0 && <tr><td colSpan={10} className="muted">No campaigns.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}