import { useEffect, useState } from "react";
import type { LureTemplate, LandingPage } from "../types";
import { api } from "../api";

export default function Templates({ role }: { role: string }) {
  const [templates, setTemplates] = useState<LureTemplate[]>([]);
  const [lands, setLands] = useState<LandingPage[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const [tName, setTName] = useState("");
  const [tLang, setTLang] = useState("en");
  const [tSubject, setTSubject] = useState("");
  const [tBody, setTBody] = useState("");

  const [lName, setLName] = useState("");
  const [lTitle, setLTitle] = useState("");
  const [lBody, setLBody] = useState("");

  function refresh() {
    api.templates().then(setTemplates).catch((e) => setErr((e as Error).message));
    api.landingPages().then(setLands).catch((e) => setErr((e as Error).message));
  }

  useEffect(refresh, []);

  const canWrite = role === "admin" || role === "security";

  async function addTemplate(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api.createTemplate({ name: tName, language: tLang, subject: tSubject, body_html: tBody });
      setMsg("Lure template added — sandboxed and read-only in the simulator.");
      setTName("");
      setTSubject("");
      setTBody("");
      refresh();
    } catch (e2) {
      setErr((e2 as Error).message);
    }
  }

  async function addLanding(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api.createLandingPage({ name: lName, title: lTitle, body_html: lBody });
      setMsg("Landing/lure page added to the lure fabric library.");
      setLName("");
      setLTitle("");
      setLBody("");
      refresh();
    } catch (e2) {
      setErr((e2 as Error).message);
    }
  }

  const langLabel: Record<string, string> = { en: "English", bn: "বাংলা" };

  return (
    <div>
      <div className="card">
        <h3>Template & Lure Engine</h3>
        <p className="hint">
          Bengali/English lure clones, A/B variants and sandboxed landing pages.
          Everything authored here is stored server-side and bound to campaign variants at launch —
          the simulator never sends a single real message outside the bank.
        </p>
        {msg && <div className="note">{msg}</div>}
        {err && <div className="err">{err}</div>}
      </div>

      {canWrite && (
        <div className="card">
          <h3>Compose E-mail Lure Template</h3>
          <form className="form-grid" onSubmit={addTemplate}>
            <input value={tName} onChange={(e) => setTName(e.target.value)} placeholder="Template name" required />
            <select value={tLang} onChange={(e) => setTLang(e.target.value)}>
              <option value="en">English</option>
              <option value="bn">বাংলা (Bengali)</option>
            </select>
            <input value={tSubject} onChange={(e) => setTSubject(e.target.value)} placeholder="E-mail subject line" required />
            <textarea
              value={tBody}
              onChange={(e) => setTBody(e.target.value)}
              placeholder='HTML body — {full_name} and {click_url} are injected at delivery time'
              required
            />
            <button className="btn primary" type="submit">Save Template</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>E-mail Lure Library</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Language</th><th>Subject</th><th>Body (preview)</th></tr>
          </thead>
          <tbody>
            {templates.map((t) => (
              <tr key={t.id}>
                <td><b>{t.name}</b></td>
                <td>{langLabel[t.language] || t.language}</td>
                <td>{t.subject}</td>
                <td className="muted">{t.body_html.slice(0, 110)}…</td>
              </tr>
            ))}
            {templates.length === 0 && <tr><td colSpan={4} className="muted">No lure templates yet.</td></tr>}
          </tbody>
        </table>
      </div>

      {canWrite && (
        <div className="card">
          <h3>Create Landing Page (fake-login lure)</h3>
          <form className="form-grid" onSubmit={addLanding}>
            <input value={lName} onChange={(e) => setLName(e.target.value)} placeholder="Landing name" required />
            <input value={lTitle} onChange={(e) => setLTitle(e.target.value)} placeholder="Page title (banking portal)" required />
            <textarea
              value={lBody}
              onChange={(e) => setLBody(e.target.value)}
              placeholder="Body copy shown under the simulated secure sign-in form"
              required
            />
            <button className="btn primary" type="submit">Save Landing Page</button>
          </form>
        </div>
      )}

      <div className="card">
        <h3>Landing / Lure Pages</h3>
        <table>
          <thead>
            <tr><th>Name</th><th>Title</th><th>Body (preview)</th></tr>
          </thead>
          <tbody>
            {lands.map((p) => (
              <tr key={p.id}>
                <td><b>{p.name}</b></td>
                <td>{p.title}</td>
                <td className="muted">{p.body_html.slice(0, 110)}…</td>
              </tr>
            ))}
            {lands.length === 0 && <tr><td colSpan={3} className="muted">No landing pages yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}