import { useEffect, useState } from "react";
import type { Delivery, Employee } from "../types";
import { api } from "../api";

export default function Targets({ role }: { role: string }) {
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [fullName, setFullName] = useState("");
  const [empCode, setEmpCode] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [branch, setBranch] = useState("Motijheel");
  const [division, setDivision] = useState("Operations");
  const [grade, setGrade] = useState("Assistant Officer");

  function refresh() {
    api.targets().then(setEmployees).catch((e) => setErr((e as Error).message));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    setMsg("");
    try {
      await api.addTarget({
        employee_code: empCode,
        full_name: fullName,
        email,
        phone,
        branch,
        division,
        job_grade: grade,
        risk_weight: 1.0,
      });
      setMsg("Employee registered. Consent record + do-not-phish flag are set to defaults.");
      setFullName("");
      setEmpCode("");
      setEmail("");
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function toggleOpt(id: number) {
    try {
      await api.toggleOptOut(id);
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  async function showDeliveries(id: number) {
    setSelected(id);
    const cs = await api.campaigns();
    const out: Delivery[] = [];
    for (const c of cs) {
      const ds = await api.deliveries(c.id);
      out.push(...ds.filter((d) => d.employee_code === employees.find((x) => x.id === id)?.employee_code));
    }
    setDeliveries(out);
  }

  const canAdd = role === "admin" || role === "hr";

  return (
    <div>
      <div className="card">
        <h3>Target Directory (Employees)</h3>
        <table>
          <thead>
            <tr><th>Code</th><th>Name</th><th>Email</th><th>Phone</th><th>Branch</th><th>Grade</th><th>Do-Not-Phish</th><th>History</th></tr>
          </thead>
          <tbody>
            {employees.map((e) => (
              <tr key={e.id}>
                <td>{e.employee_code}</td>
                <td>{e.full_name}</td>
                <td>{e.email}</td>
                <td>{e.phone}</td>
                <td>{e.branch}</td>
                <td>{e.job_grade}</td>
                <td>
                  {e.opt_out ? <span className="pill red">excluded</span> : <span className="pill green">eligible</span>}
                  {canAdd && (
                    <button className="btn ghost" onClick={() => toggleOpt(e.id)} style={{ marginLeft: 6 }}>
                      Toggle
                    </button>
                  )}
                </td>
                <td>
                  <button className="btn ghost" onClick={() => showDeliveries(e.id)}>View</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <div className="card">
          <h3>Delivery / Lure History</h3>
          <table>
            <thead>
              <tr><th>Campaign</th><th>Status</th><th>Opened At</th><th>Clicked At</th><th>Submitted At</th><th>Action</th></tr>
            </thead>
            <tbody>
              {deliveries.map((d) => (
                <tr key={d.id}>
                  <td className="muted">{d.full_name}</td>
                  <td>{d.status}</td>
                  <td>{d.opened_at ? d.opened_at.slice(0, 16) : "—"}</td>
                  <td>{d.clicked_at ? d.clicked_at.slice(0, 16) : "—"}</td>
                  <td>{d.submitted_at ? d.submitted_at.slice(0, 16) : "—"}</td>
                  <td>
                    <a className="btn ghost" href={d.click_url} target="_blank" rel="noreferrer">Preview lure</a>
                  </td>
                </tr>
              ))}
              {deliveries.length === 0 && <tr><td colSpan={6} className="muted">No lure deliveries recorded.</td></tr>}
            </tbody>
          </table>
        </div>
      )}

      {canAdd && (
        <div className="card">
          <h3>Register Employee (import-style single record)</h3>
          <form className="form-grid" onSubmit={add}>
            <input value={empCode} onChange={(e) => setEmpCode(e.target.value)} placeholder="BD012" required />
            <input value={fullName} onChange={(e) => setFullName(e.target.value)} placeholder="Full name" required />
            <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@bank.example.com" type="email" required />
            <input value={phone} onChange={(e) => setPhone(e.target.value)} placeholder="+880-1XXXXXXXXX" />
            <input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="Branch" />
            <input value={division} onChange={(e) => setDivision(e.target.value)} placeholder="Division" />
            <input value={grade} onChange={(e) => setGrade(e.target.value)} placeholder="Job grade" />
            <button className="btn primary" type="submit">Add</button>
          </form>
          {msg && <div className="note">{msg}</div>}
          {err && <div className="err">{err}</div>}
        </div>
      )}
    </div>
  );
}