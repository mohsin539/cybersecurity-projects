import { useEffect, useState } from "react";
import type { Training } from "../types";
import { api } from "../api";

export default function TrainingView() {
  const [items, setItems] = useState<Training[]>([]);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  function refresh() {
    api.trainings().then(setItems).catch((e) => setErr((e as Error).message));
  }

  useEffect(() => {
    refresh();
  }, []);

  async function autoAssign() {
    setErr("");
    setMsg("");
    try {
      const r = await api.autoAssign();
      setMsg("Auto-assigned training to " + r.assigned + " at-risk employee(s) by SE-Index band.");
      refresh();
    } catch (e) {
      setErr((e as Error).message);
    }
  }

  return (
    <div>
      <div className="card">
        <div className="row spread">
          <h3>Adaptive Security Awareness Training</h3>
          <button className="btn primary" onClick={autoAssign}>Auto-assign at-risk</button>
        </div>
        <p className="hint">
          Employees who clicked or submitted credentials are automatically pushed into the next
          training cohort. Completion improves their risk profile and removes them from upcoming
          re-test campaigns.
        </p>
        {msg && <div className="note">{msg}</div>}
        {err && <div className="err">{err}</div>}
      </div>

      <div className="card">
        <h3>Training Records</h3>
        <table>
          <thead>
            <tr><th>Employee ID</th><th>Title</th><th>Completed</th><th>Score</th><th>Enrolled</th></tr>
          </thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.id}>
                <td>{t.employee_id}</td>
                <td>{t.title}</td>
                <td>{t.completed ? <span className="ok-badge">Yes</span> : <span className="pill amber">Pending</span>}</td>
                <td>{t.score}</td>
                <td className="muted">{t.created_at ? t.created_at.slice(0, 16) : "—"}</td>
              </tr>
            ))}
            {items.length === 0 && <tr><td colSpan={5} className="muted">No training records yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}