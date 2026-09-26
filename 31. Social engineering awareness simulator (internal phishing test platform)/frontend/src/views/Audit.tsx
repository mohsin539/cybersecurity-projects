import { useEffect, useState } from "react";
import type { AuditEntry } from "../types";
import { api } from "../api";

export default function Audit() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.audit().then(setEntries).catch((e) => setErr((e as Error).message));
  }, []);

  return (
    <div>
      <div className="card">
        <h3>Tamper-Evident Audit Chain</h3>
        <p className="hint">
          Each event is hashed with the previous chain hash (SHA-256 over {`"prev_hash|actor|action|target|detail|ts"`}).
          Any modification to a past record breaks verification — satisfying ISO 27001 evidence and
          bank regulatory traceability.
        </p>
        {err && <div className="err">{err}</div>}
        <table>
          <thead>
            <tr><th>#</th><th>Actor</th><th>Action</th><th>Target</th><th>Detail</th><th>Hash (short)</th><th>Timestamp</th></tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <tr key={e.id}>
                <td className="muted">{e.id}</td>
                <td>{e.actor}</td>
                <td><b>{e.action}</b></td>
                <td>{e.target_type}{e.target_id ? " #" + e.target_id : ""}</td>
                <td className="muted">{e.detail}</td>
                <td>{e.hash.slice(0, 16)}…</td>
                <td className="muted">{e.created_at}</td>
              </tr>
            ))}
            {entries.length === 0 && <tr><td colSpan={7} className="muted">No audit entries yet.</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}