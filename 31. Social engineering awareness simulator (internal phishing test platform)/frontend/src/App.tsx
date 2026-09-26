import { useState } from "react";
import type { User } from "./types";
import { clearAuth, getUser } from "./api";
import Login from "./views/Login";
import Dashboard from "./views/Dashboard";
import Campaigns from "./views/Campaigns";
import Targets from "./views/Targets";
import Training from "./views/Training";
import Reports from "./views/Reports";
import Audit from "./views/Audit";
import Templates from "./views/Templates";

type View = "dashboard" | "campaigns" | "templates" | "targets" | "training" | "reports" | "audit";

const NAV: { key: View; label: string }[] = [
  { key: "dashboard", label: "Dashboard" },
  { key: "campaigns", label: "Campaigns" },
  { key: "templates", label: "Templates · Lures" },
  { key: "targets", label: "Targets · Directory" },
  { key: "training", label: "Training" },
  { key: "reports", label: "Reports · Exports" },
  { key: "audit", label: "Audit Chain" },
];

const TITLES: Record<View, string> = {
  dashboard: "Security Operations Dashboard",
  campaigns: "Phishing Campaign Management",
  templates: "Template & Lure Engine (.EN / .BN clones)",
  targets: "Target Directory & Lure History",
  training: "Adaptive Awareness Training",
  reports: "Reports & Compliance Exports (.xlsx / .csv / .html)",
  audit: "Tamper-Evident Audit Log",
};

export default function App() {
  const [user, setUser] = useState<User | null>(getUser());
  const [view, setView] = useState<View>("dashboard");

  async function logout() {
    clearAuth();
    setUser(null);
  }

  if (!user) {
    return <Login onLogin={setUser} />;
  }

  return (
    <>
      <aside className="sidebar">
        <div className="brand">
          SEAS
          <small>Social Engineering Simulator</small>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <button key={n.key} className={view === n.key ? "active" : ""} onClick={() => setView(n.key)}>
              {n.label}
            </button>
          ))}
        </nav>
        <div className="foot">
          <div>Signed in as <b>{user.full_name}</b></div>
          <div style={{ margin: "6px 0" }}>
            <button className="btn ghost" onClick={logout}>Sign out</button>
          </div>
          <div>RBAC role: {user.role} · OWASP-aware · ISO 27001 evidence chain</div>
        </div>
      </aside>
      <main className="main">
        <div className="topbar">
          <h1>{TITLES[view]}</h1>
          <span className="user-chip">
            {user.full_name} <span className="role">({user.role})</span>
          </span>
        </div>
        {view === "dashboard" && <Dashboard />}
        {view === "campaigns" && <Campaigns role={user.role} />}
        {view === "templates" && <Templates role={user.role} />}
        {view === "targets" && <Targets role={user.role} />}
        {view === "training" && <Training />}
        {view === "reports" && <Reports />}
        {view === "audit" && <Audit />}
      </main>
    </>
  );
}