import { useState } from "react";
import { api, saveAuth } from "../api";
import type { User } from "../types";

export default function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      const res = await api.login(username, password);
      saveAuth(res.access_token, res.user);
      onLogin(res.user);
    } catch (err) {
      setError((err as Error).message || "Login failed");
    }
  }

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>SEAS · Security Operations</h1>
        <p>Social Engineering Awareness Simulator — Bank Phishing Test Platform</p>
        <label htmlFor="u">Username</label>
        <input id="u" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        <label htmlFor="p">Password</label>
        <input id="p" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        {error && <div className="err">{error}</div>}
        <div style={{ marginTop: 16 }}>
          <button className="btn primary" style={{ width: "100%", justifyContent: "center" }}>Sign in securely</button>
        </div>
        <p className="hint">
          Seeded accounts: admin / security / hr / auditor. Passwords documented in backend/app/seed.py (Admin@12345 for admin).
        </p>
      </form>
    </div>
  );
}