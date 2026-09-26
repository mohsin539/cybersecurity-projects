import { useState } from 'react'
import { api } from '../api'

export default function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('analyst')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true); setError('')
    try {
      await api.login(username, password)
      onDone()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Sign-in failed')
    } finally { setBusy(false) }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-ink-950 text-slate-200">
      <form onSubmit={submit} className="w-full max-w-sm bg-ink-800 border border-ink-700 rounded-2xl p-8 shadow-glow">
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-xl bg-accent/15 border border-accent/40 grid place-items-center text-accent font-bold">SG</div>
          <div>
            <h1 className="font-semibold tracking-tight">SentinelGraph</h1>
            <p className="text-xs text-slate-400">AD Attack Path Visualizer — Lab</p>
          </div>
        </div>
        <label className="block text-xs text-slate-400 mb-1">Username</label>
        <input value={username} onChange={e => setUsername(e.target.value)}
               className="w-full mb-4 bg-ink-900 border border-ink-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent" />
        <label className="block text-xs text-slate-400 mb-1">Password</label>
        <input type="password" value={password} onChange={e => setPassword(e.target.value)}
               className="w-full mb-5 bg-ink-900 border border-ink-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-accent" />
        {error && <p className="mb-3 text-sm text-danger">{error}</p>}
        <button disabled={busy} className="w-full bg-accent text-ink-950 font-semibold rounded-lg py-2 text-sm hover:bg-accent/90 disabled:opacity-50">
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
        <p className="mt-5 text-[11px] leading-relaxed text-slate-500">
          Lab accounts — admin / analyst / auditor (see README). Tokens are held in memory only and expire in 15 minutes.
        </p>
      </form>
    </div>
  )
}
