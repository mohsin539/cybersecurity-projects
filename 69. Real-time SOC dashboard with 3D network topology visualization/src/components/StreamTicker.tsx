import { useEffect, useState } from 'react';
import type { SocMetrics, SocModule, StreamLine } from '../types';
import { Sparkline } from './Sparkline';

interface StreamTickerProps {
  stream: StreamLine[];
  metrics: SocMetrics;
  epsHistory: number[];
  alertRateHistory: number[];
  onGoto: (m: SocModule) => void;
}

function fmtClock() {
  return new Date().toLocaleTimeString('en-GB', { hour12: false });
}

export function StreamTicker({ stream, metrics, epsHistory, alertRateHistory, onGoto }: StreamTickerProps) {
  const [now, setNow] = useState(() => fmtClock());
  const [idx, setIdx] = useState(0);

  useEffect(() => {
    const t = window.setInterval(() => setNow(fmtClock()), 1000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    const t = window.setInterval(() => setIdx((i) => (stream.length ? (i + 1) % stream.length : 0)), 3200);
    return () => window.clearInterval(t);
  }, [stream.length]);

  const line = stream[idx];
  const sevClass = line ? `sev-${line.level}` : '';

  return (
    <div className="stream-ticker">
      <div className="ticker-left">
        <span className="status-dot live" />
        <span className="ticker-live">LIVE</span>
        <span className="ticker-sub">simulated WSS feed</span>
        <span className="sep">·</span>
        <span className="ticker-clock">{now}</span>
      </div>
      <div className="ticker-center">
        {line ? (
          <button
            className={`ticker-msg ${sevClass}`}
            onClick={() => onGoto(line.module)}
            title={`Open ${line.module}`}
          >
            <span className="ticker-time">{new Date(line.ts).toLocaleTimeString('en-GB', { hour12: false })}</span>
            <span className="ticker-text">{line.text}</span>
            <span className="ticker-mod">{line.module}</span>
          </button>
        ) : (
          <span className="ticker-msg">Standing by for telemetry…</span>
        )}
      </div>
      <div className="ticker-right">
        <span className="ticker-chip">
          <Sparkline data={epsHistory} width={64} height={22} color="var(--accent)" />
          <b>{Math.round(metrics.eps)}</b> EPS
        </span>
        <span className="ticker-chip">
          <Sparkline data={alertRateHistory} width={64} height={22} color="var(--warn)" />
          <b>{metrics.alertRate.toFixed(1)}</b>/min alerts
        </span>
        <span className="ticker-chip">
          <span className={`ticker-pct ${metrics.coverage > 99 ? 'good' : 'warn'}`}>{metrics.coverage.toFixed(1)}%</span>
          coverage
        </span>
      </div>
    </div>
  );
}