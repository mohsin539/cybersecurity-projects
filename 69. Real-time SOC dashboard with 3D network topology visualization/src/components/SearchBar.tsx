import { useEffect, useRef, useState } from 'react';
import type { BHNode } from '../types';

const KIND_ICON = {
  user: (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden>
      <path d="M12 12a5 5 0 1 0 0-10 5 5 0 0 0 0 10Zm0 2c-4.4 0-8 2.6-8 6v2h16v-2c0-3.4-3.6-6-8-6Z" />
    </svg>
  ),
  computer: (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden>
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <path d="M9 21h6m-3-4v4" stroke="currentColor" strokeWidth="2" fill="none" />
    </svg>
  ),
  group: (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden>
      <circle cx="9" cy="8" r="3.5" />
      <circle cx="17" cy="9" r="2.5" />
      <path d="M2.5 19c0-3.3 2.9-5.5 6.5-5.5s6.5 2.2 6.5 5.5v1h-13v-1ZM16 14c2.6.5 4.5 2.4 4.5 4.8V20H17" fill="none" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  ),
  domain: (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" aria-hidden>
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="2" />
      <path d="M3 12h18M12 3c2.4 2.3 3.6 5.4 3.6 9s-1.2 6.7-3.6 9c-2.4-2.3-3.6-5.4-3.6-9S9.6 5.3 12 3Z" fill="none" stroke="currentColor" strokeWidth="2" />
    </svg>
  ),
} as const;

interface SearchBarProps {
  nodes: BHNode[];
  onPick: (id: string) => void;
  onClearSelection: () => void;
}

export function SearchBar({ nodes, onPick, onClearSelection }: SearchBarProps) {
  const [q, setQ] = useState('');
  const [open, setOpen] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);

  const qq = q.trim().toLowerCase();
  const results = qq
    ? nodes
        .filter((n) => n.name.toLowerCase().includes(qq) || n.label.toLowerCase().includes(qq))
        .slice(0, 40)
    : [];

  useEffect(() => {
    const onClick = (ev: MouseEvent) => {
      if (!boxRef.current?.contains(ev.target as Node)) setOpen(false);
    };
    window.addEventListener('pointerdown', onClick);
    return () => window.removeEventListener('pointerdown', onClick);
  }, []);

  return (
    <div className="search" ref={boxRef}>
      <svg className="search-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.2-3.2" />
      </svg>
      <input
        value={q}
        onChange={(e) => {
          setQ(e.target.value);
          setOpen(true);
        }}
        onFocus={() => setOpen(true)}
        placeholder="Search users, computers, groups…"
        aria-label="Search nodes"
      />
      {q && (
        <button className="search-clear" onClick={() => { setQ(''); onClearSelection(); }} aria-label="Clear">
          ×
        </button>
      )}
      {open && qq && (
        <div className="search-dropdown">
          {results.length === 0 && <div className="search-empty">No matches in {nodes.length} nodes</div>}
          {results.map((n) => (
            <button
              key={n.id}
              className="search-item"
              onClick={() => {
                onPick(n.id);
                setOpen(false);
              }}
            >
              <span className={`kind-dot kind-${n.kind}`} aria-hidden>
                {KIND_ICON[n.kind]}
              </span>
              <span className="search-name">{n.label}</span>
              <span className="search-kind">{n.kind}</span>
              {n.owned && <span className="badge badge-danger">OWNED</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}