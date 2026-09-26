interface Stat {
  label: string;
  value: number | string;
  tone?: 'default' | 'good' | 'warn' | 'danger' | 'accent';
}

interface StatsBarProps {
  stats: Stat[];
}

export function StatsBar({ stats }: StatsBarProps) {
  return (
    <div className="stats-bar">
      {stats.map((s) => (
        <div className={`stat-chip tone-${s.tone ?? 'default'}`} key={s.label}>
          <span className="stat-value">{s.value}</span>
          <span className="stat-label">{s.label}</span>
        </div>
      ))}
    </div>
  );
}