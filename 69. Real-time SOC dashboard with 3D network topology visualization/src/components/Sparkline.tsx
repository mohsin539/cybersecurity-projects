interface SparklineProps {
  data: number[];
  width?: number;
  height?: number;
  color?: string;
}

export function Sparkline({ data, width = 120, height = 30, color = 'var(--accent)' }: SparklineProps) {
  if (data.length < 2) return <svg width={width} height={height} aria-hidden />;
  const min = Math.min(...data);
  const max = Math.max(...data);
  const span = max - min || 1;
  const step = width / (data.length - 1);
  const pts = data.map((v, i) => `${(i * step).toFixed(1)},${(height - 3 - ((v - min) / span) * (height - 6)).toFixed(1)}`);
  return (
    <svg width={width} height={height} aria-hidden viewBox={`0 0 ${width} ${height}`}>
      <defs>
        <linearGradient id={`spark-fill-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <polygon points={`0,${height} ${pts.join(' ')} ${width},${height}`} fill={`url(#spark-fill-${color})`} />
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth="1.6" />
    </svg>
  );
}