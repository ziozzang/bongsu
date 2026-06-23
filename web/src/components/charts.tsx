import React, { useState } from 'react';
import { shortDate, niceMax } from '../lib/format';
import type { VulnTrendRow, ScanActivityRow } from '../api';

// Pure-SVG chart primitives + KPI card, extracted from App.tsx (no charting dep).
const CHART_W = 720; // viewBox width; charts scale responsively via preserveAspectRatio
export const SEV_KEYS = [
  { key: 'critical_count', label: 'Critical', color: 'var(--critical)', raw: '#f04444' },
  { key: 'high_count', label: 'High', color: 'var(--high)', raw: '#f07830' },
  { key: 'medium_count', label: 'Medium', color: 'var(--medium)', raw: '#e0b020' },
  { key: 'low_count', label: 'Low', color: 'var(--low)', raw: '#30c060' },
] as const;


// StackedAreaChart: severity-over-time, stacked filled areas + line tops, with
// a hover guide and tooltip showing the day's breakdown.
export function StackedAreaChart({ rows, height = 220 }: { rows: VulnTrendRow[]; height?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const padL = 44, padR = 12, padT = 12, padB = 24;
  const w = CHART_W, h = height;
  const innerW = w - padL - padR, innerH = h - padT - padB;
  const n = rows.length;
  const totals = rows.map(r => r.critical_count + r.high_count + r.medium_count + r.low_count);
  const yMax = niceMax(Math.max(1, ...totals));
  const x = (i: number) => padL + (n <= 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v: number) => padT + innerH - (v / yMax) * innerH;

  // build cumulative stacks
  const bands = SEV_KEYS.map((sev, si) => {
    const upper = rows.map(r => SEV_KEYS.slice(0, si + 1).reduce((s, k) => s + (r as unknown as Record<string, number>)[k.key], 0));
    const lower = rows.map(r => SEV_KEYS.slice(0, si).reduce((s, k) => s + (r as unknown as Record<string, number>)[k.key], 0));
    return { sev, upper, lower };
  });
  // Catmull-Rom → cubic bezier smoothing so series read as flowing curves
  // instead of angular polylines. Both stack edges use the same smoothing so
  // adjacent bands stay flush.
  const smoothPath = (pts: { px: number; py: number }[], move = true) => {
    if (pts.length === 0) return '';
    if (pts.length === 1) return `${move ? 'M' : 'L'}${pts[0].px},${pts[0].py}`;
    let d = move ? `M${pts[0].px},${pts[0].py}` : `L${pts[0].px},${pts[0].py}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
      const c1x = p1.px + (p2.px - p0.px) / 6, c1y = p1.py + (p2.py - p0.py) / 6;
      const c2x = p2.px - (p3.px - p1.px) / 6, c2y = p2.py - (p3.py - p1.py) / 6;
      d += ` C${c1x},${c1y} ${c2x},${c2y} ${p2.px},${p2.py}`;
    }
    return d;
  };
  const toPts = (vals: number[]) => vals.map((v, i) => ({ px: x(i), py: y(v) }));
  const areaPath = (upper: number[], lower: number[]) => {
    const top = smoothPath(toPts(upper));
    const bottomPts = lower.map((_, i) => ({ px: x(n - 1 - i), py: y(lower[n - 1 - i]) }));
    return `${top} ${smoothPath(bottomPts, false)} Z`;
  };
  const linePath = (upper: number[]) => smoothPath(toPts(upper));
  const labelEvery = Math.max(1, Math.ceil(n / 6));
  const gridLines = [0, 0.25, 0.5, 0.75, 1].map(f => Math.round(yMax * f));

  return (
    <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="chart-svg" style={{ height }}>
        {gridLines.map((g, i) => (
          <g key={i}>
            <line x1={padL} x2={w - padR} y1={y(g)} y2={y(g)} stroke="var(--border)" strokeWidth={1} />
            <text x={padL - 6} y={y(g) + 3} textAnchor="end" className="chart-axis-text">{g.toLocaleString()}</text>
          </g>
        ))}
        {bands.map(b => (
          <path key={b.sev.key} d={areaPath(b.upper, b.lower)} fill={b.sev.raw} fillOpacity={0.18} />
        ))}
        {bands.map(b => (
          <path key={b.sev.key + '-l'} d={linePath(b.upper)} fill="none" stroke={b.sev.raw} strokeWidth={2} strokeLinejoin="round" />
        ))}
        {rows.map((r, i) => i % labelEvery === 0 && (
          <text key={r.date} x={x(i)} y={h - 6} textAnchor="middle" className="chart-axis-text">{shortDate(r.date)}</text>
        ))}
        {hover !== null && (
          <line x1={x(hover)} x2={x(hover)} y1={padT} y2={h - padB} stroke="var(--text-muted)" strokeWidth={1} strokeDasharray="3 3" />
        )}
        {rows.map((_, i) => (
          <rect key={i} x={x(i) - (innerW / Math.max(1, n)) / 2} y={padT} width={innerW / Math.max(1, n)} height={innerH} fill="transparent" onMouseEnter={() => setHover(i)} />
        ))}
      </svg>
      {hover !== null && rows[hover] && (
        <div className="chart-tooltip" style={{ left: `${(x(hover) / w) * 100}%` }}>
          <div className="chart-tooltip-date">{shortDate(rows[hover].date)}</div>
          {SEV_KEYS.map(s => (
            <div key={s.key} className="chart-tooltip-row">
              <span className="chart-tooltip-dot" style={{ background: s.raw }} />
              <span>{s.label}</span>
              <span className="chart-tooltip-val">{(rows[hover] as unknown as Record<string, number>)[s.key].toLocaleString()}</span>
            </div>
          ))}
          <div className="chart-tooltip-row chart-tooltip-total">
            <span>Total</span>
            <span className="chart-tooltip-val">{totals[hover].toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// BarSeries: scan activity per day (completed/degraded/failed stacked bars) plus
// a thin line overlay for packages ingested (secondary axis hint in tooltip).
export function BarSeries({ rows, height = 200 }: { rows: ScanActivityRow[]; height?: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const padL = 40, padR = 40, padT = 12, padB = 24;
  const w = CHART_W, h = height;
  const innerW = w - padL - padR, innerH = h - padT - padB;
  const n = rows.length;
  const totals = rows.map(r => r.completed + r.degraded + r.failed || r.scans);
  const yMax = niceMax(Math.max(1, ...totals));
  const pkgMax = niceMax(Math.max(1, ...rows.map(r => r.packages)));
  const slot = innerW / Math.max(1, n);
  const bw = Math.min(28, slot * 0.6);
  const y = (v: number) => padT + innerH - (v / yMax) * innerH;
  const cx = (i: number) => padL + slot * i + slot / 2;
  const py = (v: number) => padT + innerH - (v / pkgMax) * innerH;
  const segs = [
    { key: 'completed' as const, color: 'var(--primary)', raw: '#7c6cf0', label: 'Completed' },
    { key: 'degraded' as const, color: 'var(--medium)', raw: '#e0b020', label: 'Degraded' },
    { key: 'failed' as const, color: 'var(--critical)', raw: '#f04444', label: 'Failed' },
  ];
  const gridLines = [0, 0.5, 1].map(f => Math.round(yMax * f));
  const pkgLine = rows.map((r, i) => `${i === 0 ? 'M' : 'L'}${cx(i)},${py(r.packages)}`).join(' ');
  const labelEvery = Math.max(1, Math.ceil(n / 6));

  return (
    <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
      <svg viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="chart-svg" style={{ height }}>
        {gridLines.map((g, i) => (
          <g key={i}>
            <line x1={padL} x2={w - padR} y1={y(g)} y2={y(g)} stroke="var(--border)" strokeWidth={1} />
            <text x={padL - 6} y={y(g) + 3} textAnchor="end" className="chart-axis-text">{g}</text>
          </g>
        ))}
        {rows.map((r, i) => {
          let acc = 0;
          return (
            <g key={r.date}>
              {segs.map(s => {
                const v = r[s.key];
                if (v <= 0) return null;
                const yTop = y(acc + v);
                const yBot = y(acc);
                acc += v;
                return <rect key={s.key} x={cx(i) - bw / 2} y={yTop} width={bw} height={Math.max(0, yBot - yTop)} fill={s.raw} rx={1} opacity={hover === null || hover === i ? 1 : 0.45} />;
              })}
            </g>
          );
        })}
        <path d={pkgLine} fill="none" stroke="var(--text-secondary)" strokeWidth={1.5} strokeDasharray="2 3" opacity={0.7} />
        {rows.map((r, i) => <circle key={r.date} cx={cx(i)} cy={py(r.packages)} r={2} fill="var(--text-secondary)" />)}
        {rows.map((r, i) => i % labelEvery === 0 && (
          <text key={r.date} x={cx(i)} y={h - 6} textAnchor="middle" className="chart-axis-text">{shortDate(r.date)}</text>
        ))}
        {rows.map((_, i) => (
          <rect key={i} x={padL + slot * i} y={padT} width={slot} height={innerH} fill="transparent" onMouseEnter={() => setHover(i)} />
        ))}
      </svg>
      {hover !== null && rows[hover] && (
        <div className="chart-tooltip" style={{ left: `${(cx(hover) / w) * 100}%` }}>
          <div className="chart-tooltip-date">{shortDate(rows[hover].date)}</div>
          {segs.map(s => (
            <div key={s.key} className="chart-tooltip-row">
              <span className="chart-tooltip-dot" style={{ background: s.raw }} />
              <span>{s.label}</span>
              <span className="chart-tooltip-val">{rows[hover][s.key].toLocaleString()}</span>
            </div>
          ))}
          <div className="chart-tooltip-row chart-tooltip-total">
            <span>Packages</span>
            <span className="chart-tooltip-val">{rows[hover].packages.toLocaleString()}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// DonutChart: current severity distribution with center total + legend.
export function DonutChart({ segments, size = 180 }: { segments: { label: string; value: number; color: string }[]; size?: number }) {
  const total = segments.reduce((s, x) => s + x.value, 0);
  const r = size / 2 - 14;
  const cx = size / 2, cy = size / 2;
  const circ = 2 * Math.PI * r;
  let offset = 0;
  const strokeW = 18;
  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="donut-svg">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--border)" strokeWidth={strokeW} />
        {total > 0 && segments.map((s) => {
          const frac = s.value / total;
          const dash = frac * circ;
          const el = (
            <circle
              key={s.label}
              cx={cx} cy={cy} r={r}
              fill="none"
              stroke={s.color}
              strokeWidth={strokeW}
              strokeDasharray={`${dash} ${circ - dash}`}
              strokeDashoffset={-offset}
              transform={`rotate(-90 ${cx} ${cy})`}
            />
          );
          offset += dash;
          return el;
        })}
        <text x={cx} y={cy - 2} textAnchor="middle" className="donut-total">{total.toLocaleString()}</text>
        <text x={cx} y={cy + 16} textAnchor="middle" className="donut-sub">findings</text>
      </svg>
      <div className="donut-legend">
        {segments.map(s => (
          <div key={s.label} className="donut-legend-row">
            <span className="donut-legend-dot" style={{ background: s.color }} />
            <span className="donut-legend-label">{s.label}</span>
            <span className="donut-legend-val">{s.value.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// Sparkline: tiny line for stat cards.
export function Sparkline({ values, width = 90, height = 28, color = 'var(--primary)' }: { values: number[]; width?: number; height?: number; color?: string }) {
  if (values.length < 2) return <svg width={width} height={height} aria-hidden="true" />;
  const min = Math.min(...values), max = Math.max(...values);
  const span = max - min || 1;
  const x = (i: number) => (i / (values.length - 1)) * (width - 2) + 1;
  const y = (v: number) => height - 3 - ((v - min) / span) * (height - 6);
  const d = values.map((v, i) => `${i === 0 ? 'M' : 'L'}${x(i)},${y(v)}`).join(' ');
  const area = `${d} L${x(values.length - 1)},${height} L${x(0)},${height} Z`;
  return (
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`} aria-hidden="true" className="sparkline">
      <path d={area} fill={color} fillOpacity={0.12} />
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// KPI stat card with optional delta + sparkline for the ops console.
export function KpiCard({ label, value, accent, delta, deltaInverse, spark, sparkColor, onClick, sub }: {
  label: string; value: React.ReactNode; accent: string; delta?: number | null; deltaInverse?: boolean; spark?: number[]; sparkColor?: string; onClick?: () => void; sub?: React.ReactNode;
}) {
  const hasDelta = delta !== undefined && delta !== null && Number.isFinite(delta);
  // For findings, an increase is "bad" (red). deltaInverse flips that.
  const positive = hasDelta && delta! > 0;
  const negative = hasDelta && delta! < 0;
  const goodWhenDown = !deltaInverse;
  const deltaColor = !hasDelta || delta === 0 ? 'var(--text-muted)'
    : (positive === goodWhenDown ? 'var(--critical)' : 'var(--low)');
  return (
    <div className={`kpi-card${onClick ? ' kpi-card-clickable' : ''}`} onClick={onClick} role={onClick ? 'button' : undefined} tabIndex={onClick ? 0 : undefined}
      onKeyDown={onClick ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick(); } } : undefined}>
      <div className="accent-bar" style={{ background: accent }} />
      <div className="kpi-top">
        <div className="kpi-label">{label}</div>
        {spark && spark.length >= 2 && <Sparkline values={spark} color={sparkColor || accent} />}
      </div>
      <div className="kpi-value tnum" style={{ color: accent }}>{value}</div>
      <div className="kpi-foot">
        {hasDelta && (
          <span className="kpi-delta tnum" style={{ color: deltaColor }}>
            {positive ? '▲' : negative ? '▼' : '■'} {Math.abs(delta!).toLocaleString()}
            <span className="kpi-delta-note"> vs 7d</span>
          </span>
        )}
        {sub && <span className="kpi-sub">{sub}</span>}
      </div>
    </div>
  );
}
