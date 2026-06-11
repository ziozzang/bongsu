import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { api, setApiKey, getApiKey, clearApiKey, setSession, getSession, clearSession, hasAuth, onAuthFailure, type Host, type UserAccount, type ProcessSnapshot, type PortInfo, type Vuln, type Pkg, type Stats, type FilterOptions, type Scan, type ScanRequest, type HealthStatus, type CveDbEntry, type CveAffectedPackage, type CveReferenceGroupSummary, type CveDbStatsResponse, type CveSourceStat, type CveRematchPolicy, type CveEpssMergeStats, type CveDbQuality, type InstallerStatus, type SecurityDbOperationalStatus, type AgentFleetStatus, type ContainerAsset, type VulnSummaryRow, type AuditLog, type AccessSubject, type AccessPolicy, type AccessControlStatus, type ScheduledScan, type AssetGroup, type AssetGroupDetail, type VulnTrendRow, type ScanActivityRow, type VulnTrendSummary, type AtRiskHost, type Recommendation, type PostureComparison, type ExecutiveSummary, type SLAComplianceReport, type RiskBreakdownRow, type NotificationRule, type NotificationLogEntry } from './api';

const verCmp = (a: string, b: string): number => {
  const pa = versionSegments(a);
  const pb = versionSegments(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }
  const aPre = isPreReleaseVersion(a);
  const bPre = isPreReleaseVersion(b);
  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (aPre && bPre) return comparePreRelease(a, b);
  return 0;
};

const preReleaseMarkers = ['dev', 'snapshot', 'preview', 'pre', 'alpha', 'beta', 'rc'];

function versionSegments(v: string): number[] {
  const clean = stripPreReleaseSuffix(v.trim().replace(/^v?/, '').replace(/^[0-9]+:/, ''));
  return clean.split(/[^0-9]+/).filter(Boolean).map((p) => Number.parseInt(p, 10)).filter((n) => Number.isFinite(n));
}

function isPreReleaseVersion(v: string): boolean {
  const clean = v.toLowerCase().split('+')[0];
  return clean.includes('~') || preReleaseMarkers.some((m) => clean.includes(m));
}

function stripPreReleaseSuffix(v: string): string {
  const low = v.toLowerCase();
  let cut = low.includes('+') ? low.indexOf('+') : v.length;
  const tilde = low.indexOf('~');
  if (tilde >= 0 && tilde < cut) cut = tilde;
  preReleaseMarkers.forEach((marker) => {
    const idx = low.indexOf(marker);
    if (idx >= 0 && idx < cut) cut = idx;
  });
  return v.slice(0, cut).replace(/[-_.]+$/, '');
}

function comparePreRelease(a: string, b: string): number {
  const [ar, an] = preReleaseRank(a);
  const [br, bn] = preReleaseRank(b);
  if (ar !== br) return ar - br;
  return an - bn;
}

function preReleaseRank(v: string): [number, number] {
  const clean = v.toLowerCase().split('+')[0];
  for (let i = 0; i < preReleaseMarkers.length; i++) {
    const marker = preReleaseMarkers[i];
    if (clean.includes(marker)) return [i + 1, preReleaseNumber(clean, marker)];
  }
  if (clean.includes('~')) return [0, preReleaseNumber(clean, '~')];
  return [preReleaseMarkers.length + 1, 0];
}

function preReleaseNumber(v: string, marker: string): number {
  const idx = v.indexOf(marker);
  if (idx < 0) return 0;
  const match = v.slice(idx + marker.length).match(/\d+/);
  return match ? Number.parseInt(match[0], 10) : 0;
}

function findingSourceLabel(source?: string): string {
  switch (source || 'scanner') {
    case 'scanner': return 'Scanner';
    case 'cve-db': return 'CVE DB';
    default: return source || 'Scanner';
  }
}

function riskLevelLabel(level?: string): string {
  return level ? level.replace('_', ' ') : 'low';
}

function riskLevelColor(level?: string): string {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'var(--critical)';
    case 'high': return 'var(--high)';
    case 'medium': return 'var(--medium)';
    default: return 'var(--text-muted)';
  }
}

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const;

function severityColor(sev?: string): string {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'var(--critical)';
    case 'HIGH': return 'var(--high)';
    case 'MEDIUM': return 'var(--medium)';
    case 'LOW': return 'var(--low)';
    default: return 'var(--unknown)';
  }
}

function Loading({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="state-block">
      <div className="spinner" />
      <span>{label}</span>
    </div>
  );
}

function LoadError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state-block state-error">
      <span>{message}</span>
      {onRetry && <button className="btn btn-secondary btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

// EmptyState renders the standard "no results" message for an empty list/table.
function EmptyState({ message = 'No results found' }: { message?: string }) {
  return <div className="state-block">{message}</div>;
}

// ── Icon system ──────────────────────────────────────────────────────────────
// Single stroke-based inline SVG icon component (lucide-style: 1.5px stroke,
// round caps/joins, currentColor). No external icon dependency.
const ICON_PATHS: Record<string, React.ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /></>,
  hosts: <><rect x="3" y="4" width="18" height="6" rx="1.5" /><rect x="3" y="14" width="18" height="6" rx="1.5" /><path d="M7 7h.01M7 17h.01" /></>,
  packages: <><path d="M21 8v8a1.5 1.5 0 0 1-.8 1.3l-7 3.8a1.5 1.5 0 0 1-1.4 0l-7-3.8A1.5 1.5 0 0 1 3 16V8a1.5 1.5 0 0 1 .8-1.3l7-3.8a1.5 1.5 0 0 1 1.4 0l7 3.8A1.5 1.5 0 0 1 21 8Z" /><path d="m3.3 7 8.7 4.7L20.7 7M12 21.8V11.7" /></>,
  containers: <><path d="m12 2 9 4.9-9 4.9-9-4.9L12 2Z" /><path d="m3 12 9 4.9 9-4.9M3 17l9 4.9 9-4.9" /></>,
  vulnerabilities: <><path d="M12 3 5 6v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V6l-7-3Z" /><path d="M12 9v3.5M12 16h.01" /></>,
  'cve-search': <><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></>,
  scans: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 4v4h4M12 8v4l3 2" /></>,
  rbac: <><circle cx="8" cy="8" r="3.5" /><path d="m12.5 11 7 7M16 14l2.5-2.5M18.5 16.5 21 14" /></>,
  audit: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></>,
  schedules: <><rect x="3" y="4" width="18" height="17" rx="2" /><path d="M16 2v4M8 2v4M3 9h18" /><circle cx="12" cy="15" r="2.5" /><path d="M12 14v1.2l.8.8" /></>,
  'asset-groups': <><path d="M4 7a2 2 0 0 1 2-2h3.5l2 2.5H18a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7Z" /></>,
  trends: <><path d="m3 17 6-6 4 4 8-8" /><path d="M17 7h4v4" /></>,
  reports: <><path d="M3 3v18h18" /><rect x="7" y="11" width="3" height="6" rx="0.5" /><rect x="12.5" y="7" width="3" height="10" rx="0.5" /><rect x="18" y="13" width="3" height="4" rx="0.5" /></>,
  notifications: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9Z" /><path d="M13.7 21a2 2 0 0 1-3.4 0" /></>,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="m16 17 5-5-5-5M21 12H9" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1A2 2 0 1 1 7 4.5l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" /></>,
  // misc icons used in the console
  alert: <><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  flame: <><path d="M12 3c1 3 4 5 4 9a4 4 0 0 1-8 0c0-2 1-3 2-4 .5 1.5 2 2 2 3.5" /></>,
  check: <><path d="M20 6 9 17l-5-5" /></>,
  arrow: <><path d="M5 12h14M13 6l6 6-6 6" /></>,
};

function Icon({ name, size = 16, className, strokeWidth = 1.5, style }: { name: string; size?: number; className?: string; strokeWidth?: number; style?: React.CSSProperties }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={style}
    >
      {ICON_PATHS[name] || ICON_PATHS.dashboard}
    </svg>
  );
}

// Compact 22px beacon-tower brand mark (signal-fire watchtower).
function BeaconMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="beacon-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fff3e0" />
          <stop offset="1" stopColor="#ffd9a8" />
        </linearGradient>
      </defs>
      <path d="M32 10 C36 18 40 20 40 27 a8 8 0 0 1 -16 0 c0-5 4-8 5-13 1 4 3 5 3 8 a3 3 0 0 0 0-12Z" fill="url(#beacon-grad)" />
      <rect x="26" y="38" width="12" height="14" rx="2" fill="rgba(255,255,255,0.85)" />
      <rect x="20" y="52" width="24" height="4" rx="2" fill="rgba(255,255,255,0.85)" />
    </svg>
  );
}

// ── Badge ────────────────────────────────────────────────────────────────────
// One Badge look used everywhere. `dot` variant prepends a status dot for tables.
type SeverityTone = 'critical' | 'high' | 'medium' | 'low' | 'unknown' | 'neutral' | 'accent';
function toneColor(tone: SeverityTone): string {
  switch (tone) {
    case 'critical': return 'var(--critical)';
    case 'high': return 'var(--high)';
    case 'medium': return 'var(--medium)';
    case 'low': return 'var(--low)';
    case 'accent': return 'var(--primary)';
    case 'unknown': return 'var(--unknown)';
    default: return 'var(--text-muted)';
  }
}
function Badge({ tone = 'neutral', dot, children, title }: { tone?: SeverityTone; dot?: boolean; children: React.ReactNode; title?: string }) {
  const color = toneColor(tone);
  return (
    <span className="badge2" title={title} style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
      {dot && <span className="badge2-dot" style={{ background: color }} />}
      {children}
    </span>
  );
}

// ── Pure-SVG chart primitives ────────────────────────────────────────────────
const CHART_W = 720; // viewBox width; charts scale responsively via preserveAspectRatio
const SEV_KEYS = [
  { key: 'critical_count', label: 'Critical', color: 'var(--critical)', raw: '#f04444' },
  { key: 'high_count', label: 'High', color: 'var(--high)', raw: '#f07830' },
  { key: 'medium_count', label: 'Medium', color: 'var(--medium)', raw: '#e0b020' },
  { key: 'low_count', label: 'Low', color: 'var(--low)', raw: '#30c060' },
] as const;

function shortDate(d: string): string {
  const dt = new Date(d + 'T00:00:00');
  if (isNaN(dt.getTime())) return d;
  return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}
function niceMax(v: number): number {
  if (v <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  const norm = v / pow;
  const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
  return step * pow;
}

// StackedAreaChart: severity-over-time, stacked filled areas + line tops, with
// a hover guide and tooltip showing the day's breakdown.
function StackedAreaChart({ rows, height = 220 }: { rows: VulnTrendRow[]; height?: number }) {
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
function BarSeries({ rows, height = 200 }: { rows: ScanActivityRow[]; height?: number }) {
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
function DonutChart({ segments, size = 180 }: { segments: { label: string; value: number; color: string }[]; size?: number }) {
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
function Sparkline({ values, width = 90, height = 28, color = 'var(--primary)' }: { values: number[]; width?: number; height?: number; color?: string }) {
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
function KpiCard({ label, value, accent, delta, deltaInverse, spark, sparkColor, onClick, sub }: {
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

// Shared range switcher for the dashboard charts.
function RangeSwitcher({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="range-switcher" role="tablist">
      {['14', '30', '90'].map(d => (
        <button key={d} type="button" role="tab" aria-selected={value === d} className={value === d ? 'active' : ''} onClick={() => onChange(d)}>{d}d</button>
      ))}
    </div>
  );
}

// CheckboxField is the single clickable checkbox+label control used across all
// filter bars and forms (replaces ad-hoc inline-styled <label> wrappers).
function CheckboxField({ label, checked, onChange, title, disabled }: { label: string; checked: boolean; onChange: (checked: boolean) => void; title?: string; disabled?: boolean }) {
  return (
    <label className="checkbox-field" title={title}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

// Modal is the shared dialog shell: consistent backdrop, header with title + X,
// Escape-to-close, and a scrollable body.
function Modal({ title, onClose, children, width }: { title: React.ReactNode; onClose: () => void; children: React.ReactNode; width?: string }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()} style={width ? { width } : undefined}>
        <div className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close" title="Close (Esc)">×</button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

function Pager({ page, limit, total, onPage }: { page: number; limit: number; total: number; onPage: (p: number) => void }) {
  return (
    <div className="pagination" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.75rem' }}>
      <button disabled={page === 0} onClick={() => onPage(page - 1)}>Prev</button>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
        Page {page + 1} / {Math.max(1, Math.ceil(total / limit))} ({total.toLocaleString()} items)
      </span>
      <button disabled={(page + 1) * limit >= total} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}

// renderFactValue formats an arbitrary JSON fact value for display: scalars
// inline, string arrays as comma lists, arrays of objects as compact rows, and
// nested objects as an indented key/value block.
function renderFactValue(value: unknown): React.ReactNode {
  if (value === null || value === undefined) return <span style={{ color: 'var(--text-muted)' }}>-</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={{ color: 'var(--text-muted)' }}>none</span>;
    if (value.every(v => typeof v !== 'object' || v === null)) {
      return <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-word' }}>{value.join(', ')}</span>;
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {value.map((v, i) => <div key={i} style={{ borderLeft: '2px solid var(--border)', paddingLeft: '0.5rem' }}>{renderFactValue(v)}</div>)}
      </div>
    );
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      <table style={{ width: '100%' }}>
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k}>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.78rem', verticalAlign: 'top', whiteSpace: 'nowrap', paddingRight: '0.75rem', width: '1%' }}>{k}</td>
              <td style={{ fontSize: '0.8rem' }}>{renderFactValue(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-word' }}>{String(value)}</span>;
}

// FactsCard renders the unstructured host/container facts JSONB as a set of
// collapsible sections, one per top-level fact key (cpu, memory, dmi, ...).
function FactsCard({ title, facts, collectedAt }: { title: string; facts?: Record<string, unknown>; collectedAt?: string | null }) {
  const sections = facts ? Object.entries(facts) : [];
  const [open, setOpen] = useState<Record<string, boolean>>({});
  if (sections.length === 0) return null;
  return (
    <div className="card" style={{ marginBottom: '1rem' }}>
      <div className="card-header">
        <h2>{title}</h2>
        {collectedAt && <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>collected {new Date(collectedAt).toLocaleString()}</span>}
      </div>
      <div style={{ padding: '0.5rem 1rem 1rem' }}>
        {sections.sort((a, b) => a[0].localeCompare(b[0])).map(([key, val]) => {
          const isOpen = open[key] ?? (key === 'os_release' || key === 'memory');
          return (
            <div key={key} style={{ borderBottom: '1px solid var(--border)', padding: '0.4rem 0' }}>
              <div
                style={{ cursor: 'pointer', fontWeight: 600, fontSize: '0.8125rem', display: 'flex', gap: '0.4rem', userSelect: 'none' }}
                onClick={() => setOpen(o => ({ ...o, [key]: !isOpen }))}
              >
                <span style={{ color: 'var(--text-muted)' }}>{isOpen ? '▾' : '▸'}</span>{key}
              </div>
              {isOpen && <div style={{ marginTop: '0.35rem', paddingLeft: '1rem' }}>{renderFactValue(val)}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function accessSubjectRef(subject: AccessSubject): string {
  return `${subject.subject_type}:${subject.external_id}`;
}

function agentStatusColor(status?: string) {
  switch (status) {
    case 'online': return 'var(--low)';
    case 'stale': return 'var(--medium)';
    case 'offline': return 'var(--critical)';
    default: return 'var(--text-muted)';
  }
}

function formatAge(seconds?: number) {
  if (seconds === undefined || seconds === null) return '-';
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

function dateInputValue(value?: string | null) {
  if (!value) return '';
  return value.slice(0, 10);
}

function parseCvssVector(vector: string) {
  const isV4 = vector.startsWith('CVSS:4.0/');
  const isV3 = vector.startsWith('CVSS:3.');
  const prefix = isV4 ? 'CVSS:4.0/' : isV3 ? vector.substring(0, 10) + '/' : '';
  const clean = vector.replace(prefix, '').replace(/^CVSS:[0-9.]+\//, '');
  const parts = clean.split('/');

  if (isV4) {
    const labels: Record<string, string> = {
      AV: 'Attack Vector', AC: 'Attack Complexity', AT: 'Attack Requirements',
      PR: 'Privileges Required', UI: 'User Interaction', VC: 'Vuln Confidentiality',
      VI: 'Vuln Integrity', VA: 'Vuln Availability', SC: 'Sub Confidentiality',
      SI: 'Sub Integrity', SA: 'Sub Availability', E: 'Exploit Maturity',
    };
    const values: Record<string, Record<string, string>> = {
      AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
      AC: { L: 'Low', H: 'High' },
      AT: { N: 'None', P: 'Present' },
      PR: { N: 'None', L: 'Low', H: 'High' },
      UI: { N: 'None', P: 'Passive', A: 'Active' },
      VC: { N: 'None', L: 'Low', H: 'High' },
      VI: { N: 'None', L: 'Low', H: 'High' },
      VA: { N: 'None', L: 'Low', H: 'High' },
      SC: { N: 'None', L: 'Low', H: 'High' },
      SI: { N: 'None', L: 'Low', H: 'High' },
      SA: { N: 'None', L: 'Low', H: 'High' },
      E: { X: 'Not Defined', A: 'Attacked', P: 'POC', U: 'Unreported' },
    };
    return { version: '4.0', parts, labels, values };
  }

  const labels: Record<string, string> = {
    AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required',
    UI: 'User Interaction', S: 'Scope', C: 'Confidentiality',
    I: 'Integrity', A: 'Availability',
  };
  const values: Record<string, Record<string, string>> = {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    PR: { N: 'None', L: 'Low', H: 'High' },
    UI: { N: 'None', R: 'Required' },
    S: { U: 'Unchanged', C: 'Changed' },
    C: { N: 'None', L: 'Low', H: 'High' },
    I: { N: 'None', L: 'Low', H: 'High' },
    A: { N: 'None', L: 'Low', H: 'High' },
  };
  return { version: '3.x', parts, labels, values };
}

type View = 'dashboard' | 'hosts' | 'packages' | 'containers' | 'vulns' | 'vuln-detail' | 'scans' | 'audit' | 'rbac' | 'host-detail' | 'cve-search' | 'schedules' | 'asset-groups' | 'trends' | 'reports' | 'notifications';
type ScanRequestFilters = { status?: string; scan_type?: string; security_db_revision?: string; stale?: string };
type VulnerabilityFilters = { overdueOnly?: boolean; exploitedOnly?: boolean; riskLevel?: string; triageStatus?: string; owner?: string; team?: string; environment?: string; criticality?: string };
type HostFilters = { agent_status?: string; inventory_status?: string; agent_version_state?: string };

type AffectedAsset = {
  host_id: string;
  hostname: string;
  owner: string;
  team: string;
  environment: string;
  criticality: string;
  container: string;
  image_name: string;
  asset_type: string;
  pkg_name: string;
  pkg_type: string;
  installed_version: string;
  fixed_version: string;
  severity: string;
  cvss_score: number;
};
type AffectedAssetsResponse = {
  vulnerability_id: string;
  total: number;
  assets: AffectedAsset[];
};

// Direct fetch for the affected-assets endpoint (no api.ts helper exists for it yet).
async function fetchAffectedAssets(vulnerabilityId: string, limit = 500): Promise<AffectedAssetsResponse> {
  const url = new URL('/api/vulnerabilities/affected-assets', window.location.origin);
  url.searchParams.set('vulnerability_id', vulnerabilityId);
  url.searchParams.set('limit', String(limit));
  const headers: Record<string, string> = {};
  const key = getApiKey();
  const session = getSession();
  if (key) headers['X-API-Key'] = key;
  if (session) headers['Authorization'] = `Bearer ${session}`;
  const res = await fetch(url.toString(), { headers });
  if (!res.ok) throw new Error(`Failed to load affected assets (${res.status})`);
  return res.json();
}

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [scanRequestFilters, setScanRequestFilters] = useState<ScanRequestFilters>({});
  const [vulnerabilityFilters, setVulnerabilityFilters] = useState<VulnerabilityFilters>({});
  const [hostFilters, setHostFilters] = useState<HostFilters>({});
  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vuln | null>(null);
  const [authed, setAuthed] = useState(hasAuth());
  const [noAuthMode, setNoAuthMode] = useState(false);

  useEffect(() => {
    api.rawHealth().then(h => {
      if (!h.web_auth) { setNoAuthMode(true); setAuthed(true); }
    }).catch(() => {});
    onAuthFailure(() => setAuthed(false));
  }, []);

  if (!authed) return <LoginScreen onLogin={() => setAuthed(true)} />;

  const navigate = (v: View) => {
    if (v === 'scans') setScanRequestFilters({});
    if (v === 'vulns') setVulnerabilityFilters({});
    if (v === 'hosts') setHostFilters({});
    setView(v);
  };
  const openScanRequests = (filters: ScanRequestFilters) => {
    setScanRequestFilters(filters);
    setView('scans');
  };
  const openVulnerabilities = (filters: VulnerabilityFilters) => {
    setVulnerabilityFilters(filters);
    setView('vulns');
  };
  const openHosts = (filters: HostFilters) => {
    setHostFilters(filters);
    setView('hosts');
  };

  return (
    <div className="layout">
      <Sidebar view={view} onNavigate={navigate} onLogout={noAuthMode ? undefined : () => { clearApiKey(); clearSession(); setAuthed(false); }} />
      <div className="main">
        {view === 'dashboard' && <DashboardView onOpenScanRequests={openScanRequests} onOpenVulnerabilities={openVulnerabilities} onOpenHosts={openHosts} />}
        {view === 'hosts' && <HostsView initialFilters={hostFilters} onSelectHost={(id) => { setSelectedHostId(id); setView('host-detail'); }} />}
        {view === 'host-detail' && <HostDetailView key={selectedHostId} hostId={selectedHostId} onBack={() => setView('hosts')} onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'packages' && <PackagesView onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'containers' && <ContainersView />}
        {view === 'cve-search' && <CveSearchView />}
        {view === 'scans' && <ScansView initialRequestFilters={scanRequestFilters} />}
        {view === 'rbac' && <RBACView />}
        {view === 'audit' && <AuditLogView />}
        {view === 'vulns' && <VulnsView initialFilters={vulnerabilityFilters} onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'vuln-detail' && <VulnDetailView key={selectedVuln?.id || ''} vuln={selectedVuln} onBack={() => setView('vulns')} />}
        {view === 'schedules' && <SchedulesView />}
        {view === 'asset-groups' && <AssetGroupsView />}
        {view === 'trends' && <TrendsView />}
        {view === 'reports' && <ReportsView />}
        {view === 'notifications' && <NotificationsView />}
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [error, setError] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    if (!username || !password) return;
    setLoading(true);
    setError('');
    try {
      const result = await api.login(username, password);
      setSession(result.token);
      onLogin();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleApiKeyLogin = () => {
    if (!apiKeyInput) return;
    setApiKey(apiKeyInput);
    onLogin();
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Bongsu</h2>
        <div className="login-subtitle">Package Vulnerability Monitor</div>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
          autoFocus
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
        />
        {error && <div className="login-error">{error}</div>}
        <button
          className="login-btn"
          onClick={handleLogin}
          disabled={loading || !username || !password}
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
        <div className="login-divider">
          <span>or</span>
        </div>
        {showApiKey ? (
          <>
            <input
              type="password"
              placeholder="API Key"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleApiKeyLogin(); }}
            />
            <button
              className="login-btn login-btn-secondary"
              onClick={handleApiKeyLogin}
              disabled={!apiKeyInput}
            >
              Connect with API Key
            </button>
          </>
        ) : (
          <button
            className="login-btn login-btn-secondary"
            onClick={() => setShowApiKey(true)}
          >
            Use API Key
          </button>
        )}
      </div>
    </div>
  );
}

function ChangePasswordPanel({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!current || !next) { setMsg('All fields are required'); return; }
    if (next !== confirm) { setMsg('New passwords do not match'); return; }
    setBusy(true);
    setMsg('');
    try {
      await api.changePassword(current, next);
      setMsg('Password changed');
      setCurrent(''); setNext(''); setConfirm('');
      window.setTimeout(onClose, 1200);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Password change failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Change Password</div>
      <input type="password" placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
      <input type="password" placeholder="New password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
      <input type="password" placeholder="Confirm new password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="submit" className="filter-btn" disabled={busy}>{busy ? 'Saving...' : 'Save'}</button>
        <button type="button" onClick={onClose}>Cancel</button>
      </div>
      {msg && <div style={{ fontSize: '0.75rem', color: msg === 'Password changed' ? 'var(--low)' : 'var(--critical)' }}>{msg}</div>}
    </form>
  );
}

function Sidebar({ view, onNavigate, onLogout }: { view: View; onNavigate: (v: View) => void; onLogout?: () => void }) {
  const [me, setMe] = useState<{ username: string; role: string } | null>(null);
  const [showPw, setShowPw] = useState(false);
  useEffect(() => {
    if (!onLogout) return;
    api.authMe().then(r => setMe(r.user ? { username: r.user.username, role: r.user.role } : null)).catch(() => setMe(null));
  }, [onLogout]);
  const groups: { label: string; items: [View, string, string][] }[] = [
    { label: 'Overview', items: [
      ['dashboard', 'Dashboard', 'dashboard'],
      ['trends', 'Trends', 'trends'],
      ['reports', 'Reports', 'reports'],
    ] },
    { label: 'Inventory', items: [
      ['hosts', 'Hosts', 'hosts'],
      ['packages', 'Packages', 'packages'],
      ['containers', 'Containers', 'containers'],
      ['asset-groups', 'Asset Groups', 'asset-groups'],
    ] },
    { label: 'Security', items: [
      ['vulns', 'Vulnerabilities', 'vulnerabilities'],
      ['cve-search', 'CVE Search', 'cve-search'],
      ['scans', 'Scan History', 'scans'],
    ] },
    { label: 'Administration', items: [
      ['rbac', 'RBAC', 'rbac'],
      ['audit', 'Audit Log', 'audit'],
      ['schedules', 'Schedules', 'schedules'],
      ['notifications', 'Notifications', 'notifications'],
    ] },
  ];
  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <h1><span className="brand-icon"><BeaconMark size={22} /></span> Bongsu</h1>
      </div>
      <nav>
        {groups.map(group => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map(([v, label, icon]) => (
              <a key={v} className={view === v ? 'active' : ''} href="#" onClick={(e) => { e.preventDefault(); onNavigate(v); }}>
                <span className="nav-icon"><Icon name={icon} size={17} /></span>
                {label}
              </a>
            ))}
          </div>
        ))}
      </nav>
      {onLogout && showPw && <ChangePasswordPanel onClose={() => setShowPw(false)} />}
      {onLogout && (
        <div className="sidebar-footer">
          {me && (
            <button
              type="button"
              className="user-chip"
              title="Change password"
              onClick={() => setShowPw(s => !s)}
            >
              <span className="user-avatar">{me.username.slice(0, 1).toUpperCase()}</span>
              <span className="user-meta">
                <span className="user-name">{me.username}</span>
                <span className="user-role">{me.role}</span>
              </span>
              <Icon name="settings" size={15} className="user-chip-gear" />
            </button>
          )}
          <a href="#" className="logout" onClick={(e) => { e.preventDefault(); onLogout(); }}>
            <span className="nav-icon"><Icon name="logout" size={16} /></span> Logout
          </a>
        </div>
      )}
    </div>
  );
}

function DashboardView({ onOpenScanRequests, onOpenVulnerabilities, onOpenHosts }: { onOpenScanRequests: (filters: ScanRequestFilters) => void; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void; onOpenHosts: (filters: HostFilters) => void }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsError, setStatsError] = useState('');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [securityDbConfigured, setSecurityDbConfigured] = useState(false);
  const [cveSources, setCveSources] = useState<CveSourceStat[]>([]);
  const [cveRematchPolicy, setCveRematchPolicy] = useState<CveRematchPolicy | null>(null);
  const [cveAffectedIndex, setCveAffectedIndex] = useState<HealthStatus['cve_affected_package_index'] | null>(null);
  const [cveReferenceIndex, setCveReferenceIndex] = useState<HealthStatus['cve_reference_key_index'] | CveDbStatsResponse['reference_key_index'] | null>(null);
  const [cveEpssMerge, setCveEpssMerge] = useState<CveEpssMergeStats | null>(null);
  const [cveDbQuality, setCveDbQuality] = useState<CveDbQuality | null>(null);
  const [cveStatsMeta, setCveStatsMeta] = useState<Pick<CveDbStatsResponse, 'cache_status' | 'generated_at' | 'durations_ms' | 'osv_ecosystems' | 'osv_ecosystems_error'> | null>(null);
  const [installerStatus, setInstallerStatus] = useState<InstallerStatus | null>(null);
  const [securityDbStatus, setSecurityDbStatus] = useState<SecurityDbOperationalStatus | null>(null);
  const [agentFleetStatus, setAgentFleetStatus] = useState<AgentFleetStatus | null>(null);
  const [dashboardHosts, setDashboardHosts] = useState<Host[]>([]);
  const [agentCounts, setAgentCounts] = useState<Record<string, number>>({});
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [ownerSummary, setOwnerSummary] = useState<VulnSummaryRow[]>([]);
  const [teamSummary, setTeamSummary] = useState<VulnSummaryRow[]>([]);
  const [environmentSummary, setEnvironmentSummary] = useState<VulnSummaryRow[]>([]);
  const [criticalitySummary, setCriticalitySummary] = useState<VulnSummaryRow[]>([]);
  const [trendRange, setTrendRange] = useState('30');
  const [trendRows, setTrendRows] = useState<VulnTrendRow[]>([]);
  const [scanRows, setScanRows] = useState<ScanActivityRow[]>([]);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [rematching, setRematching] = useState(false);
  const [rematchMsg, setRematchMsg] = useState('');
  const [rematchMinQuality, setRematchMinQuality] = useState('');
  const [rematchCandidateLimit, setRematchCandidateLimit] = useState('');
  const [cvssRecalcBusy, setCvssRecalcBusy] = useState(false);
  const [cvssRecalcMsg, setCvssRecalcMsg] = useState('');
  const [securityRecalcBusy, setSecurityRecalcBusy] = useState(false);
  const [securityRecalcMsg, setSecurityRecalcMsg] = useState('');
  const [retentionMsg, setRetentionMsg] = useState('');
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [securityBundleMsg, setSecurityBundleMsg] = useState('');
  const [securityBundleBusy, setSecurityBundleBusy] = useState(false);
  const [securityBundleIncludeTrivy, setSecurityBundleIncludeTrivy] = useState(true);
  const applyCveStats = useCallback((r: CveDbStatsResponse) => {
    setCveSources(r.sources || []);
    setCveRematchPolicy(r.rematch_policy || null);
    setCveAffectedIndex(r.affected_package_index || null);
    setCveEpssMerge(r.epss_merge || null);
    setCveReferenceIndex(r.reference_key_index || null);
    setCveDbQuality(r.cve_db_quality || null);
    setCveStatsMeta({ cache_status: r.cache_status, generated_at: r.generated_at, durations_ms: r.durations_ms, osv_ecosystems: r.osv_ecosystems, osv_ecosystems_error: r.osv_ecosystems_error });
  }, []);
  const applySecurityDbStatus = useCallback((r: SecurityDbOperationalStatus) => {
    setSecurityDbStatus(r);
    setSecurityDbConfigured(!!r.security_db?.configured);
    if (r.cve_affected_package_index) setCveAffectedIndex(r.cve_affected_package_index);
    if (r.cve_reference_key_index) setCveReferenceIndex(r.cve_reference_key_index);
    if (r.cve_db_quality) setCveDbQuality(r.cve_db_quality);
  }, []);
  const refreshSecurityDbStatus = useCallback(() => {
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
  }, [applySecurityDbStatus]);

  const loadStats = useCallback(() => {
    setStatsError('');
    api.stats().then(setStats).catch((e) => setStatsError(e instanceof Error ? e.message : 'Failed to load stats'));
  }, []);
  useEffect(() => { loadStats(); }, [loadStats]);
  useEffect(() => {
    api.rawHealth().then(h => {
      setHealth(h);
      setSecurityDbConfigured(!!h.security_db?.configured);
      setCveAffectedIndex(h.cve_affected_package_index || null);
      setCveDbQuality(h.cve_db_quality || null);
    }).catch(() => {});
    refreshSecurityDbStatus();
  }, [updating, refreshSecurityDbStatus]);
  useEffect(() => {
    if (!health?.cve_reference_index_rebuild?.running && !health?.cve_affected_index_rebuild?.running) return;
    const timer = window.setInterval(() => {
      api.rawHealth().then(h => {
        setHealth(h);
        setSecurityDbConfigured(!!h.security_db?.configured);
        setCveAffectedIndex(h.cve_affected_package_index || null);
        setCveDbQuality(h.cve_db_quality || null);
      }).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [health?.cve_reference_index_rebuild?.running, health?.cve_affected_index_rebuild?.running, applyCveStats, refreshSecurityDbStatus]);
  useEffect(() => {
    api.cveDbStats().then(applyCveStats).catch(() => {});
    api.installerStatus().then(setInstallerStatus).catch(() => {});
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
    api.agentFleetStatus().then(r => {
      setAgentFleetStatus(r);
      if (r.installer) setInstallerStatus(r.installer);
    }).catch(() => {});
    api.packages({ limit: '1' }).then(r => setTotalPkgs(r.total)).catch(() => {});
    api.hosts().then(items => {
      setDashboardHosts(items || []);
      setAgentCounts(items.reduce((acc, h) => {
        const status = h.agent_status || 'unknown';
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>));
    }).catch(() => {});
    api.vulnSummary({ group_by: 'owner' }).then(r => setOwnerSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'team' }).then(r => setTeamSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'environment' }).then(r => setEnvironmentSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'criticality' }).then(r => setCriticalitySummary(r.items || [])).catch(() => {});
  }, [applyCveStats]);

  useEffect(() => {
    let active = true;
    setChartsLoading(true);
    Promise.all([
      api.vulnTrends({ days: trendRange }).catch(() => ({ items: [] as VulnTrendRow[] })),
      api.scanActivity({ days: trendRange }).catch(() => ({ days: 0, items: [] as ScanActivityRow[] })),
    ]).then(([t, s]) => {
      if (!active) return;
      setTrendRows(t.items || []);
      setScanRows(s.items || []);
      setChartsLoading(false);
    });
    return () => { active = false; };
  }, [trendRange]);

  const handleUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.updateTrivyDB();
      setUpdateMsg(r.message || 'Updated');
    } catch {
      setUpdateMsg('Update failed (check server logs)');
    }
    setUpdating(false);
  };

  const handleSecurityUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      await api.updateSecurityDB();
      setUpdateMsg('Security sources sync started/completed');
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Security source sync failed or is not configured');
    }
    setUpdating(false);
  };

  const handleAffectedIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveAffectedIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Affected package index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Affected package index rebuild is already running');
      } else {
        setCveAffectedIndex(r.index || null);
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Affected package index rebuilt: ${(r.indexed || 0).toLocaleString()} entries${duration}`);
      }
      if (r.affected_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_affected_index_rebuild: r.affected_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Affected package index rebuild failed');
    }
    setUpdating(false);
  };

  const handleReferenceIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveReferenceIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Reference key index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Reference key index rebuild is already running');
      } else {
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Reference key index rebuilt: ${(r.indexed || 0).toLocaleString()} keys${duration}`);
      }
      if (r.reference_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_reference_index_rebuild: r.reference_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Reference key index rebuild failed');
    }
    setUpdating(false);
  };

  const handleRematch = async () => {
    setRematching(true);
    setRematchMsg('');
    try {
      const minQuality = Number(rematchMinQuality);
      const candidateLimit = Number(rematchCandidateLimit);
      const body: { min_source_matchable_percent?: number; candidate_limit?: number } = {};
      if (Number.isFinite(minQuality) && minQuality > 0) body.min_source_matchable_percent = minQuality;
      if (Number.isFinite(candidateLimit) && candidateLimit > 0) body.candidate_limit = Math.floor(candidateLimit);
      const r = await api.rematchCVEs(body);
      const qualityMsg = minQuality > 0 ? ` with source quality >= ${minQuality}%` : '';
      const limitMsg = candidateLimit > 0 ? `, candidate limit ${Math.floor(candidateLimit).toLocaleString()}` : '';
      const limitedMsg = r.limited ? `, limited at ${r.candidate_limit.toLocaleString()} candidates` : '';
      const scanned = r.scanned_candidates || r.matched + r.skipped;
      const scannedMsg = r.scanned_candidates ? ` from ${r.scanned_candidates.toLocaleString()} scanned candidates` : '';
      const skippedPct = scanned > 0 ? `, ${(r.skipped * 100 / scanned).toFixed(1)}% skipped` : '';
      const sourceMsg = r.eligible_sources !== undefined ? `, ${r.eligible_sources.toLocaleString()} eligible sources${r.excluded_sources ? `, ${r.excluded_sources.toLocaleString()} excluded` : ''}` : '';
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setRematchMsg(`Matched ${r.matched.toLocaleString()} packages${scannedMsg}${qualityMsg}${limitMsg}, found ${r.new_vulns.toLocaleString()} new vulnerabilities (${r.skipped.toLocaleString()} skipped${skippedPct}${limitedMsg}${sourceMsg}${revisionMsg})`);
      api.stats().then(setStats).catch(() => {});
    } catch {
      setRematchMsg('Rematch failed (check server logs)');
    }
    setRematching(false);
  };

  const minQualityForDisplay = Number.parseFloat(rematchMinQuality);
  const sourceBelowQuality = (s: CveSourceStat) =>
    Number.isFinite(minQualityForDisplay) && minQualityForDisplay > 0 && (s.matchable_percent || 0) < minQualityForDisplay;
  const cveTotalRecords = cveSources.reduce((sum, s) => sum + (s.count || 0), 0);
  const cveTotalMatchable = cveSources.reduce((sum, s) => sum + (s.matchable || 0), 0);
  const cveMatchablePercent = cveTotalRecords > 0 ? (cveTotalMatchable * 100) / cveTotalRecords : 0;
  const cveRematchEligibleCount = cveRematchPolicy?.eligible_sources ?? cveSources.filter(s => s.rematch_eligible !== false).length;
  const cveRematchExcludedCount = cveRematchPolicy?.excluded_sources ?? cveSources.filter(s => s.rematch_eligible === false).length;
  const cveRematchPolicyText = cveRematchPolicy
    ? `${cveRematchPolicy.sources?.length ? `${cveRematchPolicy.sources.length} allowlisted` : 'all sources'}, min ${(cveRematchPolicy.min_source_matchable_percent || 0).toFixed(1)}%`
    : 'policy pending';
  const epssMergeCoverage = cveEpssMerge?.non_epss_coverage_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssUniverseCoverage = cveEpssMerge?.epss_universe_match_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssMergeColor = !cveEpssMerge || cveEpssMerge.epss_cves === 0
    ? 'var(--medium)'
    : epssMergeCoverage < 90
      ? 'var(--high)'
      : 'var(--low)';
  const cveAffectedIndexIndexedOnly = cveAffectedIndex?.summary_mode === 'indexed-only';
  const cveAffectedIndexUnhealthy = !!(cveAffectedIndex?.stale || (cveAffectedIndex?.orphans || 0) > 0 || (cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 || cveAffectedIndex?.error);
  const cveAffectedIndexColor = cveAffectedIndexUnhealthy ? 'var(--high)' : cveAffectedIndexIndexedOnly ? 'var(--medium)' : 'var(--low)';
  const affectedRebuild = health?.cve_affected_index_rebuild;
  const affectedRebuildLast = affectedRebuild?.last_result;
  const affectedRebuildRunning = !!affectedRebuild?.running;
  const affectedRebuildColor = affectedRebuildRunning
    ? 'var(--medium)'
    : affectedRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : affectedRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveReferenceIndexUnhealthy = !!(!cveReferenceIndex || cveReferenceIndex.stale || (cveReferenceIndex.orphans || 0) > 0 || (cveReferenceIndex.coverage_percent ?? 0) < 90);
  const cveReferenceIndexColor = cveReferenceIndexUnhealthy ? 'var(--high)' : 'var(--low)';
  const referenceRebuild = health?.cve_reference_index_rebuild;
  const referenceRebuildLast = referenceRebuild?.last_result;
  const referenceRebuildRunning = !!referenceRebuild?.running;
  const referenceRebuildColor = referenceRebuildRunning
    ? 'var(--medium)'
    : referenceRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : referenceRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveQualityStatus = cveDbQuality?.status || 'pending';
  const cveQualityColor = cveQualityStatus === 'degraded'
    ? 'var(--critical)'
    : cveQualityStatus === 'warning' || cveQualityStatus === 'pending'
      ? 'var(--medium)'
      : 'var(--low)';
  const cveQualityWarnings = cveDbQuality?.warnings || [];
  const securityDbWarnings = securityDbStatus?.warnings || [];
  const securityDbActions = securityDbStatus?.recommended_actions || [];
  const securitySourceRegistry = securityDbStatus?.security_sources || [];
  const securitySourceRegistryOk = securitySourceRegistry.filter(s => s.enabled && s.last_status === 'ok' && (s.record_count || 0) > 0).length;
  const securitySourceRegistryEnabled = securitySourceRegistry.filter(s => s.enabled).length;
  const securitySourceRegistryRecords = securitySourceRegistry.reduce((sum, s) => sum + (s.record_count || 0), 0);
  const latestSecuritySourceRegistry = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_sync_finished_at) return latest;
    if (!latest?.last_sync_finished_at) return source;
    return new Date(source.last_sync_finished_at).getTime() > new Date(latest.last_sync_finished_at).getTime() ? source : latest;
  }, null);
  const latestSecuritySourceExport = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_exported_at) return latest;
    if (!latest?.last_exported_at) return source;
    return new Date(source.last_exported_at).getTime() > new Date(latest.last_exported_at).getTime() ? source : latest;
  }, null);
  const securitySourceRegistryBroken = !!securityDbStatus?.security_sources_error || securitySourceRegistry.some(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error));
  const securityDbExportStatus = securityDbStatus?.security_db_export;
  const latestSecuritySourceDataUpdate = securityDbExportStatus?.latest_source_update_at;
  const latestSecuritySourceRegistryTime = latestSecuritySourceRegistry?.last_sync_finished_at;
  const latestSecuritySourceDisplay = latestSecuritySourceDataUpdate && (!latestSecuritySourceRegistryTime || new Date(latestSecuritySourceDataUpdate).getTime() > new Date(latestSecuritySourceRegistryTime).getTime())
    ? { label: 'data', source: 'cve rows', at: latestSecuritySourceDataUpdate }
    : latestSecuritySourceRegistryTime
      ? { label: 'registry', source: latestSecuritySourceRegistry?.id || 'source', at: latestSecuritySourceRegistryTime }
      : null;
  const securityDbExportStale = securityDbExportStatus?.status === 'stale' || securityDbExportStatus?.status === 'never';
  const securitySourceRegistryColor = securitySourceRegistryBroken
    ? 'var(--critical)'
    : securityDbExportStale
      ? 'var(--medium)'
    : securitySourceRegistry.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const cveStatsCacheStatus = cveStatsMeta?.cache_status || 'unknown';
  const cveStatsGeneratedAt = cveStatsMeta?.generated_at ? new Date(cveStatsMeta.generated_at).toLocaleString() : 'not loaded';
  const cveStatsDuration = cveStatsMeta?.durations_ms?.total;
  const osvEcosystems = cveStatsMeta?.osv_ecosystems || [];
  const osvEcosystemRows = osvEcosystems.reduce((sum, eco) => sum + (eco.indexed_rows || 0), 0);
  const oldestOsvEcosystem = osvEcosystems.reduce<typeof osvEcosystems[number] | null>((oldest, eco) => {
    const at = eco.raw_last_update || eco.last_update;
    const oldestAt = oldest ? (oldest.raw_last_update || oldest.last_update) : null;
    if (!at) return oldest;
    if (!oldestAt) return eco;
    return new Date(at).getTime() < new Date(oldestAt).getTime() ? eco : oldest;
  }, null);
  const osvEcosystemColor = cveStatsMeta?.osv_ecosystems_error
    ? 'var(--high)'
    : osvEcosystems.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const weakestCveSource = cveSources.reduce<CveSourceStat | null>((worst, source) =>
    !worst || (source.matchable_percent ?? 0) < (worst.matchable_percent ?? 0) ? source : worst, null);
  const latestCveSource = cveSources.reduce<CveSourceStat | null>((latest, source) => {
    if (!source.last_update) return latest;
    if (!latest?.last_update) return source;
    return new Date(source.last_update).getTime() > new Date(latest.last_update).getTime() ? source : latest;
  }, null);
  const latestSecurityDbSource = latestCveSource?.last_update
    ? { source: latestCveSource.source, last_update: latestCveSource.last_update }
    : health?.security_db_freshness?.latest_source && health.security_db_freshness.latest_last_update
      ? { source: health.security_db_freshness.latest_source, last_update: health.security_db_freshness.latest_last_update }
      : null;
  const osvCveSource = cveSources.find(source => source.source.toLowerCase() === 'osv') || null;
  const staleCveSources = health?.security_db_freshness?.stale_sources || [];
  const missingCveSources = health?.security_db_freshness?.missing_sources || [];
  const staleCveSourceByName = new Map(staleCveSources.map(s => [s.source.toLowerCase(), s]));
  const staleCveSourceCount = staleCveSources.length;
  const cveSourceAlertCount = staleCveSourceCount + missingCveSources.length;
  const oldestCveAgeDays = health?.security_db_freshness?.oldest_age_seconds
    ? health.security_db_freshness.oldest_age_seconds / 86400
    : 0;
  const securityDbFreshnessStatus = health?.security_db_freshness?.status || '';
  const effectiveSecurityDbStatus = health?.security_db?.effective_status || securityDbFreshnessStatus;
  const securitySourcesReady = !!health?.security_db?.configured && (
    health?.security_db?.status === 'ok' ||
    effectiveSecurityDbStatus === 'ok'
  );
  const securitySourcesLabel = !health?.security_db?.configured
    ? 'not configured'
    : securitySourcesReady
      ? 'ok'
      : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatus = !securityDbConfigured
    ? 'not configured'
    : health?.security_db?.running
      ? 'syncing'
      : securityDbStatus?.status === 'warning'
        ? 'warning'
      : health?.security_db_freshness?.stale
        ? 'stale'
        : securityDbStatus?.status === 'degraded'
          ? 'degraded'
        : effectiveSecurityDbStatus === 'ok'
          ? 'ok'
          : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatusColor = !securityDbConfigured || cveDbStatus === 'stale'
    ? 'var(--critical)'
    : cveDbStatus === 'degraded'
      ? 'var(--critical)'
    : cveDbStatus === 'syncing' || cveDbStatus === 'unknown' || cveDbStatus === 'warning'
      ? 'var(--medium)'
      : 'var(--low)';
  const securitySyncNext = health?.security_db?.next_sync && !health.security_db.next_sync.startsWith('0001-')
    ? new Date(health.security_db.next_sync).toLocaleString()
    : '';
  const securitySyncLast = health?.security_db?.last_attempt && !health.security_db.last_attempt.startsWith('0001-')
    ? new Date(health.security_db.last_attempt).toLocaleString()
    : '';
  const securitySyncStatus = health?.security_db?.running
    ? 'syncing'
    : effectiveSecurityDbStatus === 'ok'
      ? 'ok'
    : health?.security_db?.status === 'never' && latestSecurityDbSource?.last_update
      ? 'waiting'
      : health?.security_db?.status || '-';
  const securitySyncDetail = securitySyncLast
    ? `last sync ${securitySyncLast}`
    : health?.security_db?.effective_last_sync
      ? `effective ${effectiveSecurityDbStatus || 'unknown'} from ${(health.security_db.effective_source || 'source').toUpperCase()} ${new Date(health.security_db.effective_last_sync).toLocaleString()}`
    : latestSecurityDbSource?.last_update
      ? `latest source ${latestSecurityDbSource.source.toUpperCase()} ${new Date(latestSecurityDbSource.last_update).toLocaleString()}`
      : securitySyncNext
        ? `next ${securitySyncNext}`
        : `interval ${health?.security_db?.interval || '-'}`;
  const cveFreshnessColor = missingCveSources.length > 0 || staleCveSourceCount > 0 || health?.security_db_freshness?.stale ? 'var(--critical)' : 'var(--low)';
  const cveMatchableColor = cveMatchablePercent < 50 && cveTotalRecords > 0
    ? 'var(--critical)'
    : cveMatchablePercent < 80 && cveTotalRecords > 0
      ? 'var(--medium)'
      : 'var(--low)';
  const lastRecalc = health?.security_recalculation?.last_result;
  const lastManualRematch = health?.cve_db_rematch?.last_result;
  const lastAutoRescan = health?.security_db_auto_rescan?.last_result;
  const lastSecurityBundleImport = securityDbStatus?.security_db_bundle_import?.last_result;
  const lastRecalcLimited = !!lastRecalc?.rematch_limited;
  const lastManualRematchLimited = !!lastManualRematch?.limited;
  const lastRecalcColor = lastRecalc?.status === 'error'
    ? 'var(--critical)'
    : lastRecalcLimited
      ? 'var(--high)'
    : lastRecalc?.status === 'ok'
      ? 'var(--low)'
      : 'var(--medium)';
  const lastRecalcTitle = lastRecalcLimited
    ? `Rematch hit candidate limit ${lastRecalc?.rematch_candidate_limit || 0}`
    : lastRecalc?.errors?.length ? lastRecalc.errors.join('\n') : lastRecalc?.reason || '';
  const lastManualRematchColor = lastManualRematch?.status === 'error'
    ? 'var(--critical)'
    : lastManualRematchLimited
      ? 'var(--high)'
      : lastManualRematch?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const lastAutoRescanColor = lastAutoRescan?.status === 'error'
    ? 'var(--critical)'
    : lastAutoRescan?.status === 'disabled'
      ? 'var(--medium)'
      : lastAutoRescan?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const rescanProgress = stats?.security_db_rescan_progress || {};
  const rescanCompletePercent = Number(rescanProgress.complete_percent || 0);
  const rescanProgressColor = (rescanProgress.failed || 0) > 0
    ? 'var(--critical)'
    : (rescanProgress.open || 0) > 0
      ? 'var(--medium)'
      : (rescanProgress.total || 0) > 0
        ? 'var(--low)'
        : 'var(--text-muted)';
  const scanCoverage = stats?.security_db_scan_coverage || {};
  const scanCoveragePercent = Number(scanCoverage.coverage_percent || 0);
  const scanCoverageColor = (scanCoverage.stale_hosts || 0) > 0 || (scanCoverage.unknown_hosts || 0) > 0
    ? 'var(--medium)'
    : (scanCoverage.current_hosts || 0) > 0
      ? 'var(--low)'
      : 'var(--text-muted)';
  const triageActiveCounts = stats?.triage_active_counts || {};
  const triageExpiringSoonCounts = stats?.triage_expiring_soon_counts || {};
  const suppressedTriageCount = ['accepted_risk', 'false_positive', 'fixed', 'ignored']
    .reduce((sum, status) => sum + (triageActiveCounts[status] || 0), 0);
  const triageExpiringSoonTotal = Object.values(triageExpiringSoonCounts).reduce((sum, count) => sum + count, 0);
  const effectiveAgentCounts = stats?.agent_status_counts || agentCounts;
  const effectiveInventoryCounts = stats?.inventory_status_counts || {};
  const inventoryCoveragePercent = stats?.inventory_coverage_percent ?? 0;
  const inventoryFreshPercent = stats?.inventory_fresh_percent ?? 0;
  const agentFleetWarnings = agentFleetStatus?.warnings || [];
  const agentFleetActions = agentFleetStatus?.recommended_actions || [];
  const agentVersionDriftCounts = agentFleetStatus?.agent_version_drift_counts || stats?.agent_version_drift_counts || {};
  const latestAgentVersion = agentFleetStatus?.latest_agent_version || stats?.latest_agent_version || installerStatus?.agent?.version || '';
  const currentAgentCount = agentVersionDriftCounts.current ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version === latestAgentVersion).length : 0);
  const outdatedAgentCount = agentVersionDriftCounts.outdated ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version && h.agent_version !== latestAgentVersion).length : 0);
  const unknownAgentVersionCount = agentVersionDriftCounts.unknown ?? dashboardHosts.filter(h => !h.agent_version).length;
  const agentFleetOutdatedPercent = agentFleetStatus?.outdated_percent ?? (dashboardHosts.length ? (outdatedAgentCount / dashboardHosts.length) * 100 : 0);
  const inventoryCoverageColor = inventoryCoveragePercent < 70
    ? 'var(--critical)'
    : inventoryCoveragePercent < 90
      ? 'var(--medium)'
      : 'var(--low)';

  const handleCvssRecalc = async () => {
    setCvssRecalcBusy(true);
    setCvssRecalcMsg('');
    try {
      const r = await api.recalcCveCVSS();
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setCvssRecalcMsg(`Recalculated ${r.updated.toLocaleString()} CVSS records${revisionMsg}`);
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setCvssRecalcMsg('CVSS recalculation failed or requires admin API key');
    }
    setCvssRecalcBusy(false);
  };

  const handleSecurityRecalc = async () => {
    setSecurityRecalcBusy(true);
    setSecurityRecalcMsg('');
    try {
      const r = await api.recalculateSecurityDB({ reason: 'manual dashboard recalculation' });
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setSecurityRecalcMsg(`Security recalculation ${r.status}${revisionMsg}`);
      api.rawHealth().then(setHealth).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setSecurityRecalcMsg('Security recalculation queue failed or requires admin API key');
    }
    setSecurityRecalcBusy(false);
  };

  const openCurrentDBRescans = (status: string, stale?: boolean) => {
    const revision = stats?.security_db_revision || health?.security_db_revision || '';
    if (!revision) return;
    onOpenScanRequests({ status, scan_type: 'security-db-update', security_db_revision: revision, ...(stale ? { stale: 'true' } : {}) });
  };

  const handleRetentionPrune = async (dryRun: boolean) => {
    setRetentionBusy(true);
    setRetentionMsg('');
    try {
      const r = await api.pruneRetention({ dry_run: dryRun });
      const inventoryRows = r.packages + r.vulnerabilities + r.containers + r.users + r.processes + r.ports;
      const affected = r.scans + inventoryRows + r.scan_requests + r.audit_logs;
      const scanCutoff = r.scan_cutoff ? new Date(r.scan_cutoff).toLocaleString() : `${r.scan_days}d`;
      const requestCutoff = r.request_cutoff ? new Date(r.request_cutoff).toLocaleString() : `${r.request_days}d`;
      const auditCutoff = r.audit_cutoff ? new Date(r.audit_cutoff).toLocaleString() : `${r.audit_days}d`;
      setRetentionMsg(`${dryRun ? 'Dry run' : 'Pruned'}: ${affected.toLocaleString()} records (${r.scans} scans before ${scanCutoff}, ${inventoryRows} inventory rows, ${r.scan_requests} requests before ${requestCutoff}, ${r.audit_logs} audit logs before ${auditCutoff})`);
    } catch {
      setRetentionMsg('Retention prune failed or requires admin API key');
    }
    setRetentionBusy(false);
  };

  const handleSecurityBundleExport = async () => {
    setSecurityBundleBusy(true);
    setSecurityBundleMsg('Preparing bundle on the server — the full CVE DB is packaged and checksummed before the download starts, which takes roughly 30–90 seconds. The download begins automatically when ready...');
    try {
      await api.exportSecurityDBBundle(securityBundleIncludeTrivy);
      setSecurityBundleMsg(`Exported airgap bundle${securityBundleIncludeTrivy ? ' with Trivy DB when available' : ' without Trivy DB'}`);
    } catch {
      setSecurityBundleMsg('Security DB bundle export failed or requires admin API key');
    }
    setSecurityBundleBusy(false);
  };

  const handleSecurityBundleImport = async (file?: File) => {
    if (!file) return;
    setSecurityBundleBusy(true);
    setSecurityBundleMsg(`Importing ${file.name}...`);
    try {
      const r = await api.importSecurityDBBundle(file);
      const revisionMsg = r.security_db_revision ? `, rev ${r.security_db_revision}` : '';
      const createdMsg = r.bundle_created_at ? `, bundle ${new Date(r.bundle_created_at).toLocaleString()}` : '';
      const sourceMsg = typeof r.bundle_source_count === 'number' ? `, ${r.bundle_source_count} sources` : '';
      setSecurityBundleMsg(`Imported ${r.imported.toLocaleString()} CVE records${r.trivy_db_loaded ? ' and Trivy DB' : ''}${revisionMsg}${createdMsg}${sourceMsg}; recalculation started`);
      api.rawHealth().then(h => {
        setHealth(h);
        setSecurityDbConfigured(!!h.security_db?.configured);
      }).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      api.stats().then(setStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setSecurityBundleMsg('Security DB bundle import failed or requires admin API key');
    }
    setSecurityBundleBusy(false);
  };

  // ── Ops console derived data ────────────────────────────────────────────────
  const trendTotals = trendRows.map(r => r.total_vulns);
  const lastTrend = trendRows[trendRows.length - 1];
  // delta vs ~7 days ago within the loaded series (or earliest available point)
  const deltaAt = (sel: (r: VulnTrendRow) => number): number | null => {
    if (trendRows.length < 2) return null;
    const idx = Math.max(0, trendRows.length - 1 - 7);
    const ref = trendRows[idx];
    if (!lastTrend || !ref || ref === lastTrend) return null;
    return sel(lastTrend) - sel(ref);
  };
  const totalDelta = deltaAt(r => r.total_vulns);
  const critDelta = deltaAt(r => r.critical_count);
  const exploitedDelta = deltaAt(r => r.exploited_count);
  const sparkSlice = (sel: (r: VulnTrendRow) => number) => trendRows.slice(-14).map(sel);
  const enoughHistory = trendRows.length >= 2;
  const enoughScans = scanRows.length >= 2;

  const sevCounts = stats?.active_risk_level_counts || {};
  const donutSegments = [
    { label: 'Critical', value: sevCounts.critical || 0, color: '#f04444' },
    { label: 'High', value: sevCounts.high || 0, color: '#f07830' },
    { label: 'Medium', value: sevCounts.medium || 0, color: '#e0b020' },
    { label: 'Low', value: sevCounts.low || 0, color: '#30c060' },
  ];

  if (!stats) return statsError ? <LoadError message={statsError} onRetry={loadStats} /> : <Loading />;

  return (
    <>
      <section className="product-intro">
        <div>
          <div className="eyebrow">Self-hosted vulnerability watchtower</div>
          <h1>bongsu</h1>
          <p>
            Named after 봉수대, the Korean signal-fire watchtower, Bongsu gathers package evidence from hosts and running containers,
            separates OS packages from code libraries, and matches them against CVSS-aware vulnerability databases.
          </p>
        </div>
        <div className="install-box">
          <div className="label">One-line agent install</div>
          <code>curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "{window.location.origin}/api/install.sh" | sudo bash</code>
          {installerStatus && (
            <div style={{ marginTop: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
              <span className="badge" style={{ color: installerStatus.ready ? 'var(--low)' : 'var(--critical)' }}>
                installer {installerStatus.ready ? 'ready' : 'not ready'}
              </span>
              <span className="badge" style={{ color: installerStatus.agent.ready ? 'var(--low)' : 'var(--critical)' }}>
                agent {installerStatus.agent.ready ? (installerStatus.agent.version || `${Math.round((installerStatus.agent.bytes || 0) / 1024 / 1024)}MB`) : installerStatus.agent.error || 'missing'}
              </span>
              <span className="badge" style={{ color: installerStatus.trivy.ready ? 'var(--low)' : 'var(--medium)' }}>
                trivy {installerStatus.trivy.ready ? `${Math.round((installerStatus.trivy.bytes || 0) / 1024 / 1024)}MB` : installerStatus.trivy.error || 'optional'}
              </span>
            </div>
          )}
          {agentFleetWarnings.length > 0 && (
            <div style={{ marginTop: '0.5rem', color: 'var(--medium)', fontSize: '0.8125rem' }}>
              Agent fleet: {agentFleetWarnings.slice(0, 2).join('; ')}{agentFleetWarnings.length > 2 ? `; +${agentFleetWarnings.length - 2} more` : ''}
            </div>
          )}
          {agentFleetActions.length > 0 && (
            <div style={{ marginTop: '0.25rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Action: {agentFleetActions[0]}
            </div>
          )}
        </div>
      </section>

      {/* ── Operations console ──────────────────────────────────────────────── */}
      <div className="console-head">
        <div>
          <h2 className="console-title">Operations Console</h2>
          <div className="console-sub">Fleet vulnerability posture and scan activity</div>
        </div>
        <RangeSwitcher value={trendRange} onChange={setTrendRange} />
      </div>

      <div className="kpi-grid">
        <KpiCard
          label="Total Findings"
          value={(lastTrend?.total_vulns ?? stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}
          accent="var(--primary)"
          delta={totalDelta}
          spark={sparkSlice(r => r.total_vulns)}
          onClick={() => onOpenVulnerabilities({})}
        />
        <KpiCard
          label="Critical Risk"
          value={(stats.active_risk_level_counts?.critical || 0).toLocaleString()}
          accent="var(--critical)"
          delta={critDelta}
          spark={sparkSlice(r => r.critical_count)}
          sparkColor="#f04444"
          onClick={() => onOpenVulnerabilities({ riskLevel: 'critical' })}
        />
        <KpiCard
          label="Exploited"
          value={(lastTrend?.exploited_count || 0).toLocaleString()}
          accent="var(--high)"
          delta={exploitedDelta}
          spark={sparkSlice(r => r.exploited_count)}
          sparkColor="#f07830"
          onClick={() => onOpenVulnerabilities({ exploitedOnly: true })}
        />
        <KpiCard
          label="SLA Overdue"
          value={(stats.overdue_sla_count || 0).toLocaleString()}
          accent="var(--medium)"
          sub={<>C {stats.overdue_sla_risk_counts?.critical || 0} · H {stats.overdue_sla_risk_counts?.high || 0}</>}
          onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
        />
        <KpiCard
          label="Hosts"
          value={(stats.total_hosts || 0).toLocaleString()}
          accent="var(--low)"
          sub={<>{(lastTrend?.host_count ?? stats.total_hosts) || 0} reporting</>}
          onClick={() => onOpenHosts({})}
        />
      </div>

      <div className="console-charts">
        <div className="card chart-card chart-card-wide">
          <div className="card-header">
            <h2>Findings over time</h2>
            <span className="chart-legend">
              {SEV_KEYS.map(s => (
                <span key={s.key} className="chart-legend-item"><span className="chart-legend-dot" style={{ background: s.raw }} />{s.label}</span>
              ))}
            </span>
          </div>
          <div className="chart-body">
            {chartsLoading ? <Loading /> : enoughHistory ? <StackedAreaChart rows={trendRows} /> : <EmptyState message="Not enough history yet — charts appear after 2+ days of snapshots." />}
          </div>
        </div>
        <div className="card chart-card">
          <div className="card-header"><h2>Severity distribution</h2></div>
          <div className="chart-body">
            {donutSegments.reduce((s, x) => s + x.value, 0) > 0
              ? <DonutChart segments={donutSegments} />
              : <EmptyState message="No active findings." />}
          </div>
        </div>
      </div>

      <div className="card chart-card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>Scan activity ({trendRange}d)</h2>
          <span className="chart-legend">
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#7c6cf0' }} />Completed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#e0b020' }} />Degraded</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#f04444' }} />Failed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot chart-legend-line" />Packages</span>
          </span>
        </div>
        <div className="chart-body">
          {chartsLoading ? <Loading /> : enoughScans ? <BarSeries rows={scanRows} /> : <EmptyState message="Not enough scan activity yet." />}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Total Hosts</div>
          <div className="value">{stats.total_hosts}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Active Findings</div>
          <div className="value" style={{ color: 'var(--high)' }}>{(stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
          <div className="label">Raw Vulnerability Rows</div>
          <div className="value">{stats.total_vulnerabilities.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Critical Risk</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.active_risk_level_counts?.critical || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk</div>
          <div className="value" style={{ color: 'var(--high)' }}>{stats.active_risk_level_counts?.high || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Medium Risk</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.active_risk_level_counts?.medium || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Low Risk</div>
          <div className="value" style={{ color: 'var(--low)' }}>{stats.active_risk_level_counts?.low || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">SLA Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue actionable vulnerabilities"
          >
            {stats.overdue_sla_count || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            C {stats.overdue_sla_risk_counts?.critical || 0} / H {stats.overdue_sla_risk_counts?.high || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true, riskLevel: 'high' })}
            style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue high-risk vulnerabilities"
          >
            {stats.overdue_sla_risk_counts?.high || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Medium {stats.overdue_sla_risk_counts?.medium || 0} / Low {stats.overdue_sla_risk_counts?.low || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: suppressedTriageCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Suppressed Findings</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: suppressedTriageCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings"
          >
            {suppressedTriageCount}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Accepted {triageActiveCounts.accepted_risk || 0} / FP {triageActiveCounts.false_positive || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)' }} />
          <div className="label">Expiring Exceptions</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings with expiry dates"
          >
            {triageExpiringSoonTotal}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Next {stats.triage_expiring_soon_days || 14}d, accepted {triageExpiringSoonCounts.accepted_risk || 0}
          </div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Agents Online</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'online' })}
            style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open online hosts"
          >
            {effectiveAgentCounts.online || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Agents Stale</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'stale' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open stale hosts"
          >
            {effectiveAgentCounts.stale || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Agents Offline</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'offline' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open offline hosts"
          >
            {effectiveAgentCounts.offline || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: outdatedAgentCount || unknownAgentVersionCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Agent Version Drift</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_version_state: 'outdated' })}
            style={{ color: outdatedAgentCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts running an older agent than the installer binary"
          >
            {outdatedAgentCount}
          </button>
          <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
            current {currentAgentCount} / unknown {unknownAgentVersionCount}{agentFleetStatus ? ` / ${agentFleetOutdatedPercent.toFixed(1)}% outdated` : ''}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: inventoryCoverageColor }} />
          <div className="label">SBOM Coverage</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ inventory_status: 'none' })}
            style={{ color: inventoryCoverageColor, background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts without completed or degraded inventory scans"
          >
            {inventoryCoveragePercent.toFixed(1)}%
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {stats.inventory_covered_hosts || 0} / {stats.total_hosts} hosts, {inventoryFreshPercent.toFixed(1)}% fresh
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Tracked Packages</div>
          <div className="value">{(stats.inventory_latest_packages ?? totalPkgs).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE Sources</div>
          <div className="value">{cveSources.length || '-'}</div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Healthy SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'healthy' })} style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.healthy || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Degraded SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'degraded' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.degraded || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'stale' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.stale || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Empty SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'empty' })} style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.empty || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">No Completed Scan</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'none' })} style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.none || 0}</button>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Pending</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.pending || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Scan Requests Claimed</div>
          <div className="value">{stats.scan_request_counts?.claimed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Scan Requests Failed</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.scan_request_counts?.failed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Degraded</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.degraded || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale Pending Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'pending', stale: 'true' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open pending scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Stale Claimed Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'claimed', stale: 'true' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open claimed scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Current DB Rescan Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ background: 'transparent', border: 0, padding: 0, color: 'var(--text)', cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Stale Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Stale Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Degraded</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('degraded')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open degraded security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.degraded || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Rescan Failed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('failed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open failed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.failed || 0}
          </button>
        </div>
        <div className="stat-card" title={rescanProgress.revision ? `Revision ${rescanProgress.revision}` : 'Current security DB revision'}>
          <div className="accent-bar" style={{ background: rescanProgressColor }} />
          <div className="label">Current DB Rescan Done</div>
          <div className="value" style={{ color: rescanProgressColor }}>{rescanCompletePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(rescanProgress.terminal || 0).toLocaleString()} done, {(rescanProgress.open || 0).toLocaleString()} open of {(rescanProgress.total || 0).toLocaleString()}
          </div>
        </div>
        <div className="stat-card" title={scanCoverage.revision ? `Latest completed/degraded scan revision coverage for ${scanCoverage.revision}` : 'Latest completed/degraded scan revision coverage'}>
          <div className="accent-bar" style={{ background: scanCoverageColor }} />
          <div className="label">Current DB Scan Coverage</div>
          <div className="value" style={{ color: scanCoverageColor }}>{scanCoveragePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(scanCoverage.current_hosts || 0).toLocaleString()} current, {((scanCoverage.stale_hosts || 0) + (scanCoverage.unknown_hosts || 0)).toLocaleString()} stale/unknown
          </div>
        </div>
      </div>
      <div className="db-status-bar" style={{ marginTop: '1.5rem' }}>
        <h3>Vulnerability Database</h3>
        <span className={`status-dot ${health?.trivy_db_ready ? 'ready' : 'not-ready'}`}>
          Trivy: {health?.trivy_db?.status || (health?.trivy_db_ready ? 'ok' : 'not loaded')}
        </span>
        {health?.security_db && (
          <span className={`status-dot ${securitySourcesReady ? 'ready' : 'not-ready'}`} title={health.security_db.status_detail || ''}>
            Sources: {securitySourcesLabel}{health.security_db.status === 'never' && health.security_db.effective_status === 'ok' ? ' (persisted)' : ''}
          </span>
        )}
        {health?.security_recalculation && (
          <span className={`status-dot ${health.security_recalculation.running || health.security_recalculation.pending ? 'not-ready' : 'ready'}`} title={health.security_recalculation.pending_reason || ''}>
            Recalc: {health.security_recalculation.running ? 'running' : health.security_recalculation.pending ? 'queued' : 'idle'}
          </span>
        )}
        {health?.security_db_freshness && (
          <span
            className={`status-dot ${health.security_db_freshness.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={health.security_db_freshness.oldest_source ? `Oldest source: ${health.security_db_freshness.oldest_source}` : ''}
          >
            DB fresh: {health.security_db_freshness.status}
          </span>
        )}
        {health?.security_db_revision && (
          <span className="mono" title="Current merged security database revision" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            DB rev: {health.security_db_revision}
          </span>
        )}
        {lastSecurityBundleImport && (
          <span
            className={`status-dot ${lastSecurityBundleImport.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={lastSecurityBundleImport.bundle_created_at ? `Bundle created ${new Date(lastSecurityBundleImport.bundle_created_at).toLocaleString()}` : lastSecurityBundleImport.message || lastSecurityBundleImport.error || ''}
          >
            Bundle import: {lastSecurityBundleImport.status === 'ok'
              ? `${lastSecurityBundleImport.bundle_source_count ?? '-'} sources${lastSecurityBundleImport.security_db_revision ? `, rev ${lastSecurityBundleImport.security_db_revision}` : ''}`
              : lastSecurityBundleImport.stage || lastSecurityBundleImport.status}
          </span>
        )}
        {(health?.trivy_db_last_update || health?.trivy_db?.last_update) && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Trivy updated: {new Date(health.trivy_db_last_update || health.trivy_db?.last_update || '').toLocaleString()}
          </span>
        )}
        <button
          className="update-btn"
          onClick={handleUpdate}
          disabled={updating}
          style={{ marginLeft: 'auto' }}
        >
          {updating ? 'Updating...' : 'Update Trivy DB'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityUpdate}
          disabled={updating || !securityDbConfigured}
          title={securityDbConfigured ? 'Sync OSV/NVD/Trivy source database' : 'Set BONGSU_SECURITY_DB_SYNC_CMD on the server'}
          style={{ marginLeft: '0.5rem' }}
        >
          Sync Sources
        </button>
        <input
          className="compact-input"
          type="number"
          min="0"
          max="100"
          step="1"
          value={rematchMinQuality}
          onChange={(e) => setRematchMinQuality(e.target.value)}
          placeholder="Min matchable %"
          title="Only use CVE sources whose matchable record ratio is at least this percent"
          style={{ width: '9rem', marginLeft: '0.5rem' }}
        />
        <input
          className="compact-input"
          type="number"
          min="1"
          step="10000"
          value={rematchCandidateLimit}
          onChange={(e) => setRematchCandidateLimit(e.target.value)}
          placeholder={`Limit ${cveRematchPolicy?.candidate_limit?.toLocaleString() || 'default'}`}
          title="Maximum CVE-package candidates to evaluate for this manual rematch"
          style={{ width: '11rem', marginLeft: '0.5rem' }}
        />
        <button
          className="update-btn"
          onClick={handleRematch}
          disabled={rematching}
          style={{ marginLeft: '0.5rem' }}
        >
          {rematching ? 'Matching...' : 'Rematch CVEs'}
        </button>
        <button
          className="update-btn"
          onClick={handleCvssRecalc}
          disabled={cvssRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {cvssRecalcBusy ? 'Recalculating...' : 'Recalc CVSS'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityRecalc}
          disabled={securityRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {securityRecalcBusy ? 'Queueing...' : 'Full Recalc'}
        </button>
        <button
          className="update-btn"
          onClick={handleAffectedIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Affected Index
        </button>
        <button
          className="update-btn"
          onClick={handleReferenceIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Reference Index
        </button>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">CVE DB Status</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{cveDbStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {health?.security_db_revision ? `rev ${health.security_db_revision}` : `${cveSources.length || 0} sources tracked`}
          </div>
          <div style={{ color: cveStatsCacheStatus === 'stale' ? 'var(--medium)' : 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
            stats {cveStatsCacheStatus}{cveStatsDuration !== undefined ? ` · ${cveStatsDuration}ms` : ''} · {cveStatsGeneratedAt}
          </div>
          {osvCveSource?.last_update && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              OSV updated {new Date(osvCveSource.last_update).toLocaleString()}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveQualityColor }} />
          <div className="label">CVE DB Quality</div>
          <div className="value" style={{ color: cveQualityColor }}>{cveQualityStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveDbQuality?.warning_count || 0).toLocaleString()} warnings, {(cveDbQuality?.temporary_placeholders || 0).toLocaleString()} temp IDs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">Security Sync</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{securitySyncStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securitySyncDetail}
          </div>
          {securitySyncNext && securitySyncStatus !== 'syncing' && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              next {securitySyncNext}
            </div>
          )}
        </div>
        <div className="stat-card" title={latestSecuritySourceDisplay ? `Latest ${latestSecuritySourceDisplay.label} update ${new Date(latestSecuritySourceDisplay.at).toLocaleString()}` : securityDbStatus?.security_sources_error || ''}>
          <div className="accent-bar" style={{ background: securitySourceRegistryColor }} />
          <div className="label">Source Registry</div>
          <div className="value" style={{ color: securitySourceRegistryColor }}>
            {securitySourceRegistry.length ? `${securitySourceRegistryOk}/${securitySourceRegistryEnabled || securitySourceRegistry.length}` : '-'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securityDbStatus?.security_sources_error
              ? 'registry status unavailable'
              : securitySourceRegistry.length
                ? `${securitySourceRegistryRecords.toLocaleString()} records tracked`
                : 'waiting for source registry'}
          </div>
          {latestSecuritySourceDisplay && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              latest {latestSecuritySourceDisplay.source} {new Date(latestSecuritySourceDisplay.at).toLocaleString()}
            </div>
          )}
          {latestSecuritySourceExport?.last_exported_at && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {latestSecuritySourceExport.id} {new Date(latestSecuritySourceExport.last_exported_at).toLocaleString()}
            </div>
          )}
          {securityDbExportStale && (
            <div style={{ color: 'var(--medium)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {securityDbExportStatus?.status}{securityDbExportStatus?.outdated_source_count ? `, ${securityDbExportStatus.outdated_source_count} changed` : ''}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveSources.length || 0} merged sources
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveMatchableColor }} />
          <div className="label">CVE Matchable</div>
          <div className="value" style={{ color: cveMatchableColor }}>{cveTotalRecords ? cveMatchablePercent.toFixed(1) : '0.0'}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveTotalMatchable.toLocaleString()} records with ecosystem/range data
          </div>
        </div>
        <div className="stat-card" title={oldestOsvEcosystem?.last_update ? `Oldest OSV raw source ${oldestOsvEcosystem.ecosystem} updated ${new Date(oldestOsvEcosystem.raw_last_update || oldestOsvEcosystem.last_update).toLocaleString()}${oldestOsvEcosystem.indexed_last_update ? `, index rebuilt ${new Date(oldestOsvEcosystem.indexed_last_update).toLocaleString()}` : ''}` : cveStatsMeta?.osv_ecosystems_error || ''}>
          <div className="accent-bar" style={{ background: osvEcosystemColor }} />
          <div className="label">OSV Ecosystems</div>
          <div className="value" style={{ color: osvEcosystemColor }}>{osvEcosystems.length || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveStatsMeta?.osv_ecosystems_error
              ? 'ecosystem stats delayed'
              : oldestOsvEcosystem
                ? `${osvEcosystemRows.toLocaleString()} rows, ${oldestOsvEcosystem.ecosystem} raw oldest`
                : 'waiting for OSV index stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveAffectedIndexColor }} />
          <div className="label">Affected Index</div>
          <div className="value" style={{ color: cveAffectedIndexColor }}>{cveAffectedIndexIndexedOnly ? 'indexed' : cveAffectedIndex?.stale ? 'stale' : `${(cveAffectedIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveAffectedIndexIndexedOnly
              ? `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} indexed CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`
              : `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} / ${(cveAffectedIndex?.matchable_cves || 0).toLocaleString()} CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: affectedRebuildColor }} />
          <div className="label">Affected Rebuild</div>
          <div className="value" style={{ color: affectedRebuildColor }}>
            {affectedRebuildRunning ? 'running' : affectedRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {affectedRebuildRunning
              ? `${Math.round((affectedRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : affectedRebuildLast?.finished_at
                ? `${(affectedRebuildLast.indexed || 0).toLocaleString()} entries, ${(affectedRebuildLast.duration_ms || 0) > 0 ? `${((affectedRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveReferenceIndexColor }} />
          <div className="label">Reference Index</div>
          <div className="value" style={{ color: cveReferenceIndexColor }}>{cveReferenceIndex?.stale ? 'stale' : `${(cveReferenceIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveReferenceIndex?.count || 0).toLocaleString()} keys, {(cveReferenceIndex?.canonical_cves || 0).toLocaleString()} canonical CVEs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: referenceRebuildColor }} />
          <div className="label">Reference Rebuild</div>
          <div className="value" style={{ color: referenceRebuildColor }}>
            {referenceRebuildRunning ? 'running' : referenceRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {referenceRebuildRunning
              ? `${Math.round((referenceRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : referenceRebuildLast?.finished_at
                ? `${(referenceRebuildLast.indexed || 0).toLocaleString()} keys, ${(referenceRebuildLast.duration_ms || 0) > 0 ? `${((referenceRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: epssMergeColor }} />
          <div className="label">EPSS Merge</div>
          <div className="value" style={{ color: epssMergeColor }}>{epssMergeCoverage.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveEpssMerge?.non_epss_cves_with_epss || 0).toLocaleString()} / {(cveEpssMerge?.non_epss_cves || 0).toLocaleString()} local CVEs, {epssUniverseCoverage.toFixed(1)}% EPSS universe
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: weakestCveSource && (weakestCveSource.matchable_percent ?? 0) < 50 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Weakest CVE Source</div>
          <div className="value">{weakestCveSource ? weakestCveSource.source.toUpperCase() : '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {weakestCveSource ? `${(weakestCveSource.matchable_percent ?? 0).toFixed(1)}% matchable` : 'waiting for source stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Rematch Eligible Sources</div>
          <div className="value" style={{ color: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }}>{cveRematchEligibleCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveRematchExcludedCount} excluded, {cveRematchPolicyText}
          </div>
        </div>
        <div className="stat-card" title={lastRecalcTitle}>
          <div className="accent-bar" style={{ background: lastRecalcColor }} />
          <div className="label">Last Recalculation</div>
          <div className="value" style={{ color: lastRecalcColor }}>{lastRecalc?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastRecalc?.finished_at
              ? lastRecalcLimited
                ? `limited at ${(lastRecalc.rematch_candidates || 0).toLocaleString()} matches, ${(lastRecalc.rematch_scanned_candidates || 0).toLocaleString()} scanned`
                : `${new Date(lastRecalc.finished_at).toLocaleString()} · ${lastRecalc.rematch_new_vulns || 0} new · ${(lastRecalc.stale_rematch_scanned || 0).toLocaleString()} cleaned${lastRecalc.rematch_eligible_sources !== undefined ? ` · ${lastRecalc.rematch_eligible_sources} src` : ''}`
              : 'waiting for audit result'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: lastManualRematchColor }} />
          <div className="label">Manual Rematch</div>
          <div className="value" style={{ color: lastManualRematchColor }}>{lastManualRematch?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastManualRematch?.finished_at
              ? `${(lastManualRematch.matched || 0).toLocaleString()} matches, ${(lastManualRematch.scanned_candidates || 0).toLocaleString()} scanned${lastManualRematch.eligible_sources !== undefined ? ` · ${lastManualRematch.eligible_sources} src` : ''}`
              : 'no manual run yet'}
          </div>
        </div>
        <div className="stat-card" title={lastAutoRescan?.error || lastAutoRescan?.reason || ''}>
          <div className="accent-bar" style={{ background: lastAutoRescanColor }} />
          <div className="label">Auto Rescan Queue</div>
          <div className="value" style={{ color: lastAutoRescanColor }}>{lastAutoRescan?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastAutoRescan?.finished_at
              ? `${(lastAutoRescan.queued || 0).toLocaleString()} queued, ${(lastAutoRescan.already_pending || 0).toLocaleString()} pending of ${(lastAutoRescan.eligible || 0).toLocaleString()} hosts`
              : 'waiting for DB update'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveFreshnessColor }} />
          <div className="label">CVE Source Alerts</div>
          <div className="value" style={{ color: cveFreshnessColor }}>{cveSourceAlertCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {missingCveSources.length ? `missing ${missingCveSources.join(', ')}` : health?.security_db_freshness?.oldest_source ? `${health.security_db_freshness.oldest_source} oldest, ${oldestCveAgeDays.toFixed(1)}d` : 'freshness pending'}
          </div>
        </div>
      </div>
      {health?.trivy_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Trivy DB: {health.trivy_db.last_error}</div>}
      {health?.security_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security sources: {health.security_db.last_error}</div>}
      {health?.security_db_revision_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB revision: {health.security_db_revision_error}</div>}
      {health?.security_db_freshness?.error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB freshness: {health.security_db_freshness.error}</div>}
      {securityDbWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityDbStatus?.status === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>Security DB: {securityDbWarnings.slice(0, 3).join('; ')}{securityDbWarnings.length > 3 ? `; +${securityDbWarnings.length - 3} more` : ''}</div>}
      {securityDbActions.length > 0 && <div style={{ marginTop: '0.25rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Action: {securityDbActions.slice(0, 2).join('; ')}</div>}
      {securityDbStatus?.security_sources_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security source registry: {securityDbStatus.security_sources_error}</div>}
      {securitySourceRegistryBroken && !securityDbStatus?.security_sources_error && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>
          Source registry attention: {securitySourceRegistry.filter(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error)).slice(0, 5).map(s => `${s.id} ${s.last_status}${s.record_count ? ` (${s.record_count.toLocaleString()})` : ''}`).join(', ')}
        </div>
      )}
      {cveQualityWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cveQualityStatus === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>CVE DB quality: {cveQualityWarnings.slice(0, 3).join(', ')}{cveQualityWarnings.length > 3 ? `, +${cveQualityWarnings.length - 3} more` : ''}</div>}
      {cveStatsMeta?.osv_ecosystems_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>OSV ecosystem stats: {cveStatsMeta.osv_ecosystems_error}</div>}
      {cveAffectedIndex?.detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index detailed stats delayed; showing indexed-only health snapshot.</div>}
      {cveDbQuality?.affected_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index quality: {cveDbQuality.affected_index_detail_error}</div>}
      {cveDbQuality?.reference_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Reference index quality: {cveDbQuality.reference_index_detail_error}</div>}
      {cveEpssMerge && cveEpssMerge.epss_cves > 0 && cveEpssMerge.enriched_records === 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>EPSS source is loaded but no non-EPSS CVE rows are enriched.</div>}
      {cveAffectedIndex?.stale && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index is older than matchable CVE rows. Rebuild the index before trusting rematch coverage.</div>}
      {(cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index missing matchable sources: {cveAffectedIndex?.missing_matchable_sources?.join(', ')}</div>}
      {(cveAffectedIndex?.orphans || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index orphan rows: {(cveAffectedIndex?.orphans || 0).toLocaleString()}</div>}
      {lastRecalcLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>CVE rematch hit candidate limit: {(lastRecalc?.rematch_candidates || 0).toLocaleString()} / {(lastRecalc?.rematch_candidate_limit || 0).toLocaleString()} matches, {(lastRecalc?.rematch_scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {lastManualRematchLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Manual CVE rematch hit candidate limit: {(lastManualRematch?.matched || 0).toLocaleString()} / {(lastManualRematch?.candidate_limit || 0).toLocaleString()} matches, {(lastManualRematch?.scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {missingCveSources.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Missing CVE sources: {missingCveSources.join(', ')}</div>}
      {health?.security_db_freshness?.oldest_last_update && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
          Oldest CVE source: {health.security_db_freshness.oldest_source || '-'} updated {new Date(health.security_db_freshness.oldest_last_update).toLocaleString()}
        </div>
      )}
      {updateMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: updateMsg.includes('fail') ? 'var(--critical)' : 'var(--low)' }}>{updateMsg}</div>}
      {rematchMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: rematchMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{rematchMsg}</div>}
      {cvssRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cvssRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{cvssRecalcMsg}</div>}
      {securityRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{securityRecalcMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Airgap Security Bundle</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Export outside, import inside air-gapped environments</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={securityBundleIncludeTrivy} onChange={(e) => setSecurityBundleIncludeTrivy(e.target.checked)} />
          Include Trivy DB
        </label>
        <button className="update-btn" onClick={handleSecurityBundleExport} disabled={securityBundleBusy} style={{ marginLeft: '0.5rem' }}>
          Export Bundle
        </button>
        <label className="update-btn" style={{ marginLeft: '0.5rem', cursor: securityBundleBusy ? 'default' : 'pointer', opacity: securityBundleBusy ? 0.6 : 1 }}>
          Import Bundle
          <input
            type="file"
            accept=".tar.gz,.tgz,application/gzip"
            disabled={securityBundleBusy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.currentTarget.value = '';
              handleSecurityBundleImport(file);
            }}
            style={{ display: 'none' }}
          />
        </label>
      </div>
      {securityBundleMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityBundleMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{securityBundleMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Operational Retention</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Defaults: scans 180d, requests 90d, audit 365d</span>
        <button className="update-btn" onClick={() => handleRetentionPrune(true)} disabled={retentionBusy} style={{ marginLeft: 'auto' }}>Dry Run</button>
        <button
          className="delete-btn"
          onClick={() => { if (confirm('Prune old scans, completed scan requests, and audit logs using server retention defaults?')) handleRetentionPrune(false); }}
          disabled={retentionBusy}
        >
          Prune
        </button>
      </div>
      {retentionMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: retentionMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{retentionMsg}</div>}
      {(ownerSummary.length > 0 || teamSummary.length > 0 || environmentSummary.length > 0 || criticalitySummary.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          <SummaryTable title="Owner Remediation Queue" groupBy="owner" rows={ownerSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Team Remediation Queue" groupBy="team" rows={teamSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Environment Risk Queue" groupBy="environment" rows={environmentSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Criticality Risk Queue" groupBy="criticality" rows={criticalitySummary} onOpenVulnerabilities={onOpenVulnerabilities} />
        </div>
      )}
      {cveSources.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>CVE Database Sources</h2></div>
          <table>
            <thead><tr><th>Source</th><th>Records</th><th>Matchable</th><th>Matchable %</th><th>Rematch</th><th>Ecosystem</th><th>Fixed</th><th>Ranges</th><th>CVSS</th><th>Last Update</th></tr></thead>
            <tbody>
              {cveSources.map(s => {
                const belowQuality = sourceBelowQuality(s);
                const excludedByPolicy = s.rematch_eligible === false;
                const staleSource = staleCveSourceByName.get(s.source.toLowerCase());
                const rowWarn = belowQuality || excludedByPolicy || staleSource;
                return (
                  <tr key={s.source} style={rowWarn ? { background: staleSource ? 'rgba(248, 113, 113, 0.08)' : 'rgba(224, 176, 32, 0.08)' } : undefined}>
                    <td>
                      <span style={{ fontWeight: 600 }}>{s.source.toUpperCase()}</span>
                      {staleSource && <span className="badge" title={staleSource.last_update ? `last update ${new Date(staleSource.last_update).toLocaleString()}` : 'missing last update'} style={{ marginLeft: 6, color: 'var(--critical)' }}>stale</span>}
                      {belowQuality && <span className="badge" style={{ marginLeft: 6, color: 'var(--medium)' }}>below gate</span>}
                      {excludedByPolicy && <span className="badge" title={s.rematch_exclusion || ''} style={{ marginLeft: 6, color: 'var(--medium)' }}>policy excluded</span>}
                    </td>
                    <td className="mono">{s.count.toLocaleString()}</td>
                    <td className="mono">{(s.matchable || 0).toLocaleString()}</td>
                    <td className="mono" style={{ color: belowQuality || excludedByPolicy ? 'var(--medium)' : undefined }}>{(s.matchable_percent ?? 0).toFixed(1)}%</td>
                    <td>
                      <span className="badge" title={s.rematch_exclusion || ''} style={{ color: excludedByPolicy ? 'var(--medium)' : 'var(--low)' }}>
                        {excludedByPolicy ? 'excluded' : 'eligible'}
                      </span>
                    </td>
                    <td className="mono">{(s.with_ecosystem || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_fixed || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_ranges || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_cvss || 0).toLocaleString()}</td>
                    <td className="mono" style={{ fontSize: '0.8125rem', color: staleSource ? 'var(--critical)' : undefined }}>
                      {s.last_update ? new Date(s.last_update).toLocaleString() : '-'}
                      {staleSource?.age_seconds !== undefined && <div style={{ fontSize: '0.75rem' }}>{formatAge(staleSource.age_seconds)} old</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="info-card" style={{ marginTop: '1.5rem' }}>
        <div className="info-header">
          <div className="info-icon">🏔</div>
          <div>
            <h3>Bongsu</h3>
            <p>
              Bongsu is named after a Korean signal-fire watchtower. It centralizes package evidence from hosts and containers,
              then matches that inventory against CVSS-aware vulnerability databases.
            </p>
            <p>
              Agents collect package inventories periodically. The server stores host, container, image, and package context so operators
              can inspect findings by host, package, container, and vulnerability.
            </p>
            <div className="info-links">
              <span><strong>Hosts</strong> - registered systems and SBOM state</span>
              <span><strong>Packages</strong> - package search and CVSS ordering</span>
              <span><strong>Vulnerabilities</strong> - CVE detail, triage, and filtering</span>
            </div>
          </div>
        </div>
      </div>
      <div style={{ textAlign: 'right', marginTop: '1rem' }}>
        <a href="https://github.com/ziozzang/bongsu" target="_blank" rel="noopener" style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textDecoration: 'none' }}>
          github.com/ziozzang/bongsu ↗
        </a>
      </div>
    </>
  );
}

function SummaryTable({ title, groupBy, rows, onOpenVulnerabilities }: { title: string; groupBy: 'owner' | 'team' | 'environment' | 'criticality'; rows: VulnSummaryRow[]; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void }) {
  const topRows = rows.slice(0, 8);
  const openRow = (row: VulnSummaryRow, extra?: VulnerabilityFilters) => {
    onOpenVulnerabilities({ [groupBy]: row.group, ...extra });
  };
  return (
    <div className="card">
      <div className="card-header"><h2>{title}</h2></div>
      <table>
        <thead>
          <tr><th>Group</th><th>Total</th><th>Critical Risk</th><th>High Risk</th><th>Overdue</th></tr>
        </thead>
        <tbody>
          {topRows.map(row => (
            <tr key={row.group}>
              <td><button type="button" className="link-button" onClick={() => openRow(row)}>{row.group}</button></td>
              <td className="mono"><button type="button" className="link-button mono" onClick={() => openRow(row)}>{row.total.toLocaleString()}</button></td>
              <td className="mono" style={{ color: 'var(--critical)', fontWeight: row.risk?.critical ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'critical' })}>{row.risk?.critical || 0}</button></td>
              <td className="mono" style={{ color: 'var(--high)', fontWeight: row.risk?.high ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'high' })}>{row.risk?.high || 0}</button></td>
              <td className="mono" style={{ color: row.overdue ? 'var(--critical)' : 'var(--text-muted)', fontWeight: row.overdue ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { overdueOnly: true })}>{row.overdue || 0}</button></td>
            </tr>
          ))}
          {topRows.length === 0 && <tr className="empty-row"><td colSpan={5}>No findings</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function HostsView({ initialFilters = {}, onSelectHost }: { initialFilters?: HostFilters; onSelectHost: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [scanMsg, setScanMsg] = useState('');
  const [agentStatus, setAgentStatus] = useState(initialFilters.agent_status || '');
  const [inventoryStatus, setInventoryStatus] = useState(initialFilters.inventory_status || '');
  const [agentVersionState, setAgentVersionState] = useState(initialFilters.agent_version_state || '');
  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [team, setTeam] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const meta = { q: query, owner, team, environment, criticality, os: osFilter };
  const reloadHosts = () => load(agentStatus, inventoryStatus, agentVersionState, meta);
  const load = useCallback((status: string, inventory: string, versionState: string, m: { q: string; owner: string; team: string; environment: string; criticality: string; os: string }) => {
    setLoading(true);
    setLoadError('');
    const params: Record<string, string> = {};
    if (status) params.agent_status = status;
    if (inventory) params.inventory_status = inventory;
    if (versionState) params.agent_version_state = versionState;
    if (m.q) params.q = m.q;
    if (m.owner) params.owner = m.owner;
    if (m.team) params.team = m.team;
    if (m.environment) params.environment = m.environment;
    if (m.criticality) params.criticality = m.criticality;
    if (m.os) params.os = m.os;
    api.hosts(params)
      .then(h => { setHosts(h || []); setLoading(false); })
      .catch((e) => { setLoadError(e instanceof Error ? e.message : 'Failed to load hosts'); setLoading(false); });
  }, []);
  useEffect(() => { load(agentStatus, inventoryStatus, agentVersionState, meta); }, [load, agentStatus, inventoryStatus, agentVersionState]);
  const handleHostSearch = () => load(agentStatus, inventoryStatus, agentVersionState, meta);
  const handleHostKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleHostSearch(); };

  const sevColor = severityColor;

  return (
    <>
      <div className="view-title-row">
        <h1 style={{ marginBottom: 0 }}>Hosts</h1>
        <button
          className="update-btn"
          onClick={async () => {
            setScanMsg('');
            try {
              await api.createScanRequest({ scan_type: 'manual', packages_only: true, reason: 'dashboard all-host force scan' });
              setScanMsg('Force scan requested for all polling agents');
            } catch {
              setScanMsg('Force scan request failed');
            }
          }}
        >
          Force Scan All
        </button>
      </div>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={agentStatus} onChange={(e) => setAgentStatus(e.target.value)}>
            <option value="">All Agent Status</option>
            <option value="online">Online</option>
            <option value="stale">Stale</option>
            <option value="offline">Offline</option>
            <option value="unknown">Unknown</option>
          </select>
          <select value={inventoryStatus} onChange={(e) => setInventoryStatus(e.target.value)}>
            <option value="">All Inventory</option>
            <option value="healthy">Healthy SBOM</option>
            <option value="degraded">Degraded SBOM</option>
            <option value="stale">Stale SBOM</option>
            <option value="empty">Empty SBOM</option>
            <option value="none">No Completed Scan</option>
          </select>
          <select value={agentVersionState} onChange={(e) => setAgentVersionState(e.target.value)}>
            <option value="">All Agent Versions</option>
            <option value="current">Current Agent</option>
            <option value="outdated">Outdated Agent</option>
            <option value="unknown">Unknown Version</option>
          </select>
          <input
            type="text"
            placeholder="Search hostname / IP / OS..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 200 }}
            title="Substring match on hostname, IP, or OS"
          />
          <input
            type="text"
            placeholder="Owner..."
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="Team..."
            value={team}
            onChange={(e) => setTeam(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="Environment..."
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 130 }}
          />
          <input
            type="text"
            placeholder="Criticality..."
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="OS (name/version)..."
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 150 }}
          />
        </div>
        <div className="filter-controls-row">
          <span className="result-count" style={{ whiteSpace: 'normal' }}>
            Agent status uses last_seen; inventory status uses latest completed or degraded scan
          </span>
          <div className="filter-actions">
            <span className="result-count">{hosts.length.toLocaleString()} hosts</span>
            <button className="btn btn-primary" onClick={handleHostSearch}>Search</button>
          </div>
        </div>
      </div>
      {scanMsg && <div style={{ marginBottom: '0.75rem', color: scanMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{scanMsg}</div>}
      <div className="card">
        {loading ? <Loading /> : loadError ? <LoadError message={loadError} onRetry={handleHostSearch} /> : (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Agent</th>
              <th>Trust</th>
              <th>Version</th>
              <th>OS</th>
              <th>Owner</th>
              <th>Env</th>
              <th>Criticality</th>
              <th>IP</th>
              <th>Latest SBOM</th>
              <th>Active Critical</th>
              <th>Active High</th>
              <th>Active Medium</th>
              <th>Active Low</th>
              <th>Last Seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {hosts.map(h => {
              const counts = h.active_vuln_counts || h.vuln_counts || {};
              return (
                <tr key={h.id}>
                  <td><span className="host-link" title={`IP: ${h.ip_address}`} onClick={() => onSelectHost(h.id)}>{h.hostname}</span></td>
                  <td>
                    <span className="badge" style={{ color: agentStatusColor(h.agent_status), background: 'var(--bg-raised)' }}>{h.agent_status || 'unknown'}</span>
                    <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{formatAge(h.last_seen_age_seconds)}</div>
                  </td>
                  <td>
                    <span className="badge" style={{ color: h.agent_token_set ? 'var(--low)' : 'var(--medium)' }}>
                      {h.agent_token_set ? 'bound' : 'pending'}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{h.agent_version || '-'}</td>
                  <td>{h.os_name} {h.os_version}</td>
                  <td>{h.owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{h.environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{h.criticality || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono">{h.ip_address}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>
                    {h.latest_inventory?.latest_scan_id ? (
                      <>
                        {h.latest_inventory.latest_package_count || 0} pkgs / {h.latest_inventory.latest_vulnerability_count || 0} vulns / {h.latest_inventory.latest_container_count || 0} ctrs
                        {h.latest_inventory.latest_scan_status === 'degraded' && <span className="badge" style={{ color: 'var(--medium)', marginLeft: 6 }}>degraded</span>}
                        <div style={{ color: 'var(--text-muted)' }}>{h.latest_inventory.latest_scan_at ? new Date(h.latest_inventory.latest_scan_at).toLocaleString() : '-'}</div>
                      </>
                    ) : <span style={{ color: 'var(--text-muted)' }}>No completed or degraded scan</span>}
                  </td>
                  <td style={{ color: sevColor('CRITICAL'), fontWeight: 600 }}>{counts.CRITICAL || 0}</td>
                  <td style={{ color: sevColor('HIGH'), fontWeight: 600 }}>{counts.HIGH || 0}</td>
                  <td style={{ color: sevColor('MEDIUM'), fontWeight: 600 }}>{counts.MEDIUM || 0}</td>
                  <td style={{ color: sevColor('LOW'), fontWeight: 600 }}>{counts.LOW || 0}</td>
                  <td className="mono">{new Date(h.last_seen).toLocaleString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.375rem' }}>
                      <button
                        className="delete-btn"
                        onClick={async (e) => {
                          e.stopPropagation();
                          setScanMsg('');
                          try {
                            await api.createScanRequest({ host_id: h.id, scan_type: 'manual', packages_only: true, reason: `dashboard force scan: ${h.hostname}` });
                            setScanMsg(`Force scan requested for ${h.hostname}`);
                          } catch {
                            setScanMsg(`Force scan request failed for ${h.hostname}`);
                          }
                        }}
                      >
                        Scan
                      </button>
                      <button
                        className="delete-btn"
                        onClick={async (e) => {
                          e.stopPropagation();
                          if (!confirm(`Delete host ${h.hostname} and its collected inventory?`)) return;
                          setScanMsg('');
                          try {
                            await api.deleteHost(h.id);
                            setScanMsg(`Deleted ${h.hostname}`);
                            reloadHosts();
                          } catch {
                            setScanMsg(`Delete failed for ${h.hostname}`);
                          }
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {hosts.length === 0 && <tr className="empty-row"><td colSpan={16}>No hosts registered</td></tr>}
          </tbody>
        </table>
        )}
      </div>
    </>
  );
}

function HostDetailView({ hostId, onBack, onSelectVuln }: { hostId: string; onBack: () => void; onSelectVuln?: (v: Vuln) => void }) {
  const [host, setHost] = useState<Host | null>(null);
  const [vulnCounts, setVulnCounts] = useState<Record<string, number>>({});
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [pkgPage, setPkgPage] = useState(0);
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [totalUsers, setTotalUsers] = useState(0);
  const [processes, setProcesses] = useState<ProcessSnapshot[]>([]);
  const [totalProcesses, setTotalProcesses] = useState(0);
  const [ports, setPorts] = useState<PortInfo[]>([]);
  const [totalPorts, setTotalPorts] = useState(0);
  const [exportMsg, setExportMsg] = useState('');
  const [metadata, setMetadata] = useState({ owner: '', team: '', environment: '', criticality: '', tags: '{}' });
  const [metadataMsg, setMetadataMsg] = useState('');
  const [agentTokenMsg, setAgentTokenMsg] = useState('');
  const limit = 50;

  useEffect(() => {
    api.host(hostId).then(h => {
      setHost(h);
      setMetadata({
        owner: h.owner || '',
        team: h.team || '',
        environment: h.environment || '',
        criticality: h.criticality || '',
        tags: h.tags || '{}',
      });
    }).catch(() => {});
    api.hostVulnCounts(hostId).then(setVulnCounts).catch(() => {});
  }, [hostId]);

  const loadPkgs = useCallback((page: number) => {
    api.hostPackages(hostId, limit, page * limit).then(r => { setPkgs(r.items || []); setTotalPkgs(r.total); setPkgPage(page); }).catch(() => {});
  }, [hostId]);

  useEffect(() => { loadPkgs(0); }, [loadPkgs]);

  useEffect(() => {
    api.hostUsers(hostId, 20, 0).then(r => { setUsers(r.items || []); setTotalUsers(r.total || 0); }).catch(() => {});
    api.hostProcesses(hostId, 20, 0).then(r => { setProcesses(r.items || []); setTotalProcesses(r.total || 0); }).catch(() => {});
    api.hostPorts(hostId, 20, 0).then(r => { setPorts(r.items || []); setTotalPorts(r.total || 0); }).catch(() => {});
  }, [hostId]);

  if (!host) return <Loading />;

  const saveMetadata = async () => {
    setMetadataMsg('Saving...');
    try {
      JSON.parse(metadata.tags || '{}');
      const updated = await api.updateHostMetadata(host.id, metadata);
      setHost(updated);
      setMetadataMsg('Saved');
    } catch {
      setMetadataMsg('Save failed');
    }
  };

  const resetAgentToken = async () => {
    if (!confirm(`Reset agent token binding for ${host.hostname}? The next valid agent check-in will bind a new token.`)) return;
    setAgentTokenMsg('Resetting...');
    try {
      await api.resetHostAgentToken(host.id);
      setHost({ ...host, agent_token_set: false });
      setAgentTokenMsg('Agent token reset');
    } catch {
      setAgentTokenMsg('Reset failed');
    }
  };

  return (
    <>
      <button className="back-btn" onClick={onBack}>&larr; Back</button>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '1rem' }}>
        <h1 style={{ marginBottom: 0 }}>{host.hostname}</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {exportMsg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{exportMsg}</span>}
          <button
            className="filter-btn"
            onClick={async () => {
              setExportMsg('Exporting...');
              try {
                await api.exportHostSBOM(host.id, host.hostname, 'cyclonedx');
                setExportMsg('CycloneDX exported');
              } catch {
                setExportMsg('Export failed');
              }
            }}
          >
            CycloneDX
          </button>
          <button
            className="filter-btn"
            onClick={async () => {
              setExportMsg('Exporting...');
              try {
                await api.exportHostSBOM(host.id, host.hostname, 'spdx');
                setExportMsg('SPDX exported');
              } catch {
                setExportMsg('Export failed');
              }
            }}
          >
            SPDX
          </button>
        </div>
      </div>

      <div className="stats-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: agentStatusColor(host.agent_status) }} />
          <div className="label">Agent</div>
          <div style={{ fontSize: '0.875rem', color: agentStatusColor(host.agent_status), fontWeight: 700, textTransform: 'uppercase' }}>{host.agent_status || 'unknown'}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{formatAge(host.last_seen_age_seconds)} since check-in</div>
        </div>
        <div className="stat-card"><div className="label">Agent Version</div><div className="mono" style={{ fontSize: '0.875rem' }}>{host.agent_version || '-'}</div></div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: host.agent_token_set ? 'var(--low)' : 'var(--medium)' }} />
          <div className="label">Agent Trust</div>
          <div style={{ fontSize: '0.875rem', color: host.agent_token_set ? 'var(--low)' : 'var(--medium)', fontWeight: 700, textTransform: 'uppercase' }}>{host.agent_token_set ? 'bound' : 'pending bind'}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>token hash is never exposed</div>
        </div>
        <div className="stat-card"><div className="label">OS</div><div style={{ fontSize: '0.875rem' }}>{host.os_name} {host.os_version}</div></div>
        <div className="stat-card"><div className="label">Kernel</div><div className="mono" style={{ fontSize: '0.875rem' }}>{host.kernel}</div></div>
        <div className="stat-card"><div className="label">CPU</div><div style={{ fontSize: '0.875rem' }}>{host.cpu_cores} cores</div></div>
        <div className="stat-card"><div className="label">Memory</div><div style={{ fontSize: '0.875rem' }}>{(host.memory_mb / 1024).toFixed(1)} GB</div></div>
        <div className="stat-card"><div className="label">Owner</div><div style={{ fontSize: '0.875rem' }}>{host.owner || '-'}</div></div>
        <div className="stat-card"><div className="label">Environment</div><div style={{ fontSize: '0.875rem' }}>{host.environment || '-'}</div></div>
        <div className="stat-card"><div className="label">Critical</div><div className="value" style={{ color: 'var(--critical)', fontSize: '1.25rem' }}>{vulnCounts.CRITICAL || 0}</div></div>
        <div className="stat-card"><div className="label">High</div><div className="value" style={{ color: 'var(--high)', fontSize: '1.25rem' }}>{vulnCounts.HIGH || 0}</div></div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
          <h2>Asset Metadata</h2>
        </div>
        <div className="filters">
          <input type="text" placeholder="Owner" value={metadata.owner} onChange={(e) => setMetadata({ ...metadata, owner: e.target.value })} />
          <input type="text" placeholder="Team" value={metadata.team} onChange={(e) => setMetadata({ ...metadata, team: e.target.value })} />
          <select value={metadata.environment} onChange={(e) => setMetadata({ ...metadata, environment: e.target.value })}>
            <option value="">Environment</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="test">Test</option>
          </select>
          <select value={metadata.criticality} onChange={(e) => setMetadata({ ...metadata, criticality: e.target.value })}>
            <option value="">Criticality</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input type="text" placeholder='Tags JSON, e.g. {"service":"api"}' value={metadata.tags} onChange={(e) => setMetadata({ ...metadata, tags: e.target.value })} style={{ minWidth: 260 }} />
          <button className="filter-btn" onClick={saveMetadata}>Save</button>
          {metadataMsg && <span style={{ color: metadataMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>{metadataMsg}</span>}
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
          <h2>Agent Trust</h2>
        </div>
        <div className="filters">
          <button className="btn btn-secondary" onClick={resetAgentToken}>Reset Agent Token</button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Current binding: {host.agent_token_set ? 'bound to this host' : 'waiting for next valid agent token'}
          </span>
          {agentTokenMsg && <span style={{ color: agentTokenMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>{agentTokenMsg}</span>}
        </div>
      </div>

      <FactsCard title="System Facts" facts={host.facts} collectedAt={host.facts_collected_at} />

      <div className="split-grid" style={{ marginBottom: '1rem' }}>
        <div className="card">
          <div className="card-header"><h2>Users ({totalUsers})</h2></div>
          <table>
            <thead><tr><th>User</th><th>UID</th><th>GID</th><th>Shell</th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id || `${u.username}-${u.uid}`}>
                  <td className="mono">{u.username}</td><td>{u.uid}</td><td>{u.gid}</td><td className="mono">{u.shell || '-'}</td>
                </tr>
              ))}
              {users.length === 0 && <tr className="empty-row"><td colSpan={4}>No user inventory</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-header"><h2>Listening Ports ({totalPorts})</h2></div>
          <table>
            <thead><tr><th>Port</th><th>Protocol</th><th>Process</th><th>Address</th></tr></thead>
            <tbody>
              {ports.map(p => (
                <tr key={p.id || `${p.protocol}-${p.address}-${p.port}`}>
                  <td className="mono">{p.port}</td><td>{p.protocol}</td><td className="mono">{p.name || p.pid || '-'}</td><td className="mono">{p.address || '-'}</td>
                </tr>
              ))}
              {ports.length === 0 && <tr className="empty-row"><td colSpan={4}>No port inventory</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="card-header">
          <h2>Top Processes ({totalProcesses})</h2>
        </div>
        <table>
          <thead>
            <tr><th>PID</th><th>Name</th><th>User</th><th>CPU</th><th>Mem</th><th>Command</th></tr>
          </thead>
          <tbody>
            {processes.map(p => (
              <tr key={p.id || `${p.pid}-${p.name}`}>
                <td className="mono">{p.pid}</td>
                <td className="mono">{p.name}</td>
                <td>{p.user || '-'}</td>
                <td className="mono">{p.cpu_usage.toFixed(1)}%</td>
                <td className="mono">{p.mem_usage.toFixed(1)}%</td>
                <td className="mono" style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.cmdline || '-'}</td>
              </tr>
            ))}
            {processes.length === 0 && <tr className="empty-row"><td colSpan={6}>No process inventory</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Packages ({totalPkgs})</h2>
        </div>
        <table>
          <thead>
            <tr><th>Name</th><th>Version</th><th>Type</th><th>Source</th><th>Container</th><th>CVSS</th><th>Vulns</th></tr>
          </thead>
          <tbody>
            {pkgs.map(p => (
              <tr key={p.id}>
                <td className="mono">{p.name}</td>
                <td className="mono">{p.version}</td>
                <td>{p.pkg_type}</td>
                <td>{p.source}</td>
                <td>{p.container || '-'}</td>
                <td className="mono"><CvssTooltip pkgId={p.id} score={p.max_cvss} onSelectVuln={onSelectVuln} /></td>
                <td style={{ fontWeight: p.vuln_count > 0 ? 600 : 400 }}>{p.vuln_count || 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={pkgPage} limit={limit} total={totalPkgs} onPage={loadPkgs} />
      </div>
    </>
  );
}

function VulnsView({ initialFilters, onSelectVuln }: { initialFilters?: VulnerabilityFilters; onSelectVuln: (v: Vuln) => void }) {
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState('');
  const [triageStatus, setTriageStatus] = useState(initialFilters?.triageStatus || '');
  const [assignee, setAssignee] = useState('');
  const [findingSource, setFindingSource] = useState('');
  const [riskLevel, setRiskLevel] = useState(initialFilters?.riskLevel || '');
  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [pkgQuery, setPkgQuery] = useState('');
  const [sortBy, setSortBy] = useState('risk_score');
  const [sortDesc, setSortDesc] = useState(true);
  const [loading, setLoading] = useState(true);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostMeta, setHostMeta] = useState<Record<string, Host>>({});
  const [hostIds, setHostIds] = useState<string[]>([]);
  const [containers, setContainers] = useState<string[]>([]);
  const [findingSources, setFindingSources] = useState<string[]>([]);
  const [owner, setOwner] = useState(initialFilters?.owner || '');
  const [team, setTeam] = useState(initialFilters?.team || '');
  const [environment, setEnvironment] = useState(initialFilters?.environment || '');
  const [criticality, setCriticality] = useState(initialFilters?.criticality || '');
  const [showNoFix, setShowNoFix] = useState(false);
  const [showMismatch, setShowMismatch] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(!!initialFilters?.overdueOnly);
  const [exploitedOnly, setExploitedOnly] = useState(!!initialFilters?.exploitedOnly);
  const [minEpss, setMinEpss] = useState('');
  const [vulnId, setVulnId] = useState('');
  const [vEcosystem, setVEcosystem] = useState('');
  const [vPkgType, setVPkgType] = useState('');
  const [minCvss, setMinCvss] = useState('');
  const [maxCvss, setMaxCvss] = useState('');
  const [hasFix, setHasFix] = useState('');
  const [affectedFor, setAffectedFor] = useState<string | null>(null);
  const [exportMsg, setExportMsg] = useState('');
  const [loadError, setLoadError] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkAssignee, setBulkAssignee] = useState('');
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkMsg, setBulkMsg] = useState('');
  const [editAssigneeId, setEditAssigneeId] = useState('');
  const [editAssigneeVal, setEditAssigneeVal] = useState('');
  const [editAssigneeBusy, setEditAssigneeBusy] = useState(false);
  const loadSeq = useRef(0);
  const limit = 50;

  const load = useCallback((p: number, sev: string, triage: string, asg: string, source: string, risk: string, overdue: boolean, exploited: boolean, epss: string, hId: string, cont: string, own: string, tm: string, env: string, crit: string, pq: string, sBy: string, sDesc: boolean, sNoFix: boolean, sMismatch: boolean, adv: { vulnId: string; ecosystem: string; pkgType: string; minCvss: string; maxCvss: string; hasFix: string }) => {
    const seq = ++loadSeq.current;
    setLoading(true);
    setLoadError('');
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (adv.vulnId) params.vuln_id = adv.vulnId;
    if (adv.ecosystem) params.ecosystem = adv.ecosystem;
    if (adv.pkgType) params.pkg_type = adv.pkgType;
    if (adv.minCvss) params.min_cvss = adv.minCvss;
    if (adv.maxCvss) params.max_cvss = adv.maxCvss;
    if (adv.hasFix) params.has_fix = adv.hasFix;
    if (sev) params.severity = sev;
    if (triage) params.triage_status = triage;
    if (asg) params.assignee = asg;
    if (source) params.finding_source = source;
    if (risk) params.risk_level = risk;
    if (overdue) params.overdue = 'true';
    if (exploited) params.exploited = 'true';
    const minEpssParam = epssParam(epss);
    if (minEpssParam) params.min_epss = minEpssParam;
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
    if (own) params.owner = own;
    if (tm) params.team = tm;
    if (env) params.environment = env;
    if (crit) params.criticality = crit;
    if (pq) params.pkg_name = pq;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }
    if (sNoFix) params.show_no_fix = 'true';
    if (sMismatch) params.show_mismatch = 'true';
    api.vulnerabilities(params)
      .then(r => { if (seq !== loadSeq.current) return; setVulns(r.items || []); setTotal(r.total); setPage(p); setLoading(false); setSelectedIds(new Set()); setEditAssigneeId(''); })
      .catch((e) => { if (seq !== loadSeq.current) return; setLoadError(e instanceof Error ? e.message : 'Failed to load vulnerabilities'); setLoading(false); });
  }, []);

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const meta: Record<string, Host> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; meta[h.id] = h; });
      setHostMap(m);
      setHostMeta(meta);
    });
    api.vulnFilters().then(f => {
      setHostIds(f.host_ids || []);
      setContainers(f.containers || []);
      setFindingSources(f.finding_sources || []);
    }).catch(() => {});
  }, []);

  const vadv = { vulnId, ecosystem: vEcosystem, pkgType: vPkgType, minCvss, maxCvss, hasFix };

  useEffect(() => { load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv); }, [load, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, showNoFix, showMismatch, vEcosystem, vPkgType, hasFix]);

  const handleSearch = () => { load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : col === 'risk_score' || col === 'cvss_score' || col === 'severity' || col === 'exploited' || col === 'epss_score' || col === 'epss_percentile';
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, col, nextDesc, showNoFix, showMismatch, vadv);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const badgeClass = (sev: string) => `badge badge-${sev.toLowerCase()}`;
  const epssParam = (epss: string) => {
    const n = Number(epss);
    if (!Number.isFinite(n) || n <= 0) return '';
    return String(Math.min(n, 100) / 100);
  };
  const currentExportParams = (format: 'csv' | 'json') => {
    const params: Record<string, string> = { format };
    if (severity) params.severity = severity;
    if (triageStatus) params.triage_status = triageStatus;
    if (assignee) params.assignee = assignee;
    if (findingSource) params.finding_source = findingSource;
    if (riskLevel) params.risk_level = riskLevel;
    if (overdueOnly) params.overdue = 'true';
    if (exploitedOnly) params.exploited = 'true';
    const minEpssParam = epssParam(minEpss);
    if (minEpssParam) params.min_epss = minEpssParam;
    if (hostId) params.host_id = hostId;
    if (container) params.container = container;
    if (owner) params.owner = owner;
    if (team) params.team = team;
    if (environment) params.environment = environment;
    if (criticality) params.criticality = criticality;
    if (pkgQuery) params.pkg_name = pkgQuery;
    if (sortBy) { params.sort_by = sortBy; params.sort_order = sortDesc ? 'desc' : 'asc'; }
    if (showNoFix) params.show_no_fix = 'true';
    if (showMismatch) params.show_mismatch = 'true';
    return params;
  };
  const exportVulns = async (format: 'csv' | 'json') => {
    setExportMsg('Exporting...');
    try {
      await api.exportVulnerabilities(currentExportParams(format));
      setExportMsg('Exported');
    } catch {
      setExportMsg('Export failed');
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const allSelected = vulns.length > 0 && vulns.every(v => selectedIds.has(v.id));
  const toggleSelectAll = () => {
    setSelectedIds(prev => {
      if (vulns.length > 0 && vulns.every(v => prev.has(v.id))) {
        const next = new Set(prev);
        vulns.forEach(v => next.delete(v.id));
        return next;
      }
      const next = new Set(prev);
      vulns.forEach(v => next.add(v.id));
      return next;
    });
  };
  const reloadCurrent = () => load(page, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv);
  const applyBulkTriage = async () => {
    const targets = vulns.filter(v => selectedIds.has(v.id));
    if (targets.length === 0 || !bulkStatus) return;
    setBulkBusy(true);
    let done = 0;
    let failed = 0;
    for (const v of targets) {
      setBulkMsg(`Applying ${done + 1}/${targets.length}...`);
      try {
        await api.triageVulnerability({
          vulnerability_id: v.vulnerability_id,
          host_id: v.host_id,
          pkg_name: v.pkg_name,
          status: bulkStatus,
          assignee: bulkAssignee,
        });
      } catch {
        failed++;
      }
      done++;
    }
    setBulkBusy(false);
    setBulkMsg(failed ? `Applied ${done - failed}/${targets.length} (${failed} failed)` : `Applied to ${done} finding${done === 1 ? '' : 's'}`);
    reloadCurrent();
  };
  const startEditAssignee = (v: Vuln) => {
    setEditAssigneeId(v.id);
    setEditAssigneeVal(v.triage_assignee || '');
  };
  const saveEditAssignee = async (v: Vuln) => {
    setEditAssigneeBusy(true);
    try {
      await api.triageVulnerability({
        vulnerability_id: v.vulnerability_id,
        host_id: v.host_id,
        pkg_name: v.pkg_name,
        status: v.triage_status || 'open',
        assignee: editAssigneeVal,
      });
      setVulns(prev => prev.map(x => x.id === v.id ? { ...x, triage_assignee: editAssigneeVal } : x));
      setEditAssigneeId('');
    } catch {
      // keep editor open on failure
    }
    setEditAssigneeBusy(false);
  };

  const owners = Array.from(new Set(Object.values(hostMeta).map(h => h.owner || '').filter(Boolean))).sort();
  const teams = Array.from(new Set(Object.values(hostMeta).map(h => h.team || '').filter(Boolean))).sort();
  const environments = Array.from(new Set(Object.values(hostMeta).map(h => h.environment || '').filter(Boolean))).sort();
  const criticalities = Array.from(new Set(Object.values(hostMeta).map(h => h.criticality || '').filter(Boolean))).sort();
  const clearFilters = () => {
    setSeverity('');
    setTriageStatus('');
    setAssignee('');
    setFindingSource('');
    setRiskLevel('');
    setHostId('');
    setContainer('');
    setOwner('');
    setTeam('');
    setEnvironment('');
    setCriticality('');
    setPkgQuery('');
    setShowNoFix(false);
    setShowMismatch(false);
    setOverdueOnly(false);
    setExploitedOnly(false);
    setMinEpss('');
    setVulnId('');
    setVEcosystem('');
    setVPkgType('');
    setMinCvss('');
    setMaxCvss('');
    setHasFix('');
  };
  const activeFilters = [
    severity && `Severity: ${severity}`,
    triageStatus && `Status: ${triageStatus.replace('_', ' ')}`,
    assignee && `Assignee: ${assignee}`,
    findingSource && `Source: ${findingSourceLabel(findingSource)}`,
    riskLevel && `Risk: ${riskLevel}`,
    overdueOnly && 'Overdue',
    exploitedOnly && 'CISA KEV',
    minEpss && `EPSS >= ${minEpss}%`,
    hostId && `Host: ${hostMap[hostId] || hostId}`,
    container && `Container: ${container}`,
    owner && `Owner: ${owner}`,
    team && `Team: ${team}`,
    environment && `Environment: ${environment}`,
    criticality && `Criticality: ${criticality}`,
    pkgQuery && `Package: ${pkgQuery}`,
    vulnId && `CVE: ${vulnId}`,
    vEcosystem && `Ecosystem: ${vEcosystem}`,
    vPkgType && `Pkg Type: ${vPkgType}`,
    minCvss && `CVSS >= ${minCvss}`,
    maxCvss && `CVSS <= ${maxCvss}`,
    hasFix === 'yes' && 'Fix available',
    hasFix === 'no' && 'No fix available',
    showNoFix && 'No fix info',
    showMismatch && 'Wrong ecosystem',
  ].filter(Boolean) as string[];

  const cols: [string, string][] = [
    ['risk_score', 'Risk'], ['exploited', 'KEV'], ['epss_score', 'EPSS'], ['vulnerability_id', 'CVE'], ['severity', 'Severity'], ['cvss_score', 'CVSS'],
    ['pkg_name', 'Package'], ['owner', 'Owner'], ['environment', 'Env'], ['container', 'Container'], ['pkg_type', 'Pkg Type'],
    ['installed_version', 'Installed'], ['fixed_version', 'Fixed'], ['due_at', 'Due'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Vulnerabilities</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={triageStatus} onChange={(e) => setTriageStatus(e.target.value)}>
            <option value="">All Status</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <input
            type="text"
            placeholder="Assignee (or 'unassigned')"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            style={{ minWidth: 170 }}
            title="Filter by triage assignee; use 'unassigned' for findings without an assignee"
          />
          <select value={findingSource} onChange={(e) => setFindingSource(e.target.value)}>
            <option value="">All Sources</option>
            {(findingSources.length ? findingSources : ['scanner', 'cve-db']).map(s => (
              <option key={s} value={s}>{findingSourceLabel(s)}</option>
            ))}
          </select>
          <select value={riskLevel} onChange={(e) => setRiskLevel(e.target.value)}>
            <option value="">All Risk</option>
            <option value="critical">Critical Risk</option>
            <option value="high">High Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="low">Low Risk</option>
          </select>
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {hostIds.map(id => (
              <option key={id} value={id}>{hostMap[id] || id}</option>
            ))}
          </select>
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">All Containers</option>
            {containers.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <select value={owner} onChange={(e) => setOwner(e.target.value)}>
            <option value="">All Owners</option>
            {owners.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          <select value={team} onChange={(e) => setTeam(e.target.value)}>
            <option value="">All Teams</option>
            {teams.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="">All Environments</option>
            {environments.map(e => <option key={e} value={e}>{e}</option>)}
          </select>
          <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
            <option value="">All Criticality</option>
            {criticalities.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <input
            type="text"
            placeholder="Search package name..."
            value={pkgQuery}
            onChange={(e) => setPkgQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 180 }}
          />
          <input
            type="text"
            placeholder="CVE id (e.g. CVE-2024)"
            value={vulnId}
            onChange={(e) => setVulnId(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 170 }}
            title="Filter by vulnerability id substring, e.g. CVE-2024 or DEBIAN-"
          />
          <input
            type="text"
            placeholder="Ecosystem..."
            value={vEcosystem}
            onChange={(e) => setVEcosystem(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 130 }}
            title="Ecosystem, e.g. pypi/npm/debian/rhel/alpine"
            list="vuln-ecosystem-list"
          />
          <datalist id="vuln-ecosystem-list">
            <option value="pypi" /><option value="npm" /><option value="debian" /><option value="rhel" /><option value="alpine" />
            <option value="go" /><option value="maven" /><option value="cargo" /><option value="gem" /><option value="nuget" />
          </datalist>
          <input
            type="text"
            placeholder="Pkg type..."
            value={vPkgType}
            onChange={(e) => setVPkgType(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 120 }}
            title="Package type"
          />
          <select value={hasFix} onChange={(e) => setHasFix(e.target.value)} title="Fix availability">
            <option value="">All Fixes</option>
            <option value="yes">Has fix</option>
            <option value="no">No fix</option>
          </select>
          <input
            type="number"
            min="0"
            max="10"
            step="0.1"
            placeholder="Min CVSS"
            value={minCvss}
            onChange={(e) => setMinCvss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 100 }}
            title="Minimum CVSS score"
          />
          <input
            type="number"
            min="0"
            max="10"
            step="0.1"
            placeholder="Max CVSS"
            value={maxCvss}
            onChange={(e) => setMaxCvss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 100 }}
            title="Maximum CVSS score"
          />
          <input
            type="number"
            min="0"
            max="100"
            step="1"
            placeholder="Min EPSS %"
            value={minEpss}
            onChange={(e) => setMinEpss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 115 }}
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="No fix info" checked={showNoFix} onChange={setShowNoFix} />
            <CheckboxField label="Wrong ecosystem" checked={showMismatch} onChange={setShowMismatch} />
            <CheckboxField label="Overdue" checked={overdueOnly} onChange={setOverdueOnly} />
            <CheckboxField label="CISA KEV" checked={exploitedOnly} onChange={setExploitedOnly} />
          </div>
          <div className="filter-actions">
            <span className="result-count">{exportMsg || `${total.toLocaleString()} results`}</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
            <button className="btn btn-secondary" onClick={() => exportVulns('csv')}>Export CSV</button>
            <button className="btn btn-secondary" onClick={() => exportVulns('json')}>Export JSON</button>
          </div>
        </div>
        {activeFilters.length > 0 && (
          <div className="active-filters">
            {activeFilters.map(f => <span key={f} className="filter-chip">{f}</span>)}
            <button type="button" className="filter-clear" onClick={clearFilters}>Clear Filters</button>
          </div>
        )}
      </div>
      {selectedIds.size > 0 && (
        <div className="card" style={{ marginBottom: '1rem', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <strong style={{ whiteSpace: 'nowrap' }}>{selectedIds.size} selected</strong>
          <select value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)} disabled={bulkBusy}>
            <option value="">Set status...</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <input
            type="text"
            placeholder="Assignee (optional)"
            value={bulkAssignee}
            onChange={(e) => setBulkAssignee(e.target.value)}
            disabled={bulkBusy}
            style={{ minWidth: 170 }}
          />
          <button className="btn btn-primary" onClick={applyBulkTriage} disabled={bulkBusy || !bulkStatus}>
            {bulkBusy ? 'Applying...' : 'Apply to selected'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => { setSelectedIds(new Set()); setBulkMsg(''); }} disabled={bulkBusy}>Clear selection</button>
          {bulkMsg && <span className="result-count">{bulkMsg}</span>}
        </div>
      )}
      <div className="card">
        {loading ? <Loading /> : loadError ? <LoadError message={loadError} onRetry={handleSearch} /> : (
          <table>
            <thead>
              <tr>
                <th style={{ width: 28 }}><input type="checkbox" checked={allSelected} onChange={toggleSelectAll} title="Select all on page" /></th>
                <th>Host</th>
                <th>Status</th>
                <th>Source</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
                <th>Assignee</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} style={{ cursor: 'pointer' }} onClick={() => onSelectVuln(v)}>
                  <td onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
                    <input type="checkbox" checked={selectedIds.has(v.id)} onChange={() => toggleSelect(v.id)} />
                  </td>
                  <td><span className="host-link">{hostMap[v.host_id] || v.host_id.slice(0, 8)}</span></td>
                  <td><span className="badge">{(v.triage_status || 'open').replace('_', ' ')}</span></td>
                  <td>
                    <span className="badge" title={(v.advisory_sources || []).length ? `Advisory: ${(v.advisory_sources || []).join(', ')}` : ''}>{findingSourceLabel(v.finding_source)}</span>
                    {(v.advisory_sources || []).length > 0 && <div className="mono" style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>{(v.advisory_sources || []).slice(0, 2).join(', ')}</div>}
                    {(v.advisory_evidence || []).length > 0 && <div className="mono" style={{ fontSize: '0.625rem', color: '#22c55e', marginTop: 2 }}>{(v.advisory_evidence || []).length} verified</div>}
                  </td>
                  <td className="mono" style={{ fontWeight: 700, color: riskLevelColor(v.risk_level) }}>
                    {v.risk_score ? v.risk_score.toFixed(1) : '-'}
                    <div style={{ fontSize: '0.625rem', textTransform: 'uppercase', color: riskLevelColor(v.risk_level) }}>{riskLevelLabel(v.risk_level)}</div>
                  </td>
                  <td>{v.exploited ? <span className="badge badge-critical">KEV</span> : <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono" style={{ color: (v.epss_score || 0) >= 0.5 ? 'var(--critical)' : (v.epss_score || 0) >= 0.1 ? 'var(--high)' : 'var(--text-muted)' }}>
                    {v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : '-'}
                  </td>
                  <td className="mono">
                    <span className="host-link" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</span>
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ marginLeft: 6, height: '1.25rem', padding: '0 6px', fontSize: '0.625rem' }}
                      title="Show hosts & containers affected by this CVE"
                      onClick={(e) => { e.stopPropagation(); setAffectedFor(v.vulnerability_id); }}
                    >
                      assets
                    </button>
                  </td>
                  <td><span className={badgeClass(v.severity)}>{v.severity}</span></td>
                  <td className="mono" style={{ color: v.cvss_score >= 9 ? 'var(--critical)' : v.cvss_score >= 7 ? 'var(--high)' : v.cvss_score >= 4 ? 'var(--medium)' : 'inherit', fontWeight: 600 }}>{v.cvss_score > 0 ? v.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{v.pkg_name}</td>
                  <td>{v.host_owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{v.host_environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono">{v.container || '(host)'}</td>
                  <td className="mono">{v.pkg_type || v.ecosystem || '-'}</td>
                  <td className="mono">{v.installed_version}</td>
                  <td className="mono">
                    {v.fixed_version
                      ? (v.installed_version
                        ? (() => {
                            const cmp = verCmp(v.installed_version, v.fixed_version);
                            const sym = cmp >= 0 ? '≥' : '<';
                            const color = cmp >= 0 ? '#22c55e' : 'var(--high)';
                            return <span style={{ fontWeight: 600 }}>
                              <span style={{ color, fontWeight: 700, marginRight: 2 }}>{sym}</span>
                              {v.fixed_version}
                              {cmp >= 0 && <span style={{ fontSize: '0.625rem', background: 'rgba(34,197,94,0.15)', padding: '1px 5px', borderRadius: 3, marginLeft: 4 }}>FIXED</span>}
                            </span>;
                          })()
                        : v.fixed_version)
                      : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                  </td>
                  <td className="mono" style={{ color: v.overdue ? 'var(--critical)' : 'var(--text-muted)' }}>
                    {v.due_at ? new Date(v.due_at).toLocaleDateString() : '-'}
                  </td>
                  <td onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
                    {editAssigneeId === v.id ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <input
                          type="text"
                          autoFocus
                          value={editAssigneeVal}
                          onChange={(e) => setEditAssigneeVal(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') saveEditAssignee(v); if (e.key === 'Escape') setEditAssigneeId(''); }}
                          disabled={editAssigneeBusy}
                          style={{ width: 110 }}
                        />
                        <button className="filter-btn" onClick={() => saveEditAssignee(v)} disabled={editAssigneeBusy} style={{ padding: '2px 6px' }}>✓</button>
                        <button type="button" className="filter-clear" onClick={() => setEditAssigneeId('')} disabled={editAssigneeBusy} style={{ padding: '2px 6px' }}>✕</button>
                      </span>
                    ) : (
                      <span
                        className="host-link"
                        title="Click to set assignee"
                        onClick={() => startEditAssignee(v)}
                        style={{ color: v.triage_assignee ? 'inherit' : 'var(--text-muted)' }}
                      >
                        {v.triage_assignee || '—'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {vulns.length === 0 && <tr className="empty-row"><td colSpan={19}>No vulnerabilities found</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv)} />
      </div>
      {affectedFor && <AffectedAssetsModal vulnerabilityId={affectedFor} onClose={() => setAffectedFor(null)} />}
    </>
  );
}

function AffectedAssetsModal({ vulnerabilityId, onClose }: { vulnerabilityId: string; onClose: () => void }) {
  const [data, setData] = useState<AffectedAssetsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    fetchAffectedAssets(vulnerabilityId, 500)
      .then(r => { if (active) { setData(r); setLoading(false); } })
      .catch(e => { if (active) { setError(e instanceof Error ? e.message : 'Failed to load affected assets'); setLoading(false); } });
    return () => { active = false; };
  }, [vulnerabilityId]);

  const assets = data?.assets || [];

  return (
    <Modal
      onClose={onClose}
      title={<>
        Affected assets — <span className="mono" style={{ color: 'var(--primary)' }}>{vulnerabilityId}</span>
        {data && <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 10, fontSize: '0.8125rem' }}>{data.total} asset{data.total === 1 ? '' : 's'}</span>}
      </>}
    >
      <>
          {loading ? <Loading label="Loading affected assets..." /> : error ? (
            <LoadError message={error} />
          ) : assets.length === 0 ? (
            <EmptyState message="No affected assets found" />
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Asset</th>
                  <th>Container / Image</th>
                  <th>Package</th>
                  <th>Pkg Type</th>
                  <th>Installed → Fixed</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Owner</th>
                  <th>Env</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a, i) => (
                  <tr key={`${a.host_id}-${a.container}-${a.pkg_name}-${i}`}>
                    <td>{a.hostname || a.host_id.slice(0, 8)}</td>
                    <td><span className="badge">{a.asset_type || (a.container ? 'container' : 'host')}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {a.container || a.image_name
                        ? <>{a.container || '-'}{a.image_name ? <div style={{ color: 'var(--text-muted)' }}>{a.image_name}</div> : null}</>
                        : <span style={{ color: 'var(--text-muted)' }}>(host)</span>}
                    </td>
                    <td className="mono">{a.pkg_name}</td>
                    <td className="mono">{a.pkg_type || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {a.installed_version || '-'}
                      {a.fixed_version
                        ? <span style={{ color: 'var(--low)', fontWeight: 600 }}> → {a.fixed_version}</span>
                        : <span style={{ color: 'var(--text-muted)' }}> → no fix</span>}
                    </td>
                    <td><span className={`badge badge-${(a.severity || 'unknown').toLowerCase()}`}>{a.severity || '-'}</span></td>
                    <td className="mono" style={{ color: severityColor(a.severity), fontWeight: 600 }}>{a.cvss_score > 0 ? a.cvss_score.toFixed(1) : '-'}</td>
                    <td>{a.owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                    <td>{a.environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </>
    </Modal>
  );
}

function VulnDetailView({ vuln, onBack }: { vuln: Vuln | null; onBack: () => void }) {
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [triageStatus, setTriageStatus] = useState(vuln?.triage_status || 'open');
  const [triageReason, setTriageReason] = useState(vuln?.triage_reason || '');
  const [triageAssignee, setTriageAssignee] = useState(vuln?.triage_assignee || '');
  const [triageComment, setTriageComment] = useState(vuln?.triage_comment || '');
  const [triageExpiresAt, setTriageExpiresAt] = useState(dateInputValue(vuln?.triage_expires_at));
  const [triageScope, setTriageScope] = useState<'finding' | 'host' | 'global'>('finding');
  const [triageMsg, setTriageMsg] = useState('');

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m); setHostIPMap(ip);
    });
  }, []);

  useEffect(() => {
    setTriageStatus(vuln?.triage_status || 'open');
    setTriageReason(vuln?.triage_reason || '');
    setTriageAssignee(vuln?.triage_assignee || '');
    setTriageComment(vuln?.triage_comment || '');
    setTriageExpiresAt(dateInputValue(vuln?.triage_expires_at));
    setTriageMsg('');
  }, [vuln]);

  if (!vuln) return <div>No vulnerability selected</div>;

  const badgeClass = `badge badge-${vuln.severity.toLowerCase()}`;
  const sevColor = severityColor(vuln.severity);
  const saveTriage = async () => {
    setTriageMsg('Saving...');
    try {
      await api.triageVulnerability({
        vulnerability_id: vuln.vulnerability_id,
        host_id: triageScope === 'global' ? '' : vuln.host_id,
        pkg_name: triageScope === 'finding' ? vuln.pkg_name : '',
        status: triageStatus,
        reason: triageReason,
        comment: triageComment,
        assignee: triageAssignee,
        expires_at: triageExpiresAt ? `${triageExpiresAt}T00:00:00Z` : null,
      });
      setTriageMsg('Saved');
    } catch (err) {
      setTriageMsg(err instanceof Error ? err.message : 'Save failed');
    }
  };

  return (
    <>
      <button className="back-btn" onClick={onBack}>&larr; Back</button>
      <h1 style={{ marginBottom: '1rem' }}>{vuln.vulnerability_id}</h1>

      <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="label">Severity</div>
          <div className="value"><span className={badgeClass}>{vuln.severity}</span></div>
        </div>
        <div className="stat-card">
          <div className="label">CVSS Score</div>
          <div className="value" style={{ color: sevColor }}>{vuln.cvss_score > 0 ? vuln.cvss_score.toFixed(1) : '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Risk Score</div>
          <div className="value" style={{ color: (vuln.risk_score || 0) >= 80 ? 'var(--critical)' : (vuln.risk_score || 0) >= 60 ? 'var(--high)' : (vuln.risk_score || 0) >= 40 ? 'var(--medium)' : 'inherit' }}>
            {vuln.risk_score ? vuln.risk_score.toFixed(1) : '-'}
          </div>
          <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: riskLevelColor(vuln.risk_level) }}>{riskLevelLabel(vuln.risk_level)} Risk</div>
        </div>
        <div className="stat-card">
          <div className="label">Host</div>
          <div style={{ fontSize: '0.875rem' }}><span className="host-link" title={`IP: ${hostIPMap[vuln.host_id] || ''}`}>{hostMap[vuln.host_id] || vuln.host_id.slice(0, 8)}</span></div>
        </div>
        <div className="stat-card">
          <div className="label">Container</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.container || '(host)'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Source</div>
          <div style={{ fontSize: '0.875rem' }}>{findingSourceLabel(vuln.finding_source)}</div>
          {(vuln.advisory_sources || []).length > 0 && (
            <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              {(vuln.advisory_sources || []).join(', ')}
            </div>
          )}
          {(vuln.advisory_evidence || []).length > 0 && (
            <div style={{ fontSize: '0.75rem', color: '#22c55e', marginTop: '0.25rem' }}>
              {(vuln.advisory_evidence || []).length} verified advisories
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="label">CISA KEV</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.exploited ? <span className="badge badge-critical">Known exploited</span> : '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">EPSS</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(2)}%` : '-'}</div>
          {vuln.epss_percentile ? <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>p{(vuln.epss_percentile * 100).toFixed(1)}</div> : null}
        </div>
        <div className="stat-card">
          <div className="label">Triage</div>
          <div style={{ fontSize: '0.875rem', textTransform: 'capitalize' }}>{(triageStatus || 'open').replace('_', ' ')}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {triageExpiresAt ? `expires ${triageExpiresAt}` : 'no expiry'}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">SLA Due</div>
          <div style={{ fontSize: '0.875rem', color: vuln.overdue ? 'var(--critical)' : 'inherit' }}>
            {vuln.due_at ? new Date(vuln.due_at).toLocaleDateString() : '-'}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <h3 style={{ margin: '0 0 0.75rem' }}>Triage</h3>
        <div className="filters" style={{ marginBottom: '0.75rem' }}>
          <select value={triageStatus} onChange={(e) => setTriageStatus(e.target.value)}>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <select value={triageScope} onChange={(e) => setTriageScope(e.target.value as 'finding' | 'host' | 'global')}>
            <option value="finding">This host and package</option>
            <option value="host">This host and CVE</option>
            <option value="global">All hosts for this CVE</option>
          </select>
          <input type="text" placeholder="Reason" value={triageReason} onChange={(e) => setTriageReason(e.target.value)} />
          <input type="text" placeholder="Assignee (담당자)" value={triageAssignee} onChange={(e) => setTriageAssignee(e.target.value)} title="Assignee responsible for remediation" />
          <input type="date" value={triageExpiresAt} onChange={(e) => setTriageExpiresAt(e.target.value)} title="Triage expiry date" />
          {triageExpiresAt && <button className="btn btn-secondary btn-sm" onClick={() => setTriageExpiresAt('')}>Clear Expiry</button>}
        </div>
        <textarea
          value={triageComment}
          onChange={(e) => setTriageComment(e.target.value)}
          placeholder="Operator note, exception approval, remediation owner, ticket reference..."
          style={{ width: '100%', minHeight: 90, resize: 'vertical', marginBottom: '0.75rem' }}
        />
        <button className="filter-btn" onClick={saveTriage}>Save Triage</button>
        {triageMsg && <span style={{ marginLeft: '0.75rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{triageMsg}</span>}
        {triageComment && <div style={{ marginTop: '0.75rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Current note: {triageComment}</div>}
      </div>

      {vuln.title && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>Title</h3>
          <div>{vuln.title}</div>
        </div>
      )}

      {vuln.description && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>Description</h3>
          <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>{vuln.description}</div>
        </div>
      )}

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <h3 style={{ margin: '0 0 0.75rem' }}>Affected Package</h3>
        <table>
          <tbody>
            <tr><td style={{ color: 'var(--text-muted)', width: 140 }}>Package</td><td className="mono">{vuln.pkg_name}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Asset Type</td><td className="mono">{vuln.asset_type || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Package Type</td><td className="mono">{vuln.pkg_type || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Ecosystem</td><td className="mono">{vuln.ecosystem || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Advisory Sources</td><td className="mono">{(vuln.advisory_sources || []).length ? (vuln.advisory_sources || []).join(', ') : '-'}</td></tr>
            {vuln.image_name && <tr><td style={{ color: 'var(--text-muted)' }}>Image</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.image_name}</td></tr>}
            {vuln.image_id && <tr><td style={{ color: 'var(--text-muted)' }}>Image ID</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.image_id}</td></tr>}
            {vuln.container_id && <tr><td style={{ color: 'var(--text-muted)' }}>Container ID</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.container_id}</td></tr>}
            {vuln.target && <tr><td style={{ color: 'var(--text-muted)' }}>Target</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.target}</td></tr>}
            <tr><td style={{ color: 'var(--text-muted)' }}>Installed Version</td><td className="mono">{vuln.installed_version}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Fixed Version</td><td className="mono" style={{ color: vuln.fixed_version ? 'var(--low)' : 'var(--critical)', fontWeight: 600 }}>{vuln.fixed_version || 'No fix available'}</td></tr>
            {vuln.pkg_path && <tr><td style={{ color: 'var(--text-muted)' }}>Path</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.pkg_path}</td></tr>}
          </tbody>
        </table>
      </div>

      {(vuln.advisory_evidence || []).length > 0 && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.75rem' }}>Advisory Evidence</h3>
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Ecosystem</th>
                <th>Fixed</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Title</th>
              </tr>
            </thead>
            <tbody>
              {(vuln.advisory_evidence || []).map((e, idx) => (
                <tr key={`${e.source}-${idx}`}>
                  <td><span className="badge">{e.source}</span></td>
                  <td className="mono">{e.ecosystem || '-'}</td>
                  <td className="mono">{e.fixed_version || '-'}</td>
                  <td className="mono">{e.cvss_score ? e.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{e.epss_score ? `${(e.epss_score * 100).toFixed(1)}%` : '-'}</td>
                  <td style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.title || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {vuln.cvss_vector && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>CVSS Vector</h3>
          <div className="mono" style={{ fontSize: '0.8125rem', marginBottom: '0.75rem', color: 'var(--primary)' }}>{vuln.cvss_vector}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {(() => {
              const parsed = parseCvssVector(vuln.cvss_vector);
              return parsed.parts.map(p => {
                const [k, v] = p.split(':');
                if (!k || v === undefined) return null;
                return <div key={k} style={{ display: 'inline-block', marginRight: '1.25rem', marginBottom: '0.25rem' }}><strong style={{ color: 'var(--text)' }}>{parsed.labels[k] || k}</strong>: {parsed.values[k]?.[v] || v}</div>;
              });
            })()}
          </div>
        </div>
      )}

      {(vuln.primary_url || vuln.vulnerability_id.startsWith('CVE-')) && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>External References</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', fontSize: '0.8125rem' }}>
            {vuln.primary_url && <a href={vuln.primary_url} target="_blank" rel="noopener">{vuln.primary_url} ↗</a>}
            {vuln.vulnerability_id.startsWith('CVE-') && <a href={`https://nvd.nist.gov/vuln/detail/${vuln.vulnerability_id}`} target="_blank" rel="noopener">NVD - {vuln.vulnerability_id} ↗</a>}
          </div>
        </div>
      )}
    </>
  );
}

const LANG_GROUPS: Record<string, string[]> = {
  'OS Packages': ['debian', 'alpine', 'redhat', 'ubuntu', 'amazon', 'oracle', 'suse', 'photon', 'centos', 'rocky', 'almalinux', 'fedora', 'arch', 'busybox', 'wolfi'],
  'Python': ['python-pkg', 'pip', 'poetry', 'pipenv', 'conda'],
  'Node.js': ['node-pkg', 'npm', 'yarn', 'pnpm', 'node'],
  'Go': ['gomod', 'go', 'gobinary'],
  'Rust': ['cargo', 'rustbinary'],
  'Java': ['jar', 'maven', 'gradle'],
  'PHP': ['composer'],
  'Ruby': ['gem', 'bundler'],
  '.NET': ['nuget', 'dotnet'],
};

function resolvePkgTypes(langLabel: string, allTypes: string[]): string[] {
  if (langLabel === '' || langLabel === '__all__') return [];
  if (langLabel === '__other__') {
    const known = new Set(Object.values(LANG_GROUPS).flat());
    return allTypes.filter(t => !known.has(t));
  }
  const group = LANG_GROUPS[langLabel];
  if (group) return group.filter(t => allTypes.includes(t));
  return allTypes.filter(t => t === langLabel);
}

function PackagesView({ onSelectVuln }: { onSelectVuln?: (v: Vuln) => void }) {
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const loadSeq = useRef(0);
  const [filterOpts, setFilterOpts] = useState<FilterOptions | null>(null);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});

  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [lang, setLang] = useState('');
  const [source, setSource] = useState('');
  const [query, setQuery] = useState('');
  const [version, setVersion] = useState('');
  const [ecosystem, setEcosystem] = useState('');
  const [arch, setArch] = useState('');
  const [assetType, setAssetType] = useState('');
  const [hasVulns, setHasVulns] = useState(false);
  const [minCvss, setMinCvss] = useState('');
  const [sortBy, setSortBy] = useState('');
  const [sortDesc, setSortDesc] = useState(false);
  const limit = 100;

  useEffect(() => {
    api.packageFilters().then(setFilterOpts).catch(() => {});
    api.hosts().then(hosts => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hosts || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m);
      setHostIPMap(ip);
    }).catch(() => {});
  }, []);

  const load = useCallback((p: number, hId: string, cont: string, langLabel: string, src: string, q: string, sBy: string, sDesc: boolean, adv: { version: string; ecosystem: string; arch: string; assetType: string; hasVulns: boolean; minCvss: string }) => {
    const seq = ++loadSeq.current;
    setLoading(true);
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
    if (src) params.source = src;
    if (q) params.q = q;
    if (adv.version) params.version = adv.version;
    if (adv.ecosystem) params.ecosystem = adv.ecosystem;
    if (adv.arch) params.arch = adv.arch;
    if (adv.assetType) params.asset_type = adv.assetType;
    if (adv.hasVulns) params.has_vulns = 'true';
    if (adv.minCvss) params.min_cvss = adv.minCvss;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }

    const types = resolvePkgTypes(langLabel, filterOpts?.pkg_types || []);
    if (types.length === 1) params.pkg_type = types[0];

    api.packages(params)
      .then(r => {
        let items = r.items || [];
        if (types.length > 1) {
          const typeSet = new Set(types);
          items = items.filter(pkg => typeSet.has(pkg.pkg_type));
        }
        if (seq !== loadSeq.current) return;
        setPkgs(items);
        setTotal(types.length > 1 ? items.length : r.total);
        setPage(p);
        setLoading(false);
      })
      .catch(() => { if (seq === loadSeq.current) setLoading(false); });
  }, [filterOpts]);

  const adv = { version, ecosystem, arch, assetType, hasVulns, minCvss };

  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); }, [filterOpts]);
  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); }, [hostId, container, lang, source, ecosystem, arch, assetType, hasVulns]);

  const handleSearch = () => { load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : false;
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, hostId, container, lang, source, query, col, nextDesc, adv);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const cols: [string, string][] = [
    ['name', 'Name'], ['version', 'Version'], ['pkg_type', 'Type'],
    ['max_cvss', 'CVSS'], ['vuln_count', 'Vulns'],
    ['container', 'Container'], ['source', 'Source'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Packages</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {(filterOpts?.host_ids || []).map(id => (
              <option key={id} value={id}>{hostMap[id] || id}</option>
            ))}
          </select>
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">All Containers</option>
            {(filterOpts?.containers || []).map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <select value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">All Types</option>
            {(() => {
              const dbTypes = new Set(filterOpts?.pkg_types || []);
              return Object.entries(LANG_GROUPS)
                .filter(([, types]) => types.some(t => dbTypes.has(t)))
                .map(([label]) => (
                  <option key={label} value={label}>{label}</option>
                ));
            })()}
            {(() => {
              const known = new Set(Object.values(LANG_GROUPS).flat());
              const others = (filterOpts?.pkg_types || []).filter(t => !known.has(t));
              return others.length > 0 ? <option value="__other__">Other</option> : null;
            })()}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">All Sources</option>
            {(filterOpts?.sources || []).map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Search package name..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 200 }}
          />
          <input
            type="text"
            placeholder="Version (exact)..."
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 140 }}
            title="Exact installed version"
          />
          <input
            type="text"
            placeholder="Ecosystem (pypi, npm...)"
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 150 }}
            title="Ecosystem, e.g. pypi/npm/debian/rhel/alpine"
            list="pkg-ecosystem-list"
          />
          <datalist id="pkg-ecosystem-list">
            <option value="pypi" /><option value="npm" /><option value="debian" /><option value="rhel" /><option value="alpine" />
            <option value="go" /><option value="maven" /><option value="cargo" /><option value="gem" /><option value="nuget" />
          </datalist>
          <input
            type="text"
            placeholder="Arch..."
            value={arch}
            onChange={(e) => setArch(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 90 }}
            title="Package architecture, e.g. x86_64, amd64, noarch"
          />
          <select value={assetType} onChange={(e) => setAssetType(e.target.value)} title="Asset type">
            <option value="">All Asset Types</option>
            <option value="host">Host</option>
            <option value="container">Container</option>
          </select>
          <input
            type="number"
            min="0"
            max="10"
            step="0.1"
            placeholder="Min CVSS"
            value={minCvss}
            onChange={(e) => setMinCvss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 110 }}
            title="Minimum CVSS score"
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Has vulnerabilities" checked={hasVulns} onChange={setHasVulns} />
          </div>
          <div className="filter-actions">
            <span className="result-count">{total.toLocaleString()} packages</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
                <th>Path</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {pkgs.map(p => (
                <tr key={p.id}>
                  <td><span className="host-link" title={`IP: ${hostIPMap[p.host_id] || ''}`}>{hostMap[p.host_id] || p.host_id}</span></td>
                  <td className="mono">{p.name}</td>
                  <td className="mono">{p.version}</td>
                  <td>{p.pkg_type}</td>
                  <td className="mono"><CvssTooltip pkgId={p.id} score={p.max_cvss} onSelectVuln={onSelectVuln} /></td>
                  <td style={{ fontWeight: p.vuln_count > 0 ? 600 : 400 }}>{p.vuln_count || 0}</td>
                  <td>{p.container || <span style={{ color: 'var(--text-muted)' }}>host</span>}</td>
                  <td>{p.source}</td>
                  <td className="path-cell">{(() => { const fp = p.file_path || (p.target ? "/" + p.target : ""); return fp ? <>{fp.length > 35 ? fp.slice(0, 35) + "..." : fp}<span className="path-tip">{fp}</span></> : "-"; })()}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{p.created_at ? new Date(p.created_at).toLocaleDateString() : '-'}</td>
                </tr>
              ))}
              {pkgs.length === 0 && <tr className="empty-row"><td colSpan={10}>No packages found</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, hostId, container, lang, source, query, sortBy, sortDesc, adv)} />
      </div>
    </>
  );
}

function ContainersView() {
  const [containers, setContainers] = useState<ContainerAsset[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expandedFacts, setExpandedFacts] = useState('');
  const loadSeq = useRef(0);

  const [hostId, setHostId] = useState('');
  const [runtime, setRuntime] = useState('');
  const [state, setState] = useState('');
  const [image, setImage] = useState('');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortDesc, setSortDesc] = useState(true);
  const limit = 100;

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHosts(hs || []);
      setHostMap(m);
      setHostIPMap(ip);
    }).catch(() => {});
  }, []);

  const load = useCallback((p: number, hId: string, rt: string, st: string, img: string, q: string, sBy: string, sDesc: boolean) => {
    const seq = ++loadSeq.current;
    setLoading(true);
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (hId) params.host_id = hId;
    if (rt) params.runtime = rt;
    if (st) params.state = st;
    if (img) params.image = img;
    if (q) params.q = q;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }

    api.containers(params)
      .then(r => {
        if (seq !== loadSeq.current) return;
        setContainers(r.items || []);
        setTotal(r.total || 0);
        setPage(p);
        setLoading(false);
      })
      .catch(() => { if (seq === loadSeq.current) setLoading(false); });
  }, []);

  useEffect(() => { load(0, hostId, runtime, state, image, query, sortBy, sortDesc); }, [hostId, runtime, state]);

  const handleSearch = () => { load(0, hostId, runtime, state, image, query, sortBy, sortDesc); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : false;
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, hostId, runtime, state, image, query, col, nextDesc);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const runtimes = Array.from(new Set(['docker', 'containerd', 'podman', ...containers.map(c => c.runtime).filter(Boolean)])).sort();
  const states = Array.from(new Set(['running', 'exited', 'created', 'paused', 'restarting', 'dead', ...containers.map(c => c.state).filter(Boolean)])).sort();
  const cols: [string, string][] = [
    ['name', 'Name'], ['state', 'State'], ['runtime', 'Runtime'],
    ['image_name', 'Image'], ['container_id', 'Container ID'],
    ['vulnerability_count', 'Findings'], ['critical_count', 'Critical'], ['high_count', 'High'], ['max_cvss', 'Max CVSS'], ['package_count', 'Packages'],
    ['started_at', 'Started'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Containers</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {hosts.map(h => (
              <option key={h.id} value={h.id}>{h.hostname || h.id}</option>
            ))}
          </select>
          <select value={runtime} onChange={(e) => setRuntime(e.target.value)}>
            <option value="">All Runtimes</option>
            {runtimes.map(rt => <option key={rt} value={rt}>{rt}</option>)}
          </select>
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">All States</option>
            {states.map(st => <option key={st} value={st}>{st}</option>)}
          </select>
          <input
            type="text"
            placeholder="Image name..."
            value={image}
            onChange={(e) => setImage(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 180 }}
          />
          <input
            type="text"
            placeholder="Name, container ID, image ID..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 240 }}
          />
          <div className="filter-actions">
            <span className="result-count">{total.toLocaleString()} containers</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
                <th>Labels</th>
                <th>Image ID</th>
                <th>Scan</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {containers.map(c => (
                <React.Fragment key={c.id}>
                <tr>
                  <td><span className="host-link" title={`IP: ${hostIPMap[c.host_id] || ''}`}>{hostMap[c.host_id] || c.host_id}</span></td>
                  <td
                    className="mono"
                    style={{ cursor: c.facts ? 'pointer' : 'default' }}
                    title={c.facts ? 'Show container OS facts' : ''}
                    onClick={() => c.facts && setExpandedFacts(e => (e === c.id ? '' : c.id))}
                  >{c.facts ? (expandedFacts === c.id ? '▾ ' : '▸ ') : ''}{c.name || '-'}</td>
                  <td><span className="badge">{c.state || '-'}</span></td>
                  <td>{c.runtime || '-'}</td>
                  <td className="mono" title={c.image_name}>{c.image_name || '-'}</td>
                  <td className="mono" title={c.container_id}>{c.container_id ? c.container_id.slice(0, 16) : '-'}</td>
                  <td className="mono" style={{ color: c.vulnerability_count ? 'var(--high)' : 'var(--text-muted)', fontWeight: c.vulnerability_count ? 700 : 400 }}>{c.vulnerability_count || 0}</td>
                  <td className="mono" style={{ color: c.critical_count ? 'var(--critical)' : 'var(--text-muted)', fontWeight: c.critical_count ? 700 : 400 }}>{c.critical_count || 0}</td>
                  <td className="mono" style={{ color: c.high_count ? 'var(--high)' : 'var(--text-muted)', fontWeight: c.high_count ? 700 : 400 }}>{c.high_count || 0}</td>
                  <td className="mono" style={{ color: (c.max_cvss || 0) >= 9 ? 'var(--critical)' : (c.max_cvss || 0) >= 7 ? 'var(--high)' : 'var(--text-muted)' }}>{c.max_cvss ? c.max_cvss.toFixed(1) : '-'}</td>
                  <td className="mono">{c.package_count || 0}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{c.started_at ? new Date(c.started_at).toLocaleString() : '-'}</td>
                  <td className="mono" title={c.labels_redacted ? 'Labels hidden by default; use include_labels=true in the API for raw labels' : ''}>{c.label_count || 0}</td>
                  <td className="mono" title={c.image_id}>{c.image_id ? c.image_id.replace(/^sha256:/, '').slice(0, 18) : '-'}</td>
                  <td className="mono" title={c.latest_scan_id || c.scan_id}>{(c.latest_scan_id || c.scan_id || '').slice(0, 8) || '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{c.created_at ? new Date(c.created_at).toLocaleString() : '-'}</td>
                </tr>
                {expandedFacts === c.id && c.facts && (
                  <tr>
                    <td colSpan={16} style={{ background: 'var(--bg)', padding: '0.75rem 1.5rem' }}>
                      {renderFactValue(c.facts)}
                    </td>
                  </tr>
                )}
                </React.Fragment>
              ))}
              {containers.length === 0 && <tr className="empty-row"><td colSpan={16}>No containers found</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, hostId, runtime, state, image, query, sortBy, sortDesc)} />
      </div>
    </>
  );
}

function CveSearchView() {
  const [results, setResults] = useState<{items: CveDbEntry[]; total: number}>({items: [], total: 0});
  const [query, setQuery] = useState('');
  const [referenceKey, setReferenceKey] = useState('');
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [sources, setSources] = useState<string[]>([]);
  const [minCvss, setMinCvss] = useState('');
  const [minEpss, setMinEpss] = useState('');
  const [minEpssPercentile, setMinEpssPercentile] = useState('');
  const [matchableOnly, setMatchableOnly] = useState(false);
  const [includePrioritySources, setIncludePrioritySources] = useState(false);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [indexedAffected, setIndexedAffected] = useState<Record<string, { loading?: boolean; error?: string; items?: CveAffectedPackage[]; total?: number }>>({});
  const [referenceGroups, setReferenceGroups] = useState<Record<string, { loading?: boolean; error?: string; data?: CveReferenceGroupSummary }>>({});
  const [sortBy, setSortBy] = useState('published_date');
  const [sortDesc, setSortDesc] = useState(true);
  const initialSearchStarted = useRef(false);
  const limit = 50;

  const doSearch = useCallback((p: number, sBy?: string, sDesc?: boolean, refKeyOverride?: string) => {
    setLoading(true);
    setError('');
    const sb = sBy ?? sortBy;
    const sd = sDesc ?? sortDesc;
    const refKey = refKeyOverride ?? referenceKey;
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (query.trim()) params.q = query.trim();
    if (refKey.trim()) params.reference_key = refKey.trim();
    if (severity) params.severity = severity;
    if (source) params.source = source;
    if (minCvss) params.min_cvss = minCvss;
    if (minEpss) params.min_epss = minEpss;
    if (minEpssPercentile) params.min_epss_percentile = minEpssPercentile;
    if (matchableOnly) params.matchable = 'true';
    if (includePrioritySources) params.include_priority_sources = 'true';
    params.sort_by = sb;
    params.sort_order = sd ? 'desc' : 'asc';
    api.cveDbSearch(params)
      .then(r => {
        setResults({items: r.items || [], total: r.total});
        setPage(p);
        setSearched(true);
        setLoading(false);
      })
      .catch((err) => {
        setError(err?.message || 'CVE database search failed');
        setSearched(true);
        setLoading(false);
      });
  }, [query, referenceKey, severity, source, minCvss, minEpss, minEpssPercentile, matchableOnly, includePrioritySources, sortBy, sortDesc]);

  useEffect(() => {
    api.cveDbSources().then(data => {
      setSources(data.sources || []);
    }).catch((err) => setError(err?.message || 'CVE source list failed'));
  }, []);

  useEffect(() => {
    if (initialSearchStarted.current) return;
    initialSearchStarted.current = true;
    doSearch(0, 'published_date', true);
  }, [doSearch]);

  const badge = (s: string) => "badge badge-" + (s || "unknown").toLowerCase();
  const cvssClr = (n: number) => n >= 9 ? "var(--critical)" : n >= 7 ? "var(--high)" : n >= 4 ? "var(--medium)" : "inherit";

  const loadIndexedAffected = (entry: CveDbEntry, offset = 0) => {
    setIndexedAffected(prev => ({ ...prev, [entry.id]: { ...(prev[entry.id] || {}), loading: true, error: '' } }));
    api.cveDbAffectedPackages(entry.id, { limit: '200', offset: String(offset) })
      .then(r => setIndexedAffected(prev => ({
        ...prev,
        [entry.id]: {
          items: offset > 0 ? [...(prev[entry.id]?.items || []), ...(r.items || [])] : (r.items || []),
          total: r.total,
        },
      })))
      .catch(err => setIndexedAffected(prev => ({ ...prev, [entry.id]: { ...(prev[entry.id] || {}), loading: false, error: err?.message || 'Indexed affected packages failed' } })));
  };

  const loadReferenceGroup = (key: string) => {
    if (!key || referenceGroups[key]?.data || referenceGroups[key]?.loading) return;
    setReferenceGroups(prev => ({ ...prev, [key]: { ...(prev[key] || {}), loading: true, error: '' } }));
    api.cveDbReferenceGroup({ key, limit: '10' })
      .then(data => setReferenceGroups(prev => ({ ...prev, [key]: { data } })))
      .catch(err => setReferenceGroups(prev => ({ ...prev, [key]: { loading: false, error: err?.message || 'Reference group summary failed' } })));
  };

  const toggleExpand = (entry: CveDbEntry) => {
    setExpanded(prev => prev === entry.id ? null : entry.id);
    if ((entry.matchable_affected_count || 0) > 0 && !indexedAffected[entry.id]) {
      loadIndexedAffected(entry, 0);
    }
    const groupKey = entry.reference_group_key || (entry.reference_keys || []).find(key => key.startsWith('cve:')) || (entry.reference_keys || [])[0];
    if (groupKey) loadReferenceGroup(groupKey);
  };

  const formatDate = (d: string | null | undefined) => {
    if (!d) return "-";
    try { return new Date(d).toLocaleDateString(); } catch { return "-"; }
  };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : true;
    setSortBy(col);
    setSortDesc(nextDesc);
    doSearch(0, col, nextDesc);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };
  const searchReferenceGroup = (key: string) => {
    setReferenceKey(key);
    doSearch(0, sortBy, sortDesc, key);
  };

  const parseJson = (raw: string | null | undefined): any[] => {
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  };
  const affectedPackageFixedVersions = (pkg: any): string[] => {
    const out: string[] = [];
    const seen = new Set<string>();
    const add = (v: unknown) => {
      if (typeof v !== 'string') return;
      const fixed = v.trim();
      if (!fixed || seen.has(fixed)) return;
      seen.add(fixed);
      out.push(fixed);
    };
    if (Array.isArray(pkg?.fixed)) pkg.fixed.forEach(add);
    if (Array.isArray(pkg?.ranges)) {
      pkg.ranges.forEach((range: any) => {
        if (Array.isArray(range?.events)) range.events.forEach((event: any) => add(event?.fixed));
      });
    }
    return out;
  };
  const affectedPackageTarget = (pkg: any, entry: CveDbEntry): string => {
    const target = typeof pkg?.ecosystem === 'string' && pkg.ecosystem.trim() ? pkg.ecosystem : entry.ecosystem;
    return typeof target === 'string' ? target.trim() : '';
  };
  const isPriorityFeed = (entry: CveDbEntry): boolean => entry.source === 'epss' || entry.source === 'cisa-kev';
  const isMatchableAffectedPackage = (pkg: any, entry: CveDbEntry): boolean =>
    typeof pkg?.name === 'string' && pkg.name.trim() !== '' &&
    affectedPackageTarget(pkg, entry) !== '' &&
    affectedPackageFixedVersions(pkg).length > 0;

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>CVE Search</h1>

      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input
            type="text"
            placeholder="CVE, package, ecosystem, keyword..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doSearch(0); }}
            style={{ minWidth: 220 }}
          />
          <input
            type="text"
            placeholder="Reference group"
            value={referenceKey}
            onChange={e => setReferenceKey(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doSearch(0); }}
            style={{ minWidth: 190 }}
          />
          <select value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={source} onChange={e => setSource(e.target.value)}>
            <option value="">{includePrioritySources ? 'All Sources' : 'Advisory Sources'}</option>
            {sources.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input
            type="number"
            placeholder="Min CVSS"
            value={minCvss}
            onChange={e => setMinCvss(e.target.value)}
            min="0" max="10" step="0.1"
            style={{ width: 90 }}
          />
          <input
            type="number"
            placeholder="Min EPSS"
            value={minEpss}
            onChange={e => setMinEpss(e.target.value)}
            min="0" max="1" step="0.01"
            style={{ width: 90 }}
          />
          <input
            type="number"
            placeholder="Min EPSS %ile"
            value={minEpssPercentile}
            onChange={e => setMinEpssPercentile(e.target.value)}
            min="0" max="1" step="0.01"
            style={{ width: 120 }}
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Matchable only" checked={matchableOnly} onChange={setMatchableOnly} />
            <CheckboxField label="Include priority feeds" checked={includePrioritySources} onChange={setIncludePrioritySources} />
          </div>
          <div className="filter-actions">
            {searched && <span className="result-count">{results.total.toLocaleString()} results</span>}
            <button className="btn btn-primary" onClick={() => doSearch(0)} disabled={loading}>{loading ? 'Searching...' : 'Search'}</button>
          </div>
        </div>
      </div>

      {error && <div className="card"><LoadError message={error} onRetry={() => doSearch(0)} /></div>}

      {!searched && !loading && !error && (
        <div className="card">
          <EmptyState message="Search the CVE database by CVE ID, affected package, ecosystem, keyword, severity, source, or minimum CVSS score." />
        </div>
      )}

      {loading && <div className="card"><Loading label="Searching..." /></div>}

      {searched && !loading && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th className="clickable" onClick={() => toggleSort('vulnerability_id')} style={{ userSelect: 'none' }}>CVE ID{sortArrow('vulnerability_id')}</th>
                <th className="clickable" onClick={() => toggleSort('severity')} style={{ userSelect: 'none' }}>Severity{sortArrow('severity')}</th>
                <th className="clickable" onClick={() => toggleSort('cvss_score')} style={{ userSelect: 'none' }}>CVSS{sortArrow('cvss_score')}</th>
                <th className="clickable" onClick={() => toggleSort('epss_score')} style={{ userSelect: 'none' }}>EPSS{sortArrow('epss_score')}</th>
                <th className="clickable" onClick={() => toggleSort('source')} style={{ userSelect: 'none' }}>Source{sortArrow('source')}</th>
                <th>Match</th>
                <th className="clickable" onClick={() => toggleSort('title')} style={{ userSelect: 'none' }}>Title{sortArrow('title')}</th>
                <th className="clickable" onClick={() => toggleSort('published_date')} style={{ userSelect: 'none' }}>Published{sortArrow('published_date')}</th>
              </tr>
            </thead>
            <tbody>
              {results.items.map(entry => {
                const isExpanded = expanded === entry.id;
                const prods = parseJson(entry.affected_products);
                const refs = parseJson(entry.references);
                const priorityFeed = isPriorityFeed(entry);
                const groupKey = entry.reference_group_key || (entry.reference_keys || []).find(key => key.startsWith('cve:')) || (entry.reference_keys || [])[0];
                const groupSummary = groupKey ? referenceGroups[groupKey] : undefined;

                return (
                  <React.Fragment key={entry.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
                      onClick={() => toggleExpand(entry)}
                    >
                      <td className="mono">
                        <span className="host-link" style={{ color: 'var(--primary)' }}>
                          {entry.vulnerability_id}
                        </span>
                        {(entry.reference_group_total || 0) > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: 3 }}>
                            <span className="badge" style={{ color: '#22c55e' }}>
                              group {entry.reference_group_total}
                            </span>
                            {entry.reference_group_key && (
                              <span className="badge" style={{ color: 'var(--text-muted)' }}>
                                {entry.reference_group_key}
                              </span>
                            )}
                            <span className="badge" style={{ color: 'var(--text-muted)' }}>
                              {entry.reference_group_sources || 0} src
                            </span>
                            <span className="badge" style={{ color: (entry.reference_group_matchable || 0) > 0 ? '#22c55e' : 'var(--text-muted)' }}>
                              {entry.reference_group_matchable || 0} match
                            </span>
                          </div>
                        )}
                        {entry.reference_group_status === 'unavailable' && (
                          <div className="badge" style={{ marginTop: 3, color: 'var(--medium)' }}>
                            group summary unavailable
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={badge(entry.severity)}>
                          {entry.severity || '-'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontWeight: 600, color: cvssClr(entry.cvss_score) }}>
                        {entry.cvss_score > 0 ? entry.cvss_score.toFixed(1) : '-'}
                      </td>
                      <td className="mono" style={{ color: (entry.epss_score || 0) >= 0.5 ? 'var(--critical)' : (entry.epss_score || 0) >= 0.1 ? 'var(--high)' : 'var(--text-muted)' }}>
                        {entry.epss_score ? `${(entry.epss_score * 100).toFixed(1)}%` : '-'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {entry.source}
                        {priorityFeed && (
                          <span className="badge" style={{ marginLeft: '0.375rem', color: 'var(--medium)' }}>priority</span>
                        )}
                      </td>
                      <td>
                        <span className="badge" style={{ color: entry.matchable ? '#22c55e' : priorityFeed ? 'var(--medium)' : 'var(--text-muted)' }}>
                          {entry.matchable ? 'matchable' : priorityFeed ? 'priority' : 'reference'}
                        </span>
                        {(entry.matchable_affected_count || 0) > 0 && (
                          <div className="mono" style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>
                            {entry.matchable_affected_count} affected
                          </div>
                        )}
                        {!entry.matchable && entry.matchability_reason && (
                          <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>
                            {entry.matchability_reason}
                          </div>
                        )}
                      </td>
                      <td style={{ maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.title || '-'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.8125rem' }}>
                        {formatDate(entry.published_date)}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={8} style={{ background: 'var(--surface)', padding: '1rem 1.5rem' }}>
                          {entry.description && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong>Description</strong>
                              <div style={{ fontSize: '0.8125rem', whiteSpace: 'pre-wrap', lineHeight: 1.5, color: 'var(--text-muted)', maxHeight: 200, overflow: 'auto', marginTop: '0.25rem' }}>
                                {entry.description}
                              </div>
                            </div>
                          )}
                          {entry.cvss_vector && (
                            <div style={{ marginBottom: '0.75rem', fontSize: '0.8125rem' }}>
                              <strong>CVSS Vector:</strong>{' '}
                              <code style={{ background: 'var(--bg)', padding: '2px 6px', borderRadius: 3 }}>
                                {entry.cvss_vector}
                              </code>
                            </div>
                          )}
                          {(entry.reference_keys || []).length > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Reference Groups</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {(entry.reference_keys || []).slice(0, 20).map(key => (
                                  <button
                                    key={key}
                                    className="badge"
                                    style={{ marginRight: '0.375rem', marginBottom: '0.25rem', color: key.startsWith('cve:') ? '#22c55e' : 'var(--text-muted)', cursor: 'pointer' }}
                                    onClick={e => {
                                      e.preventDefault();
                                      e.stopPropagation();
                                      searchReferenceGroup(key);
                                    }}
                                  >
                                    {key}
                                  </button>
                                ))}
                              </div>
                            </div>
                          )}
                          {groupKey && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Group Context</strong>
                              {groupSummary?.loading && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '0.25rem' }}>Loading...</div>}
                              {groupSummary?.error && <div style={{ color: 'var(--critical)', fontSize: '0.8125rem', marginTop: '0.25rem' }}>{groupSummary.error}</div>}
                              {groupSummary?.data && (
                                <div style={{ marginTop: '0.25rem', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '0.5rem 0.75rem' }}>
                                  <div className="mono" style={{ fontSize: '0.75rem', marginBottom: '0.375rem' }}>
                                    {groupSummary.data.key} · {groupSummary.data.total.toLocaleString()} records · {groupSummary.data.matchable.toLocaleString()} matchable
                                  </div>
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginBottom: '0.375rem' }}>
                                    {(groupSummary.data.sources || []).slice(0, 8).map(b => (
                                      <span key={b.name} className="badge">{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                  </div>
                                  {(groupSummary.data.source_groups || []).length > 0 && (
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginBottom: '0.375rem' }}>
                                      {(groupSummary.data.source_groups || []).slice(0, 8).map(b => (
                                        <span key={b.name} className="badge" style={{ color: '#22c55e' }}>{b.name}: {b.count.toLocaleString()}</span>
                                      ))}
                                    </div>
                                  )}
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                                    {(groupSummary.data.categories || []).slice(0, 6).map(b => (
                                      <span key={b.name} className="badge" style={{ color: 'var(--text-muted)' }}>{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                    {(groupSummary.data.ecosystems || []).slice(0, 6).map(b => (
                                      <span key={b.name} className="badge" style={{ color: 'var(--text-muted)' }}>{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                  </div>
                                  {(groupSummary.data.affected_packages || []).length > 0 && (
                                    <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                                      <strong style={{ fontSize: '0.75rem' }}>Group Match Evidence</strong>
                                      <span className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                        showing {(groupSummary.data.affected_packages || []).length.toLocaleString()} of {(groupSummary.data.affected_package_total || 0).toLocaleString()}
                                      </span>
                                      <div style={{ marginTop: '0.375rem', display: 'grid', gap: '0.25rem' }}>
                                        {(groupSummary.data.affected_packages || []).slice(0, 10).map((item, idx) => (
                                          <div key={`${item.cve_id}-${item.package_name}-${item.ecosystem}-${item.fixed_version}-${idx}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(7rem, 1fr) minmax(8rem, 1.2fr) minmax(6rem, 0.8fr) minmax(5rem, 0.8fr) minmax(7rem, 1fr)', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                            <span className="mono" style={{ color: 'var(--text)' }}>{item.vulnerability_id}</span>
                                            <span style={{ fontWeight: 600, color: 'var(--text)' }}>{item.package_name}</span>
                                            <span className="mono">{item.ecosystem}</span>
                                            <span>{item.source || '-'}</span>
                                            <span className="mono" style={{ color: '#22c55e' }}>Fixed {item.fixed_version}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {(groupSummary.data.items || []).length > 0 && (
                                    <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                                      <strong style={{ fontSize: '0.75rem' }}>Grouped Evidence</strong>
                                      <div style={{ marginTop: '0.375rem', display: 'grid', gap: '0.25rem' }}>
                                        {(groupSummary.data.items || []).slice(0, 8).map(item => {
                                          const itemPriority = isPriorityFeed(item);
                                          return (
                                            <div key={item.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(8rem, 1.4fr) minmax(6rem, 0.8fr) minmax(7rem, 1fr) minmax(6rem, 1fr) auto minmax(7rem, 1fr) auto auto', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                              <span className="mono" style={{ color: 'var(--text)' }}>{item.vulnerability_id}</span>
                                              <span>{item.source || '-'}</span>
                                              <span>{item.category || '-'}</span>
                                              <span className="mono">{item.ecosystem || '-'}</span>
                                              <span className="badge" style={{ color: item.matchable ? '#22c55e' : itemPriority ? 'var(--medium)' : 'var(--text-muted)' }}>
                                                {item.matchable ? 'matchable' : itemPriority ? 'priority' : 'reference'}
                                              </span>
                                              <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                {item.matchability_reason || ''}
                                              </span>
                                              <span className="mono" style={{ color: cvssClr(item.cvss_score), justifySelf: 'end' }}>
                                                CVSS {item.cvss_score > 0 ? item.cvss_score.toFixed(1) : '-'}
                                              </span>
                                              <span className="mono" style={{ justifySelf: 'end' }}>
                                                EPSS {item.epss_score ? `${(item.epss_score * 100).toFixed(1)}%` : '-'}
                                              </span>
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                          {(entry.matchable_affected_count || 0) > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Indexed Match Evidence</strong>
                              <span className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                showing {(indexedAffected[entry.id]?.items || []).length.toLocaleString()} of {((indexedAffected[entry.id]?.total ?? entry.matchable_affected_count) || 0).toLocaleString()}
                              </span>
                              <div style={{ marginTop: '0.25rem' }}>
                                {indexedAffected[entry.id]?.loading && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Loading...</div>}
                                {indexedAffected[entry.id]?.error && <div style={{ color: 'var(--critical)', fontSize: '0.8125rem' }}>{indexedAffected[entry.id]?.error}</div>}
                                {(indexedAffected[entry.id]?.items || []).map((item, idx) => (
                                  <div key={`${item.package_name}-${item.ecosystem}-${item.fixed_version}-${idx}`} style={{ background: 'var(--bg)', padding: '0.4rem 0.75rem', borderRadius: 4, border: '1px solid var(--border)', marginBottom: '0.25rem' }}>
                                    <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{item.package_name}</span>
                                    <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{item.ecosystem}</span>
                                    <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '1px 6px', borderRadius: 3, fontWeight: 600, marginLeft: '0.5rem' }}>Fixed: {item.fixed_version}</span>
                                  </div>
                                ))}
                                {((indexedAffected[entry.id]?.items || []).length < (indexedAffected[entry.id]?.total || 0)) && (
                                  <button
                                    style={{ marginTop: '0.25rem' }}
                                    disabled={indexedAffected[entry.id]?.loading}
                                    onClick={e => {
                                      e.stopPropagation();
                                      loadIndexedAffected(entry, (indexedAffected[entry.id]?.items || []).length);
                                    }}
                                  >
                                    Load More
                                  </button>
                                )}
                              </div>
                            </div>
                          )}
                          {prods.length > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Affected Packages</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {prods.slice(0, 20).map((pkg: any, idx: number) => {
                                  const fixedArr = affectedPackageFixedVersions(pkg);
                                  const lastFixed = fixedArr.length > 0 ? fixedArr[fixedArr.length - 1] : '';
                                  const target = affectedPackageTarget(pkg, entry);
                                  const matchablePkg = isMatchableAffectedPackage(pkg, entry);
                                  return (
                                    <div key={idx} style={{ background: 'var(--bg)', padding: '0.4rem 0.75rem', borderRadius: 4, border: '1px solid var(--border)', marginBottom: '0.25rem' }}>
                                      <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{pkg.name || 'unknown'}</span>
                                      {target && (
                                        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{target}</span>
                                      )}
                                      {lastFixed && (
                                        <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '1px 6px', borderRadius: 3, fontWeight: 600, marginLeft: '0.5rem' }}>
                                          Fixed: {lastFixed}
                                        </span>
                                      )}
                                      <span style={{ fontSize: '0.6875rem', color: matchablePkg ? '#22c55e' : 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                        {matchablePkg ? 'used for matching' : 'reference only'}
                                      </span>
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                          {refs.length > 0 && (
                            <div>
                              <strong style={{ fontSize: '0.8125rem' }}>References</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {refs.slice(0, 10).map((ref: any, idx: number) => (
                                  <div key={idx}>
                                    <a href={ref.url} target="_blank" rel="noopener" style={{ fontSize: '0.75rem', color: 'var(--primary)' }}>
                                      {ref.url}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {results.items.length === 0 && (
                <tr className="empty-row"><td colSpan={8}>No results found</td></tr>
              )}
            </tbody>
          </table>
          {results.total > limit && (
            <Pager page={page} limit={limit} total={results.total} onPage={doSearch} />
          )}
        </div>
      )}
    </>
  );
}

function ScansView({ initialRequestFilters = {} }: { initialRequestFilters?: ScanRequestFilters }) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [requests, setRequests] = useState<ScanRequest[]>([]);
  const [requestTotal, setRequestTotal] = useState(0);
  const [requestStatus, setRequestStatus] = useState(initialRequestFilters.status || '');
  const [requestType, setRequestType] = useState(initialRequestFilters.scan_type || '');
  const [requestRevision, setRequestRevision] = useState(initialRequestFilters.security_db_revision || '');
  const [requestStale, setRequestStale] = useState(initialRequestFilters.stale || '');
  const [requestMsg, setRequestMsg] = useState('');
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [requestsLoading, setRequestsLoading] = useState(true);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const limit = 50;

  useEffect(() => {
    api.hosts().then(hosts => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hosts || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m);
      setHostIPMap(ip);
    }).catch(() => {});
  }, []);

  const load = useCallback((p: number) => {
    setLoading(true);
    api.scans({ limit: String(limit), offset: String(p * limit) })
      .then(r => { setScans(r.items || []); setTotal(r.total); setPage(p); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  const loadRequests = useCallback((status: string, scanType: string, revision: string, stale: string) => {
    setRequestsLoading(true);
    const params: Record<string, string> = { limit: '50', offset: '0' };
    if (status) params.status = status;
    if (scanType) params.scan_type = scanType;
    if (revision.trim()) params.security_db_revision = revision.trim();
    if (stale) params.stale = stale;
    api.scanRequests(params)
      .then(r => { setRequests(r.items || []); setRequestTotal(r.total || 0); setRequestsLoading(false); })
      .catch(() => setRequestsLoading(false));
  }, []);

  useEffect(() => { load(0); }, [load]);
  useEffect(() => { loadRequests(requestStatus, requestType, requestRevision, requestStale); }, [loadRequests, requestStatus, requestType, requestRevision, requestStale]);

  const statusColor = (s: string) => s === 'completed' ? 'var(--low)' : s === 'degraded' ? 'var(--medium)' : s === 'failed' ? 'var(--critical)' : 'var(--medium)';
  const cancelRequest = async (id: string) => {
    setRequestMsg('');
    try {
      await api.cancelScanRequest(id);
      setRequestMsg('Scan request cancelled');
      loadRequests(requestStatus, requestType, requestRevision, requestStale);
    } catch {
      setRequestMsg('Cancel failed');
    }
  };
  const requeueStale = async () => {
    setRequestMsg('');
    try {
      const r = await api.requeueStaleScanRequests();
      const cancelled = r.cancelled_duplicates ? `; cancelled ${r.cancelled_duplicates} duplicate DB requests` : '';
      setRequestMsg(`Requeued ${r.requeued} stale claimed requests${cancelled}`);
      loadRequests(requestStatus, requestType, requestRevision, requestStale);
    } catch {
      setRequestMsg('Requeue failed');
    }
  };
  const requeueRequest = async (req: ScanRequest) => {
    setRequestMsg('');
    try {
      await api.requeueScanRequest(req.id, { message: `dashboard retry: ${req.scan_type}` });
      setRequestMsg('Scan request requeued');
      loadRequests(requestStatus, requestType, requestRevision, requestStale);
    } catch {
      setRequestMsg('Requeue failed');
    }
  };
  const requeueFiltered = async () => {
    setRequestMsg('');
    if (requestStatus && !['failed', 'degraded', 'cancelled'].includes(requestStatus)) {
      setRequestMsg('Bulk requeue requires Failed, Degraded, or Cancelled status');
      return;
    }
    if (!requestStatus && !requestType && !requestRevision) {
      setRequestMsg('Set a status, type, or DB revision filter before bulk requeue');
      return;
    }
    const filterLabel = [
      requestStatus ? `status=${requestStatus}` : 'status=failed/degraded/cancelled',
      requestType ? `type=${requestType}` : '',
      requestRevision.trim() ? `DB rev=${requestRevision.trim()}` : '',
    ].filter(Boolean).join(', ');
    const totalLabel = requestStatus ? `${requestTotal} matching requests` : 'all failed/degraded/cancelled requests matching these filters';
    if (!confirm(`Requeue ${totalLabel} (${filterLabel})?`)) return;
    try {
      const r = await api.requeueFilteredScanRequests({
        status: requestStatus || undefined,
        scan_type: requestType || undefined,
        security_db_revision: requestRevision.trim() || undefined,
        message: 'dashboard bulk retry',
      });
      setRequestMsg(`Requeued ${r.requeued} scan requests`);
      loadRequests(requestStatus, requestType, requestRevision, requestStale);
    } catch {
      setRequestMsg('Bulk requeue failed');
    }
  };
  const canBulkRequeue = (!requestStatus || ['failed', 'degraded', 'cancelled'].includes(requestStatus)) && Boolean(requestStatus || requestType || requestRevision.trim());

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Scan History</h1>
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="card-header">
          <h2>{requestTotal} scan requests</h2>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button className="update-btn" onClick={requeueStale}>Requeue Stale</button>
            <button
              className="update-btn"
              onClick={requeueFiltered}
              disabled={!canBulkRequeue}
              title="Requeue failed, degraded, or cancelled requests matching the current filters"
            >
              Requeue Filtered
            </button>
            <select value={requestStatus} onChange={(e) => setRequestStatus(e.target.value)}>
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="claimed">Claimed</option>
              <option value="completed">Completed</option>
              <option value="degraded">Degraded</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
            <select value={requestType} onChange={(e) => setRequestType(e.target.value)}>
              <option value="">All Types</option>
              <option value="manual">Manual</option>
              <option value="daily">Daily</option>
              <option value="security-db-update">Security DB</option>
            </select>
            <select value={requestStale} onChange={(e) => setRequestStale(e.target.value)}>
              <option value="">All Ages</option>
              <option value="true">Only Stale</option>
            </select>
            <input
              type="text"
              className="mono"
              placeholder="DB revision"
              value={requestRevision}
              onChange={(e) => setRequestRevision(e.target.value)}
              style={{ maxWidth: '12rem' }}
            />
            {(requestStatus || requestType || requestRevision || requestStale) && <button className="btn btn-secondary btn-sm" onClick={() => { setRequestStatus(''); setRequestType(''); setRequestRevision(''); setRequestStale(''); }}>Clear</button>}
          </div>
        </div>
        {requestMsg && <div style={{ padding: '0.75rem 1rem 0', color: requestMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{requestMsg}</div>}
        {requestsLoading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Requested</th><th>Age</th><th>Host</th><th>Claimed By</th><th>Type</th><th>Status</th><th>Mode</th><th>DB Rev</th><th>Reason</th><th>Claimed</th><th>Claim Age</th><th>Completed</th><th></th></tr>
            </thead>
            <tbody>
              {requests.map(req => (
                <tr key={req.id}>
                  <td className="mono">{new Date(req.created_at).toLocaleString()}</td>
                  <td className="mono" style={{ fontSize: '0.75rem', color: req.request_stale ? 'var(--medium)' : 'var(--text-muted)' }}>{formatAge(req.request_age_seconds)}</td>
                  <td><span className="host-link" title={`IP: ${req.host_id ? hostIPMap[req.host_id] || '' : ''}`}>{req.host_id ? hostMap[req.host_id] || req.host_id : 'All polling agents'}</span></td>
                  <td><span className="host-link" title={`IP: ${req.claimed_by_host_id ? hostIPMap[req.claimed_by_host_id] || '' : ''}`}>{req.claimed_by_host_id ? hostMap[req.claimed_by_host_id] || req.claimed_by_host_id : '-'}</span></td>
                  <td>{req.scan_type}</td>
                  <td style={{ color: statusColor(req.status), fontWeight: 600 }}>{req.status}</td>
                  <td>{req.packages_only ? 'packages' : 'full'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.security_db_revision || '-'}</td>
                  <td className="path-cell">{req.reason || req.error_message || '-'}{(req.reason || req.error_message) && <span className="path-tip">{req.reason || req.error_message}</span>}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.claimed_at ? new Date(req.claimed_at).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem', color: req.claim_stale ? 'var(--medium)' : 'var(--text-muted)' }}>{req.claimed_at ? formatAge(req.claim_age_seconds) : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.completed_at ? new Date(req.completed_at).toLocaleString() : '-'}</td>
                  <td>
                    {['pending', 'claimed'].includes(req.status) && <button className="delete-btn" onClick={() => cancelRequest(req.id)}>Cancel</button>}
                    {['failed', 'degraded', 'cancelled'].includes(req.status) && <button className="update-btn" onClick={() => requeueRequest(req)}>Requeue</button>}
                  </td>
                </tr>
              ))}
              {requests.length === 0 && <tr className="empty-row"><td colSpan={13}>No scan requests</td></tr>}
            </tbody>
          </table>
        )}
      </div>
      <div className="card">
        <div className="card-header">
          <h2>{total} scans</h2>
        </div>
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Date</th><th>Host</th><th>Type</th><th>Status</th><th>Issue</th><th>Inventory</th><th>Delta</th><th>Started</th><th>Finished</th><th></th></tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id}>
                  <td className="mono">{new Date(s.created_at).toLocaleString()}</td>
                  <td><span className="host-link" title={`IP: ${hostIPMap[s.host_id] || ''}`}>{hostMap[s.host_id] || s.host_id}</span></td>
                  <td>{s.scan_type}</td>
                  <td style={{ color: statusColor(s.status), fontWeight: 600 }}>{s.status}</td>
                  <td className="path-cell" style={{ maxWidth: '18rem' }}>{s.error_summary || '-'}{s.error_summary && <span className="path-tip">{s.error_summary}</span>}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.package_count || 0} pkgs / {s.vulnerability_count || 0} vulns / {s.container_count || 0} ctrs</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>+{s.packages_added || 0} / -{s.packages_removed || 0} / ~{s.packages_changed || 0}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.finished_at ? new Date(s.finished_at).toLocaleString() : '-'}</td>
                  <td><button className="delete-btn" onClick={() => {
                    if (!confirm('Delete this scan and all associated data?')) return;
                    api.deleteScan(s.id).then(() => load(page)).catch(() => {
                      if (['completed', 'degraded'].includes(s.status) && confirm('This appears to be the latest usable inventory scan for its host. Force delete it anyway?')) {
                        api.deleteScan(s.id, true).then(() => load(page)).catch(() => alert('Delete failed'));
                      } else {
                        alert('Delete failed');
                      }
                    });
                  }}>Delete</button></td>
                </tr>
              ))}
              {scans.length === 0 && <tr className="empty-row"><td colSpan={10}>No scans recorded</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={load} />
      </div>
    </>
  );
}

function RBACView() {
  const [subjects, setSubjects] = useState<AccessSubject[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [rbacStatus, setRbacStatus] = useState<AccessControlStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [subjectType, setSubjectType] = useState('user');
  const [externalID, setExternalID] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [policySubjectID, setPolicySubjectID] = useState('');
  const [resourceType, setResourceType] = useState('host');
  const [resourceID, setResourceID] = useState('');
  const [permission, setPermission] = useState('read');
  const [subjectFilter, setSubjectFilter] = useState('');

  const load = useCallback((filter = '') => {
    setLoading(true);
    setMessage('');
    Promise.all([
      api.rbacSubjects(),
      api.rbacPolicies(filter ? { subject_external_id: filter } : undefined),
      api.rbacStatus(),
    ])
      .then(([s, p, status]) => {
        setSubjects(s.items || []);
        setPolicies(p.items || []);
        setRbacStatus(status);
        setLoading(false);
      })
      .catch(() => {
        setMessage('RBAC management requires an admin API key');
        setLoading(false);
      });
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveSubject = () => {
    if (!externalID.trim()) {
      setMessage('external_id is required');
      return;
    }
    api.upsertRbacSubject({ subject_type: subjectType, external_id: externalID.trim(), display_name: displayName.trim() })
      .then(() => {
        setMessage('Subject saved');
        setExternalID('');
        setDisplayName('');
        load();
      })
      .catch(() => setMessage('Failed to save subject'));
  };

  const savePolicy = () => {
    const subject = policySubjectID.trim();
    if (!subject || !resourceType) {
      setMessage('subject and resource type are required');
      return;
    }
    api.upsertRbacPolicy({ subject_id: subject, resource_type: resourceType, resource_id: resourceID.trim() || '*', permission })
      .then(() => {
        setMessage('Policy saved');
        setResourceID('');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to save policy. Create the subject first.'));
  };

  const deleteSubject = (subject: AccessSubject) => {
    if (!confirm(`Revoke subject ${subject.subject_type}/${subject.external_id} and all attached policies?`)) return;
    api.deleteRbacSubject(subject.id)
      .then(() => {
        setMessage('Subject revoked');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to revoke subject'));
  };

  const deletePolicy = (policy: AccessPolicy) => {
    if (!confirm(`Revoke ${policy.permission} on ${policy.resource_type}/${policy.resource_id || '*'} for ${policy.subject_type}/${policy.subject_external_id}?`)) return;
    api.deleteRbacPolicy(policy.id)
      .then(() => {
        setMessage('Policy revoked');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to revoke policy'));
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>RBAC</h1>
      {rbacStatus && (
        <div className="db-status-bar" style={{ marginBottom: '1rem' }}>
          <h3>Access Control</h3>
          <span className={`status-dot ${rbacStatus.status === 'ok' ? 'ready' : 'not-ready'}`}>
            RBAC: {rbacStatus.status}
          </span>
          <span className={`status-dot ${rbacStatus.auth?.web_auth_enabled ? 'ready' : 'not-ready'}`}>
            Web auth: {rbacStatus.auth?.web_auth_enabled ? 'on' : 'off'}
          </span>
          <span className={`status-dot ${(rbacStatus.auth?.viewer_key_count || 0) > 0 ? 'ready' : 'not-ready'}`}>
            Viewer keys: {(rbacStatus.auth?.viewer_key_count || 0).toLocaleString()}
          </span>
          <span className={`status-dot ${rbacStatus.auth?.oidc_configured ? 'ready' : 'not-ready'}`}>
            OIDC: {rbacStatus.auth?.oidc_configured ? 'on' : 'off'}
          </span>
          {rbacStatus.auth?.oidc_configured && (
            <span className={`status-dot ${rbacStatus.auth.oidc_jwks_configured ? 'ready' : 'not-ready'}`}>
              JWKS: {rbacStatus.auth.oidc_jwks_configured ? 'set' : 'missing'}
            </span>
          )}
          <span className={`status-dot ${rbacStatus.auth?.trusted_identity_configured ? 'ready' : 'not-ready'}`}>
            Trusted identity: {rbacStatus.auth?.trusted_identity_configured ? 'on' : 'off'}
          </span>
          {rbacStatus.auth?.trusted_identity_configured && (
            <span className={`status-dot ${(rbacStatus.auth.trusted_proxy_cidr_count || 0) > 0 ? 'ready' : 'not-ready'}`}>
              Proxy CIDRs: {(rbacStatus.auth.trusted_proxy_cidr_count || 0).toLocaleString()}
            </span>
          )}
          {rbacStatus.auth?.trusted_identity_configured && (
            <span className={`status-dot ${rbacStatus.auth.trusted_identity_admin_configured ? 'ready' : 'not-ready'}`}>
              Trusted admins: {((rbacStatus.auth.trusted_admin_user_count || 0) + (rbacStatus.auth.trusted_admin_group_count || 0)).toLocaleString()}
            </span>
          )}
          {rbacStatus.warnings && rbacStatus.warnings.length > 0 && (
            <span style={{ color: 'var(--medium)', fontSize: '0.8125rem' }}>{rbacStatus.warnings.slice(0, 2).join('; ')}</span>
          )}
        </div>
      )}
      <div className="grid-2" style={{ marginBottom: '1rem' }}>
        <div className="card" style={{ padding: '1rem' }}>
          <div className="card-header"><h2>Subject</h2></div>
          <div className="filters">
            <select value={subjectType} onChange={(e) => setSubjectType(e.target.value)}>
              <option value="user">User</option>
              <option value="group">Group</option>
            </select>
            <input type="text" placeholder="external_id" value={externalID} onChange={(e) => setExternalID(e.target.value)} />
            <input type="text" placeholder="Display name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            <button className="filter-btn" onClick={saveSubject}>Save Subject</button>
          </div>
        </div>
        <div className="card" style={{ padding: '1rem' }}>
          <div className="card-header"><h2>Policy</h2></div>
          <div className="filters">
            <select value={policySubjectID} onChange={(e) => setPolicySubjectID(e.target.value)}>
              <option value="">Select Subject</option>
              {subjects.map(s => <option key={s.id} value={s.id}>{s.subject_type}/{s.external_id}</option>)}
            </select>
            <datalist id="rbac-subjects">{subjects.map(s => <option key={s.id} value={accessSubjectRef(s)} />)}</datalist>
            <select value={resourceType} onChange={(e) => setResourceType(e.target.value)}>
              <option value="host">Host</option>
              <option value="container">Container</option>
              <option value="image">Image</option>
              <option value="asset_group">Asset Group</option>
              <option value="all">All</option>
            </select>
            <input type="text" placeholder={resourceType === 'asset_group' ? 'team:platform or tag:service=api' : 'resource_id or *'} value={resourceID} onChange={(e) => setResourceID(e.target.value)} />
            <select value={permission} onChange={(e) => setPermission(e.target.value)}>
              <option value="read">Read</option>
              <option value="export">Export</option>
              <option value="write">Write</option>
              <option value="admin">Admin</option>
            </select>
            <button className="filter-btn" onClick={savePolicy}>Save Policy</button>
          </div>
        </div>
      </div>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input list="rbac-subjects" type="text" placeholder="Filter by user:alice or group:platform" value={subjectFilter} onChange={(e) => setSubjectFilter(e.target.value)} />
          <div className="filter-actions">
            <span className="result-count" style={{ color: message.startsWith('Failed') || message.includes('requires') || message.includes('required') ? 'var(--critical)' : 'var(--text-muted)' }}>
              {message || `${subjects.length} subjects / ${policies.length} policies`}
            </span>
            <button className="btn btn-primary" onClick={() => load(subjectFilter)}>Search</button>
            <button className="btn btn-secondary" onClick={() => { setSubjectFilter(''); load(''); }}>Clear</button>
          </div>
        </div>
      </div>
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h2>Subjects</h2></div>
          {loading ? <Loading /> : (
            <table>
              <thead><tr><th>Type</th><th>External ID</th><th>Name</th><th>Updated</th><th></th></tr></thead>
              <tbody>
                {subjects.map(s => (
                  <tr key={s.id}>
                    <td><span className="badge">{s.subject_type}</span></td>
                    <td className="mono">{s.external_id}</td>
                    <td>{s.display_name || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(s.updated_at).toLocaleString()}</td>
                    <td><button className="delete-btn" onClick={() => deleteSubject(s)}>Revoke</button></td>
                  </tr>
                ))}
                {subjects.length === 0 && <tr className="empty-row"><td colSpan={5}>No subjects</td></tr>}
              </tbody>
            </table>
          )}
        </div>
        <div className="card">
          <div className="card-header"><h2>Policies</h2></div>
          {loading ? <Loading /> : (
            <table>
              <thead><tr><th>Subject</th><th>Resource</th><th>Permission</th><th>Created</th><th></th></tr></thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id}>
                    <td>{p.subject_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.subject_external_id}</div></td>
                    <td>{p.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.resource_id || '*'}</div></td>
                    <td><span className="badge">{p.permission}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(p.created_at).toLocaleString()}</td>
                    <td><button className="delete-btn" onClick={() => deletePolicy(p)}>Revoke</button></td>
                  </tr>
                ))}
                {policies.length === 0 && <tr className="empty-row"><td colSpan={5}>No policies</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

function AuditLogView() {
  const [items, setItems] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actorType, setActorType] = useState('');
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [status, setStatus] = useState('');
  const [createdFrom, setCreatedFrom] = useState('');
  const [createdTo, setCreatedTo] = useState('');
  const [query, setQuery] = useState('');
  const limit = 50;

  const load = useCallback((p: number, at: string, act: string, rt: string, st: string, from: string, to: string, q: string) => {
    setLoading(true);
    setError('');
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (at) params.actor_type = at;
    if (act) params.action = act;
    if (rt) params.resource_type = rt;
    if (st) params.status = st;
    if (from) params.created_from = from;
    if (to) params.created_to = to;
    if (q) {
      if (q.includes('/')) {
        const [rType, rID] = q.split('/', 2);
        params.resource_type = rType;
        params.resource_id = rID;
      } else {
        params.actor_id = q;
      }
    }
    api.auditLogs(params)
      .then(r => { setItems(r.items || []); setTotal(r.total || 0); setPage(p); setLoading(false); })
      .catch(() => { setError('Audit logs require an admin API key'); setLoading(false); });
  }, []);

  useEffect(() => { load(0, actorType, action, resourceType, status, createdFrom, createdTo, query); }, [load, actorType, action, resourceType, status, createdFrom, createdTo]);
  const handleSearch = () => load(0, actorType, action, resourceType, status, createdFrom, createdTo, query);
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Audit Log</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={actorType} onChange={(e) => setActorType(e.target.value)}>
            <option value="">All Actors</option>
            <option value="admin">Admin</option>
            <option value="agent">Agent</option>
            <option value="viewer">Viewer</option>
            <option value="system">System</option>
          </select>
          <select value={resourceType} onChange={(e) => setResourceType(e.target.value)}>
            <option value="">All Resources</option>
            <option value="host">Host</option>
            <option value="scan">Scan</option>
            <option value="scan_request">Scan Request</option>
            <option value="vulnerability">Vulnerability</option>
            <option value="security_db">Security DB</option>
            <option value="cve_db">CVE DB</option>
            <option value="access_policy">RBAC Policy</option>
          </select>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All Status</option>
            <option value="ok">OK</option>
            <option value="started">Started</option>
            <option value="error">Error</option>
            <option value="forbidden">Forbidden</option>
            <option value="degraded">Degraded</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <datalist id="audit-actions">
            <option value="agent.report" />
            <option value="host.agent_token.reset" />
            <option value="host.metadata.update" />
            <option value="security_db.auto_rescan" />
            <option value="security_db.recalculation" />
            <option value="security_db.update" />
            <option value="security_db.import" />
            <option value="sbom.export" />
            <option value="vulnerability.export" />
            <option value="scan_request.claim" />
            <option value="scan_request.complete" />
            <option value="scan_request.requeue_stale" />
            <option value="webhook.send" />
          </datalist>
          <input
            list="audit-actions"
            type="text"
            placeholder="Action"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 180 }}
          />
          <input
            type="text"
            placeholder="Actor ID or resource_type/resource_id"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 260 }}
          />
          <input
            type="date"
            aria-label="Audit created from"
            value={createdFrom}
            onChange={(e) => setCreatedFrom(e.target.value)}
          />
          <input
            type="date"
            aria-label="Audit created to"
            value={createdTo}
            onChange={(e) => setCreatedTo(e.target.value)}
          />
          <div className="filter-actions">
            <span className="result-count" style={{ color: error ? 'var(--critical)' : 'var(--text-muted)' }}>{error || `${total.toLocaleString()} events`}</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Status</th><th>Client</th><th>Metadata</th></tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id}>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(item.created_at).toLocaleString()}</td>
                  <td>{item.actor_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.actor_id || '-'}</div></td>
                  <td className="mono">{item.action}</td>
                  <td>{item.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.resource_id || '-'}</div></td>
                  <td><span className="badge">{item.status}</span></td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{item.ip_address || '-'}</td>
                  <td className="path-cell">{JSON.stringify(item.metadata || {})}<span className="path-tip">{JSON.stringify(item.metadata || {}, null, 2)}</span></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No audit events</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, actorType, action, resourceType, status, createdFrom, createdTo, query)} />
      </div>
    </>
  );
}

function CvssTooltip({ pkgId, score, onSelectVuln }: { pkgId: string; score: number | undefined; onSelectVuln?: (v: Vuln) => void }) {
  const s = score ?? 0;
  const [vulns, setVulns] = useState<Vuln[] | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const [show, setShow] = useState(false);
  const timerRef = useState<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = (e: React.MouseEvent) => {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    setPos({ x: rect.left, y: rect.bottom + 4 });
    setShow(true);
    if (!vulns) {
      api.packageVulns(pkgId).then(setVulns).catch(() => setVulns([]));
    }
  };

  const handleLeave = () => {
    setShow(false);
  };

  const sevColor = severityColor;

  if (s <= 0) return <span className="mono">-</span>;

  return (
    <>
      <span className="mono" style={{ color: s >= 9 ? 'var(--critical)' : s >= 7 ? 'var(--high)' : s >= 4 ? 'var(--medium)' : 'var(--low)', cursor: 'help' }}
        onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
        {s.toFixed(1)}
      </span>
      {show && pos && (
        <div style={{
          position: 'fixed', left: Math.min(pos.x, window.innerWidth - 340), top: pos.y,
          background: '#1e2030', border: '1px solid var(--border)', borderRadius: 8,
          padding: '0.75rem', minWidth: 280, maxWidth: 360, zIndex: 1000,
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)', fontSize: '0.8125rem',
          maxHeight: 320, overflowY: 'auto',
        }} onMouseEnter={() => setShow(true)} onMouseLeave={handleLeave}>
          {!vulns ? <span style={{ color: 'var(--text-muted)' }}>Loading...</span> :
           vulns.length === 0 ? <span style={{ color: 'var(--text-muted)' }}>No details</span> :
           vulns.map(v => (
             <div key={v.id} style={{ padding: '0.375rem 0', borderBottom: '1px solid var(--border)' }}>
               <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                 <span className="mono" style={{ fontSize: '0.75rem' }}>
                   {onSelectVuln
                     ? <a href="#" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onSelectVuln(v); setShow(false); }} style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a>
                     : v.primary_url ? <a href={v.primary_url} target="_blank" rel="noopener" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a> : v.vulnerability_id}
                 </span>
                 <span style={{ color: sevColor(v.severity), fontWeight: 600, fontSize: '0.75rem' }}>{v.severity} {v.cvss_score > 0 ? v.cvss_score.toFixed(1) : ''}</span>
               </div>
               {v.title && <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: 2 }}>{v.title}</div>}
               {(v.advisory_evidence || []).length > 0 && <div className="mono" style={{ color: '#22c55e', fontSize: '0.6875rem', marginTop: 2 }}>Advisory: {(v.advisory_evidence || []).map(e => e.source).join(', ')}</div>}
               <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem', marginTop: 2 }}>
                 {v.installed_version}
                 {v.fixed_version && v.installed_version
                   ? (() => {
                       const cmp = verCmp(v.installed_version, v.fixed_version);
                       const sym = cmp >= 0 ? '≥' : '<';
                       const color = cmp >= 0 ? '#22c55e' : 'var(--critical)';
                       return <span style={{ margin: '0 4px', color, fontWeight: 700 }}>{sym}</span>;
                     })()
                   : v.fixed_version ? ' → ' : ''}
                 {v.fixed_version || ''}
                 {v.fixed_version && v.installed_version && verCmp(v.installed_version, v.fixed_version) >= 0 &&
                   <span style={{ color: '#22c55e', fontWeight: 600, marginLeft: 4, fontSize: '0.625rem', background: 'rgba(34,197,94,0.15)', padding: '1px 4px', borderRadius: 3 }}>FIXED</span>}
               </div>
             </div>
           ))
          }
        </div>
      )}
    </>
  );
}

function SchedulesView() {
  const [items, setItems] = useState<ScheduledScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [cronExpr, setCronExpr] = useState('');
  const [scanType, setScanType] = useState('full');
  const [msg, setMsg] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.schedules()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!name || !cronExpr) return;
    setMsg('');
    try {
      await api.createSchedule({ name, cron_expr: cronExpr, scan_type: 'manual', packages_only: scanType === 'packages_only' });
      setMsg('Schedule created');
      setName('');
      setCronExpr('');
      load();
    } catch {
      setMsg('Failed to create schedule');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteSchedule(id);
      setMsg('Schedule deleted');
      load();
    } catch {
      setMsg('Failed to delete schedule');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Schedules</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create Schedule</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input type="text" placeholder="Cron expression (e.g. 0 2 * * *)" value={cronExpr} onChange={(e) => setCronExpr(e.target.value)} style={{ minWidth: 260 }} />
          <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
            <option value="full">Full Scan</option>
            <option value="packages_only">Packages Only</option>
          </select>
          <div className="filter-actions">
            {msg && <span className="result-count" style={{ color: msg.includes('Failed') ? 'var(--critical)' : 'var(--low)' }}>{msg}</span>}
            <button className="btn btn-primary" onClick={handleCreate}>Create</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Cron</th><th>Scan Type</th><th>Enabled</th><th>Last Run</th><th>Next Run</th><th></th></tr>
            </thead>
            <tbody>
              {items.map(s => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.cron_expr}</td>
                  <td>{s.packages_only ? 'packages_only' : s.scan_type}</td>
                  <td><span className="badge" style={{ color: s.enabled ? 'var(--low)' : 'var(--medium)' }}>{s.enabled ? 'yes' : 'no'}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.last_run ? new Date(s.last_run).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.next_run ? new Date(s.next_run).toLocaleString() : '-'}</td>
                  <td><button className="btn btn-danger btn-sm" onClick={() => handleDelete(s.id)}>Delete</button></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No schedules</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function AssetGroupsView() {
  const [items, setItems] = useState<AssetGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [groupType, setGroupType] = useState('static');
  const [ruleExpr, setRuleExpr] = useState('');
  const [msg, setMsg] = useState('');
  const [allHosts, setAllHosts] = useState<Host[]>([]);
  const [expandedId, setExpandedId] = useState('');
  const [detail, setDetail] = useState<AssetGroupDetail | null>(null);
  const [addHostId, setAddHostId] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.assetGroups()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.hosts().then(hs => setAllHosts(hs || [])).catch(() => {}); }, []);

  const loadDetail = useCallback((id: string) => {
    api.assetGroup(id).then(setDetail).catch(() => setDetail(null));
  }, []);

  const toggleExpand = (id: string) => {
    if (expandedId === id) { setExpandedId(''); setDetail(null); return; }
    setExpandedId(id);
    setDetail(null);
    setAddHostId('');
    loadDetail(id);
  };

  const handleAddHost = async (groupId: string) => {
    if (!addHostId) return;
    setMsg('');
    try {
      await api.addHostToAssetGroup(groupId, addHostId);
      setAddHostId('');
      loadDetail(groupId);
      load();
    } catch {
      setMsg('Failed to add host to group');
    }
  };

  const handleRemoveHost = async (groupId: string, hostId: string) => {
    setMsg('');
    try {
      await api.removeHostFromAssetGroup(groupId, hostId);
      loadDetail(groupId);
      load();
    } catch {
      setMsg('Failed to remove host from group');
    }
  };

  const handleCreate = async () => {
    if (!name) return;
    setMsg('');
    try {
      await api.createAssetGroup({ name, description, rule_type: groupType, rule_expr: groupType === 'dynamic' ? ruleExpr : '' });
      setMsg('Asset group created');
      setName('');
      setDescription('');
      setRuleExpr('');
      load();
    } catch {
      setMsg('Failed to create asset group');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteAssetGroup(id);
      setMsg('Asset group deleted');
      load();
    } catch {
      setMsg('Failed to delete asset group');
    }
  };

  const handleScan = async (id: string) => {
    setMsg('');
    try {
      await api.triggerAssetGroupScan(id);
      setMsg('Asset group scan triggered');
    } catch {
      setMsg('Failed to trigger asset group scan');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Asset Groups</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}><h2>Create Asset Group</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input type="text" placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
          <select value={groupType} onChange={(e) => setGroupType(e.target.value)}>
            <option value="static">Static</option>
            <option value="dynamic">Dynamic</option>
          </select>
          {groupType === 'dynamic' && <input type="text" placeholder="Rule expression" value={ruleExpr} onChange={(e) => setRuleExpr(e.target.value)} style={{ minWidth: 260 }} />}
          <button className="filter-btn" onClick={handleCreate}>Create</button>
          {msg && <span style={{ color: msg.includes('Failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{msg}</span>}
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Description</th><th>Type</th><th>Rule</th><th>Hosts</th><th></th><th></th></tr>
            </thead>
            <tbody>
              {items.map(g => (
                <React.Fragment key={g.id}>
                <tr style={{ cursor: 'pointer' }} onClick={() => toggleExpand(g.id)}>
                  <td>{expandedId === g.id ? '▾ ' : '▸ '}{g.name}</td>
                  <td>{g.description || '-'}</td>
                  <td><span className="badge">{g.rule_type}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{g.rule_expr || '-'}</td>
                  <td className="mono">{g.host_count || 0}</td>
                  <td><button className="update-btn" onClick={(e) => { e.stopPropagation(); handleScan(g.id); }}>Scan</button></td>
                  <td><button className="delete-btn" onClick={(e) => { e.stopPropagation(); handleDelete(g.id); }}>Delete</button></td>
                </tr>
                {expandedId === g.id && (
                  <tr>
                    <td colSpan={7} style={{ background: 'var(--bg)', padding: '0.75rem 1rem' }}>
                      {!detail ? <span style={{ color: 'var(--text-muted)' }}>Loading members...</span> : (
                        <>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', marginBottom: (detail.host_ids || []).length ? '0.5rem' : 0 }}>
                            {(detail.host_ids || []).map(hid => (
                              <span key={hid} className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                                {allHosts.find(h => h.id === hid)?.hostname || hid}
                                {g.rule_type === 'static' && (
                                  <button className="delete-btn" style={{ padding: '0 0.3rem', fontSize: '0.7rem' }} onClick={() => handleRemoveHost(g.id, hid)}>x</button>
                                )}
                              </span>
                            ))}
                            {(detail.host_ids || []).length === 0 && <span style={{ color: 'var(--text-muted)' }}>No member hosts</span>}
                          </div>
                          {g.rule_type === 'static' && (
                            <div className="filters" style={{ margin: 0 }}>
                              <select value={addHostId} onChange={(e) => setAddHostId(e.target.value)}>
                                <option value="">Add host...</option>
                                {allHosts.filter(h => !(detail.host_ids || []).includes(h.id)).map(h => (
                                  <option key={h.id} value={h.id}>{h.hostname || h.id}</option>
                                ))}
                              </select>
                              <button className="filter-btn" disabled={!addHostId} onClick={() => handleAddHost(g.id)}>Add Host</button>
                            </div>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                )}
                </React.Fragment>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No asset groups</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

function TrendsView() {
  const [summary, setSummary] = useState<VulnTrendSummary | null>(null);
  const [rows, setRows] = useState<VulnTrendRow[]>([]);
  const [posture, setPosture] = useState<PostureComparison | null>(null);
  const [postureDays, setPostureDays] = useState('7');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.vulnTrendSummary().catch(() => null),
      api.vulnTrends({ days: '90' }).catch(() => ({ items: [] as VulnTrendRow[] })),
    ]).then(([s, r]) => {
      setSummary(s);
      setRows(r?.items || []);
      setLoading(false);
    });
  }, []);

  useEffect(() => {
    api.vulnPosture({ days: postureDays }).then(setPosture).catch(() => setPosture(null));
  }, [postureDays]);

  const trendColor = (dir: string) => dir === 'up' ? 'var(--critical)' : dir === 'down' ? 'var(--low)' : 'var(--medium)';
  const n = (value: unknown) => Number.isFinite(Number(value)) ? Number(value) : 0;
  const currentTotal = n(summary?.current_total);
  const previousTotal = n(summary?.previous_total);
  const delta = n(summary?.delta);
  const deltaPercent = n(summary?.delta_percent);
  const trendDirection = summary?.trend_direction || 'flat';

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Vulnerability Trends</h1>
      {loading ? <Loading /> : (
        <>
          {summary && (
            <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
              <div className="stat-card">
                <div className="accent-bar" style={{ background: 'var(--primary)' }} />
                <div className="label">Current Total</div>
                <div className="value">{currentTotal.toLocaleString()}</div>
              </div>
              <div className="stat-card">
                <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
                <div className="label">Previous Total</div>
                <div className="value">{previousTotal.toLocaleString()}</div>
              </div>
              <div className="stat-card">
                <div className="accent-bar" style={{ background: delta > 0 ? 'var(--critical)' : 'var(--low)' }} />
                <div className="label">Delta</div>
                <div className="value" style={{ color: delta > 0 ? 'var(--critical)' : 'var(--low)' }}>
                  {delta > 0 ? '+' : ''}{delta.toLocaleString()}
                </div>
              </div>
              <div className="stat-card">
                <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
                <div className="label">Delta %</div>
                <div className="value">{deltaPercent.toFixed(1)}%</div>
              </div>
              <div className="stat-card">
                <div className="accent-bar" style={{ background: trendColor(trendDirection) }} />
                <div className="label">Trend</div>
                <div className="value" style={{ color: trendColor(trendDirection), textTransform: 'uppercase' }}>{trendDirection}</div>
              </div>
            </div>
          )}
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header">
              <h2>Posture Comparison</h2>
              <div className="filters" style={{ margin: 0 }}>
                <select value={postureDays} onChange={(e) => setPostureDays(e.target.value)}>
                  <option value="7">vs 7 days ago</option>
                  <option value="14">vs 14 days ago</option>
                  <option value="30">vs 30 days ago</option>
                </select>
              </div>
            </div>
            {!posture ? <div style={{ padding: '1rem', color: 'var(--text-muted)' }}>No posture data</div> : (
              <table>
                <thead>
                  <tr><th>Current ({posture.current_date || '-'})</th><th>Previous ({posture.previous_date || 'no snapshot'})</th><th>Delta</th><th>Trend</th></tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="mono">{posture.current_total.toLocaleString()}</td>
                    <td className="mono">{posture.previous_date ? posture.previous_total.toLocaleString() : '-'}</td>
                    <td className="mono" style={{ color: posture.delta > 0 ? 'var(--critical)' : posture.delta < 0 ? 'var(--low)' : 'var(--text-muted)' }}>
                      {posture.delta > 0 ? '+' : ''}{posture.delta.toLocaleString()}{posture.previous_date ? ` (${posture.delta_percent.toFixed(1)}%)` : ''}
                    </td>
                    <td style={{ color: trendColor(posture.trend_direction), textTransform: 'uppercase', fontWeight: 600 }}>{posture.trend_direction}</td>
                  </tr>
                </tbody>
              </table>
            )}
          </div>
          <div className="card chart-card" style={{ marginBottom: '1rem' }}>
            <div className="card-header">
              <h2>Findings over time</h2>
              <span className="chart-legend">
                {SEV_KEYS.map(s => (
                  <span key={s.key} className="chart-legend-item"><span className="chart-legend-dot" style={{ background: s.raw }} />{s.label}</span>
                ))}
              </span>
            </div>
            <div className="chart-body">
              {rows.length >= 2 ? <StackedAreaChart rows={rows} height={260} /> : <EmptyState message="Not enough history yet — at least 2 days of snapshots are needed." />}
            </div>
          </div>
          <div className="card">
            <div className="card-header"><h2>Daily Vulnerability Counts</h2></div>
            <table className="tnum">
              <thead>
                <tr><th>Date</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Exploited</th></tr>
              </thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.date}>
                    <td className="mono" style={{ fontSize: '0.8125rem' }}>{r.date}</td>
                    <td className="mono">{n(r.total_vulns).toLocaleString()}</td>
                    <td className="mono" style={{ color: 'var(--critical)', fontWeight: n(r.critical_count) ? 600 : 400 }}>{n(r.critical_count)}</td>
                    <td className="mono" style={{ color: 'var(--high)', fontWeight: n(r.high_count) ? 600 : 400 }}>{n(r.high_count)}</td>
                    <td className="mono" style={{ color: 'var(--medium)', fontWeight: n(r.medium_count) ? 600 : 400 }}>{n(r.medium_count)}</td>
                    <td className="mono" style={{ color: 'var(--low)', fontWeight: n(r.low_count) ? 600 : 400 }}>{n(r.low_count)}</td>
                    <td className="mono" style={{ color: n(r.exploited_count) ? 'var(--high)' : 'var(--text-muted)', fontWeight: n(r.exploited_count) ? 600 : 400 }}>{n(r.exploited_count)}</td>
                  </tr>
                ))}
                {rows.length === 0 && <tr className="empty-row"><td colSpan={7}>No trend data</td></tr>}
              </tbody>
            </table>
          </div>
        </>
      )}
    </>
  );
}

function ReportsView() {
  const [summary, setSummary] = useState<ExecutiveSummary | null>(null);
  const [sla, setSla] = useState<SLAComplianceReport | null>(null);
  const [riskRows, setRiskRows] = useState<RiskBreakdownRow[]>([]);
  const [riskGroupBy, setRiskGroupBy] = useState('owner');
  const [topRisk, setTopRisk] = useState<AtRiskHost[]>([]);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [loading, setLoading] = useState(true);
  const [exportMsg, setExportMsg] = useState('');

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.executiveSummary().catch(() => null),
      api.slaCompliance().catch(() => null),
      api.riskBreakdown({ group_by: riskGroupBy }).catch(() => ({ items: [], group_by: riskGroupBy })),
      api.topRiskHosts({ limit: '10' }).catch(() => ({ items: [] })),
      api.recommendations().catch(() => ({ items: [] })),
    ]).then(([s, sl, r, tr, rec]) => {
      setSummary(s);
      setSla(sl);
      setRiskRows(r?.items || []);
      setTopRisk(tr?.items || []);
      setRecommendations(rec?.items || []);
      setLoading(false);
    });
  }, []);

  const loadRiskBreakdown = useCallback((groupBy: string) => {
    api.riskBreakdown({ group_by: groupBy })
      .then(r => { setRiskRows(r.items || []); setRiskGroupBy(groupBy); })
      .catch(() => {});
  }, []);

  const handleExport = async () => {
    setExportMsg('Exporting...');
    try {
      await api.exportReport({ format: 'json' });
      setExportMsg('Report exported');
    } catch {
      setExportMsg('Export failed');
    }
  };

  const sevColor = severityColor;

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Reports</h1>
      {loading ? <Loading /> : (
        <>
          {summary && (
            <>
              <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: 'var(--primary)' }} />
                  <div className="label">Total Hosts</div>
                  <div className="value">{summary.total_hosts}</div>
                </div>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: 'var(--high)' }} />
                  <div className="label">Active Vulnerabilities</div>
                  <div className="value" style={{ color: 'var(--high)' }}>{summary.active_vulnerabilities.toLocaleString()}</div>
                </div>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: 'var(--critical)' }} />
                  <div className="label">Exploited</div>
                  <div className="value" style={{ color: 'var(--critical)' }}>{summary.exploited_count}</div>
                </div>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: summary.overdue_sla_count > 0 ? 'var(--critical)' : 'var(--low)' }} />
                  <div className="label">Overdue SLA</div>
                  <div className="value" style={{ color: summary.overdue_sla_count > 0 ? 'var(--critical)' : 'var(--low)' }}>{summary.overdue_sla_count}</div>
                </div>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: 'var(--low)' }} />
                  <div className="label">SLA Compliance</div>
                  <div className="value" style={{ color: 'var(--low)' }}>{summary.sla_compliance_percent.toFixed(1)}%</div>
                </div>
                <div className="stat-card">
                  <div className="accent-bar" style={{ background: summary.trend_direction === 'up' ? 'var(--critical)' : 'var(--low)' }} />
                  <div className="label">Trend</div>
                  <div className="value" style={{ color: summary.trend_direction === 'up' ? 'var(--critical)' : 'var(--low)', textTransform: 'uppercase' }}>{summary.trend_direction}</div>
                </div>
              </div>
              <div className="card" style={{ marginBottom: '1rem' }}>
                <div className="card-header"><h2>Severity Counts</h2></div>
                <div style={{ display: 'flex', gap: '1rem', padding: '1rem', flexWrap: 'wrap' }}>
                  {SEVERITY_ORDER.filter(sev => sev in (summary.severity_counts || {})).map(sev => (
                    <div key={sev} style={{ textAlign: 'center' }}>
                      <div className="mono" style={{ fontSize: '1.25rem', fontWeight: 700, color: sevColor(sev) }}>{summary.severity_counts[sev]}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{sev}</div>
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}
          {sla && (
            <div className="card" style={{ marginBottom: '1rem' }}>
              <div className="card-header"><h2>SLA Compliance</h2></div>
              <table>
                <thead>
                  <tr><th>Severity</th><th>Total</th><th>Overdue</th><th>Compliance %</th></tr>
                </thead>
                <tbody>
                  {SEVERITY_ORDER.filter(sev => sev in (sla.by_severity || {})).map(sev => { const stats = sla.by_severity[sev]; return (
                    <tr key={sev}>
                      <td><span className="badge" style={{ color: sevColor(sev) }}>{sev}</span></td>
                      <td className="mono">{stats.total}</td>
                      <td className="mono" style={{ color: stats.overdue > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>{stats.overdue}</td>
                      <td className="mono">{stats.compliance_percent.toFixed(1)}%</td>
                    </tr>
                  ); })}
                  {Object.keys(sla.by_severity || {}).length === 0 && <tr className="empty-row"><td colSpan={4}>No SLA data</td></tr>}
                </tbody>
              </table>
            </div>
          )}
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header">
              <h2>Risk Breakdown</h2>
              <div className="filters" style={{ margin: 0 }}>
                <select value={riskGroupBy} onChange={(e) => loadRiskBreakdown(e.target.value)}>
                  <option value="owner">Owner</option>
                  <option value="team">Team</option>
                  <option value="environment">Environment</option>
                  <option value="criticality">Criticality</option>
                </select>
              </div>
            </div>
            <table>
              <thead>
                <tr><th>Group</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr>
              </thead>
              <tbody>
                {riskRows.map(r => (
                  <tr key={r.group}>
                    <td>{r.group || '(unassigned)'}</td>
                    <td className="mono">{r.total.toLocaleString()}</td>
                    <td className="mono" style={{ color: 'var(--critical)' }}>{r.severity_counts?.CRITICAL || 0}</td>
                    <td className="mono" style={{ color: 'var(--high)' }}>{r.severity_counts?.HIGH || 0}</td>
                    <td className="mono" style={{ color: 'var(--medium)' }}>{r.severity_counts?.MEDIUM || 0}</td>
                    <td className="mono" style={{ color: 'var(--low)' }}>{r.severity_counts?.LOW || 0}</td>
                  </tr>
                ))}
                {riskRows.length === 0 && <tr className="empty-row"><td colSpan={6}>No risk breakdown data</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header"><h2>Top Risk Hosts</h2></div>
            <table>
              <thead>
                <tr><th>Host</th><th>Total Vulns</th><th>Critical</th><th>High</th><th>Exploited</th><th>Overdue</th><th>Max Risk</th></tr>
              </thead>
              <tbody>
                {topRisk.map(h => (
                  <tr key={h.host_id}>
                    <td>{h.hostname || h.host_id}</td>
                    <td className="mono">{h.total_vulns.toLocaleString()}</td>
                    <td className="mono" style={{ color: 'var(--critical)' }}>{h.critical_count}</td>
                    <td className="mono" style={{ color: 'var(--high)' }}>{h.high_count}</td>
                    <td className="mono" style={{ color: h.exploited_count > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>{h.exploited_count}</td>
                    <td className="mono" style={{ color: h.overdue_count > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>{h.overdue_count}</td>
                    <td className="mono" style={{ color: riskLevelColor(h.max_risk_score >= 80 ? 'critical' : h.max_risk_score >= 60 ? 'high' : h.max_risk_score >= 40 ? 'medium' : 'low') }}>{h.max_risk_score.toFixed(1)}</td>
                  </tr>
                ))}
                {topRisk.length === 0 && <tr className="empty-row"><td colSpan={7}>No host risk data</td></tr>}
              </tbody>
            </table>
          </div>
          <div className="card" style={{ marginBottom: '1rem' }}>
            <div className="card-header"><h2>Recommendations</h2></div>
            <table>
              <thead>
                <tr><th>Priority</th><th>Category</th><th>Recommendation</th></tr>
              </thead>
              <tbody>
                {recommendations.map((rec, i) => (
                  <tr key={`${rec.category}-${i}`}>
                    <td><span className="badge" style={{ color: riskLevelColor(rec.priority) }}>{rec.priority || '-'}</span></td>
                    <td>{rec.category.replace(/_/g, ' ')}</td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{rec.title}</div>
                      {rec.description && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{rec.description}</div>}
                    </td>
                  </tr>
                ))}
                {recommendations.length === 0 && <tr className="empty-row"><td colSpan={3}>No recommendations</td></tr>}
              </tbody>
            </table>
          </div>
          <div style={{ marginBottom: '1rem' }}>
            <button className="update-btn" onClick={handleExport}>Export Report (JSON)</button>
            {exportMsg && <span style={{ marginLeft: '0.75rem', color: exportMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{exportMsg}</span>}
          </div>
        </>
      )}
    </>
  );
}

function NotificationsView() {
  const [items, setItems] = useState<NotificationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [triggerEvent, setTriggerEvent] = useState('scan.completed');
  const [minSeverity, setMinSeverity] = useState('CRITICAL');
  const [channelType, setChannelType] = useState('webhook');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');
  const [emailTo, setEmailTo] = useState('');
  const [emailSubjectPrefix, setEmailSubjectPrefix] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [msg, setMsg] = useState('');
  const [logEntries, setLogEntries] = useState<NotificationLogEntry[]>([]);
  const [showLog, setShowLog] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api.notificationRules()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!name) return;
    setMsg('');
    const channelConfig: Record<string, string> = {};
    if (channelType === 'webhook') {
      if (!webhookUrl.trim()) { setMsg('Webhook URL is required'); return; }
      channelConfig.url = webhookUrl.trim();
      if (webhookSecret.trim()) channelConfig.secret = webhookSecret.trim();
    } else if (channelType === 'email') {
      if (!emailTo.trim()) { setMsg('Recipient email is required'); return; }
      channelConfig.to = emailTo.trim();
      if (emailSubjectPrefix.trim()) channelConfig.subject_prefix = emailSubjectPrefix.trim();
    }
    try {
      await api.createNotificationRule({ name, trigger_event: triggerEvent, min_severity: minSeverity, channel_type: channelType, channel_config: channelConfig, enabled });
      setMsg('Notification rule created');
      setName('');
      setWebhookUrl(''); setWebhookSecret(''); setEmailTo(''); setEmailSubjectPrefix('');
      load();
    } catch (err) {
      setMsg(err instanceof Error ? `Failed to create rule: ${err.message}` : 'Failed to create notification rule');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteNotificationRule(id);
      setMsg('Notification rule deleted');
      load();
    } catch {
      setMsg('Failed to delete notification rule');
    }
  };

  const handleTest = async (id: string) => {
    setMsg('');
    try {
      await api.testNotificationRule(id);
      setMsg('Test notification sent');
    } catch {
      setMsg('Failed to send test notification');
    }
  };

  const handleLoadLog = async () => {
    if (showLog) { setShowLog(false); return; }
    try {
      const r = await api.notificationLog({ limit: '20' });
      setLogEntries(r.items || []);
      setShowLog(true);
    } catch {
      setMsg('Failed to load notification log');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Notifications</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create Notification Rule</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={triggerEvent} onChange={(e) => setTriggerEvent(e.target.value)}>
            <option value="scan.completed">Scan Completed</option>
            <option value="vulnerability.discovered">Vulnerability Discovered</option>
            <option value="security_db.updated">Security DB Updated</option>
          </select>
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={channelType} onChange={(e) => setChannelType(e.target.value)}>
            <option value="webhook">Webhook</option>
            <option value="email">Email</option>
            <option value="log">Log</option>
          </select>
          {channelType === 'webhook' && (
            <>
              <input type="text" placeholder="Webhook URL" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} style={{ minWidth: 240 }} />
              <input type="text" placeholder="HMAC secret (optional)" value={webhookSecret} onChange={(e) => setWebhookSecret(e.target.value)} />
            </>
          )}
          {channelType === 'email' && (
            <>
              <input type="text" placeholder="Recipients (comma-separated)" value={emailTo} onChange={(e) => setEmailTo(e.target.value)} style={{ minWidth: 240 }} />
              <input type="text" placeholder="Subject prefix (optional)" value={emailSubjectPrefix} onChange={(e) => setEmailSubjectPrefix(e.target.value)} />
            </>
          )}
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Enabled" checked={enabled} onChange={setEnabled} />
          </div>
          <div className="filter-actions">
            {msg && <span className="result-count" style={{ color: msg.includes('Failed') ? 'var(--critical)' : 'var(--low)' }}>{msg}</span>}
            <button className="btn btn-primary" onClick={handleCreate}>Create</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Trigger Event</th><th>Min Severity</th><th>Channel</th><th>Enabled</th><th>Last Triggered</th><th></th><th></th></tr>
            </thead>
            <tbody>
              {items.map(r => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{r.trigger_event}</td>
                  <td><span className="badge">{r.min_severity || '-'}</span></td>
                  <td>{r.channel_type}</td>
                  <td><span className="badge" style={{ color: r.enabled ? 'var(--low)' : 'var(--medium)' }}>{r.enabled ? 'yes' : 'no'}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{r.last_triggered ? new Date(r.last_triggered).toLocaleString() : '-'}</td>
                  <td><button className="btn btn-secondary btn-sm" onClick={() => handleTest(r.id)}>Test</button></td>
                  <td><button className="btn btn-danger btn-sm" onClick={() => handleDelete(r.id)}>Delete</button></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={8}>No notification rules</td></tr>}
            </tbody>
          </table>
        )}
      </div>
      <div style={{ marginTop: '1rem' }}>
        <button className="btn btn-secondary" onClick={handleLoadLog}>{showLog ? 'Hide Log' : 'Show Log'}</button>
      </div>
      {showLog && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>Notification Log</h2></div>
          <table>
            <thead>
              <tr><th>Time</th><th>Rule</th><th>Event</th><th>Channel</th><th>Status</th><th>Error</th></tr>
            </thead>
            <tbody>
              {logEntries.map(e => (
                <tr key={e.id}>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(e.created_at).toLocaleString()}</td>
                  <td>{e.rule_name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{e.trigger_event}</td>
                  <td>{e.channel_type}</td>
                  <td><span className="badge">{e.status}</span></td>
                  <td style={{ fontSize: '0.8125rem', color: e.error_message ? 'var(--critical)' : 'var(--text-muted)' }}>{e.error_message || '-'}</td>
                </tr>
              ))}
              {logEntries.length === 0 && <tr className="empty-row"><td colSpan={6}>No log entries</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
