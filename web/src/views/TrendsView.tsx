import { useState, useEffect } from 'react';
import { api, type VulnTrendRow, type VulnTrendSummary, type PostureComparison } from '../api';
import { Loading, EmptyState } from '../components/primitives';
import { StackedAreaChart, SEV_KEYS } from '../components/charts';
import { fmtCount } from '../lib/format';

export function TrendsView() {
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
                    <td className="mono">{fmtCount(n(r.total_vulns))}</td>
                    <td className="mono" style={{ color: 'var(--critical)', fontWeight: n(r.critical_count) ? 600 : 400 }}>{fmtCount(n(r.critical_count))}</td>
                    <td className="mono" style={{ color: 'var(--high)', fontWeight: n(r.high_count) ? 600 : 400 }}>{fmtCount(n(r.high_count))}</td>
                    <td className="mono" style={{ color: 'var(--medium)', fontWeight: n(r.medium_count) ? 600 : 400 }}>{fmtCount(n(r.medium_count))}</td>
                    <td className="mono" style={{ color: 'var(--low)', fontWeight: n(r.low_count) ? 600 : 400 }}>{fmtCount(n(r.low_count))}</td>
                    <td className="mono" style={{ color: n(r.exploited_count) ? 'var(--high)' : 'var(--text-muted)', fontWeight: n(r.exploited_count) ? 600 : 400 }}>{fmtCount(n(r.exploited_count))}</td>
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
