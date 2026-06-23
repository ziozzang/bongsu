import React, { useState, useEffect, useCallback } from 'react';
import { api, type ExecutiveSummary, type SLAComplianceReport, type RiskBreakdownRow, type AtRiskHost, type Recommendation } from '../api';
import { Loading } from '../components/primitives';
import { fmtCount } from '../lib/format';
import { severityColor, riskLevelColor, SEVERITY_ORDER } from '../lib/severity';

export function ReportsView() {
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
                      <td className="mono">{fmtCount(stats.total)}</td>
                      <td className="mono" style={{ color: stats.overdue > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>{fmtCount(stats.overdue)}</td>
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
                {recommendations.length === 0 && <tr className="empty-row"><td colSpan={3}>No recommendations right now — this populates once findings accumulate and SLAs are at risk.</td></tr>}
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
