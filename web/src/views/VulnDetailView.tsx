import React, { useEffect,useState } from 'react';
import { api, type Vuln, type Host } from '../api';
import { findingSourceLabel, riskLevelColor, riskLevelLabel, severityColor } from '../lib/severity';
import { formatDateOnly, dateInputValue } from '../lib/format';
import { parseCvssVector } from '../lib/cvss';
import { AiAssessmentCard } from '../components/AiAssessmentCard';

export function VulnDetailView({ vuln, onBack }: { vuln: Vuln | null; onBack: () => void }) {
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [triageStatus, setTriageStatus] = useState(vuln?.triage_status || 'open');
  const [triageReason, setTriageReason] = useState(vuln?.triage_reason || '');
  const [triageAssignee, setTriageAssignee] = useState(vuln?.triage_assignee || '');
  const [triageComment, setTriageComment] = useState(vuln?.triage_comment || '');
  const [triageExpiresAt, setTriageExpiresAt] = useState(dateInputValue(vuln?.triage_expires_at));
  const [triageScope, setTriageScope] = useState<'finding' | 'host' | 'global'>('finding');
  const [triageMsg, setTriageMsg] = useState('');

  // Escape returns to the vulnerability list (unless typing in a field).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const t = e.target as HTMLElement | null;
      if (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
      onBack();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onBack]);

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
          <div style={{ fontSize: '0.875rem' }}>{vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(1)}%` : '-'}</div>
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
            {formatDateOnly(vuln.due_at)}
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

      <AiAssessmentCard vuln={vuln} />

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
