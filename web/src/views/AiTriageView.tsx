import { useState, useEffect, useCallback } from 'react';
import { api, type Vuln, type VulnAnalysis, type AIPolicyStatus, type LLMStatus } from '../api';
import { Loading, LoadError, EmptyState, Badge } from '../components/primitives';
import { Icon } from '../components/Icon';
import { recommendedActionLabel, recommendedActionTone, riskLevelTone, aiPolicyModeTone, aiPolicyModeBlurb, aiApprovalStatusTone } from '../lib/severity';

export function AiTriageView({ onSelectVuln }: { onSelectVuln?: (v: Vuln) => void }) {
  const [llm, setLlm] = useState<LLMStatus | null>(null);
  const [policy, setPolicy] = useState<AIPolicyStatus | null>(null);
  const [analyses, setAnalyses] = useState<VulnAnalysis[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [running, setRunning] = useState(false);
  const [applyingId, setApplyingId] = useState('');
  const [filter, setFilter] = useState('');
  const [expanded, setExpanded] = useState<string>('');

  const load = useCallback((action: string) => {
    setLoading(true);
    setError('');
    api.listVulnAnalyses(action || undefined)
      .then(r => {
        setAnalyses(r.analyses || []);
        setCounts(r.counts || {});
        setTotal(r.total || 0);
        setLoading(false);
      })
      .catch(err => { setError(err instanceof Error ? err.message : 'Failed to load AI analyses'); setLoading(false); });
  }, []);

  useEffect(() => {
    let active = true;
    api.llmStatus().then(s => { if (active) setLlm(s); }).catch(() => { if (active) setLlm(null); });
    api.aiPolicy().then(p => { if (active) setPolicy(p); }).catch(() => { if (active) setPolicy(null); });
    return () => { active = false; };
  }, []);

  useEffect(() => { load(filter); }, [load, filter]);

  const runAnalysis = async () => {
    setRunning(true);
    setMsg('');
    try {
      const r = await api.runVulnAnalysis(20);
      setMsg(`Analyzed ${r.analyzed} finding${r.analyzed === 1 ? '' : 's'}`);
      load(filter);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setRunning(false);
    }
  };

  const applyOne = async (a: VulnAnalysis) => {
    setApplyingId(a.id);
    setMsg('');
    try {
      const r = await api.applyVulnAnalysis(a.id);
      setMsg(`${a.vulnerability_id} applied as ${r.triage_status}`);
      load(filter);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Apply failed');
    } finally {
      setApplyingId('');
    }
  };

  const enabled = !!llm && llm.enabled;
  const countEntries = Object.entries(counts).filter(([, n]) => n > 0);

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>AI Triage</h1>
      <div className="card ai-card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.375rem' }}>
              <Icon name="ai-triage" size={16} />
              <strong>LLM Analysis</strong>
              <Badge tone={enabled ? 'low' : 'unknown'} dot>{enabled ? 'enabled' : 'disabled'}</Badge>
            </div>
            <div className="mono" style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
              {llm ? `${llm.provider || 'none'} · ${llm.model || '-'}` : 'status unavailable'}
              {llm && llm.enabled && (
                <> · auto-apply ≥ {Math.round((llm.autoapply_confidence || 0) * 100)}% · worker every {llm.worker_interval_min}m</>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            {msg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{msg}</span>}
            <button className="btn btn-primary btn-sm" onClick={runAnalysis} disabled={!enabled || running}>
              {running ? 'Running...' : 'Run analysis'}
            </button>
          </div>
        </div>
        {!enabled && (
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '0.5rem' }}>
            AI analysis not configured — set an LLM provider to enable on-demand and periodic triage.
          </div>
        )}
        {countEntries.length > 0 && (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginTop: '0.75rem' }}>
            {countEntries.map(([action, n]) => (
              <Badge key={action} tone={recommendedActionTone(action)}>{recommendedActionLabel(action)}: {n}</Badge>
            ))}
          </div>
        )}
      </div>

      {policy && (
        <div className="card ai-card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <Icon name="ai-approvals" size={16} />
              <strong>AI Action Policy</strong>
              <Badge tone={aiPolicyModeTone(policy.mode)} dot>{policy.mode || 'off'}</Badge>
              <span className="mono" style={{ fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
                min confidence {Math.round((policy.min_confidence || 0) * 100)}% · protect production {policy.protect_production ? 'on' : 'off'}
              </span>
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
              {(['pending', 'approved', 'rejected'] as const).map(s => (
                <Badge key={s} tone={aiApprovalStatusTone(s)}>{s}: {policy.approval_counts?.[s] || 0}</Badge>
              ))}
            </div>
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '0.5rem' }}>
            {aiPolicyModeBlurb(policy.mode)}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <h2>Analyses {total > 0 ? `(${total})` : ''}</h2>
          <select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="">All actions</option>
            <option value="false_positive">False positive</option>
            <option value="accept_risk">Accept risk</option>
            <option value="remediate">Remediate</option>
            <option value="investigate">Investigate</option>
            <option value="monitor">Monitor</option>
          </select>
        </div>
        {loading ? <Loading /> : error ? <LoadError message={error} onRetry={() => load(filter)} /> : analyses.length === 0 ? (
          <EmptyState message="No AI analyses yet — run analysis or enable the periodic worker." />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Vulnerability</th>
                <th>Package</th>
                <th>Host</th>
                <th>Recommended action</th>
                <th>Risk</th>
                <th>Exploitability</th>
                <th>Confidence</th>
                <th>Auto-applied</th>
                <th>Reasoning</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {analyses.map(a => {
                const actionable = a.recommended_action === 'false_positive' || a.recommended_action === 'accept_risk';
                const isOpen = expanded === a.id;
                return (
                  <tr key={a.id}>
                    <td className="mono" style={{ fontSize: '0.8125rem' }}>
                      {onSelectVuln
                        ? <a href="#" style={{ color: 'var(--primary)' }} onClick={(e) => { e.preventDefault(); onSelectVuln({ vulnerability_id: a.vulnerability_id, pkg_name: a.pkg_name, host_id: a.host_id } as Vuln); }}>{a.vulnerability_id}</a>
                        : a.vulnerability_id}
                    </td>
                    <td className="mono" style={{ fontSize: '0.8125rem' }}>{a.pkg_name || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{a.host_id ? a.host_id.slice(0, 8) : '-'}</td>
                    <td><Badge tone={recommendedActionTone(a.recommended_action)}>{recommendedActionLabel(a.recommended_action)}</Badge></td>
                    <td><Badge tone={riskLevelTone(a.risk_level)} dot>{a.risk_level || 'unknown'}</Badge></td>
                    <td className="mono" style={{ fontSize: '0.8125rem' }}>{a.exploitability || '-'}</td>
                    <td className="mono">{Math.round((a.confidence || 0) * 100)}%</td>
                    <td>{a.auto_applied ? <Badge tone="accent">auto</Badge> : <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                    <td style={{ maxWidth: 320 }}>
                      {a.reasoning ? (
                        <span
                          title={a.reasoning}
                          onClick={() => setExpanded(isOpen ? '' : a.id)}
                          style={{ cursor: 'pointer', display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', whiteSpace: isOpen ? 'normal' : 'nowrap', overflow: isOpen ? 'visible' : 'hidden', textOverflow: 'ellipsis' }}
                        >
                          {a.reasoning}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                    </td>
                    <td>
                      {actionable && (
                        <button className="btn btn-primary btn-sm" onClick={() => applyOne(a)} disabled={applyingId === a.id}>
                          {applyingId === a.id ? 'Applying...' : 'Apply'}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
