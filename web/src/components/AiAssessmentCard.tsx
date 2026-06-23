import React, { useState, useEffect, useMemo } from 'react';
import { api, type Vuln, type VulnAnalysis, type LLMStatus } from '../api';
import { Icon } from './Icon';
import { Loading, Badge } from './primitives';
import { isVulnAnalysis, recommendedActionLabel, recommendedActionTone, riskLevelTone } from '../lib/severity';
import { formatDateTime } from '../lib/format';

export function AiAssessmentCard({ vuln }: { vuln: Vuln }) {
  const [llm, setLlm] = useState<LLMStatus | null>(null);
  const [llmLoaded, setLlmLoaded] = useState(false);
  const [analysis, setAnalysis] = useState<VulnAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [applying, setApplying] = useState(false);
  const [applyMsg, setApplyMsg] = useState('');

  const params = useMemo(() => ({
    vulnerability_id: vuln.vulnerability_id,
    ...(vuln.pkg_name ? { pkg_name: vuln.pkg_name } : {}),
    ...(vuln.host_id ? { host_id: vuln.host_id } : {}),
  }), [vuln.vulnerability_id, vuln.pkg_name, vuln.host_id]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    setAnalysis(null);
    setApplyMsg('');
    api.llmStatus()
      .then(status => {
        if (!active) return;
        setLlm(status);
        setLlmLoaded(true);
        if (!status.enabled) { setLoading(false); return; }
        return api.vulnAnalysis(params)
          .then(r => { if (active) setAnalysis(isVulnAnalysis(r) ? r : null); })
          .finally(() => { if (active) setLoading(false); });
      })
      .catch(() => {
        // Treat an unreachable/failed status check as "not configured" rather
        // than breaking the vuln detail page.
        if (active) { setLlmLoaded(true); setLoading(false); }
      });
    return () => { active = false; };
  }, [params]);

  const runAnalyze = async () => {
    setRunning(true);
    setError('');
    try {
      const r = await api.vulnAnalysis({ ...params, analyze: true });
      setAnalysis(isVulnAnalysis(r) ? r : null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI analysis is not configured');
    } finally {
      setRunning(false);
    }
  };

  const applyAnalysis = async () => {
    if (!analysis) return;
    setApplying(true);
    setApplyMsg('');
    try {
      const r = await api.applyVulnAnalysis(analysis.id);
      setApplyMsg(`applied as ${r.triage_status}`);
    } catch (err) {
      setApplyMsg(err instanceof Error ? err.message : 'Apply failed');
    } finally {
      setApplying(false);
    }
  };

  const disabled = llmLoaded && (!llm || !llm.enabled);

  return (
    <div className="card ai-card" style={{ marginBottom: '1rem', padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Icon name="ai-triage" size={16} /> AI Assessment
      </h3>
      {!llmLoaded || loading ? (
        <Loading label="Loading AI assessment..." />
      ) : disabled ? (
        <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>AI analysis not configured</div>
      ) : analysis ? (
        <AiAnalysisBody analysis={analysis} onApply={applyAnalysis} applyMsg={applyMsg} applying={applying} />
      ) : (
        <div>
          <button className="btn btn-primary btn-sm" onClick={runAnalyze} disabled={running}>
            {running ? 'Analyzing...' : 'Analyze with AI'}
          </button>
          {error && <span style={{ marginLeft: '0.75rem', color: 'var(--critical)', fontSize: '0.8125rem' }}>{error}</span>}
        </div>
      )}
    </div>
  );
}

function AiAnalysisBody({ analysis, onApply, applyMsg, applying }: {
  analysis: VulnAnalysis;
  onApply?: () => void;
  applyMsg?: string;
  applying?: boolean;
}) {
  const actionable = analysis.recommended_action === 'false_positive' || analysis.recommended_action === 'accept_risk';
  return (
    <>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem' }}>
        <Badge tone={recommendedActionTone(analysis.recommended_action)}>{recommendedActionLabel(analysis.recommended_action)}</Badge>
        <Badge tone={riskLevelTone(analysis.risk_level)} dot>{analysis.risk_level || 'unknown'} risk</Badge>
        {analysis.auto_applied && <Badge tone="accent">auto-applied</Badge>}
      </div>
      <table style={{ marginBottom: '0.75rem' }}>
        <tbody>
          <tr><td style={{ color: 'var(--text-muted)', width: 160 }}>Exploitability</td><td className="mono">{analysis.exploitability || '-'}</td></tr>
          <tr><td style={{ color: 'var(--text-muted)' }}>Confidence</td><td className="mono">{Math.round((analysis.confidence || 0) * 100)}%</td></tr>
          <tr><td style={{ color: 'var(--text-muted)' }}>Likely false positive</td><td className="mono">{analysis.likely_false_positive ? 'Yes' : 'No'}</td></tr>
        </tbody>
      </table>
      {analysis.reasoning && (
        <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '0.75rem' }}>{analysis.reasoning}</div>
      )}
      {onApply && actionable && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <button className="btn btn-primary btn-sm" onClick={onApply} disabled={applying}>{applying ? 'Applying...' : 'Apply'}</button>
          {applyMsg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{applyMsg}</span>}
        </div>
      )}
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }} className="mono">
        {analysis.model || '-'} · {analysis.provider || '-'} · updated {formatDateTime(analysis.updated_at)}
      </div>
    </>
  );
}
