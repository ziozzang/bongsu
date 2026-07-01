import { useState, useEffect, useCallback } from 'react';
import { api, type IntelRunOutcome } from '../api';
import { Loading, EmptyState, Badge } from '../components/primitives';
import { Icon } from '../components/Icon';

// Per-scenario parameter hints — the agent prompt validates required params, so
// the form mirrors what each scenario's BuildPrompt needs.
const SCENARIO_PARAMS: Record<string, { key: string; label: string; required: boolean; placeholder: string }[]> = {
  correlate: [{ key: 'cve', label: 'CVE id', required: true, placeholder: 'CVE-2024-3094' }],
  triage: [
    { key: 'cve', label: 'CVE id', required: true, placeholder: 'CVE-2024-3094' },
    { key: 'scan_id', label: 'Scan id', required: false, placeholder: 'optional' },
    { key: 'package', label: 'Package', required: false, placeholder: 'optional' },
  ],
  campaign: [
    { key: 'ecosystem', label: 'Ecosystem', required: true, placeholder: 'npm' },
    { key: 'package', label: 'Package', required: true, placeholder: 'left-pad' },
  ],
  remediate: [{ key: 'cve', label: 'CVE id', required: true, placeholder: 'CVE-2024-3094' }],
  verify: [
    { key: 'cve', label: 'CVE id', required: true, placeholder: 'CVE-2024-3094' },
    { key: 'scan_id', label: 'Scan id', required: false, placeholder: 'optional' },
    { key: 'package', label: 'Package', required: false, placeholder: 'optional' },
  ],
  report: [{ key: 'cve', label: 'CVE id', required: true, placeholder: 'CVE-2024-3094' }],
  nl_query: [{ key: 'question', label: 'Question', required: true, placeholder: 'Which hosts run a known-compromised package?' }],
};

const SCENARIO_BLURB: Record<string, string> = {
  correlate: 'Reconcile a CVE across OSV/NVD/Trivy and decide a canonical severity.',
  triage: 'Judge whether a finding is reachable / a false positive.',
  campaign: 'Estimate supply-chain compromise propagation from an exposure.',
  remediate: 'Produce a fix plan (fixed version, upgrade path, dependents).',
  verify: 'Adversarially validate a finding — try to refute it (false-positive check).',
  report: 'Produce a CVE-grade structured report (severity, attack chain, remediation).',
  nl_query: 'Ask a free-form security question about your assets.',
};

function statusTone(s: string): 'critical' | 'high' | 'medium' | 'low' {
  if (s === 'completed') return 'low';
  if (s === 'failed' || s === 'timeout') return 'critical';
  return 'medium';
}

export function IntelView() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [scenario, setScenario] = useState('');
  const [params, setParams] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [outcome, setOutcome] = useState<IntelRunOutcome | null>(null);

  useEffect(() => {
    let active = true;
    api.intelScenarios()
      .then((r) => {
        if (!active) return;
        setEnabled(r.enabled);
        setScenarios(r.scenarios || []);
        if ((r.scenarios || []).length) setScenario(r.scenarios[0]);
      })
      .catch(() => { if (active) setEnabled(false); });
    return () => { active = false; };
  }, []);

  const fields = SCENARIO_PARAMS[scenario] || [];

  const run = useCallback(() => {
    setError('');
    setOutcome(null);
    for (const f of fields) {
      if (f.required && !(params[f.key] || '').trim()) {
        setError(`${f.label} is required`);
        return;
      }
    }
    setRunning(true);
    api.runIntel(scenario, params)
      .then((o) => { setOutcome(o); setRunning(false); })
      .catch((e) => { setError(e instanceof Error ? e.message : 'Run failed'); setRunning(false); });
  }, [scenario, params, fields]);

  if (enabled === null) return <Loading />;

  return (
    <>
      <h1 style={{ marginBottom: '0.25rem' }}><Icon name="ai-triage" size={20} /> Security Intelligence</h1>
      <p className="muted" style={{ marginBottom: '1.5rem' }}>Run an agentic scenario over your security data via the jikji backbone. Every run is audited.</p>

      {!enabled && (
        <EmptyState message="Intelligence backbone not configured — set BONGSU_INTEL_JIKJI_URL to point at a jikji server to enable scenario runs." />
      )}

      {enabled && (
        <div className="card" style={{ display: 'grid', gap: 12, maxWidth: 720 }}>
          <label className="field">
            <span>Scenario</span>
            <select value={scenario} onChange={(e) => { setScenario(e.target.value); setParams({}); setOutcome(null); }}>
              {scenarios.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          {scenario && <p className="muted" style={{ margin: 0 }}>{SCENARIO_BLURB[scenario]}</p>}
          {fields.map((f) => (
            <label className="field" key={f.key}>
              <span>{f.label}{f.required && ' *'}</span>
              <input
                value={params[f.key] || ''}
                placeholder={f.placeholder}
                onChange={(e) => setParams((p) => ({ ...p, [f.key]: e.target.value }))}
              />
            </label>
          ))}
          <div>
            <button className="btn btn-primary" disabled={running || !scenario} onClick={run}>
              {running ? 'Running…' : 'Run scenario'}
            </button>
          </div>
          {error && <div className="banner banner-error">{error}</div>}
        </div>
      )}

      {outcome && (
        <div className="card" style={{ marginTop: 16, maxWidth: 720 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
            <Badge tone={statusTone(outcome.status)}>{outcome.status}</Badge>
            <span className="muted">{outcome.tool_steps} tool calls · {outcome.total_tokens} tokens · run {outcome.run_id.slice(0, 8)}</span>
          </div>
          <pre className="codeblock" style={{ whiteSpace: 'pre-wrap', maxHeight: 480, overflow: 'auto' }}>{outcome.response}</pre>
        </div>
      )}
    </>
  );
}
