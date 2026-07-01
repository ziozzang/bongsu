import { useState, useEffect, useCallback, useMemo } from 'react';
import { api, type IntelRunOutcome, type IntelPipelineInfo, type IntelPipelineOutcome, type IntelVerificationOutcome } from '../api';
import { Loading, EmptyState, Badge } from '../components/primitives';
import { Icon } from '../components/Icon';

type ParamField = { key: string; label: string; required: boolean; placeholder: string };

// Per-scenario parameter hints — the agent prompt validates required params, so
// the form mirrors what each scenario's BuildPrompt needs.
const SCENARIO_PARAMS: Record<string, ParamField[]> = {
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

// A pipeline's form is the union of its stages' params (all stages share params).
function pipelineFields(scenarios: string[]): ParamField[] {
  const seen = new Set<string>();
  const out: ParamField[] = [];
  for (const s of scenarios) {
    for (const f of SCENARIO_PARAMS[s] || []) {
      if (seen.has(f.key)) continue;
      seen.add(f.key);
      out.push(f);
    }
  }
  return out;
}

function statusTone(s: string): 'critical' | 'high' | 'medium' | 'low' {
  if (s === 'completed' || s === 'complete') return 'low';
  if (s === 'failed' || s === 'timeout') return 'critical';
  return 'medium';
}

function verdictTone(v: string): 'critical' | 'high' | 'medium' | 'low' {
  if (v === 'valid') return 'critical';   // confirmed real finding
  if (v === 'refuted') return 'low';      // likely false positive
  return 'medium';                        // inconclusive
}

export function IntelView() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [mode, setMode] = useState<'scenario' | 'pipeline' | 'verify'>('scenario');
  const [scenarios, setScenarios] = useState<string[]>([]);
  const [pipelines, setPipelines] = useState<IntelPipelineInfo[]>([]);
  const [scenario, setScenario] = useState('');
  const [pipeline, setPipeline] = useState('');
  const [params, setParams] = useState<Record<string, string>>({});
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [outcome, setOutcome] = useState<IntelRunOutcome | null>(null);
  const [pipeOutcome, setPipeOutcome] = useState<IntelPipelineOutcome | null>(null);
  const [verifyOutcome, setVerifyOutcome] = useState<IntelVerificationOutcome | null>(null);
  const [voters, setVoters] = useState(3);

  useEffect(() => {
    let active = true;
    api.intelScenarios()
      .then((r) => {
        if (!active) return;
        setEnabled(r.enabled);
        setScenarios(r.scenarios || []);
        setPipelines(r.pipelines || []);
        if ((r.scenarios || []).length) setScenario(r.scenarios[0]);
        if ((r.pipelines || []).length) setPipeline(r.pipelines[0].name);
      })
      .catch(() => { if (active) setEnabled(false); });
    return () => { active = false; };
  }, []);

  const selectedPipeline = useMemo(() => pipelines.find((p) => p.name === pipeline), [pipelines, pipeline]);
  const fields = mode === 'scenario'
    ? (SCENARIO_PARAMS[scenario] || [])
    : mode === 'verify'
      ? SCENARIO_PARAMS.verify
      : (selectedPipeline ? pipelineFields(selectedPipeline.scenarios) : []);

  const reset = () => { setParams({}); setOutcome(null); setPipeOutcome(null); setVerifyOutcome(null); setError(''); };

  const run = useCallback(() => {
    setError('');
    setOutcome(null);
    setPipeOutcome(null);
    setVerifyOutcome(null);
    for (const f of fields) {
      if (f.required && !(params[f.key] || '').trim()) {
        setError(`${f.label} is required`);
        return;
      }
    }
    setRunning(true);
    const done = () => setRunning(false);
    const fail = (e: unknown) => { setError(e instanceof Error ? e.message : 'Run failed'); done(); };
    if (mode === 'scenario') {
      api.runIntel(scenario, params).then((o) => { setOutcome(o); done(); }).catch(fail);
    } else if (mode === 'pipeline') {
      api.runIntelPipeline(pipeline, params).then((o) => { setPipeOutcome(o); done(); }).catch(fail);
    } else {
      api.runIntelVerify({ cve: params.cve, scan_id: params.scan_id || undefined, package: params.package || undefined, voters })
        .then((o) => { setVerifyOutcome(o); done(); }).catch(fail);
    }
  }, [mode, scenario, pipeline, params, fields, voters]);

  if (enabled === null) return <Loading />;

  return (
    <>
      <h1 style={{ marginBottom: '0.25rem' }}><Icon name="ai-triage" size={20} /> Security Intelligence</h1>
      <p className="muted" style={{ marginBottom: '1.5rem' }}>Run an agentic scenario — or a reviewed pipeline of scenarios — over your security data via the jikji backbone. Every run is audited.</p>

      {!enabled && (
        <EmptyState message="Intelligence backbone not configured — set BONGSU_INTEL_JIKJI_URL to point at a jikji server to enable scenario runs." />
      )}

      {enabled && (
        <div className="card" style={{ display: 'grid', gap: 12, maxWidth: 720 }}>
          <div className="segmented" style={{ display: 'flex', gap: 4 }}>
            <button className={`btn ${mode === 'scenario' ? 'btn-primary' : ''}`} onClick={() => { setMode('scenario'); reset(); }}>Scenario</button>
            <button className={`btn ${mode === 'pipeline' ? 'btn-primary' : ''}`} disabled={!pipelines.length} onClick={() => { setMode('pipeline'); reset(); }}>Pipeline</button>
            <button className={`btn ${mode === 'verify' ? 'btn-primary' : ''}`} onClick={() => { setMode('verify'); reset(); }}>Verify (vote)</button>
          </div>

          {mode === 'scenario' ? (
            <label className="field">
              <span>Scenario</span>
              <select value={scenario} onChange={(e) => { setScenario(e.target.value); reset(); }}>
                {scenarios.map((s) => <option key={s} value={s}>{s}</option>)}
              </select>
            </label>
          ) : (
            <label className="field">
              <span>Pipeline</span>
              <select value={pipeline} onChange={(e) => { setPipeline(e.target.value); reset(); }}>
                {pipelines.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
              </select>
            </label>
          )}

          {mode === 'verify' && (
            <>
              <p className="muted" style={{ margin: 0 }}>Run N independent lens-diverse voters that each try to refute the finding; the verdict is a majority over the successful voters (ties → refuted).</p>
              <label className="field">
                <span>Voters</span>
                <select value={voters} onChange={(e) => setVoters(Number(e.target.value))}>
                  {[1, 3, 5].map((n) => <option key={n} value={n}>{n}</option>)}
                </select>
              </label>
            </>
          )}
          {mode === 'scenario' && scenario && <p className="muted" style={{ margin: 0 }}>{SCENARIO_BLURB[scenario]}</p>}
          {mode === 'pipeline' && selectedPipeline && (
            <p className="muted" style={{ margin: 0 }}>
              {selectedPipeline.description}
              <br />
              <span style={{ fontSize: '0.85em' }}>Stages: {selectedPipeline.scenarios.join(' → ')}</span>
            </p>
          )}

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
            <button className="btn btn-primary" disabled={running || (mode === 'scenario' ? !scenario : mode === 'pipeline' ? !pipeline : false)} onClick={run}>
              {running ? 'Running…' : mode === 'scenario' ? 'Run scenario' : mode === 'pipeline' ? 'Run pipeline' : 'Run verification'}
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

      {verifyOutcome && (
        <div className="card" style={{ marginTop: 16, maxWidth: 720 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
            <Badge tone={verdictTone(verifyOutcome.verdict)}>{verifyOutcome.verdict}</Badge>
            <span className="muted">
              {verifyOutcome.counts.valid}/{verifyOutcome.counts.succeeded} upheld ·
              {' '}{Math.round(verifyOutcome.confidence * 100)}% confidence ·
              {' '}{verifyOutcome.counts.failed > 0 ? `${verifyOutcome.counts.failed} failed · ` : ''}
              {verifyOutcome.status}
            </span>
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            {verifyOutcome.voters.map((v) => (
              <div key={v.index} style={{ borderLeft: '2px solid var(--border, #333)', paddingLeft: 12 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <span className="muted">{v.lens}</span>
                  {v.status === 'success'
                    ? <Badge tone={v.valid ? 'critical' : 'low'}>{v.valid ? 'upheld' : 'refuted'}</Badge>
                    : <Badge tone="medium">failed</Badge>}
                  {v.status === 'success' && <span className="muted" style={{ fontSize: '0.85em' }}>{Math.round((v.confidence || 0) * 100)}%</span>}
                </div>
                {v.refutation && <p className="muted" style={{ margin: '4px 0 0', fontSize: '0.85em' }}>{v.refutation}</p>}
                {v.error && <p className="muted" style={{ margin: '4px 0 0', fontSize: '0.85em', color: 'var(--danger, #c33)' }}>{v.error}</p>}
              </div>
            ))}
          </div>
        </div>
      )}

      {pipeOutcome && (
        <div className="card" style={{ marginTop: 16, maxWidth: 720 }}>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 12 }}>
            <Badge tone={statusTone(pipeOutcome.status)}>{pipeOutcome.status}</Badge>
            <span className="muted">{pipeOutcome.stages.length} stages · session {pipeOutcome.session_id.slice(0, 8)}</span>
          </div>
          <div style={{ display: 'grid', gap: 12 }}>
            {pipeOutcome.stages.map((st, i) => (
              <div key={st.run_id || i} style={{ borderLeft: '2px solid var(--border, #333)', paddingLeft: 12 }}>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 6 }}>
                  <span className="muted">{i + 1}.</span>
                  <strong>{st.scenario}</strong>
                  <Badge tone={statusTone(st.status)}>{st.status}</Badge>
                </div>
                {st.error
                  ? <div className="banner banner-error" style={{ margin: 0 }}>{st.error}</div>
                  : <pre className="codeblock" style={{ whiteSpace: 'pre-wrap', maxHeight: 320, overflow: 'auto', margin: 0 }}>{st.response}</pre>}
              </div>
            ))}
          </div>
        </div>
      )}
    </>
  );
}
