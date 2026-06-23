import { useState, useEffect, useCallback } from 'react';
import { api, type AIApproval, type AIPolicyStatus } from '../api';
import { Loading, LoadError, EmptyState, Badge } from '../components/primitives';
import { Icon } from '../components/Icon';
import { aiActionLabel, aiApprovalStatusTone, aiProposedSummary, strField, aiPolicyModeTone, aiPolicyModeBlurb } from '../lib/severity';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function AiApprovalsView() {
  const [approvals, setApprovals] = useState<AIApproval[]>([]);
  const [counts, setCounts] = useState<Record<string, number>>({});
  const [total, setTotal] = useState(0);
  const [policy, setPolicy] = useState<AIPolicyStatus | null>(null);
  const [filter, setFilter] = useState('pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [actingId, setActingId] = useState('');
  const [expanded, setExpanded] = useState('');

  const load = useCallback((status: string) => {
    setLoading(true);
    setError('');
    api.listAiApprovals(status === 'all' ? undefined : status)
      .then(r => {
        setApprovals(r.approvals || []);
        setCounts(r.counts || {});
        setTotal(r.total || 0);
        setLoading(false);
      })
      .catch(err => { setError(err instanceof Error ? err.message : 'Failed to load AI approvals'); setLoading(false); });
  }, []);

  useEffect(() => {
    let active = true;
    api.aiPolicy().then(p => { if (active) setPolicy(p); }).catch(() => { if (active) setPolicy(null); });
    return () => { active = false; };
  }, []);

  useEffect(() => { load(filter); }, [load, filter]);

  const decide = async (a: AIApproval, action: 'approve' | 'reject') => {
    const prompt = action === 'approve'
      ? 'Approve and execute this AI action?'
      : 'Reject this AI action?';
    if (!confirm(prompt)) return;
    setActingId(a.id);
    setMsg('');
    try {
      const r = action === 'approve' ? await api.approveAiApproval(a.id) : await api.rejectAiApproval(a.id);
      setMsg(`${a.subject || a.id} ${r.status || action + 'd'}`);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : `${action} failed`);
    } finally {
      setActingId('');
      load(filter);
    }
  };

  const countEntries = Object.entries(counts).filter(([, n]) => n > 0);

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>AI Approvals</h1>
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
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '0.5rem' }}>
            {aiPolicyModeBlurb(policy.mode)}
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <h2>Approval Queue {total > 0 ? `(${total})` : ''}</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            {msg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{msg}</span>}
            {countEntries.length > 0 && countEntries.map(([s, n]) => (
              <Badge key={s} tone={aiApprovalStatusTone(s)}>{s}: {n}</Badge>
            ))}
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="pending">Pending</option>
              <option value="approved">Approved</option>
              <option value="rejected">Rejected</option>
              <option value="all">All</option>
            </select>
          </div>
        </div>
        {loading ? <Loading /> : error ? <LoadError message={error} onRetry={() => load(filter)} /> : approvals.length === 0 ? (
          <EmptyState message="No AI actions awaiting approval." />
        ) : (
          <table>
            <thead>
              <tr>
                <th>Subject</th>
                <th>Action</th>
                <th>Proposed</th>
                <th>Confidence</th>
                <th>Rule</th>
                <th>Reason</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map(a => {
                const pending = a.status === 'pending';
                const isOpen = expanded === a.id;
                const reasoning = strField(a.context, 'reasoning');
                const decided = a.decided_by || a.decided_at;
                return (
                  <tr key={a.id}>
                    <td className="mono" style={{ fontSize: '0.8125rem' }}>{a.subject || strField(a.proposed, 'vulnerability_id') || '-'}</td>
                    <td><Badge tone="accent">{aiActionLabel(a.action_type)}</Badge></td>
                    <td className="mono" style={{ fontSize: '0.8125rem' }} title={(() => { try { return JSON.stringify(a.proposed); } catch { return ''; } })()}>
                      {aiProposedSummary(a.action_type, a.proposed)}
                    </td>
                    <td className="mono">{Math.round((a.confidence || 0) * 100)}%</td>
                    <td>{a.rule ? <Badge tone="neutral">{a.rule}</Badge> : <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                    <td style={{ maxWidth: 300 }}>
                      {a.reason || reasoning ? (
                        <span
                          title={reasoning || a.reason}
                          onClick={() => setExpanded(isOpen ? '' : a.id)}
                          style={{ cursor: 'pointer', display: 'block', fontSize: '0.8125rem', color: 'var(--text-muted)', whiteSpace: isOpen ? 'normal' : 'nowrap', overflow: isOpen ? 'visible' : 'hidden', textOverflow: 'ellipsis' }}
                        >
                          {a.reason || reasoning}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                    </td>
                    <td><Badge tone={aiApprovalStatusTone(a.status)} dot>{a.status}</Badge></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(a.created_at)}>{formatDateTime(a.created_at)}</td>
                    <td>
                      {pending ? (
                        <div style={{ display: 'flex', gap: '0.375rem' }}>
                          <button className="btn btn-primary btn-sm" onClick={() => decide(a, 'approve')} disabled={actingId === a.id}>
                            {actingId === a.id ? '...' : 'Approve'}
                          </button>
                          <button className="btn btn-secondary btn-sm" onClick={() => decide(a, 'reject')} disabled={actingId === a.id}>
                            Reject
                          </button>
                        </div>
                      ) : decided ? (
                        <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
                          {a.decided_by || 'system'}
                          {a.decided_at ? ` · ${formatDateTime(a.decided_at)}` : ''}
                        </span>
                      ) : <span style={{ color: 'var(--text-muted)' }}>-</span>}
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

