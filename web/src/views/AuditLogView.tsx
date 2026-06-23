import { useState, useEffect, useCallback } from 'react';
import { api, type AuditLog } from '../api';
import { Loading } from '../components/primitives';
import { Pager } from '../components/controls';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function AuditLogView() {
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
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(item.created_at)}>{formatDateTime(item.created_at)}</td>
                  <td>{item.actor_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.actor_id || '-'}</div></td>
                  <td className="mono">{item.action}</td>
                  <td>{item.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.resource_id || '-'}</div></td>
                  <td><span className="badge">{item.status}</span></td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{item.ip_address || '-'}</td>
                  <td className="path-cell">{JSON.stringify(item.metadata || {})}<span className="path-tip">{JSON.stringify(item.metadata || {}, null, 2)}</span></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No audit events match — clear the filters above. Privileged actions (auth, RBAC, scans) are recorded here.</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, actorType, action, resourceType, status, createdFrom, createdTo, query)} />
      </div>
    </>
  );
}

