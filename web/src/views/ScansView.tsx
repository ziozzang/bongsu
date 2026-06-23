import { useState, useEffect, useCallback } from 'react';
import { api, type Scan, type ScanRequest } from '../api';
import { type ScanRequestFilters } from '../lib/viewTypes';
import { Loading } from '../components/primitives';
import { Pager } from '../components/controls';
import { formatDateTime, formatDateTimeFull, fmtCount, formatAge } from '../lib/format';

export function ScansView({ initialRequestFilters = {} }: { initialRequestFilters?: ScanRequestFilters }) {
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
                  <td className="mono" title={formatDateTimeFull(req.created_at)}>{formatDateTime(req.created_at)}</td>
                  <td className="mono" style={{ fontSize: '0.75rem', color: req.request_stale ? 'var(--medium)' : 'var(--text-muted)' }}>{formatAge(req.request_age_seconds)}</td>
                  <td><span className="host-link" title={`IP: ${req.host_id ? hostIPMap[req.host_id] || '' : ''}`}>{req.host_id ? hostMap[req.host_id] || req.host_id : 'All polling agents'}</span></td>
                  <td><span className="host-link" title={`IP: ${req.claimed_by_host_id ? hostIPMap[req.claimed_by_host_id] || '' : ''}`}>{req.claimed_by_host_id ? hostMap[req.claimed_by_host_id] || req.claimed_by_host_id : '-'}</span></td>
                  <td>{req.scan_type}</td>
                  <td style={{ color: statusColor(req.status), fontWeight: 600 }}>{req.status}</td>
                  <td>{req.packages_only ? 'packages' : 'full'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.security_db_revision || '-'}</td>
                  <td className="path-cell">{req.reason || req.error_message || '-'}{(req.reason || req.error_message) && <span className="path-tip">{req.reason || req.error_message}</span>}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(req.claimed_at)}>{formatDateTime(req.claimed_at)}</td>
                  <td className="mono" style={{ fontSize: '0.75rem', color: req.claim_stale ? 'var(--medium)' : 'var(--text-muted)' }}>{req.claimed_at ? formatAge(req.claim_age_seconds) : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(req.completed_at)}>{formatDateTime(req.completed_at)}</td>
                  <td>
                    {['pending', 'claimed'].includes(req.status) && <button className="delete-btn" onClick={() => cancelRequest(req.id)}>Cancel</button>}
                    {['failed', 'degraded', 'cancelled'].includes(req.status) && <button className="update-btn" onClick={() => requeueRequest(req)}>Requeue</button>}
                  </td>
                </tr>
              ))}
              {requests.length === 0 && <tr className="empty-row"><td colSpan={13}>No scan requests in the queue — requests appear here when you trigger a scan or a schedule fires.</td></tr>}
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
                  <td className="mono" title={formatDateTimeFull(s.created_at)}>{formatDateTime(s.created_at)}</td>
                  <td><span className="host-link" title={`IP: ${hostIPMap[s.host_id] || ''}`}>{hostMap[s.host_id] || s.host_id}</span></td>
                  <td>{s.scan_type}</td>
                  <td style={{ color: statusColor(s.status), fontWeight: 600 }}>{s.status}</td>
                  <td className="path-cell" style={{ maxWidth: '18rem' }}>{s.error_summary || '-'}{s.error_summary && <span className="path-tip">{s.error_summary}</span>}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{fmtCount(s.package_count)} pkgs / {fmtCount(s.vulnerability_count)} vulns / {fmtCount(s.container_count)} ctrs</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>+{s.packages_added || 0} / -{s.packages_removed || 0} / ~{s.packages_changed || 0}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(s.started_at)}>{formatDateTime(s.started_at)}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(s.finished_at)}>{formatDateTime(s.finished_at)}</td>
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
              {scans.length === 0 && <tr className="empty-row"><td colSpan={10}>No scans recorded yet — completed agent scans appear here. Trigger one from Hosts or a Schedule.</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={load} />
      </div>
    </>
  );
}

