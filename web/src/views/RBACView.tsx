import { useState, useEffect, useCallback } from 'react';
import { api, type AccessSubject, type AccessPolicy, type AccessControlStatus } from '../api';
import { Loading } from '../components/primitives';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

function accessSubjectRef(subject: AccessSubject): string {
  return `${subject.subject_type}:${subject.external_id}`;
}

export function RBACView() {
  const [subjects, setSubjects] = useState<AccessSubject[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
  const [rbacStatus, setRbacStatus] = useState<AccessControlStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState('');
  const [subjectType, setSubjectType] = useState('user');
  const [externalID, setExternalID] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [policySubjectID, setPolicySubjectID] = useState('');
  const [resourceType, setResourceType] = useState('host');
  const [resourceID, setResourceID] = useState('');
  const [permission, setPermission] = useState('read');
  const [subjectFilter, setSubjectFilter] = useState('');

  const load = useCallback((filter = '') => {
    setLoading(true);
    setMessage('');
    Promise.all([
      api.rbacSubjects(),
      api.rbacPolicies(filter ? { subject_external_id: filter } : undefined),
      api.rbacStatus(),
    ])
      .then(([s, p, status]) => {
        setSubjects(s.items || []);
        setPolicies(p.items || []);
        setRbacStatus(status);
        setLoading(false);
      })
      .catch(() => {
        setMessage('RBAC management requires an admin API key');
        setLoading(false);
      });
  }, []);

  useEffect(() => { load(); }, [load]);

  const saveSubject = () => {
    if (!externalID.trim()) {
      setMessage('external_id is required');
      return;
    }
    api.upsertRbacSubject({ subject_type: subjectType, external_id: externalID.trim(), display_name: displayName.trim() })
      .then(() => {
        setMessage('Subject saved');
        setExternalID('');
        setDisplayName('');
        load();
      })
      .catch(() => setMessage('Failed to save subject'));
  };

  const savePolicy = () => {
    const subject = policySubjectID.trim();
    if (!subject || !resourceType) {
      setMessage('subject and resource type are required');
      return;
    }
    api.upsertRbacPolicy({ subject_id: subject, resource_type: resourceType, resource_id: resourceID.trim() || '*', permission })
      .then(() => {
        setMessage('Policy saved');
        setResourceID('');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to save policy. Create the subject first.'));
  };

  const deleteSubject = (subject: AccessSubject) => {
    if (!confirm(`Revoke subject ${subject.subject_type}/${subject.external_id} and all attached policies?`)) return;
    api.deleteRbacSubject(subject.id)
      .then(() => {
        setMessage('Subject revoked');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to revoke subject'));
  };

  const deletePolicy = (policy: AccessPolicy) => {
    if (!confirm(`Revoke ${policy.permission} on ${policy.resource_type}/${policy.resource_id || '*'} for ${policy.subject_type}/${policy.subject_external_id}?`)) return;
    api.deleteRbacPolicy(policy.id)
      .then(() => {
        setMessage('Policy revoked');
        load(subjectFilter);
      })
      .catch(() => setMessage('Failed to revoke policy'));
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>RBAC</h1>
      {rbacStatus && (
        <div className="db-status-bar" style={{ marginBottom: '1rem' }}>
          <h3>Access Control</h3>
          <span className={`status-dot ${rbacStatus.status === 'ok' ? 'ready' : 'not-ready'}`}>
            RBAC: {rbacStatus.status}
          </span>
          <span className={`status-dot ${rbacStatus.auth?.web_auth_enabled ? 'ready' : 'not-ready'}`}>
            Web auth: {rbacStatus.auth?.web_auth_enabled ? 'on' : 'off'}
          </span>
          <span className={`status-dot ${(rbacStatus.auth?.viewer_key_count || 0) > 0 ? 'ready' : 'not-ready'}`}>
            Viewer keys: {(rbacStatus.auth?.viewer_key_count || 0).toLocaleString()}
          </span>
          <span className={`status-dot ${rbacStatus.auth?.oidc_configured ? 'ready' : 'not-ready'}`}>
            OIDC: {rbacStatus.auth?.oidc_configured ? 'on' : 'off'}
          </span>
          {rbacStatus.auth?.oidc_configured && (
            <span className={`status-dot ${rbacStatus.auth.oidc_jwks_configured ? 'ready' : 'not-ready'}`}>
              JWKS: {rbacStatus.auth.oidc_jwks_configured ? 'set' : 'missing'}
            </span>
          )}
          <span className={`status-dot ${rbacStatus.auth?.trusted_identity_configured ? 'ready' : 'not-ready'}`}>
            Trusted identity: {rbacStatus.auth?.trusted_identity_configured ? 'on' : 'off'}
          </span>
          {rbacStatus.auth?.trusted_identity_configured && (
            <span className={`status-dot ${(rbacStatus.auth.trusted_proxy_cidr_count || 0) > 0 ? 'ready' : 'not-ready'}`}>
              Proxy CIDRs: {(rbacStatus.auth.trusted_proxy_cidr_count || 0).toLocaleString()}
            </span>
          )}
          {rbacStatus.auth?.trusted_identity_configured && (
            <span className={`status-dot ${rbacStatus.auth.trusted_identity_admin_configured ? 'ready' : 'not-ready'}`}>
              Trusted admins: {((rbacStatus.auth.trusted_admin_user_count || 0) + (rbacStatus.auth.trusted_admin_group_count || 0)).toLocaleString()}
            </span>
          )}
          {rbacStatus.warnings && rbacStatus.warnings.length > 0 && (
            <span style={{ color: 'var(--medium)', fontSize: '0.8125rem' }}>{rbacStatus.warnings.slice(0, 2).join('; ')}</span>
          )}
        </div>
      )}
      <div className="grid-2" style={{ marginBottom: '1rem' }}>
        <div className="card" style={{ padding: '1rem' }}>
          <div className="card-header"><h2>Subject</h2></div>
          <div className="filters">
            <select value={subjectType} onChange={(e) => setSubjectType(e.target.value)}>
              <option value="user">User</option>
              <option value="group">Group</option>
            </select>
            <input type="text" placeholder="external_id" value={externalID} onChange={(e) => setExternalID(e.target.value)} />
            <input type="text" placeholder="Display name" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
            <button className="filter-btn" onClick={saveSubject}>Save Subject</button>
          </div>
        </div>
        <div className="card" style={{ padding: '1rem' }}>
          <div className="card-header"><h2>Policy</h2></div>
          <div className="filters">
            <select value={policySubjectID} onChange={(e) => setPolicySubjectID(e.target.value)}>
              <option value="">Select Subject</option>
              {subjects.map(s => <option key={s.id} value={s.id}>{s.subject_type}/{s.external_id}</option>)}
            </select>
            <datalist id="rbac-subjects">{subjects.map(s => <option key={s.id} value={accessSubjectRef(s)} />)}</datalist>
            <select value={resourceType} onChange={(e) => setResourceType(e.target.value)}>
              <option value="host">Host</option>
              <option value="container">Container</option>
              <option value="image">Image</option>
              <option value="asset_group">Asset Group</option>
              <option value="all">All</option>
            </select>
            <input type="text" placeholder={resourceType === 'asset_group' ? 'team:platform or tag:service=api' : 'resource_id or *'} value={resourceID} onChange={(e) => setResourceID(e.target.value)} />
            <select value={permission} onChange={(e) => setPermission(e.target.value)}>
              <option value="read">Read</option>
              <option value="export">Export</option>
              <option value="write">Write</option>
              <option value="admin">Admin</option>
            </select>
            <button className="filter-btn" onClick={savePolicy}>Save Policy</button>
          </div>
        </div>
      </div>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input list="rbac-subjects" type="text" placeholder="Filter by user:alice or group:platform" value={subjectFilter} onChange={(e) => setSubjectFilter(e.target.value)} />
          <div className="filter-actions">
            <span className="result-count" style={{ color: message.startsWith('Failed') || message.includes('requires') || message.includes('required') ? 'var(--critical)' : 'var(--text-muted)' }}>
              {message || `${subjects.length} subjects / ${policies.length} policies`}
            </span>
            <button className="btn btn-primary" onClick={() => load(subjectFilter)}>Search</button>
            <button className="btn btn-secondary" onClick={() => { setSubjectFilter(''); load(''); }}>Clear</button>
          </div>
        </div>
      </div>
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h2>Subjects</h2></div>
          {loading ? <Loading /> : (
            <table>
              <thead><tr><th>Type</th><th>External ID</th><th>Name</th><th>Updated</th><th></th></tr></thead>
              <tbody>
                {subjects.map(s => (
                  <tr key={s.id}>
                    <td><span className="badge">{s.subject_type}</span></td>
                    <td className="mono">{s.external_id}</td>
                    <td>{s.display_name || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(s.updated_at)}>{formatDateTime(s.updated_at)}</td>
                    <td><button className="delete-btn" onClick={() => deleteSubject(s)}>Revoke</button></td>
                  </tr>
                ))}
                {subjects.length === 0 && <tr className="empty-row"><td colSpan={5}>No subjects yet — add a user, group, or token above before granting it policies.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
        <div className="card">
          <div className="card-header"><h2>Policies</h2></div>
          {loading ? <Loading /> : (
            <table>
              <thead><tr><th>Subject</th><th>Resource</th><th>Permission</th><th>Created</th><th></th></tr></thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id}>
                    <td>{p.subject_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.subject_external_id}</div></td>
                    <td>{p.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.resource_id || '*'}</div></td>
                    <td><span className="badge">{p.permission}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(p.created_at)}>{formatDateTime(p.created_at)}</td>
                    <td><button className="delete-btn" onClick={() => deletePolicy(p)}>Revoke</button></td>
                  </tr>
                ))}
                {policies.length === 0 && <tr className="empty-row"><td colSpan={5}>No policies yet — grant a subject a permission on a resource above. With none defined, default role access applies.</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

