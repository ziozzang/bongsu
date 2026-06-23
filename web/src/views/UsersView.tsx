import { useState, useEffect, useCallback } from 'react';
import { api, type LocalUser } from '../api';
import { DataTable } from '../components/DataTable';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function UsersView() {
  const [users, setUsers] = useState<LocalUser[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('viewer');
  const [resetId, setResetId] = useState('');
  const [resetPassword, setResetPassword] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.listUsers()
      .then(r => { setUsers(r.users || []); setLoading(false); })
      .catch(err => { setError(err instanceof Error ? err.message : 'Failed to load users'); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    setMsg('');
    if (!newUsername.trim()) { setMsg('Username is required'); return; }
    try {
      await api.createUser({ username: newUsername.trim(), password: newPassword, role: newRole });
      setMsg('User created');
      setNewUsername('');
      setNewPassword('');
      setNewRole('viewer');
      load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to create user');
    }
  };

  const handleToggleRole = async (u: LocalUser) => {
    setMsg('');
    const nextRole = u.role === 'admin' ? 'viewer' : 'admin';
    try {
      await api.updateUserRole(u.id, nextRole);
      setMsg(`${u.username} is now ${nextRole}`);
      load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to change role');
    }
  };

  const handleReset = async (u: LocalUser) => {
    setMsg('');
    try {
      const r = await api.resetUserPassword(u.id, resetPassword);
      setMsg(`Password reset for ${u.username} — sessions revoked: ${r.sessions_revoked}`);
      setResetId('');
      setResetPassword('');
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to reset password');
    }
  };

  const handleDelete = async (u: LocalUser) => {
    if (!confirm(`Delete user ${u.username}? This cannot be undone.`)) return;
    setMsg('');
    try {
      await api.deleteUser(u.id);
      setMsg(`User ${u.username} deleted`);
      load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Users</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create User</h2></div>
        <div className="filters">
          <input type="text" placeholder="Username" value={newUsername} onChange={(e) => setNewUsername(e.target.value)} />
          <input type="password" placeholder="Password (min 12 chars)" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} style={{ minWidth: 200 }} />
          <select value={newRole} onChange={(e) => setNewRole(e.target.value)}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
          <div className="filter-actions">
            {msg && <span className="result-count" style={{ color: /revoked|created|deleted|now/.test(msg) ? 'var(--low)' : 'var(--critical)' }}>{msg}</span>}
            <button className="btn btn-primary" onClick={handleCreate}>Create</button>
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><h2>Users</h2></div>
        <DataTable<LocalUser>
          rows={users}
          loading={loading}
          error={error || null}
          onRetry={load}
          rowKey={(u) => u.id}
          empty="No users yet — create one above. Admins manage the console; viewers have read-only access."
          columns={[
            { key: 'username', header: 'Username', render: (u) => u.username },
            { key: 'role', header: 'Role', render: (u) => <span className={`badge ${u.role === 'admin' ? 'badge-high' : ''}`}>{u.role}</span> },
            { key: 'created', header: 'Created', className: 'mono', render: (u) => <span title={formatDateTimeFull(u.created_at)}>{formatDateTime(u.created_at)}</span> },
            { key: 'updated', header: 'Updated', className: 'mono', render: (u) => <span title={formatDateTimeFull(u.updated_at)}>{formatDateTime(u.updated_at)}</span> },
            { key: 'actions', header: 'Actions', render: (u) => (
              <div style={{ display: 'flex', gap: '0.375rem', alignItems: 'center', flexWrap: 'wrap' }}>
                <button className="btn btn-secondary btn-sm" onClick={() => handleToggleRole(u)}>
                  Make {u.role === 'admin' ? 'viewer' : 'admin'}
                </button>
                {resetId === u.id ? (
                  <>
                    <input type="password" placeholder="New password" value={resetPassword} onChange={(e) => setResetPassword(e.target.value)} style={{ height: '1.75rem', width: 150 }} />
                    <button className="btn btn-primary btn-sm" onClick={() => handleReset(u)}>Save</button>
                    <button className="btn btn-secondary btn-sm" onClick={() => { setResetId(''); setResetPassword(''); }}>Cancel</button>
                  </>
                ) : (
                  <button className="btn btn-secondary btn-sm" onClick={() => { setResetId(u.id); setResetPassword(''); setMsg(''); }}>Reset password</button>
                )}
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(u)}>Delete</button>
              </div>
            ) },
          ]}
        />
      </div>
    </>
  );
}

