import { useState, useEffect, useCallback } from 'react';
import { api, type ApiToken } from '../api';
import { Loading, LoadError } from '../components/primitives';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function ApiTokensView() {
  const [tokens, setTokens] = useState<ApiToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [msg, setMsg] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState('viewer');
  const [subject, setSubject] = useState('');
  const [expiresInDays, setExpiresInDays] = useState('');
  const [secret, setSecret] = useState('');
  const [secretName, setSecretName] = useState('');
  const [copied, setCopied] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.listApiTokens()
      .then(r => { setTokens(r.tokens || []); setLoading(false); })
      .catch(err => { setError(err instanceof Error ? err.message : 'Failed to load API tokens'); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    setMsg('');
    if (!name.trim()) { setMsg('Name is required'); return; }
    if (role === 'viewer' && !subject.trim()) { setMsg('Subject is required for viewer tokens'); return; }
    const days = expiresInDays.trim() ? Number(expiresInDays) : undefined;
    if (days !== undefined && (!Number.isFinite(days) || days < 0)) { setMsg('Expires in days must be a non-negative number'); return; }
    try {
      const r = await api.createApiToken({
        name: name.trim(),
        role,
        subject: role === 'viewer' ? subject.trim() : undefined,
        expires_in_days: days && days > 0 ? days : undefined,
      });
      setSecret(r.secret);
      setSecretName(r.token.name);
      setCopied(false);
      setMsg('Token created');
      setName('');
      setSubject('');
      setExpiresInDays('');
      load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to create token');
    }
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(secret);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  const handleRevoke = async (t: ApiToken) => {
    if (!confirm(`Revoke token "${t.name}"? Clients using it will stop working immediately.`)) return;
    setMsg('');
    try {
      await api.revokeApiToken(t.id);
      setMsg(`Token "${t.name}" revoked`);
      load();
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Failed to revoke token');
    }
  };

  const renderExpires = (t: ApiToken) => {
    if (!t.expires_at) return <span style={{ color: 'var(--text-muted)' }}>never</span>;
    const expired = new Date(t.expires_at).getTime() < Date.now();
    return (
      <span className="mono" style={{ fontSize: '0.75rem', color: expired ? 'var(--critical)' : undefined }} title={formatDateTimeFull(t.expires_at)}>
        {formatDateTime(t.expires_at)}{expired ? ' (expired)' : ''}
      </span>
    );
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>API Tokens</h1>
      {secret && (
        <div className="token-secret-callout" style={{ marginBottom: '1rem' }}>
          <div className="token-secret-warning">Copy this token now — it will not be shown again.</div>
          <div className="token-secret-row">
            <code className="token-secret-value">{secret}</code>
            <button className="btn btn-primary btn-sm" onClick={handleCopy}>{copied ? 'Copied' : 'Copy'}</button>
            <button className="btn btn-secondary btn-sm" onClick={() => { setSecret(''); setCopied(false); }}>Dismiss</button>
          </div>
          <div className="token-secret-meta">Secret for token <strong>{secretName}</strong></div>
        </div>
      )}
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create Token</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
          {role === 'viewer' && (
            <input type="text" placeholder="user:alice or group:platform" value={subject} onChange={(e) => setSubject(e.target.value)} style={{ minWidth: 220 }} />
          )}
          <input type="number" min={0} placeholder="Expires in days (0 = never)" value={expiresInDays} onChange={(e) => setExpiresInDays(e.target.value)} style={{ width: 180 }} />
          <div className="filter-actions">
            {msg && <span className="result-count" style={{ color: /created|revoked/.test(msg) ? 'var(--low)' : 'var(--critical)' }}>{msg}</span>}
            <button className="btn btn-primary" onClick={handleCreate}>Create</button>
          </div>
        </div>
      </div>
      <div className="card">
        <div className="card-header"><h2>Tokens</h2></div>
        {loading ? <Loading /> : error ? <LoadError message={error} onRetry={load} /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Role</th><th>Subject</th><th>Prefix</th><th>Created</th><th>Expires</th><th>Last used</th><th>Status</th><th>Actions</th></tr>
            </thead>
            <tbody>
              {tokens.map(t => {
                const revoked = !!t.revoked_at;
                return (
                  <tr key={t.id} className={revoked ? 'row-dim' : ''}>
                    <td>{t.name}</td>
                    <td><span className={`badge ${t.role === 'admin' ? 'badge-high' : ''}`}>{t.role}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{t.subject || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{t.prefix}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(t.created_at)}>{formatDateTime(t.created_at)}</td>
                    <td>{renderExpires(t)}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }} title={t.last_used_at ? formatDateTimeFull(t.last_used_at) : undefined}>
                      {t.last_used_at ? formatDateTime(t.last_used_at) : <span style={{ color: 'var(--text-muted)' }}>never</span>}
                    </td>
                    <td><span className={`badge ${revoked ? 'badge-unknown' : 'badge-low'}`}>{revoked ? 'revoked' : 'active'}</span></td>
                    <td>
                      <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(t)} disabled={revoked}>Revoke</button>
                    </td>
                  </tr>
                );
              })}
              {tokens.length === 0 && <tr className="empty-row"><td colSpan={9}>No API tokens yet — create one above for programmatic access. The secret is shown only once at creation.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
