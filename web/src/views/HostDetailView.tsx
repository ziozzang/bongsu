import React, { useCallback,useEffect,useState } from 'react';
import { api, type Host, type ProcessSnapshot, type PortInfo, type Vuln, type Pkg, type UserAccount } from '../api';
import { Loading } from '../components/primitives';
import { Pager } from '../components/controls';
import { CvssTooltip } from '../components/CvssTooltip';
import { FactsCard } from '../components/FactsCard';
import { agentStatusColor } from '../lib/severity';
import { formatAge } from '../lib/format';

export function HostDetailView({ hostId, onBack, onSelectVuln }: { hostId: string; onBack: () => void; onSelectVuln?: (v: Vuln) => void }) {
  const [host, setHost] = useState<Host | null>(null);
  const [vulnCounts, setVulnCounts] = useState<Record<string, number>>({});
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [pkgPage, setPkgPage] = useState(0);
  const [users, setUsers] = useState<UserAccount[]>([]);
  const [totalUsers, setTotalUsers] = useState(0);
  const [processes, setProcesses] = useState<ProcessSnapshot[]>([]);
  const [totalProcesses, setTotalProcesses] = useState(0);
  const [ports, setPorts] = useState<PortInfo[]>([]);
  const [totalPorts, setTotalPorts] = useState(0);
  const [exportMsg, setExportMsg] = useState('');
  const [metadata, setMetadata] = useState({ owner: '', team: '', environment: '', criticality: '', tags: '{}' });
  const [metadataMsg, setMetadataMsg] = useState('');
  const [agentTokenMsg, setAgentTokenMsg] = useState('');
  const limit = 50;

  // Escape returns to the host list (matches dialog dismissal feel).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      const t = e.target as HTMLElement | null;
      if (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
      onBack();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onBack]);

  useEffect(() => {
    api.host(hostId).then(h => {
      setHost(h);
      setMetadata({
        owner: h.owner || '',
        team: h.team || '',
        environment: h.environment || '',
        criticality: h.criticality || '',
        tags: h.tags || '{}',
      });
    }).catch(() => {});
    api.hostVulnCounts(hostId).then(setVulnCounts).catch(() => {});
  }, [hostId]);

  const loadPkgs = useCallback((page: number) => {
    api.hostPackages(hostId, limit, page * limit).then(r => { setPkgs(r.items || []); setTotalPkgs(r.total); setPkgPage(page); }).catch(() => {});
  }, [hostId]);

  useEffect(() => { loadPkgs(0); }, [loadPkgs]);

  useEffect(() => {
    api.hostUsers(hostId, 20, 0).then(r => { setUsers(r.items || []); setTotalUsers(r.total || 0); }).catch(() => {});
    api.hostProcesses(hostId, 20, 0).then(r => { setProcesses(r.items || []); setTotalProcesses(r.total || 0); }).catch(() => {});
    api.hostPorts(hostId, 20, 0).then(r => { setPorts(r.items || []); setTotalPorts(r.total || 0); }).catch(() => {});
  }, [hostId]);

  if (!host) return <Loading />;

  const saveMetadata = async () => {
    setMetadataMsg('Saving...');
    try {
      JSON.parse(metadata.tags || '{}');
      const updated = await api.updateHostMetadata(host.id, metadata);
      setHost(updated);
      setMetadataMsg('Saved');
    } catch {
      setMetadataMsg('Save failed');
    }
  };

  const resetAgentToken = async () => {
    if (!confirm(`Reset agent token binding for ${host.hostname}? The next valid agent check-in will bind a new token.`)) return;
    setAgentTokenMsg('Resetting...');
    try {
      await api.resetHostAgentToken(host.id);
      setHost({ ...host, agent_token_set: false });
      setAgentTokenMsg('Agent token reset');
    } catch {
      setAgentTokenMsg('Reset failed');
    }
  };

  return (
    <>
      <button className="back-btn" onClick={onBack}>&larr; Back</button>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', marginBottom: '1rem' }}>
        <h1 style={{ marginBottom: 0 }}>{host.hostname}</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          {exportMsg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{exportMsg}</span>}
          <button
            className="filter-btn"
            onClick={async () => {
              setExportMsg('Exporting...');
              try {
                await api.exportHostSBOM(host.id, host.hostname, 'cyclonedx');
                setExportMsg('CycloneDX exported');
              } catch {
                setExportMsg('Export failed');
              }
            }}
          >
            CycloneDX
          </button>
          <button
            className="filter-btn"
            onClick={async () => {
              setExportMsg('Exporting...');
              try {
                await api.exportHostSBOM(host.id, host.hostname, 'spdx');
                setExportMsg('SPDX exported');
              } catch {
                setExportMsg('Export failed');
              }
            }}
          >
            SPDX
          </button>
        </div>
      </div>

      <div className="stats-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: agentStatusColor(host.agent_status) }} />
          <div className="label">Agent</div>
          <div style={{ fontSize: '0.875rem', color: agentStatusColor(host.agent_status), fontWeight: 700, textTransform: 'uppercase' }}>{host.agent_status || 'unknown'}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>{formatAge(host.last_seen_age_seconds)} since check-in</div>
        </div>
        <div className="stat-card"><div className="label">Agent Version</div><div className="mono" style={{ fontSize: '0.875rem' }}>{host.agent_version || '-'}</div></div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: host.agent_token_set ? 'var(--low)' : 'var(--medium)' }} />
          <div className="label">Agent Trust</div>
          <div style={{ fontSize: '0.875rem', color: host.agent_token_set ? 'var(--low)' : 'var(--medium)', fontWeight: 700, textTransform: 'uppercase' }}>{host.agent_token_set ? 'bound' : 'pending bind'}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>token hash is never exposed</div>
        </div>
        <div className="stat-card"><div className="label">OS</div><div style={{ fontSize: '0.875rem' }}>{host.os_name} {host.os_version}</div></div>
        <div className="stat-card"><div className="label">Kernel</div><div className="mono" style={{ fontSize: '0.875rem' }}>{host.kernel}</div></div>
        <div className="stat-card"><div className="label">CPU</div><div style={{ fontSize: '0.875rem' }}>{host.cpu_cores} cores</div></div>
        <div className="stat-card"><div className="label">Memory</div><div style={{ fontSize: '0.875rem' }}>{(host.memory_mb / 1024).toFixed(1)} GB</div></div>
        <div className="stat-card"><div className="label">Owner</div><div style={{ fontSize: '0.875rem' }}>{host.owner || '-'}</div></div>
        <div className="stat-card"><div className="label">Environment</div><div style={{ fontSize: '0.875rem' }}>{host.environment || '-'}</div></div>
        <div className="stat-card"><div className="label">Critical</div><div className="value" style={{ color: 'var(--critical)', fontSize: '1.25rem' }}>{vulnCounts.CRITICAL || 0}</div></div>
        <div className="stat-card"><div className="label">High</div><div className="value" style={{ color: 'var(--high)', fontSize: '1.25rem' }}>{vulnCounts.HIGH || 0}</div></div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
          <h2>Asset Metadata</h2>
        </div>
        <div className="filters">
          <input type="text" placeholder="Owner" value={metadata.owner} onChange={(e) => setMetadata({ ...metadata, owner: e.target.value })} />
          <input type="text" placeholder="Team" value={metadata.team} onChange={(e) => setMetadata({ ...metadata, team: e.target.value })} />
          <select value={metadata.environment} onChange={(e) => setMetadata({ ...metadata, environment: e.target.value })}>
            <option value="">Environment</option>
            <option value="production">Production</option>
            <option value="staging">Staging</option>
            <option value="development">Development</option>
            <option value="test">Test</option>
          </select>
          <select value={metadata.criticality} onChange={(e) => setMetadata({ ...metadata, criticality: e.target.value })}>
            <option value="">Criticality</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <input type="text" placeholder='Tags JSON, e.g. {"service":"api"}' value={metadata.tags} onChange={(e) => setMetadata({ ...metadata, tags: e.target.value })} style={{ minWidth: 260 }} />
          <button className="filter-btn" onClick={saveMetadata}>Save</button>
          {metadataMsg && <span style={{ color: metadataMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>{metadataMsg}</span>}
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
          <h2>Agent Trust</h2>
        </div>
        <div className="filters">
          <button className="btn btn-secondary" onClick={resetAgentToken}>Reset Agent Token</button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Current binding: {host.agent_token_set ? 'bound to this host' : 'waiting for next valid agent token'}
          </span>
          {agentTokenMsg && <span style={{ color: agentTokenMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>{agentTokenMsg}</span>}
        </div>
      </div>

      <FactsCard title="System Facts" facts={host.facts} collectedAt={host.facts_collected_at} />

      <div className="split-grid" style={{ marginBottom: '1rem' }}>
        <div className="card">
          <div className="card-header"><h2>Users ({totalUsers})</h2></div>
          <table>
            <thead><tr><th>User</th><th>UID</th><th>GID</th><th>Shell</th></tr></thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id || `${u.username}-${u.uid}`}>
                  <td className="mono">{u.username}</td><td>{u.uid}</td><td>{u.gid}</td><td className="mono">{u.shell || '-'}</td>
                </tr>
              ))}
              {users.length === 0 && <tr className="empty-row"><td colSpan={4}>No user inventory</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="card">
          <div className="card-header"><h2>Listening Ports ({totalPorts})</h2></div>
          <table>
            <thead><tr><th>Port</th><th>Protocol</th><th>Process</th><th>Address</th></tr></thead>
            <tbody>
              {ports.map(p => (
                <tr key={p.id || `${p.protocol}-${p.address}-${p.port}`}>
                  <td className="mono">{p.port}</td><td>{p.protocol}</td><td className="mono">{p.name || p.pid || '-'}</td><td className="mono">{p.address || '-'}</td>
                </tr>
              ))}
              {ports.length === 0 && <tr className="empty-row"><td colSpan={4}>No port inventory</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="card-header">
          <h2>Top Processes ({totalProcesses})</h2>
        </div>
        <table>
          <thead>
            <tr><th>PID</th><th>Name</th><th>User</th><th>CPU</th><th>Mem</th><th>Command</th></tr>
          </thead>
          <tbody>
            {processes.map(p => (
              <tr key={p.id || `${p.pid}-${p.name}`}>
                <td className="mono">{p.pid}</td>
                <td className="mono">{p.name}</td>
                <td>{p.user || '-'}</td>
                <td className="mono">{p.cpu_usage.toFixed(1)}%</td>
                <td className="mono">{p.mem_usage.toFixed(1)}%</td>
                <td className="mono" style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.cmdline || '-'}</td>
              </tr>
            ))}
            {processes.length === 0 && <tr className="empty-row"><td colSpan={6}>No process inventory</td></tr>}
          </tbody>
        </table>
      </div>

      <div className="card">
        <div className="card-header">
          <h2>Packages ({totalPkgs})</h2>
        </div>
        <table>
          <thead>
            <tr><th>Name</th><th>Version</th><th>Type</th><th>Source</th><th>Container</th><th>CVSS</th><th>Vulns</th></tr>
          </thead>
          <tbody>
            {pkgs.map(p => (
              <tr key={p.id}>
                <td className="mono">{p.name}</td>
                <td className="mono">{p.version}</td>
                <td>{p.pkg_type}</td>
                <td>{p.source}</td>
                <td>{p.container || '-'}</td>
                <td className="mono"><CvssTooltip pkgId={p.id} score={p.max_cvss} onSelectVuln={onSelectVuln} /></td>
                <td style={{ fontWeight: p.vuln_count > 0 ? 600 : 400 }}>{p.vuln_count || 0}</td>
              </tr>
            ))}
          </tbody>
        </table>
        <Pager page={pkgPage} limit={limit} total={totalPkgs} onPage={loadPkgs} />
      </div>
    </>
  );
}
