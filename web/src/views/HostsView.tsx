import React, { useState, useEffect, useCallback } from 'react';
import { api, type Host } from '../api';
import { type HostFilters } from '../lib/viewTypes';
import { Loading, LoadError } from '../components/primitives';
import { formatDateTime, formatDateTimeFull, fmtCount, formatAge } from '../lib/format';
import { severityColor, agentStatusColor } from '../lib/severity';

export function HostsView({ initialFilters = {}, onSelectHost }: { initialFilters?: HostFilters; onSelectHost: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [scanMsg, setScanMsg] = useState('');
  const [agentStatus, setAgentStatus] = useState(initialFilters.agent_status || '');
  const [inventoryStatus, setInventoryStatus] = useState(initialFilters.inventory_status || '');
  const [agentVersionState, setAgentVersionState] = useState(initialFilters.agent_version_state || '');
  const [query, setQuery] = useState('');
  const [owner, setOwner] = useState('');
  const [team, setTeam] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const meta = { q: query, owner, team, environment, criticality, os: osFilter };
  const reloadHosts = () => load(agentStatus, inventoryStatus, agentVersionState, meta);
  const load = useCallback((status: string, inventory: string, versionState: string, m: { q: string; owner: string; team: string; environment: string; criticality: string; os: string }) => {
    setLoading(true);
    setLoadError('');
    const params: Record<string, string> = {};
    if (status) params.agent_status = status;
    if (inventory) params.inventory_status = inventory;
    if (versionState) params.agent_version_state = versionState;
    if (m.q) params.q = m.q;
    if (m.owner) params.owner = m.owner;
    if (m.team) params.team = m.team;
    if (m.environment) params.environment = m.environment;
    if (m.criticality) params.criticality = m.criticality;
    if (m.os) params.os = m.os;
    api.hosts(params)
      .then(h => { setHosts(h || []); setLoading(false); })
      .catch((e) => { setLoadError(e instanceof Error ? e.message : 'Failed to load hosts'); setLoading(false); });
  }, []);
  useEffect(() => { load(agentStatus, inventoryStatus, agentVersionState, meta); }, [load, agentStatus, inventoryStatus, agentVersionState]);
  const handleHostSearch = () => load(agentStatus, inventoryStatus, agentVersionState, meta);
  const handleHostKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleHostSearch(); };

  const sevColor = severityColor;

  return (
    <>
      <div className="view-title-row">
        <h1 style={{ marginBottom: 0 }}>Hosts</h1>
        <button
          className="update-btn"
          onClick={async () => {
            setScanMsg('');
            try {
              await api.createScanRequest({ scan_type: 'manual', packages_only: true, reason: 'dashboard all-host force scan' });
              setScanMsg('Force scan requested for all polling agents');
            } catch {
              setScanMsg('Force scan request failed');
            }
          }}
        >
          Force Scan All
        </button>
      </div>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={agentStatus} onChange={(e) => setAgentStatus(e.target.value)}>
            <option value="">All Agent Status</option>
            <option value="online">Online</option>
            <option value="stale">Stale</option>
            <option value="offline">Offline</option>
            <option value="unknown">Unknown</option>
          </select>
          <select value={inventoryStatus} onChange={(e) => setInventoryStatus(e.target.value)}>
            <option value="">All Inventory</option>
            <option value="healthy">Healthy SBOM</option>
            <option value="degraded">Degraded SBOM</option>
            <option value="stale">Stale SBOM</option>
            <option value="empty">Empty SBOM</option>
            <option value="none">No Completed Scan</option>
          </select>
          <select value={agentVersionState} onChange={(e) => setAgentVersionState(e.target.value)}>
            <option value="">All Agent Versions</option>
            <option value="current">Current Agent</option>
            <option value="outdated">Outdated Agent</option>
            <option value="unknown">Unknown Version</option>
          </select>
          <input
            type="text"
            placeholder="Search hostname / IP / OS..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 200 }}
            title="Substring match on hostname, IP, or OS"
          />
          <input
            type="text"
            placeholder="Owner..."
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="Team..."
            value={team}
            onChange={(e) => setTeam(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="Environment..."
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 130 }}
          />
          <input
            type="text"
            placeholder="Criticality..."
            value={criticality}
            onChange={(e) => setCriticality(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 120 }}
          />
          <input
            type="text"
            placeholder="OS (name/version)..."
            value={osFilter}
            onChange={(e) => setOsFilter(e.target.value)}
            onKeyDown={handleHostKeyDown}
            style={{ minWidth: 150 }}
          />
        </div>
        <div className="filter-controls-row">
          <span className="result-count" style={{ whiteSpace: 'normal' }}>
            Agent status uses last_seen; inventory status uses latest completed or degraded scan
          </span>
          <div className="filter-actions">
            <span className="result-count">{hosts.length.toLocaleString()} hosts</span>
            <button className="btn btn-primary" onClick={handleHostSearch}>Search</button>
          </div>
        </div>
      </div>
      {scanMsg && <div style={{ marginBottom: '0.75rem', color: scanMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{scanMsg}</div>}
      <div className="card">
        {loading ? <Loading /> : loadError ? <LoadError message={loadError} onRetry={handleHostSearch} /> : (
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Agent</th>
              <th>Trust</th>
              <th>Version</th>
              <th>OS</th>
              <th>Owner</th>
              <th>Env</th>
              <th>Criticality</th>
              <th>IP</th>
              <th>Latest SBOM</th>
              <th>Active Critical</th>
              <th>Active High</th>
              <th>Active Medium</th>
              <th>Active Low</th>
              <th>Last Seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {hosts.map(h => {
              const counts = h.active_vuln_counts || h.vuln_counts || {};
              return (
                <tr key={h.id}>
                  <td><span className="host-link" title={`IP: ${h.ip_address}`} onClick={() => onSelectHost(h.id)}>{h.hostname}</span></td>
                  <td>
                    <span className="badge" style={{ color: agentStatusColor(h.agent_status), background: 'var(--bg-raised)' }}>{h.agent_status || 'unknown'}</span>
                    <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{formatAge(h.last_seen_age_seconds)}</div>
                  </td>
                  <td>
                    <span className="badge" style={{ color: h.agent_token_set ? 'var(--low)' : 'var(--medium)' }}>
                      {h.agent_token_set ? 'bound' : 'pending'}
                    </span>
                  </td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{h.agent_version || '-'}</td>
                  <td>{h.os_name} {h.os_version}</td>
                  <td>{h.owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{h.environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{h.criticality || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono">{h.ip_address}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>
                    {h.latest_inventory?.latest_scan_id ? (
                      <>
                        {fmtCount(h.latest_inventory.latest_package_count)} pkgs / {fmtCount(h.latest_inventory.latest_vulnerability_count)} vulns / {fmtCount(h.latest_inventory.latest_container_count)} ctrs
                        {h.latest_inventory.latest_scan_status === 'degraded' && <span className="badge" style={{ color: 'var(--medium)', marginLeft: 6 }}>degraded</span>}
                        <div style={{ color: 'var(--text-muted)' }} title={formatDateTimeFull(h.latest_inventory.latest_scan_at)}>{formatDateTime(h.latest_inventory.latest_scan_at)}</div>
                      </>
                    ) : <span style={{ color: 'var(--text-muted)' }}>No completed or degraded scan</span>}
                  </td>
                  <td style={{ color: sevColor('CRITICAL'), fontWeight: 600 }}>{counts.CRITICAL || 0}</td>
                  <td style={{ color: sevColor('HIGH'), fontWeight: 600 }}>{counts.HIGH || 0}</td>
                  <td style={{ color: sevColor('MEDIUM'), fontWeight: 600 }}>{counts.MEDIUM || 0}</td>
                  <td style={{ color: sevColor('LOW'), fontWeight: 600 }}>{counts.LOW || 0}</td>
                  <td className="mono" title={formatDateTimeFull(h.last_seen)}>{formatDateTime(h.last_seen)}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.375rem' }}>
                      <button
                        className="delete-btn"
                        onClick={async (e) => {
                          e.stopPropagation();
                          setScanMsg('');
                          try {
                            await api.createScanRequest({ host_id: h.id, scan_type: 'manual', packages_only: true, reason: `dashboard force scan: ${h.hostname}` });
                            setScanMsg(`Force scan requested for ${h.hostname}`);
                          } catch {
                            setScanMsg(`Force scan request failed for ${h.hostname}`);
                          }
                        }}
                      >
                        Scan
                      </button>
                      <button
                        className="delete-btn"
                        onClick={async (e) => {
                          e.stopPropagation();
                          if (!confirm(`Delete host ${h.hostname} and its collected inventory?`)) return;
                          setScanMsg('');
                          try {
                            await api.deleteHost(h.id);
                            setScanMsg(`Deleted ${h.hostname}`);
                            reloadHosts();
                          } catch {
                            setScanMsg(`Delete failed for ${h.hostname}`);
                          }
                        }}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
            {hosts.length === 0 && <tr className="empty-row"><td colSpan={16}>No hosts match — clear the filters above, or register an agent to start reporting inventory.</td></tr>}
          </tbody>
        </table>
        )}
      </div>
    </>
  );
}
