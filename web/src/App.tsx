import React, { useState, useEffect, useCallback } from 'react';
import { api, setApiKey, getApiKey, clearApiKey, onAuthFailure, type Host, type Vuln, type Pkg, type Stats, type FilterOptions, type Scan, type ScanRequest, type HealthStatus, type CveDbEntry, type CveSourceStat, type ContainerAsset, type VulnSummaryRow, type AuditLog, type AccessSubject, type AccessPolicy } from './api';

const verCmp = (a: string, b: string): number => {
  const pa = a.replace(/^v?/, '').split(/[._-]/);
  const pb = b.replace(/^v?/, '').split(/[._-]/);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = parseInt(pa[i] || '0', 10);
    const nb = parseInt(pb[i] || '0', 10);
    if (!isNaN(na) && !isNaN(nb)) { if (na !== nb) return na - nb; }
    else { const c = (pa[i] || '').localeCompare(pb[i] || ''); if (c !== 0) return c; }
  }
  return 0;
};

function agentStatusColor(status?: string) {
  switch (status) {
    case 'online': return 'var(--low)';
    case 'stale': return 'var(--medium)';
    case 'offline': return 'var(--critical)';
    default: return 'var(--text-muted)';
  }
}

function formatAge(seconds?: number) {
  if (seconds === undefined || seconds === null) return '-';
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h`;
  return `${Math.floor(hours / 24)}d`;
}

function dateInputValue(value?: string | null) {
  if (!value) return '';
  return value.slice(0, 10);
}

function parseCvssVector(vector: string) {
  const isV4 = vector.startsWith('CVSS:4.0/');
  const isV3 = vector.startsWith('CVSS:3.');
  const prefix = isV4 ? 'CVSS:4.0/' : isV3 ? vector.substring(0, 10) + '/' : '';
  const clean = vector.replace(prefix, '').replace(/^CVSS:[0-9.]+\//, '');
  const parts = clean.split('/');

  if (isV4) {
    const labels: Record<string, string> = {
      AV: 'Attack Vector', AC: 'Attack Complexity', AT: 'Attack Requirements',
      PR: 'Privileges Required', UI: 'User Interaction', VC: 'Vuln Confidentiality',
      VI: 'Vuln Integrity', VA: 'Vuln Availability', SC: 'Sub Confidentiality',
      SI: 'Sub Integrity', SA: 'Sub Availability', E: 'Exploit Maturity',
    };
    const values: Record<string, Record<string, string>> = {
      AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
      AC: { L: 'Low', H: 'High' },
      AT: { N: 'None', P: 'Present' },
      PR: { N: 'None', L: 'Low', H: 'High' },
      UI: { N: 'None', P: 'Passive', A: 'Active' },
      VC: { N: 'None', L: 'Low', H: 'High' },
      VI: { N: 'None', L: 'Low', H: 'High' },
      VA: { N: 'None', L: 'Low', H: 'High' },
      SC: { N: 'None', L: 'Low', H: 'High' },
      SI: { N: 'None', L: 'Low', H: 'High' },
      SA: { N: 'None', L: 'Low', H: 'High' },
      E: { X: 'Not Defined', A: 'Attacked', P: 'POC', U: 'Unreported' },
    };
    return { version: '4.0', parts, labels, values };
  }

  const labels: Record<string, string> = {
    AV: 'Attack Vector', AC: 'Attack Complexity', PR: 'Privileges Required',
    UI: 'User Interaction', S: 'Scope', C: 'Confidentiality',
    I: 'Integrity', A: 'Availability',
  };
  const values: Record<string, Record<string, string>> = {
    AV: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
    AC: { L: 'Low', H: 'High' },
    PR: { N: 'None', L: 'Low', H: 'High' },
    UI: { N: 'None', R: 'Required' },
    S: { U: 'Unchanged', C: 'Changed' },
    C: { N: 'None', L: 'Low', H: 'High' },
    I: { N: 'None', L: 'Low', H: 'High' },
    A: { N: 'None', L: 'Low', H: 'High' },
  };
  return { version: '3.x', parts, labels, values };
}

type View = 'dashboard' | 'hosts' | 'packages' | 'containers' | 'vulns' | 'vuln-detail' | 'scans' | 'audit' | 'rbac' | 'host-detail' | 'cve-search';

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vuln | null>(null);
  const [authed, setAuthed] = useState(!!getApiKey());
  const [noAuthMode, setNoAuthMode] = useState(false);

  useEffect(() => {
    api.rawHealth().then(h => {
      if (!h.web_auth) { setNoAuthMode(true); setAuthed(true); }
    }).catch(() => {});
    onAuthFailure(() => setAuthed(false));
  }, []);

  if (!authed) return <LoginScreen onLogin={() => setAuthed(true)} />;

  return (
    <div className="layout">
      <Sidebar view={view} onNavigate={setView} onLogout={noAuthMode ? undefined : () => { clearApiKey(); setAuthed(false); }} />
      <div className="main">
        {view === 'dashboard' && <DashboardView />}
        {view === 'hosts' && <HostsView onSelectHost={(id) => { setSelectedHostId(id); setView('host-detail'); }} />}
        {view === 'host-detail' && <HostDetailView hostId={selectedHostId} onBack={() => setView('hosts')} onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'packages' && <PackagesView onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'containers' && <ContainersView />}
        {view === 'cve-search' && <CveSearchView />}
        {view === 'scans' && <ScansView />}
        {view === 'rbac' && <RBACView />}
        {view === 'audit' && <AuditLogView />}
        {view === 'vulns' && <VulnsView onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'vuln-detail' && <VulnDetailView vuln={selectedVuln} onBack={() => setView('vulns')} />}
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  const [key, setKey] = useState('');
  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Bongsu</h2>
        <div className="login-subtitle">Package Vulnerability Monitor</div>
        <input
          type="password"
          placeholder="API Key"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && key) { setApiKey(key); onLogin(); } }}
        />
        <button
          className="login-btn"
          onClick={() => { if (key) { setApiKey(key); onLogin(); } }}
        >
          Connect
        </button>
      </div>
    </div>
  );
}

function Sidebar({ view, onNavigate, onLogout }: { view: View; onNavigate: (v: View) => void; onLogout?: () => void }) {
  const items: [View, string, string][] = [
    ['dashboard', 'Dashboard', '■'],
    ['hosts', 'Hosts', '▣'],
    ['packages', 'Packages', '▦'],
    ['containers', 'Containers', '▤'],
    ['vulns', 'Vulnerabilities', '◆'],
    ['cve-search', 'CVE Search', '◈'],
    ['scans', 'Scan History', '☰'],
    ['rbac', 'RBAC', '◎'],
    ['audit', 'Audit Log', '◇'],
  ];
  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <h1><span className="brand-icon">☀</span> Bongsu</h1>
      </div>
      <nav>
        {items.map(([v, label, icon]) => (
          <a key={v} className={view === v ? 'active' : ''} href="#" onClick={(e) => { e.preventDefault(); onNavigate(v); }}>
            <span className="nav-icon">{icon}</span>
            {label}
          </a>
        ))}
      </nav>
      {onLogout && <a href="#" className="logout" onClick={(e) => { e.preventDefault(); onLogout(); }}><span className="nav-icon">↩</span> Logout</a>}
    </div>
  );
}

function DashboardView() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [dbStatus, setDbStatus] = useState<{ready: boolean; lastUpdate: string | null} | null>(null);
  const [securityDbConfigured, setSecurityDbConfigured] = useState(false);
  const [cveSources, setCveSources] = useState<CveSourceStat[]>([]);
  const [agentCounts, setAgentCounts] = useState<Record<string, number>>({});
  const [inventoryCounts, setInventoryCounts] = useState<Record<string, number>>({});
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [ownerSummary, setOwnerSummary] = useState<VulnSummaryRow[]>([]);
  const [environmentSummary, setEnvironmentSummary] = useState<VulnSummaryRow[]>([]);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [rematching, setRematching] = useState(false);
  const [rematchMsg, setRematchMsg] = useState('');
  const [rematchMinQuality, setRematchMinQuality] = useState('');
  const [retentionMsg, setRetentionMsg] = useState('');
  const [retentionBusy, setRetentionBusy] = useState(false);

  useEffect(() => { api.stats().then(setStats).catch(() => {}); }, []);
  useEffect(() => {
    api.rawHealth().then(h => {
      setDbStatus({ ready: h.trivy_db_ready, lastUpdate: h.trivy_db_last_update || null });
      setSecurityDbConfigured(!!h.security_db?.configured);
    }).catch(() => {});
  }, [updating]);
  useEffect(() => {
    api.cveDbStats().then(r => setCveSources(r.sources || [])).catch(() => {});
    api.packages({ limit: '1' }).then(r => setTotalPkgs(r.total)).catch(() => {});
    api.hosts().then(items => {
      setAgentCounts(items.reduce((acc, h) => {
        const status = h.agent_status || 'unknown';
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>));
    }).catch(() => {});
    Promise.all([
      api.hosts({ inventory_status: 'healthy' }),
      api.hosts({ inventory_status: 'stale' }),
      api.hosts({ inventory_status: 'empty' }),
      api.hosts({ inventory_status: 'none' }),
    ]).then(([healthy, stale, empty, none]) => setInventoryCounts({
      healthy: healthy.length,
      stale: stale.length,
      empty: empty.length,
      none: none.length,
    })).catch(() => {});
    api.vulnSummary({ group_by: 'owner' }).then(r => setOwnerSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'environment' }).then(r => setEnvironmentSummary(r.items || [])).catch(() => {});
  }, []);

  const handleUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.updateTrivyDB();
      setUpdateMsg(r.message || 'Updated');
    } catch {
      setUpdateMsg('Update failed (check server logs)');
    }
    setUpdating(false);
  };

  const handleSecurityUpdate = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      await api.updateSecurityDB();
      setUpdateMsg('Security sources sync started/completed');
      api.cveDbStats().then(r => setCveSources(r.sources || [])).catch(() => {});
    } catch {
      setUpdateMsg('Security source sync failed or is not configured');
    }
    setUpdating(false);
  };

  const handleRematch = async () => {
    setRematching(true);
    setRematchMsg('');
    try {
      const minQuality = Number(rematchMinQuality);
      const body = Number.isFinite(minQuality) && minQuality > 0 ? { min_source_matchable_percent: minQuality } : {};
      const r = await api.rematchCVEs(body);
      const qualityMsg = minQuality > 0 ? ` with source quality >= ${minQuality}%` : '';
      setRematchMsg(`Matched ${r.matched.toLocaleString()} packages${qualityMsg}, found ${r.new_vulns.toLocaleString()} new vulnerabilities (${r.skipped} skipped)`);
      api.stats().then(setStats).catch(() => {});
    } catch {
      setRematchMsg('Rematch failed (check server logs)');
    }
    setRematching(false);
  };

  const handleRetentionPrune = async (dryRun: boolean) => {
    setRetentionBusy(true);
    setRetentionMsg('');
    try {
      const r = await api.pruneRetention({ dry_run: dryRun });
      const affected = r.scans + r.scan_requests + r.audit_logs;
      setRetentionMsg(`${dryRun ? 'Dry run' : 'Pruned'}: ${affected.toLocaleString()} records (${r.scans} scans, ${r.scan_requests} requests, ${r.audit_logs} audit logs)`);
    } catch {
      setRetentionMsg('Retention prune failed or requires admin API key');
    }
    setRetentionBusy(false);
  };

  if (!stats) return <div style={{ color: 'var(--text-muted)', padding: '2rem' }}>Loading...</div>;

  return (
    <>
      <section className="product-intro">
        <div>
          <div className="eyebrow">Self-hosted vulnerability watchtower</div>
          <h1>bongsu</h1>
          <p>
            봉수대처럼 각 호스트와 동작 중인 컨테이너에서 패키지 정보를 모아,
            OS 패키지와 코드 라이브러리를 분리해 CVSS 기반 취약점 데이터베이스와 매칭합니다.
          </p>
        </div>
        <div className="install-box">
          <div className="label">One-line agent install</div>
          <code>curl -fsSL {window.location.origin}/api/install.sh | sudo bash</code>
        </div>
      </section>
      <div className="stats-grid">
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Total Hosts</div>
          <div className="value">{stats.total_hosts}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
          <div className="label">Total Vulnerabilities</div>
          <div className="value">{stats.total_vulnerabilities}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Critical</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.severity_counts.CRITICAL || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High</div>
          <div className="value" style={{ color: 'var(--high)' }}>{stats.severity_counts.HIGH || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Medium</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.severity_counts.MEDIUM || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Low</div>
          <div className="value" style={{ color: 'var(--low)' }}>{stats.severity_counts.LOW || 0}</div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Agents Online</div>
          <div className="value" style={{ color: 'var(--low)' }}>{agentCounts.online || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Agents Stale</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{agentCounts.stale || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Agents Offline</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{agentCounts.offline || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Tracked Packages</div>
          <div className="value">{totalPkgs.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveSources.reduce((s, x) => s + x.count, 0).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE Sources</div>
          <div className="value">{cveSources.length || '-'}</div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Healthy SBOM</div>
          <div className="value" style={{ color: 'var(--low)' }}>{inventoryCounts.healthy || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale SBOM</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{inventoryCounts.stale || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Empty SBOM</div>
          <div className="value" style={{ color: 'var(--high)' }}>{inventoryCounts.empty || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">No Completed Scan</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{inventoryCounts.none || 0}</div>
        </div>
      </div>
      <div className="db-status-bar" style={{ marginTop: '1.5rem' }}>
        <h3>Vulnerability Database</h3>
        <span className={`status-dot ${dbStatus?.ready ? 'ready' : 'not-ready'}`}>
          {dbStatus?.ready ? 'Ready' : 'Not loaded'}
        </span>
        {dbStatus?.lastUpdate && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Updated: {new Date(dbStatus.lastUpdate).toLocaleString()}
          </span>
        )}
        <button
          className="update-btn"
          onClick={handleUpdate}
          disabled={updating}
          style={{ marginLeft: 'auto' }}
        >
          {updating ? 'Updating...' : 'Update Trivy DB'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityUpdate}
          disabled={updating || !securityDbConfigured}
          title={securityDbConfigured ? 'Sync OSV/NVD/Trivy source database' : 'Set BONGSU_SECURITY_DB_SYNC_CMD on the server'}
          style={{ marginLeft: '0.5rem' }}
        >
          Sync Sources
        </button>
        <input
          className="compact-input"
          type="number"
          min="0"
          max="100"
          step="1"
          value={rematchMinQuality}
          onChange={(e) => setRematchMinQuality(e.target.value)}
          placeholder="Min matchable %"
          title="Only use CVE sources whose matchable record ratio is at least this percent"
          style={{ width: '9rem', marginLeft: '0.5rem' }}
        />
        <button
          className="update-btn"
          onClick={handleRematch}
          disabled={rematching}
          style={{ marginLeft: '0.5rem' }}
        >
          {rematching ? 'Matching...' : 'Rematch CVEs'}
        </button>
      </div>
      {updateMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: updateMsg.includes('fail') ? 'var(--critical)' : 'var(--low)' }}>{updateMsg}</div>}
      {rematchMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: rematchMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{rematchMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Operational Retention</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Defaults: scans 180d, requests 90d, audit 365d</span>
        <button className="update-btn" onClick={() => handleRetentionPrune(true)} disabled={retentionBusy} style={{ marginLeft: 'auto' }}>Dry Run</button>
        <button
          className="delete-btn"
          onClick={() => { if (confirm('Prune old scans, completed scan requests, and audit logs using server retention defaults?')) handleRetentionPrune(false); }}
          disabled={retentionBusy}
        >
          Prune
        </button>
      </div>
      {retentionMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: retentionMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{retentionMsg}</div>}
      {(ownerSummary.length > 0 || environmentSummary.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          <SummaryTable title="Owner Remediation Queue" rows={ownerSummary} />
          <SummaryTable title="Environment Risk Queue" rows={environmentSummary} />
        </div>
      )}
      {cveSources.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>CVE Database Sources</h2></div>
          <table>
            <thead><tr><th>Source</th><th>Records</th><th>Matchable</th><th>Ecosystem</th><th>Fixed</th><th>Ranges</th><th>CVSS</th><th>Last Update</th></tr></thead>
            <tbody>
              {cveSources.map(s => (
                <tr key={s.source}>
                  <td><span style={{ fontWeight: 600 }}>{s.source.toUpperCase()}</span></td>
                  <td className="mono">{s.count.toLocaleString()}</td>
                  <td className="mono">{(s.matchable || 0).toLocaleString()}</td>
                  <td className="mono">{(s.with_ecosystem || 0).toLocaleString()}</td>
                  <td className="mono">{(s.with_fixed || 0).toLocaleString()}</td>
                  <td className="mono">{(s.with_ranges || 0).toLocaleString()}</td>
                  <td className="mono">{(s.with_cvss || 0).toLocaleString()}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.last_update ? new Date(s.last_update).toLocaleString() : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="info-card" style={{ marginTop: '1.5rem' }}>
        <div className="info-header">
          <div className="info-icon">🏔</div>
          <div>
            <h3>봉수 (Bongsu)</h3>
            <p>
              봉수대(烽燧臺)에서 이름을 따온 자체 호스팅 패키지 취약점 모니터링 시스템입니다.
              봉수대가 변방의 정보를 중앙으로 전달하듯, Bongsu는 각 호스트와 컨테이너에서 수집한 패키지 정보를 서버로 모아 CVSS 취약점 데이터베이스와 매칭하여 결과를 보여줍니다.
            </p>
            <p>
              Agent가 각 호스트에 설치되어 주기적으로 패키지 목록을 수집하고, 서버에서 Trivy 취약점 데이터베이스를 기반으로 CVE 매칭을 수행합니다.
              검색 결과는 이 대시보드를 통해 호스트, 패키지, 취약점 단위로 조회할 수 있습니다.
            </p>
            <div className="info-links">
              <span><strong>Hosts</strong> — 등록된 호스트 및 취약점 분포</span>
              <span><strong>Packages</strong> — 전체 패키지 검색 및 CVSS 정렬</span>
              <span><strong>Vulnerabilities</strong> — CVE 상세 정보 및 필터링</span>
            </div>
          </div>
        </div>
      </div>
      <div style={{ textAlign: 'right', marginTop: '1rem' }}>
        <a href="https://github.com/ziozzang/bongsu" target="_blank" rel="noopener" style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', textDecoration: 'none' }}>
          github.com/ziozzang/bongsu ↗
        </a>
      </div>
    </>
  );
}

function SummaryTable({ title, rows }: { title: string; rows: VulnSummaryRow[] }) {
  const topRows = rows.slice(0, 8);
  return (
    <div className="card">
      <div className="card-header"><h2>{title}</h2></div>
      <table>
        <thead>
          <tr><th>Group</th><th>Total</th><th>Critical</th><th>High</th><th>Overdue</th></tr>
        </thead>
        <tbody>
          {topRows.map(row => (
            <tr key={row.group}>
              <td>{row.group}</td>
              <td className="mono">{row.total.toLocaleString()}</td>
              <td className="mono" style={{ color: 'var(--critical)', fontWeight: row.severity.CRITICAL ? 700 : 400 }}>{row.severity.CRITICAL || 0}</td>
              <td className="mono" style={{ color: 'var(--high)', fontWeight: row.severity.HIGH ? 700 : 400 }}>{row.severity.HIGH || 0}</td>
              <td className="mono" style={{ color: row.overdue ? 'var(--critical)' : 'var(--text-muted)', fontWeight: row.overdue ? 700 : 400 }}>{row.overdue || 0}</td>
            </tr>
          ))}
          {topRows.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No findings</td></tr>}
        </tbody>
      </table>
    </div>
  );
}

function HostsView({ onSelectHost }: { onSelectHost: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanMsg, setScanMsg] = useState('');
  const [agentStatus, setAgentStatus] = useState('');
  const [inventoryStatus, setInventoryStatus] = useState('');
  const load = useCallback((status: string, inventory: string) => {
    setLoading(true);
    api.hosts({ ...(status ? { agent_status: status } : {}), ...(inventory ? { inventory_status: inventory } : {}) })
      .then(h => { setHosts(h || []); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);
  useEffect(() => { load(agentStatus, inventoryStatus); }, [load, agentStatus, inventoryStatus]);

  if (loading) return <div>Loading...</div>;

  const sevColor = (sev: string) => ({ CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' }[sev] || 'var(--unknown)');

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
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
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
            <option value="stale">Stale SBOM</option>
            <option value="empty">Empty SBOM</option>
            <option value="none">No Completed Scan</option>
          </select>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Agent status uses last_seen; inventory status uses latest completed scan
          </span>
        </div>
      </div>
      {scanMsg && <div style={{ marginBottom: '0.75rem', color: scanMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{scanMsg}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Agent</th>
              <th>OS</th>
              <th>Owner</th>
              <th>Env</th>
              <th>Criticality</th>
              <th>IP</th>
              <th>Latest SBOM</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Last Seen</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {hosts.map(h => (
              <tr key={h.id}>
                <td><span className="host-link" title={`IP: ${h.ip_address}`} onClick={() => onSelectHost(h.id)}>{h.hostname}</span></td>
                <td>
                  <span className="badge" style={{ color: agentStatusColor(h.agent_status), background: 'var(--bg-raised)' }}>{h.agent_status || 'unknown'}</span>
                  <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{formatAge(h.last_seen_age_seconds)}</div>
                </td>
                <td>{h.os_name} {h.os_version}</td>
                <td>{h.owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                <td>{h.environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                <td>{h.criticality || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                <td className="mono">{h.ip_address}</td>
                <td className="mono" style={{ fontSize: '0.75rem' }}>
                  {h.latest_inventory?.latest_scan_id ? (
                    <>
                      {h.latest_inventory.latest_package_count || 0} pkgs / {h.latest_inventory.latest_vulnerability_count || 0} vulns / {h.latest_inventory.latest_container_count || 0} ctrs
                      <div style={{ color: 'var(--text-muted)' }}>{h.latest_inventory.latest_scan_at ? new Date(h.latest_inventory.latest_scan_at).toLocaleString() : '-'}</div>
                    </>
                  ) : <span style={{ color: 'var(--text-muted)' }}>No completed scan</span>}
                </td>
                <td style={{ color: sevColor('CRITICAL'), fontWeight: 600 }}>{h.vuln_counts?.CRITICAL || 0}</td>
                <td style={{ color: sevColor('HIGH'), fontWeight: 600 }}>{h.vuln_counts?.HIGH || 0}</td>
                <td style={{ color: sevColor('MEDIUM'), fontWeight: 600 }}>{h.vuln_counts?.MEDIUM || 0}</td>
                <td style={{ color: sevColor('LOW'), fontWeight: 600 }}>{h.vuln_counts?.LOW || 0}</td>
                <td className="mono">{new Date(h.last_seen).toLocaleString()}</td>
                <td>
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
                </td>
              </tr>
            ))}
            {hosts.length === 0 && <tr><td colSpan={14} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No hosts registered</td></tr>}
          </tbody>
        </table>
      </div>
    </>
  );
}

function HostDetailView({ hostId, onBack, onSelectVuln }: { hostId: string; onBack: () => void; onSelectVuln?: (v: Vuln) => void }) {
  const [host, setHost] = useState<Host | null>(null);
  const [vulnCounts, setVulnCounts] = useState<Record<string, number>>({});
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [pkgPage, setPkgPage] = useState(0);
  const [exportMsg, setExportMsg] = useState('');
  const [metadata, setMetadata] = useState({ owner: '', team: '', environment: '', criticality: '', tags: '{}' });
  const [metadataMsg, setMetadataMsg] = useState('');
  const limit = 50;

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

  if (!host) return <div>Loading...</div>;

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
                await api.exportHostSBOM(host.id, host.hostname);
                setExportMsg('Exported');
              } catch {
                setExportMsg('Export failed');
              }
            }}
          >
            Export SBOM
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
        <div className="pagination">
          <button disabled={pkgPage === 0} onClick={() => loadPkgs(pkgPage - 1)}>Prev</button>
          <span>Page {pkgPage + 1} of {Math.max(1, Math.ceil(totalPkgs / limit))}</span>
          <button disabled={(pkgPage + 1) * limit >= totalPkgs} onClick={() => loadPkgs(pkgPage + 1)}>Next</button>
        </div>
      </div>
    </>
  );
}

function VulnsView({ onSelectVuln }: { onSelectVuln: (v: Vuln) => void }) {
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState('');
  const [triageStatus, setTriageStatus] = useState('');
  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [pkgQuery, setPkgQuery] = useState('');
  const [sortBy, setSortBy] = useState('cvss_score');
  const [sortDesc, setSortDesc] = useState(true);
  const [loading, setLoading] = useState(true);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostMeta, setHostMeta] = useState<Record<string, Host>>({});
  const [hostIds, setHostIds] = useState<string[]>([]);
  const [containers, setContainers] = useState<string[]>([]);
  const [owner, setOwner] = useState('');
  const [team, setTeam] = useState('');
  const [environment, setEnvironment] = useState('');
  const [criticality, setCriticality] = useState('');
  const [showNoFix, setShowNoFix] = useState(false);
  const [showMismatch, setShowMismatch] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(false);
  const [exportMsg, setExportMsg] = useState('');
  const limit = 50;

  const load = useCallback((p: number, sev: string, triage: string, overdue: boolean, hId: string, cont: string, own: string, tm: string, env: string, crit: string, pq: string, sBy: string, sDesc: boolean, sNoFix: boolean, sMismatch: boolean) => {
    setLoading(true);
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (sev) params.severity = sev;
    if (triage) params.triage_status = triage;
    if (overdue) params.overdue = 'true';
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
    if (own) params.owner = own;
    if (tm) params.team = tm;
    if (env) params.environment = env;
    if (crit) params.criticality = crit;
    if (pq) params.pkg_name = pq;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }
    if (sNoFix) params.show_no_fix = 'true';
    if (sMismatch) params.show_mismatch = 'true';
    api.vulnerabilities(params)
      .then(r => { setVulns(r.items || []); setTotal(r.total); setPage(p); setLoading(false); })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const meta: Record<string, Host> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; meta[h.id] = h; });
      setHostMap(m);
      setHostMeta(meta);
    });
    api.vulnFilters().then(f => {
      setHostIds(f.host_ids || []);
      setContainers(f.containers || []);
    }).catch(() => {});
  }, []);

  useEffect(() => { load(0, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch); }, [load, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, showNoFix, showMismatch]);

  const handleSearch = () => { load(0, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : col === 'cvss_score' || col === 'severity';
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, pkgQuery, col, nextDesc, showNoFix, showMismatch);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const badgeClass = (sev: string) => `badge badge-${sev.toLowerCase()}`;
  const currentExportParams = (format: 'csv' | 'json') => {
    const params: Record<string, string> = { format };
    if (severity) params.severity = severity;
    if (triageStatus) params.triage_status = triageStatus;
    if (overdueOnly) params.overdue = 'true';
    if (hostId) params.host_id = hostId;
    if (container) params.container = container;
    if (owner) params.owner = owner;
    if (team) params.team = team;
    if (environment) params.environment = environment;
    if (criticality) params.criticality = criticality;
    if (pkgQuery) params.pkg_name = pkgQuery;
    if (sortBy) { params.sort_by = sortBy; params.sort_order = sortDesc ? 'desc' : 'asc'; }
    if (showNoFix) params.show_no_fix = 'true';
    if (showMismatch) params.show_mismatch = 'true';
    return params;
  };
  const exportVulns = async (format: 'csv' | 'json') => {
    setExportMsg('Exporting...');
    try {
      await api.exportVulnerabilities(currentExportParams(format));
      setExportMsg('Exported');
    } catch {
      setExportMsg('Export failed');
    }
  };

  const owners = Array.from(new Set(Object.values(hostMeta).map(h => h.owner || '').filter(Boolean))).sort();
  const teams = Array.from(new Set(Object.values(hostMeta).map(h => h.team || '').filter(Boolean))).sort();
  const environments = Array.from(new Set(Object.values(hostMeta).map(h => h.environment || '').filter(Boolean))).sort();
  const criticalities = Array.from(new Set(Object.values(hostMeta).map(h => h.criticality || '').filter(Boolean))).sort();

  const cols: [string, string][] = [
    ['vulnerability_id', 'CVE'], ['severity', 'Severity'], ['cvss_score', 'CVSS'],
    ['pkg_name', 'Package'], ['owner', 'Owner'], ['environment', 'Env'], ['container', 'Container'],
    ['installed_version', 'Installed'], ['fixed_version', 'Fixed'], ['due_at', 'Due'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Vulnerabilities</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={triageStatus} onChange={(e) => setTriageStatus(e.target.value)}>
            <option value="">All Status</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {hostIds.map(id => (
              <option key={id} value={id}>{hostMap[id] || id}</option>
            ))}
          </select>
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">All Containers</option>
            {containers.map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <select value={owner} onChange={(e) => setOwner(e.target.value)}>
            <option value="">All Owners</option>
            {owners.map(o => <option key={o} value={o}>{o}</option>)}
          </select>
          <select value={team} onChange={(e) => setTeam(e.target.value)}>
            <option value="">All Teams</option>
            {teams.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
          <select value={environment} onChange={(e) => setEnvironment(e.target.value)}>
            <option value="">All Environments</option>
            {environments.map(e => <option key={e} value={e}>{e}</option>)}
          </select>
          <select value={criticality} onChange={(e) => setCriticality(e.target.value)}>
            <option value="">All Criticality</option>
            {criticalities.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <input
            type="text"
            placeholder="Search package name..."
            value={pkgQuery}
            onChange={(e) => setPkgQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 180 }}
          />
          <button className="filter-btn" onClick={handleSearch}>
            Search
          </button>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.8125rem', color: 'var(--text-muted)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            <input type="checkbox" checked={showNoFix} onChange={e => setShowNoFix(e.target.checked)} /> No fix info
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.8125rem', color: 'var(--text-muted)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            <input type="checkbox" checked={showMismatch} onChange={e => setShowMismatch(e.target.checked)} /> Wrong ecosystem
          </label>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: '0.8125rem', color: 'var(--text-muted)', cursor: 'pointer', whiteSpace: 'nowrap' }}>
            <input type="checkbox" checked={overdueOnly} onChange={e => setOverdueOnly(e.target.checked)} /> Overdue
          </label>
          <button className="filter-btn" onClick={() => exportVulns('csv')}>Export CSV</button>
          <button className="filter-btn" onClick={() => exportVulns('json')}>JSON</button>
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{exportMsg || `${total} results`}</span>
        </div>
      </div>
      <div className="card">
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Status</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} style={{ cursor: 'pointer' }} onClick={() => onSelectVuln(v)}>
                  <td><span className="host-link">{hostMap[v.host_id] || v.host_id.slice(0, 8)}</span></td>
                  <td><span className="badge">{(v.triage_status || 'open').replace('_', ' ')}</span></td>
                  <td className="mono">
                    <span className="host-link" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</span>
                  </td>
                  <td><span className={badgeClass(v.severity)}>{v.severity}</span></td>
                  <td className="mono" style={{ color: v.cvss_score >= 9 ? 'var(--critical)' : v.cvss_score >= 7 ? 'var(--high)' : v.cvss_score >= 4 ? 'var(--medium)' : 'inherit', fontWeight: 600 }}>{v.cvss_score > 0 ? v.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{v.pkg_name}</td>
                  <td>{v.host_owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{v.host_environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono">{v.container || '(host)'}</td>
                  <td className="mono">{v.installed_version}</td>
                  <td className="mono">
                    {v.fixed_version
                      ? (v.installed_version
                        ? (() => {
                            const cmp = verCmp(v.installed_version, v.fixed_version);
                            const sym = cmp >= 0 ? '≥' : '<';
                            const color = cmp >= 0 ? '#22c55e' : 'var(--high)';
                            return <span style={{ fontWeight: 600 }}>
                              <span style={{ color, fontWeight: 700, marginRight: 2 }}>{sym}</span>
                              {v.fixed_version}
                              {cmp >= 0 && <span style={{ fontSize: '0.625rem', background: 'rgba(34,197,94,0.15)', padding: '1px 5px', borderRadius: 3, marginLeft: 4 }}>FIXED</span>}
                            </span>;
                          })()
                        : v.fixed_version)
                      : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                  </td>
                  <td className="mono" style={{ color: v.overdue ? 'var(--critical)' : 'var(--text-muted)' }}>
                    {v.due_at ? new Date(v.due_at).toLocaleDateString() : '-'}
                  </td>
                </tr>
              ))}
              {vulns.length === 0 && <tr><td colSpan={13} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No vulnerabilities found</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1, severity, triageStatus, overdueOnly, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch)}>Next</button>
        </div>
      </div>
    </>
  );
}

function VulnDetailView({ vuln, onBack }: { vuln: Vuln | null; onBack: () => void }) {
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [triageStatus, setTriageStatus] = useState(vuln?.triage_status || 'open');
  const [triageReason, setTriageReason] = useState(vuln?.triage_reason || '');
  const [triageComment, setTriageComment] = useState(vuln?.triage_comment || '');
  const [triageExpiresAt, setTriageExpiresAt] = useState(dateInputValue(vuln?.triage_expires_at));
  const [triageScope, setTriageScope] = useState<'finding' | 'host' | 'global'>('finding');
  const [triageMsg, setTriageMsg] = useState('');

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m); setHostIPMap(ip);
    });
  }, []);

  useEffect(() => {
    setTriageStatus(vuln?.triage_status || 'open');
    setTriageReason(vuln?.triage_reason || '');
    setTriageComment(vuln?.triage_comment || '');
    setTriageExpiresAt(dateInputValue(vuln?.triage_expires_at));
    setTriageMsg('');
  }, [vuln]);

  if (!vuln) return <div>No vulnerability selected</div>;

  const badgeClass = `badge badge-${vuln.severity.toLowerCase()}`;
  const sevColor = vuln.severity === 'CRITICAL' ? 'var(--critical)' : vuln.severity === 'HIGH' ? 'var(--high)' : vuln.severity === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';
  const saveTriage = async () => {
    setTriageMsg('Saving...');
    try {
      await api.triageVulnerability({
        vulnerability_id: vuln.vulnerability_id,
        host_id: triageScope === 'global' ? '' : vuln.host_id,
        pkg_name: triageScope === 'finding' ? vuln.pkg_name : '',
        status: triageStatus,
        reason: triageReason,
        comment: triageComment,
        expires_at: triageExpiresAt ? `${triageExpiresAt}T00:00:00Z` : null,
      });
      setTriageMsg('Saved');
    } catch {
      setTriageMsg('Save failed');
    }
  };

  return (
    <>
      <button className="back-btn" onClick={onBack}>&larr; Back</button>
      <h1 style={{ marginBottom: '1rem' }}>{vuln.vulnerability_id}</h1>

      <div className="stats-grid" style={{ marginBottom: '1.5rem' }}>
        <div className="stat-card">
          <div className="label">Severity</div>
          <div className="value"><span className={badgeClass}>{vuln.severity}</span></div>
        </div>
        <div className="stat-card">
          <div className="label">CVSS Score</div>
          <div className="value" style={{ color: sevColor }}>{vuln.cvss_score > 0 ? vuln.cvss_score.toFixed(1) : '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Host</div>
          <div style={{ fontSize: '0.875rem' }}><span className="host-link" title={`IP: ${hostIPMap[vuln.host_id] || ''}`}>{hostMap[vuln.host_id] || vuln.host_id.slice(0, 8)}</span></div>
        </div>
        <div className="stat-card">
          <div className="label">Container</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.container || '(host)'}</div>
        </div>
        <div className="stat-card">
          <div className="label">Triage</div>
          <div style={{ fontSize: '0.875rem', textTransform: 'capitalize' }}>{(triageStatus || 'open').replace('_', ' ')}</div>
          <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
            {triageExpiresAt ? `expires ${triageExpiresAt}` : 'no expiry'}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">SLA Due</div>
          <div style={{ fontSize: '0.875rem', color: vuln.overdue ? 'var(--critical)' : 'inherit' }}>
            {vuln.due_at ? new Date(vuln.due_at).toLocaleDateString() : '-'}
          </div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <h3 style={{ margin: '0 0 0.75rem' }}>Triage</h3>
        <div className="filters" style={{ marginBottom: '0.75rem' }}>
          <select value={triageStatus} onChange={(e) => setTriageStatus(e.target.value)}>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <select value={triageScope} onChange={(e) => setTriageScope(e.target.value as 'finding' | 'host' | 'global')}>
            <option value="finding">This host and package</option>
            <option value="host">This host and CVE</option>
            <option value="global">All hosts for this CVE</option>
          </select>
          <input type="text" placeholder="Reason" value={triageReason} onChange={(e) => setTriageReason(e.target.value)} />
          <input type="date" value={triageExpiresAt} onChange={(e) => setTriageExpiresAt(e.target.value)} title="Triage expiry date" />
          {triageExpiresAt && <button onClick={() => setTriageExpiresAt('')}>Clear Expiry</button>}
        </div>
        <textarea
          value={triageComment}
          onChange={(e) => setTriageComment(e.target.value)}
          placeholder="Operator note, exception approval, remediation owner, ticket reference..."
          style={{ width: '100%', minHeight: 90, resize: 'vertical', marginBottom: '0.75rem' }}
        />
        <button className="filter-btn" onClick={saveTriage}>Save Triage</button>
        {triageMsg && <span style={{ marginLeft: '0.75rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{triageMsg}</span>}
        {triageComment && <div style={{ marginTop: '0.75rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Current note: {triageComment}</div>}
      </div>

      {vuln.title && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>Title</h3>
          <div>{vuln.title}</div>
        </div>
      )}

      {vuln.description && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>Description</h3>
          <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>{vuln.description}</div>
        </div>
      )}

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <h3 style={{ margin: '0 0 0.75rem' }}>Affected Package</h3>
        <table>
          <tbody>
            <tr><td style={{ color: 'var(--text-muted)', width: 140 }}>Package</td><td className="mono">{vuln.pkg_name}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Installed Version</td><td className="mono">{vuln.installed_version}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Fixed Version</td><td className="mono" style={{ color: vuln.fixed_version ? 'var(--low)' : 'var(--critical)', fontWeight: 600 }}>{vuln.fixed_version || 'No fix available'}</td></tr>
            {vuln.pkg_path && <tr><td style={{ color: 'var(--text-muted)' }}>Path</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.pkg_path}</td></tr>}
          </tbody>
        </table>
      </div>

      {vuln.cvss_vector && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>CVSS Vector</h3>
          <div className="mono" style={{ fontSize: '0.8125rem', marginBottom: '0.75rem', color: 'var(--primary)' }}>{vuln.cvss_vector}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            {(() => {
              const parsed = parseCvssVector(vuln.cvss_vector);
              return parsed.parts.map(p => {
                const [k, v] = p.split(':');
                if (!k || v === undefined) return null;
                return <div key={k} style={{ display: 'inline-block', marginRight: '1.25rem', marginBottom: '0.25rem' }}><strong style={{ color: 'var(--text)' }}>{parsed.labels[k] || k}</strong>: {parsed.values[k]?.[v] || v}</div>;
              });
            })()}
          </div>
        </div>
      )}

      {(vuln.primary_url || vuln.vulnerability_id.startsWith('CVE-')) && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.5rem' }}>External References</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.375rem', fontSize: '0.8125rem' }}>
            {vuln.primary_url && <a href={vuln.primary_url} target="_blank" rel="noopener">{vuln.primary_url} ↗</a>}
            {vuln.vulnerability_id.startsWith('CVE-') && <a href={`https://nvd.nist.gov/vuln/detail/${vuln.vulnerability_id}`} target="_blank" rel="noopener">NVD - {vuln.vulnerability_id} ↗</a>}
          </div>
        </div>
      )}
    </>
  );
}

const LANG_GROUPS: Record<string, string[]> = {
  'OS Packages': ['debian', 'alpine', 'redhat', 'ubuntu', 'amazon', 'oracle', 'suse', 'photon', 'centos', 'rocky', 'almalinux', 'fedora', 'arch', 'busybox', 'wolfi'],
  'Python': ['python-pkg', 'pip', 'poetry', 'pipenv', 'conda'],
  'Node.js': ['node-pkg', 'npm', 'yarn', 'pnpm', 'node'],
  'Go': ['gomod', 'go', 'gobinary'],
  'Rust': ['cargo', 'rustbinary'],
  'Java': ['jar', 'maven', 'gradle'],
  'PHP': ['composer'],
  'Ruby': ['gem', 'bundler'],
  '.NET': ['nuget', 'dotnet'],
};

function resolvePkgTypes(langLabel: string, allTypes: string[]): string[] {
  if (langLabel === '' || langLabel === '__all__') return [];
  if (langLabel === '__other__') {
    const known = new Set(Object.values(LANG_GROUPS).flat());
    return allTypes.filter(t => !known.has(t));
  }
  const group = LANG_GROUPS[langLabel];
  if (group) return group.filter(t => allTypes.includes(t));
  return allTypes.filter(t => t === langLabel);
}

function PackagesView({ onSelectVuln }: { onSelectVuln?: (v: Vuln) => void }) {
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filterOpts, setFilterOpts] = useState<FilterOptions | null>(null);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});

  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [lang, setLang] = useState('');
  const [source, setSource] = useState('');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('');
  const [sortDesc, setSortDesc] = useState(false);
  const limit = 100;

  useEffect(() => {
    api.packageFilters().then(setFilterOpts).catch(() => {});
    api.hosts().then(hosts => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hosts || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m);
      setHostIPMap(ip);
    }).catch(() => {});
  }, []);

  const load = useCallback((p: number, hId: string, cont: string, langLabel: string, src: string, q: string, sBy: string, sDesc: boolean) => {
    setLoading(true);
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
    if (src) params.source = src;
    if (q) params.q = q;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }

    const types = resolvePkgTypes(langLabel, filterOpts?.pkg_types || []);
    if (types.length === 1) params.pkg_type = types[0];

    api.packages(params)
      .then(r => {
        let items = r.items || [];
        if (types.length > 1) {
          const typeSet = new Set(types);
          items = items.filter(pkg => typeSet.has(pkg.pkg_type));
        }
        setPkgs(items);
        setTotal(types.length > 1 ? items.length : r.total);
        setPage(p);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [filterOpts]);

  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc); }, [filterOpts]);
  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc); }, [hostId, container, lang, source]);

  const handleSearch = () => { load(0, hostId, container, lang, source, query, sortBy, sortDesc); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : false;
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, hostId, container, lang, source, query, col, nextDesc);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const cols: [string, string][] = [
    ['name', 'Name'], ['version', 'Version'], ['pkg_type', 'Type'],
    ['max_cvss', 'CVSS'], ['vuln_count', 'Vulns'],
    ['container', 'Container'], ['source', 'Source'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Packages</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {(filterOpts?.host_ids || []).map(id => (
              <option key={id} value={id}>{hostMap[id] || id}</option>
            ))}
          </select>
          <select value={container} onChange={(e) => setContainer(e.target.value)}>
            <option value="">All Containers</option>
            {(filterOpts?.containers || []).map(c => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>
          <select value={lang} onChange={(e) => setLang(e.target.value)}>
            <option value="">All Types</option>
            {(() => {
              const dbTypes = new Set(filterOpts?.pkg_types || []);
              return Object.entries(LANG_GROUPS)
                .filter(([, types]) => types.some(t => dbTypes.has(t)))
                .map(([label]) => (
                  <option key={label} value={label}>{label}</option>
                ));
            })()}
            {(() => {
              const known = new Set(Object.values(LANG_GROUPS).flat());
              const others = (filterOpts?.pkg_types || []).filter(t => !known.has(t));
              return others.length > 0 ? <option value="__other__">Other</option> : null;
            })()}
          </select>
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">All Sources</option>
            {(filterOpts?.sources || []).map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <input
            type="text"
            placeholder="Search package name..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 200 }}
          />
          <button
            className="filter-btn"
            onClick={handleSearch}
          >
            Search
          </button>
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <h2>{total} packages</h2>
        </div>
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
                <th>Path</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {pkgs.map(p => (
                <tr key={p.id}>
                  <td><span className="host-link" title={`IP: ${hostIPMap[p.host_id] || ''}`}>{hostMap[p.host_id] || p.host_id}</span></td>
                  <td className="mono">{p.name}</td>
                  <td className="mono">{p.version}</td>
                  <td>{p.pkg_type}</td>
                  <td className="mono"><CvssTooltip pkgId={p.id} score={p.max_cvss} onSelectVuln={onSelectVuln} /></td>
                  <td style={{ fontWeight: p.vuln_count > 0 ? 600 : 400 }}>{p.vuln_count || 0}</td>
                  <td>{p.container || <span style={{ color: 'var(--text-muted)' }}>host</span>}</td>
                  <td>{p.source}</td>
                  <td className="path-cell">{(() => { const fp = p.file_path || (p.target ? "/" + p.target : ""); return fp ? <>{fp.length > 35 ? fp.slice(0, 35) + "..." : fp}<span className="path-tip">{fp}</span></> : "-"; })()}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{p.created_at ? new Date(p.created_at).toLocaleDateString() : '-'}</td>
                </tr>
              ))}
              {pkgs.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No packages found</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1, hostId, container, lang, source, query, sortBy, sortDesc)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1, hostId, container, lang, source, query, sortBy, sortDesc)}>Next</button>
        </div>
      </div>
    </>
  );
}

function ContainersView() {
  const [containers, setContainers] = useState<ContainerAsset[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);

  const [hostId, setHostId] = useState('');
  const [runtime, setRuntime] = useState('');
  const [state, setState] = useState('');
  const [image, setImage] = useState('');
  const [query, setQuery] = useState('');
  const [sortBy, setSortBy] = useState('created_at');
  const [sortDesc, setSortDesc] = useState(true);
  const limit = 100;

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHosts(hs || []);
      setHostMap(m);
      setHostIPMap(ip);
    }).catch(() => {});
  }, []);

  const load = useCallback((p: number, hId: string, rt: string, st: string, img: string, q: string, sBy: string, sDesc: boolean) => {
    setLoading(true);
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (hId) params.host_id = hId;
    if (rt) params.runtime = rt;
    if (st) params.state = st;
    if (img) params.image = img;
    if (q) params.q = q;
    if (sBy) { params.sort_by = sBy; params.sort_order = sDesc ? 'desc' : 'asc'; }

    api.containers(params)
      .then(r => {
        setContainers(r.items || []);
        setTotal(r.total || 0);
        setPage(p);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(0, hostId, runtime, state, image, query, sortBy, sortDesc); }, [hostId, runtime, state]);

  const handleSearch = () => { load(0, hostId, runtime, state, image, query, sortBy, sortDesc); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : false;
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, hostId, runtime, state, image, query, col, nextDesc);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const runtimes = Array.from(new Set(['docker', 'containerd', 'podman', ...containers.map(c => c.runtime).filter(Boolean)])).sort();
  const states = Array.from(new Set(['running', 'exited', 'created', 'paused', 'restarting', 'dead', ...containers.map(c => c.state).filter(Boolean)])).sort();
  const cols: [string, string][] = [
    ['name', 'Name'], ['state', 'State'], ['runtime', 'Runtime'],
    ['image_name', 'Image'], ['container_id', 'Container ID'], ['started_at', 'Started'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Containers</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <select value={hostId} onChange={(e) => setHostId(e.target.value)}>
            <option value="">All Hosts</option>
            {hosts.map(h => (
              <option key={h.id} value={h.id}>{h.hostname || h.id}</option>
            ))}
          </select>
          <select value={runtime} onChange={(e) => setRuntime(e.target.value)}>
            <option value="">All Runtimes</option>
            {runtimes.map(rt => <option key={rt} value={rt}>{rt}</option>)}
          </select>
          <select value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">All States</option>
            {states.map(st => <option key={st} value={st}>{st}</option>)}
          </select>
          <input
            type="text"
            placeholder="Image name..."
            value={image}
            onChange={(e) => setImage(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 180 }}
          />
          <input
            type="text"
            placeholder="Name, container ID, image ID..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 240 }}
          />
          <button className="filter-btn" onClick={handleSearch}>Search</button>
        </div>
      </div>
      <div className="card">
        <div className="card-header">
          <h2>{total} containers</h2>
        </div>
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
                <th>Image ID</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {containers.map(c => (
                <tr key={c.id}>
                  <td><span className="host-link" title={`IP: ${hostIPMap[c.host_id] || ''}`}>{hostMap[c.host_id] || c.host_id}</span></td>
                  <td className="mono">{c.name || '-'}</td>
                  <td><span className="badge">{c.state || '-'}</span></td>
                  <td>{c.runtime || '-'}</td>
                  <td className="mono" title={c.image_name}>{c.image_name || '-'}</td>
                  <td className="mono" title={c.container_id}>{c.container_id ? c.container_id.slice(0, 16) : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{c.started_at ? new Date(c.started_at).toLocaleString() : '-'}</td>
                  <td className="mono" title={c.image_id}>{c.image_id ? c.image_id.replace(/^sha256:/, '').slice(0, 18) : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{c.created_at ? new Date(c.created_at).toLocaleString() : '-'}</td>
                </tr>
              ))}
              {containers.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No containers found</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1, hostId, runtime, state, image, query, sortBy, sortDesc)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1, hostId, runtime, state, image, query, sortBy, sortDesc)}>Next</button>
        </div>
      </div>
    </>
  );
}

function CveSearchView() {
  const [results, setResults] = useState<{items: CveDbEntry[]; total: number}>({items: [], total: 0});
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [sources, setSources] = useState<string[]>([]);
  const [minCvss, setMinCvss] = useState('');
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [sortBy, setSortBy] = useState('published_date');
  const [sortDesc, setSortDesc] = useState(true);
  const limit = 50;

  useEffect(() => {
    api.cveDbSources().then(data => {
      if (Array.isArray(data)) setSources(data);
    }).catch(() => {});
  }, []);

  const doSearch = useCallback((p: number, sBy?: string, sDesc?: boolean) => {
    setLoading(true);
    const sb = sBy ?? sortBy;
    const sd = sDesc ?? sortDesc;
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (query.trim()) params.q = query.trim();
    if (severity) params.severity = severity;
    if (source) params.source = source;
    if (minCvss) params.min_cvss = minCvss;
    params.sort_by = sb;
    params.sort_order = sd ? 'desc' : 'asc';
    api.cveDbSearch(params)
      .then(r => {
        setResults({items: r.items || [], total: r.total});
        setPage(p);
        setSearched(true);
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, [query, severity, source, minCvss, sortBy, sortDesc]);

  const badge = (s: string) => "badge badge-" + (s || "unknown").toLowerCase();
  const cvssClr = (n: number) => n >= 9 ? "var(--critical)" : n >= 7 ? "var(--high)" : n >= 4 ? "var(--medium)" : "inherit";

  const toggleExpand = (id: string) => {
    setExpanded(prev => prev === id ? null : id);
  };

  const formatDate = (d: string | null | undefined) => {
    if (!d) return "-";
    try { return new Date(d).toLocaleDateString(); } catch { return "-"; }
  };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : true;
    setSortBy(col);
    setSortDesc(nextDesc);
    doSearch(0, col, nextDesc);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const parseJson = (raw: string | null | undefined): any[] => {
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>CVE Search</h1>

      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input
            type="text"
            placeholder="CVE ID or keyword..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doSearch(0); }}
            style={{ minWidth: 220 }}
          />
          <select value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={source} onChange={e => setSource(e.target.value)}>
            <option value="">All Sources</option>
            {sources.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <input
            type="number"
            placeholder="Min CVSS"
            value={minCvss}
            onChange={e => setMinCvss(e.target.value)}
            min="0" max="10" step="0.1"
            style={{ width: 90 }}
          />
          <button className="filter-btn" onClick={() => doSearch(0)}>Search</button>
          {searched && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{results.total.toLocaleString()} results</span>}
        </div>
      </div>

      {!searched && !loading && (
        <div className="card" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-muted)' }}>
          Search the CVE database by CVE ID, keyword, severity, source, or minimum CVSS score.
        </div>
      )}

      {loading && <div className="card" style={{ padding: '2rem', textAlign: 'center' }}>Searching...</div>}

      {searched && !loading && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <th className="clickable" onClick={() => toggleSort('vulnerability_id')} style={{ userSelect: 'none' }}>CVE ID{sortArrow('vulnerability_id')}</th>
                <th className="clickable" onClick={() => toggleSort('severity')} style={{ userSelect: 'none' }}>Severity{sortArrow('severity')}</th>
                <th className="clickable" onClick={() => toggleSort('cvss_score')} style={{ userSelect: 'none' }}>CVSS{sortArrow('cvss_score')}</th>
                <th className="clickable" onClick={() => toggleSort('source')} style={{ userSelect: 'none' }}>Source{sortArrow('source')}</th>
                <th className="clickable" onClick={() => toggleSort('title')} style={{ userSelect: 'none' }}>Title{sortArrow('title')}</th>
                <th className="clickable" onClick={() => toggleSort('published_date')} style={{ userSelect: 'none' }}>Published{sortArrow('published_date')}</th>
              </tr>
            </thead>
            <tbody>
              {results.items.map(entry => {
                const isExpanded = expanded === entry.id;
                const prods = parseJson(entry.affected_products);
                const refs = parseJson(entry.references);

                return (
                  <React.Fragment key={entry.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
                      onClick={() => toggleExpand(entry.id)}
                    >
                      <td className="mono">
                        <span className="host-link" style={{ color: 'var(--primary)' }}>
                          {entry.vulnerability_id}
                        </span>
                      </td>
                      <td>
                        <span className={badge(entry.severity)}>
                          {entry.severity || '-'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontWeight: 600, color: cvssClr(entry.cvss_score) }}>
                        {entry.cvss_score > 0 ? entry.cvss_score.toFixed(1) : '-'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {entry.source}
                      </td>
                      <td style={{ maxWidth: 350, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {entry.title || '-'}
                      </td>
                      <td className="mono" style={{ fontSize: '0.8125rem' }}>
                        {formatDate(entry.published_date)}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr>
                        <td colSpan={6} style={{ background: 'var(--surface)', padding: '1rem 1.5rem' }}>
                          {entry.description && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong>Description</strong>
                              <div style={{ fontSize: '0.8125rem', whiteSpace: 'pre-wrap', lineHeight: 1.5, color: 'var(--text-muted)', maxHeight: 200, overflow: 'auto', marginTop: '0.25rem' }}>
                                {entry.description}
                              </div>
                            </div>
                          )}
                          {entry.cvss_vector && (
                            <div style={{ marginBottom: '0.75rem', fontSize: '0.8125rem' }}>
                              <strong>CVSS Vector:</strong>{' '}
                              <code style={{ background: 'var(--bg)', padding: '2px 6px', borderRadius: 3 }}>
                                {entry.cvss_vector}
                              </code>
                            </div>
                          )}
                          {prods.length > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Affected Packages</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {prods.slice(0, 20).map((pkg: any, idx: number) => {
                                  const fixedArr = pkg.fixed || [];
                                  const lastFixed = fixedArr.length > 0 ? fixedArr[fixedArr.length - 1] : '';
                                  return (
                                    <div key={idx} style={{ background: 'var(--bg)', padding: '0.4rem 0.75rem', borderRadius: 4, border: '1px solid var(--border)', marginBottom: '0.25rem' }}>
                                      <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{pkg.name || 'unknown'}</span>
                                      {pkg.ecosystem && (
                                        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{pkg.ecosystem}</span>
                                      )}
                                      {lastFixed && (
                                        <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '1px 6px', borderRadius: 3, fontWeight: 600, marginLeft: '0.5rem' }}>
                                          Fixed: {lastFixed}
                                        </span>
                                      )}
                                    </div>
                                  );
                                })}
                              </div>
                            </div>
                          )}
                          {refs.length > 0 && (
                            <div>
                              <strong style={{ fontSize: '0.8125rem' }}>References</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {refs.slice(0, 10).map((ref: any, idx: number) => (
                                  <div key={idx}>
                                    <a href={ref.url} target="_blank" rel="noopener" style={{ fontSize: '0.75rem', color: 'var(--primary)' }}>
                                      {ref.url}
                                    </a>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
              {results.items.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No results found</td></tr>
              )}
            </tbody>
          </table>
          {results.total > limit && (
            <div className="pagination">
              <button disabled={page === 0} onClick={() => doSearch(page - 1)}>Prev</button>
              <span>Page {page + 1} of {Math.max(1, Math.ceil(results.total / limit))}</span>
              <button disabled={(page + 1) * limit >= results.total} onClick={() => doSearch(page + 1)}>Next</button>
            </div>
          )}
        </div>
      )}
    </>
  );
}

function ScansView() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [requests, setRequests] = useState<ScanRequest[]>([]);
  const [requestTotal, setRequestTotal] = useState(0);
  const [requestStatus, setRequestStatus] = useState('');
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

  const loadRequests = useCallback((status: string) => {
    setRequestsLoading(true);
    const params: Record<string, string> = { limit: '50', offset: '0' };
    if (status) params.status = status;
    api.scanRequests(params)
      .then(r => { setRequests(r.items || []); setRequestTotal(r.total || 0); setRequestsLoading(false); })
      .catch(() => setRequestsLoading(false));
  }, []);

  useEffect(() => { load(0); }, [load]);
  useEffect(() => { loadRequests(requestStatus); }, [loadRequests, requestStatus]);

  const statusColor = (s: string) => s === 'completed' ? 'var(--low)' : s === 'failed' ? 'var(--critical)' : 'var(--medium)';
  const cancelRequest = async (id: string) => {
    setRequestMsg('');
    try {
      await api.cancelScanRequest(id);
      setRequestMsg('Scan request cancelled');
      loadRequests(requestStatus);
    } catch {
      setRequestMsg('Cancel failed');
    }
  };
  const requeueStale = async () => {
    setRequestMsg('');
    try {
      const r = await api.requeueStaleScanRequests();
      setRequestMsg(`Requeued ${r.requeued} stale claimed requests`);
      loadRequests(requestStatus);
    } catch {
      setRequestMsg('Requeue failed');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Scan History</h1>
      <div className="card" style={{ marginBottom: '1rem' }}>
        <div className="card-header">
          <h2>{requestTotal} scan requests</h2>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <button className="update-btn" onClick={requeueStale}>Requeue Stale</button>
            <select value={requestStatus} onChange={(e) => setRequestStatus(e.target.value)}>
              <option value="">All Status</option>
              <option value="pending">Pending</option>
              <option value="claimed">Claimed</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
            </select>
          </div>
        </div>
        {requestMsg && <div style={{ padding: '0.75rem 1rem 0', color: requestMsg.includes('failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{requestMsg}</div>}
        {requestsLoading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr><th>Requested</th><th>Host</th><th>Type</th><th>Status</th><th>Mode</th><th>Reason</th><th>Claimed</th><th>Completed</th><th></th></tr>
            </thead>
            <tbody>
              {requests.map(req => (
                <tr key={req.id}>
                  <td className="mono">{new Date(req.created_at).toLocaleString()}</td>
                  <td><span className="host-link" title={`IP: ${req.host_id ? hostIPMap[req.host_id] || '' : ''}`}>{req.host_id ? hostMap[req.host_id] || req.host_id : 'All polling agents'}</span></td>
                  <td>{req.scan_type}</td>
                  <td style={{ color: statusColor(req.status), fontWeight: 600 }}>{req.status}</td>
                  <td>{req.packages_only ? 'packages' : 'full'}</td>
                  <td className="path-cell">{req.reason || req.error_message || '-'}{(req.reason || req.error_message) && <span className="path-tip">{req.reason || req.error_message}</span>}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.claimed_at ? new Date(req.claimed_at).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{req.completed_at ? new Date(req.completed_at).toLocaleString() : '-'}</td>
                  <td>{['pending', 'claimed'].includes(req.status) && <button className="delete-btn" onClick={() => cancelRequest(req.id)}>Cancel</button>}</td>
                </tr>
              ))}
              {requests.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No scan requests</td></tr>}
            </tbody>
          </table>
        )}
      </div>
      <div className="card">
        <div className="card-header">
          <h2>{total} scans</h2>
        </div>
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr><th>Date</th><th>Host</th><th>Type</th><th>Status</th><th>Inventory</th><th>Delta</th><th>Started</th><th>Finished</th><th></th></tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id}>
                  <td className="mono">{new Date(s.created_at).toLocaleString()}</td>
                  <td><span className="host-link" title={`IP: ${hostIPMap[s.host_id] || ''}`}>{hostMap[s.host_id] || s.host_id}</span></td>
                  <td>{s.scan_type}</td>
                  <td style={{ color: statusColor(s.status), fontWeight: 600 }}>{s.status}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.package_count || 0} pkgs / {s.vulnerability_count || 0} vulns / {s.container_count || 0} ctrs</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>+{s.packages_added || 0} / -{s.packages_removed || 0} / ~{s.packages_changed || 0}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.finished_at ? new Date(s.finished_at).toLocaleString() : '-'}</td>
                  <td><button className="delete-btn" onClick={() => { if (confirm('Delete this scan and all associated data?')) { api.deleteScan(s.id).then(() => load(page)).catch(() => alert('Delete failed')); } }}>Delete</button></td>
                </tr>
              ))}
              {scans.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No scans recorded</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1)}>Next</button>
        </div>
      </div>
    </>
  );
}

function RBACView() {
  const [subjects, setSubjects] = useState<AccessSubject[]>([]);
  const [policies, setPolicies] = useState<AccessPolicy[]>([]);
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
    ])
      .then(([s, p]) => {
        setSubjects(s.items || []);
        setPolicies(p.items || []);
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
            <datalist id="rbac-subjects">{subjects.map(s => <option key={s.id} value={s.external_id} />)}</datalist>
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
              <option value="write">Write</option>
              <option value="admin">Admin</option>
            </select>
            <button className="filter-btn" onClick={savePolicy}>Save Policy</button>
          </div>
        </div>
      </div>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input list="rbac-subjects" type="text" placeholder="Filter policies by subject" value={subjectFilter} onChange={(e) => setSubjectFilter(e.target.value)} />
          <button className="filter-btn" onClick={() => load(subjectFilter)}>Search</button>
          <button onClick={() => { setSubjectFilter(''); load(''); }}>Clear</button>
          <span style={{ color: message.startsWith('Failed') || message.includes('requires') || message.includes('required') ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {message || `${subjects.length} subjects / ${policies.length} policies`}
          </span>
        </div>
      </div>
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h2>Subjects</h2></div>
          {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
            <table>
              <thead><tr><th>Type</th><th>External ID</th><th>Name</th><th>Updated</th><th></th></tr></thead>
              <tbody>
                {subjects.map(s => (
                  <tr key={s.id}>
                    <td><span className="badge">{s.subject_type}</span></td>
                    <td className="mono">{s.external_id}</td>
                    <td>{s.display_name || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(s.updated_at).toLocaleString()}</td>
                    <td><button className="delete-btn" onClick={() => deleteSubject(s)}>Revoke</button></td>
                  </tr>
                ))}
                {subjects.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No subjects</td></tr>}
              </tbody>
            </table>
          )}
        </div>
        <div className="card">
          <div className="card-header"><h2>Policies</h2></div>
          {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
            <table>
              <thead><tr><th>Subject</th><th>Resource</th><th>Permission</th><th>Created</th><th></th></tr></thead>
              <tbody>
                {policies.map(p => (
                  <tr key={p.id}>
                    <td>{p.subject_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.subject_external_id}</div></td>
                    <td>{p.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{p.resource_id || '*'}</div></td>
                    <td><span className="badge">{p.permission}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(p.created_at).toLocaleString()}</td>
                    <td><button className="delete-btn" onClick={() => deletePolicy(p)}>Revoke</button></td>
                  </tr>
                ))}
                {policies.length === 0 && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No policies</td></tr>}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}

function AuditLogView() {
  const [items, setItems] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [actorType, setActorType] = useState('');
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [status, setStatus] = useState('');
  const [query, setQuery] = useState('');
  const limit = 50;

  const load = useCallback((p: number, at: string, act: string, rt: string, st: string, q: string) => {
    setLoading(true);
    setError('');
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (at) params.actor_type = at;
    if (act) params.action = act;
    if (rt) params.resource_type = rt;
    if (st) params.status = st;
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

  useEffect(() => { load(0, actorType, action, resourceType, status, query); }, [load, actorType, action, resourceType, status]);
  const handleSearch = () => load(0, actorType, action, resourceType, status, query);
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Audit Log</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
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
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
          <input
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
          <button className="filter-btn" onClick={handleSearch}>Search</button>
          <span style={{ color: error ? 'var(--critical)' : 'var(--text-muted)', fontSize: '0.8125rem' }}>{error || `${total} events`}</span>
        </div>
      </div>
      <div className="card">
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Resource</th><th>Status</th><th>Client</th><th>Metadata</th></tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.id}>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{new Date(item.created_at).toLocaleString()}</td>
                  <td>{item.actor_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.actor_id || '-'}</div></td>
                  <td className="mono">{item.action}</td>
                  <td>{item.resource_type}<div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>{item.resource_id || '-'}</div></td>
                  <td><span className="badge">{item.status}</span></td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{item.ip_address || '-'}</td>
                  <td className="path-cell">{JSON.stringify(item.metadata || {})}<span className="path-tip">{JSON.stringify(item.metadata || {}, null, 2)}</span></td>
                </tr>
              ))}
              {items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No audit events</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1, actorType, action, resourceType, status, query)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1, actorType, action, resourceType, status, query)}>Next</button>
        </div>
      </div>
    </>
  );
}

function CvssTooltip({ pkgId, score, onSelectVuln }: { pkgId: string; score: number | undefined; onSelectVuln?: (v: Vuln) => void }) {
  const s = score ?? 0;
  const [vulns, setVulns] = useState<Vuln[] | null>(null);
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);
  const [show, setShow] = useState(false);
  const timerRef = useState<ReturnType<typeof setTimeout> | null>(null);

  const handleEnter = (e: React.MouseEvent) => {
    const rect = (e.target as HTMLElement).getBoundingClientRect();
    setPos({ x: rect.left, y: rect.bottom + 4 });
    setShow(true);
    if (!vulns) {
      api.packageVulns(pkgId).then(setVulns).catch(() => setVulns([]));
    }
  };

  const handleLeave = () => {
    setShow(false);
  };

  const sevColor = (s: string) => s === 'CRITICAL' ? 'var(--critical)' : s === 'HIGH' ? 'var(--high)' : s === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';

  if (s <= 0) return <span className="mono">-</span>;

  return (
    <>
      <span className="mono" style={{ color: s >= 9 ? 'var(--critical)' : s >= 7 ? 'var(--high)' : s >= 4 ? 'var(--medium)' : 'var(--low)', cursor: 'help' }}
        onMouseEnter={handleEnter} onMouseLeave={handleLeave}>
        {s.toFixed(1)}
      </span>
      {show && pos && (
        <div style={{
          position: 'fixed', left: Math.min(pos.x, window.innerWidth - 340), top: pos.y,
          background: '#1e2030', border: '1px solid var(--border)', borderRadius: 8,
          padding: '0.75rem', minWidth: 280, maxWidth: 360, zIndex: 1000,
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)', fontSize: '0.8125rem',
          maxHeight: 320, overflowY: 'auto',
        }} onMouseEnter={() => setShow(true)} onMouseLeave={handleLeave}>
          {!vulns ? <span style={{ color: 'var(--text-muted)' }}>Loading...</span> :
           vulns.length === 0 ? <span style={{ color: 'var(--text-muted)' }}>No details</span> :
           vulns.map(v => (
             <div key={v.id} style={{ padding: '0.375rem 0', borderBottom: '1px solid var(--border)' }}>
               <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                 <span className="mono" style={{ fontSize: '0.75rem' }}>
                   {onSelectVuln
                     ? <a href="#" onClick={(e) => { e.preventDefault(); e.stopPropagation(); onSelectVuln(v); setShow(false); }} style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a>
                     : v.primary_url ? <a href={v.primary_url} target="_blank" rel="noopener" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</a> : v.vulnerability_id}
                 </span>
                 <span style={{ color: sevColor(v.severity), fontWeight: 600, fontSize: '0.75rem' }}>{v.severity} {v.cvss_score > 0 ? v.cvss_score.toFixed(1) : ''}</span>
               </div>
               {v.title && <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: 2 }}>{v.title}</div>}
               <div style={{ color: 'var(--text-muted)', fontSize: '0.6875rem', marginTop: 2 }}>
                 {v.installed_version}
                 {v.fixed_version && v.installed_version
                   ? (() => {
                       const cmp = verCmp(v.installed_version, v.fixed_version);
                       const sym = cmp >= 0 ? '≥' : '<';
                       const color = cmp >= 0 ? '#22c55e' : 'var(--critical)';
                       return <span style={{ margin: '0 4px', color, fontWeight: 700 }}>{sym}</span>;
                     })()
                   : v.fixed_version ? ' → ' : ''}
                 {v.fixed_version || ''}
                 {v.fixed_version && v.installed_version && verCmp(v.installed_version, v.fixed_version) >= 0 &&
                   <span style={{ color: '#22c55e', fontWeight: 600, marginLeft: 4, fontSize: '0.625rem', background: 'rgba(34,197,94,0.15)', padding: '1px 4px', borderRadius: 3 }}>FIXED</span>}
               </div>
             </div>
           ))
          }
        </div>
      )}
    </>
  );
}
