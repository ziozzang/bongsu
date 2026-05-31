import React, { useState, useEffect, useCallback } from 'react';
import { api, setApiKey, getApiKey, clearApiKey, onAuthFailure, type Host, type Vuln, type Pkg, type Stats, type FilterOptions, type Scan, type HealthStatus, type CveDbEntry, type CveSourceStat } from './api';

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

type View = 'dashboard' | 'hosts' | 'packages' | 'vulns' | 'vuln-detail' | 'scans' | 'host-detail' | 'cve-search';

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
        {view === 'cve-search' && <CveSearchView />}
        {view === 'scans' && <ScansView />}
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
    ['vulns', 'Vulnerabilities', '◆'],
    ['cve-search', 'CVE Search', '◈'],
    ['scans', 'Scan History', '☰'],
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
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [rematching, setRematching] = useState(false);
  const [rematchMsg, setRematchMsg] = useState('');

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
      const r = await api.rematchCVEs();
      setRematchMsg(`Matched ${r.matched.toLocaleString()} packages, found ${r.new_vulns.toLocaleString()} new vulnerabilities (${r.skipped} already known)`);
      api.stats().then(setStats).catch(() => {});
    } catch {
      setRematchMsg('Rematch failed (check server logs)');
    }
    setRematching(false);
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
      {cveSources.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>CVE Database Sources</h2></div>
          <table>
            <thead><tr><th>Source</th><th>Records</th><th>Last Update</th></tr></thead>
            <tbody>
              {cveSources.map(s => (
                <tr key={s.source}>
                  <td><span style={{ fontWeight: 600 }}>{s.source.toUpperCase()}</span></td>
                  <td className="mono">{s.count.toLocaleString()}</td>
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

function HostsView({ onSelectHost }: { onSelectHost: (id: string) => void }) {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { api.hosts().then(h => { setHosts(h || []); setLoading(false); }).catch(() => setLoading(false)); }, []);

  if (loading) return <div>Loading...</div>;

  const sevColor = (sev: string) => ({ CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' }[sev] || 'var(--unknown)');

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Hosts</h1>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Hostname</th>
              <th>OS</th>
              <th>IP</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map(h => (
              <tr key={h.id}>
                <td><span className="host-link" title={`IP: ${h.ip_address}`} onClick={() => onSelectHost(h.id)}>{h.hostname}</span></td>
                <td>{h.os_name} {h.os_version}</td>
                <td className="mono">{h.ip_address}</td>
                <td style={{ color: sevColor('CRITICAL'), fontWeight: 600 }}>{h.vuln_counts?.CRITICAL || 0}</td>
                <td style={{ color: sevColor('HIGH'), fontWeight: 600 }}>{h.vuln_counts?.HIGH || 0}</td>
                <td style={{ color: sevColor('MEDIUM'), fontWeight: 600 }}>{h.vuln_counts?.MEDIUM || 0}</td>
                <td style={{ color: sevColor('LOW'), fontWeight: 600 }}>{h.vuln_counts?.LOW || 0}</td>
                <td className="mono">{new Date(h.last_seen).toLocaleString()}</td>
              </tr>
            ))}
            {hosts.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No hosts registered</td></tr>}
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
  const limit = 50;

  useEffect(() => {
    api.host(hostId).then(setHost).catch(() => {});
    api.hostVulnCounts(hostId).then(setVulnCounts).catch(() => {});
  }, [hostId]);

  const loadPkgs = useCallback((page: number) => {
    api.hostPackages(hostId, limit, page * limit).then(r => { setPkgs(r.items || []); setTotalPkgs(r.total); setPkgPage(page); }).catch(() => {});
  }, [hostId]);

  useEffect(() => { loadPkgs(0); }, [loadPkgs]);

  if (!host) return <div>Loading...</div>;

  return (
    <>
      <button className="back-btn" onClick={onBack}>&larr; Back</button>
      <h1 style={{ marginBottom: '1rem' }}>{host.hostname}</h1>

      <div className="stats-grid" style={{ marginBottom: '2rem' }}>
        <div className="stat-card"><div className="label">OS</div><div style={{ fontSize: '0.875rem' }}>{host.os_name} {host.os_version}</div></div>
        <div className="stat-card"><div className="label">Kernel</div><div className="mono" style={{ fontSize: '0.875rem' }}>{host.kernel}</div></div>
        <div className="stat-card"><div className="label">CPU</div><div style={{ fontSize: '0.875rem' }}>{host.cpu_cores} cores</div></div>
        <div className="stat-card"><div className="label">Memory</div><div style={{ fontSize: '0.875rem' }}>{(host.memory_mb / 1024).toFixed(1)} GB</div></div>
        <div className="stat-card"><div className="label">Critical</div><div className="value" style={{ color: 'var(--critical)', fontSize: '1.25rem' }}>{vulnCounts.CRITICAL || 0}</div></div>
        <div className="stat-card"><div className="label">High</div><div className="value" style={{ color: 'var(--high)', fontSize: '1.25rem' }}>{vulnCounts.HIGH || 0}</div></div>
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
  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [pkgQuery, setPkgQuery] = useState('');
  const [sortBy, setSortBy] = useState('cvss_score');
  const [sortDesc, setSortDesc] = useState(true);
  const [loading, setLoading] = useState(true);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIds, setHostIds] = useState<string[]>([]);
  const [containers, setContainers] = useState<string[]>([]);
  const [showNoFix, setShowNoFix] = useState(false);
  const [showMismatch, setShowMismatch] = useState(false);
  const limit = 50;

  const load = useCallback((p: number, sev: string, hId: string, cont: string, pq: string, sBy: string, sDesc: boolean, sNoFix: boolean, sMismatch: boolean) => {
    setLoading(true);
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (sev) params.severity = sev;
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
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
      (hs || []).forEach(h => { m[h.id] = h.hostname; });
      setHostMap(m);
    });
    api.vulnFilters().then(f => {
      setHostIds(f.host_ids || []);
      setContainers(f.containers || []);
    }).catch(() => {});
  }, []);

  useEffect(() => { load(0, severity, hostId, container, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch); }, [load, severity, hostId, container, showNoFix, showMismatch]);

  const handleSearch = () => { load(0, severity, hostId, container, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : col === 'cvss_score' || col === 'severity';
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, severity, hostId, container, pkgQuery, col, nextDesc, showNoFix, showMismatch);
  };

  const sortArrow = (col: string) => {
    if (sortBy !== col) return ' ↕';
    return sortDesc ? ' ▼' : ' ▲';
  };

  const badgeClass = (sev: string) => `badge badge-${sev.toLowerCase()}`;

  const cols: [string, string][] = [
    ['vulnerability_id', 'CVE'], ['severity', 'Severity'], ['cvss_score', 'CVSS'],
    ['pkg_name', 'Package'], ['container', 'Container'],
    ['installed_version', 'Installed'], ['fixed_version', 'Fixed'],
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
          <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{total} results</span>
        </div>
      </div>
      <div className="card">
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <th key={key} className="clickable" onClick={() => toggleSort(key)} style={{ userSelect: 'none' }}>{label}{sortArrow(key)}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} style={{ cursor: 'pointer' }} onClick={() => onSelectVuln(v)}>
                  <td><span className="host-link">{hostMap[v.host_id] || v.host_id.slice(0, 8)}</span></td>
                  <td className="mono">
                    <span className="host-link" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</span>
                  </td>
                  <td><span className={badgeClass(v.severity)}>{v.severity}</span></td>
                  <td className="mono" style={{ color: v.cvss_score >= 9 ? 'var(--critical)' : v.cvss_score >= 7 ? 'var(--high)' : v.cvss_score >= 4 ? 'var(--medium)' : 'inherit', fontWeight: 600 }}>{v.cvss_score > 0 ? v.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{v.pkg_name}</td>
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
                </tr>
              ))}
              {vulns.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No vulnerabilities found</td></tr>}
            </tbody>
          </table>
        )}
        <div className="pagination">
          <button disabled={page === 0} onClick={() => load(page - 1, severity, hostId, container, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch)}>Prev</button>
          <span>Page {page + 1} of {Math.max(1, Math.ceil(total / limit))}</span>
          <button disabled={(page + 1) * limit >= total} onClick={() => load(page + 1, severity, hostId, container, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch)}>Next</button>
        </div>
      </div>
    </>
  );
}

function VulnDetailView({ vuln, onBack }: { vuln: Vuln | null; onBack: () => void }) {
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});

  useEffect(() => {
    api.hosts().then(hs => {
      const m: Record<string, string> = {};
      const ip: Record<string, string> = {};
      (hs || []).forEach(h => { m[h.id] = h.hostname; ip[h.id] = h.ip_address; });
      setHostMap(m); setHostIPMap(ip);
    });
  }, []);

  if (!vuln) return <div>No vulnerability selected</div>;

  const badgeClass = `badge badge-${vuln.severity.toLowerCase()}`;
  const sevColor = vuln.severity === 'CRITICAL' ? 'var(--critical)' : vuln.severity === 'HIGH' ? 'var(--high)' : vuln.severity === 'MEDIUM' ? 'var(--medium)' : 'var(--low)';

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
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
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

  useEffect(() => { load(0); }, [load]);

  const statusColor = (s: string) => s === 'completed' ? 'var(--low)' : s === 'failed' ? 'var(--critical)' : 'var(--medium)';

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Scan History</h1>
      <div className="card">
        <div className="card-header">
          <h2>{total} scans</h2>
        </div>
        {loading ? <div style={{ padding: '2rem', textAlign: 'center' }}>Loading...</div> : (
          <table>
            <thead>
              <tr><th>Date</th><th>Host</th><th>Type</th><th>Status</th><th>Started</th><th>Finished</th><th></th></tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id}>
                  <td className="mono">{new Date(s.created_at).toLocaleString()}</td>
                  <td><span className="host-link" title={`IP: ${hostIPMap[s.host_id] || ''}`}>{hostMap[s.host_id] || s.host_id}</span></td>
                  <td>{s.scan_type}</td>
                  <td style={{ color: statusColor(s.status), fontWeight: 600 }}>{s.status}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>{s.finished_at ? new Date(s.finished_at).toLocaleString() : '-'}</td>
                  <td><button className="delete-btn" onClick={() => { if (confirm('Delete this scan and all associated data?')) { api.deleteScan(s.id).then(() => load(page)).catch(() => alert('Delete failed')); } }}>Delete</button></td>
                </tr>
              ))}
              {scans.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No scans recorded</td></tr>}
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
