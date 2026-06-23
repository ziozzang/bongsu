import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useTheme } from './hooks/useTheme';
import { LiveIndicator } from './components/LiveIndicator';
import { subscribeLiveBus } from './hooks/useLiveEvents';
import { CommandPalette, type CommandItem } from './components/CommandPalette';
import { DataTable, type Column } from './components/DataTable';
import { getHashView, setHashView } from './hooks/useHashRoute';
import { verCmp } from './lib/version';
import { type SeverityTone, findingSourceLabel, riskLevelLabel, riskLevelColor, recommendedActionLabel, recommendedActionTone, riskLevelTone, isVulnAnalysis, aiPolicyModeTone, aiPolicyModeBlurb, aiApprovalStatusTone, aiActionLabel, aiProposedSummary, strField, SEVERITY_ORDER, severityColor, agentStatusColor } from './lib/severity';
import { formatDateTime, formatDateTimeFull, formatDateOnly, fmtCount, shortDate, niceMax, formatAge } from './lib/format';
import { type ScanRequestFilters, type VulnerabilityFilters, type HostFilters } from './lib/viewTypes';
import { Icon, BeaconMark } from './components/Icon';
import { Loading, LoadError, EmptyState, SortHeader, Badge, toneColor } from './components/primitives';
import { StackedAreaChart, BarSeries, DonutChart, Sparkline, KpiCard, SEV_KEYS } from './components/charts';
import { RangeSwitcher, CheckboxField, Modal, Pager } from './components/controls';
import { renderFactValue, FactsCard } from './components/FactsCard';
import { CvssTooltip } from './components/CvssTooltip';
import { UsersView } from './views/UsersView';
import { ApiTokensView } from './views/ApiTokensView';
import { AuditLogView } from './views/AuditLogView';
import { SchedulesView } from './views/SchedulesView';
import { AiApprovalsView } from './views/AiApprovalsView';
import { RBACView } from './views/RBACView';
import { NotificationsView } from './views/NotificationsView';
import { ContainersView } from './views/ContainersView';
import { TrendsView } from './views/TrendsView';
import { ScansView } from './views/ScansView';
import { AiTriageView } from './views/AiTriageView';
import { PackagesView } from './views/PackagesView';
import { AssetGroupsView } from './views/AssetGroupsView';
import { CveSearchView } from './views/CveSearchView';
import { HostsView } from './views/HostsView';
import { ReportsView } from './views/ReportsView';
import { TopologyView } from './views/TopologyView';
import { api, setApiKey, getApiKey, clearApiKey, setSession, getSession, clearSession, hasAuth, onAuthFailure, type Host, type UserAccount, type ProcessSnapshot, type PortInfo, type Vuln, type Pkg, type Stats, type FilterOptions, type Scan, type ScanRequest, type HealthStatus, type CveDbEntry, type CveAffectedPackage, type CveReferenceGroupSummary, type CveDbStatsResponse, type CveSourceStat, type CveRematchPolicy, type CveEpssMergeStats, type CveDbQuality, type InstallerStatus, type SecurityDbOperationalStatus, type AgentFleetStatus, type ContainerAsset, type VulnSummaryRow, type AuditLog, type AccessSubject, type AccessPolicy, type AccessControlStatus, type ScheduledScan, type AssetGroup, type AssetGroupDetail, type VulnTrendRow, type ScanActivityRow, type VulnTrendSummary, type AtRiskHost, type Recommendation, type PostureComparison, type ExecutiveSummary, type SLAComplianceReport, type RiskBreakdownRow, type NotificationRule, type NotificationLogEntry, type GraphNodeType, type GraphNode, type GraphNeighborhood, type GraphSchema, type GraphOverview, type BlastRadiusRollup, type ExposedService, type ImageExposure, type OrgExposure, type OrgExposureRow, type RemediationRow, type CveGraphInfo, type LocalUser, type ApiToken, type LLMStatus, type VulnAnalysis, type AIPolicyStatus, type AIApproval } from './api';





// renderFactValue formats an arbitrary JSON fact value for display: scalars
// inline, string arrays as comma lists, arrays of objects as compact rows, and
// nested objects as an indented key/value block.


function dateInputValue(value?: string | null) {
  if (!value) return '';
  return value.slice(0, 10);
}

// ── Shared formatting helpers ────────────────────────────────────────────────
// One date/time format used across every view: local "YYYY-MM-DD HH:mm".

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

type View = 'dashboard' | 'hosts' | 'packages' | 'containers' | 'vulns' | 'vuln-detail' | 'scans' | 'audit' | 'rbac' | 'host-detail' | 'cve-search' | 'schedules' | 'asset-groups' | 'trends' | 'reports' | 'notifications' | 'topology' | 'users' | 'tokens' | 'ai-triage' | 'ai-approvals';

type AffectedAsset = {
  host_id: string;
  hostname: string;
  owner: string;
  team: string;
  environment: string;
  criticality: string;
  container: string;
  image_name: string;
  asset_type: string;
  pkg_name: string;
  pkg_type: string;
  installed_version: string;
  fixed_version: string;
  severity: string;
  cvss_score: number;
};
type AffectedAssetsResponse = {
  vulnerability_id: string;
  total: number;
  assets: AffectedAsset[];
};

// Direct fetch for the affected-assets endpoint (no api.ts helper exists for it yet).
async function fetchAffectedAssets(vulnerabilityId: string, limit = 500): Promise<AffectedAssetsResponse> {
  const url = new URL('/api/vulnerabilities/affected-assets', window.location.origin);
  url.searchParams.set('vulnerability_id', vulnerabilityId);
  url.searchParams.set('limit', String(limit));
  const headers: Record<string, string> = {};
  const key = getApiKey();
  const session = getSession();
  if (key) headers['X-API-Key'] = key;
  if (session) headers['Authorization'] = `Bearer ${session}`;
  const res = await fetch(url.toString(), { headers });
  if (!res.ok) throw new Error(`Failed to load affected assets (${res.status})`);
  return res.json();
}

export default function App() {
  const [view, setView] = useState<View>(viewFromHash);
  const [scanRequestFilters, setScanRequestFilters] = useState<ScanRequestFilters>({});
  const [vulnerabilityFilters, setVulnerabilityFilters] = useState<VulnerabilityFilters>({});
  const [hostFilters, setHostFilters] = useState<HostFilters>({});
  const [selectedHostId, setSelectedHostId] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<Vuln | null>(null);
  const [authed, setAuthed] = useState(hasAuth());
  const [noAuthMode, setNoAuthMode] = useState(false);
  const [cmdkOpen, setCmdkOpen] = useState(false);

  useEffect(() => {
    api.rawHealth().then(h => {
      if (!h.web_auth) { setNoAuthMode(true); setAuthed(true); }
    }).catch(() => {});
    onAuthFailure(() => setAuthed(false));
  }, []);

  // ⌘K / Ctrl-K toggles the command palette globally.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) {
        e.preventDefault();
        setCmdkOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Keep the URL hash and the active view in sync both ways (deep links + back/
  // forward). The guards make the two effects idempotent so they can't loop.
  useEffect(() => {
    setHashView(view);
  }, [view]);
  useEffect(() => {
    const onHash = () => {
      const v = viewFromHash();
      setView((prev) => (prev === v ? prev : v));
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  if (!authed) return <LoginScreen onLogin={() => setAuthed(true)} />;

  const navigate = (v: View) => {
    if (v === 'scans') setScanRequestFilters({});
    if (v === 'vulns') setVulnerabilityFilters({});
    if (v === 'hosts') setHostFilters({});
    setView(v);
  };
  const openScanRequests = (filters: ScanRequestFilters) => {
    setScanRequestFilters(filters);
    setView('scans');
  };
  const openVulnerabilities = (filters: VulnerabilityFilters) => {
    setVulnerabilityFilters(filters);
    setView('vulns');
  };
  const openHosts = (filters: HostFilters) => {
    setHostFilters(filters);
    setView('hosts');
  };

  const cmdkItems: CommandItem[] = NAV_GROUPS.flatMap((g) =>
    g.items.map(([v, label, icon]) => ({
      id: v,
      label,
      group: g.label,
      keywords: v,
      icon: <Icon name={icon} size={16} />,
      run: () => navigate(v),
    })),
  );

  return (
    <div className="layout">
      <CommandPalette open={cmdkOpen} onClose={() => setCmdkOpen(false)} items={cmdkItems} placeholder="Jump to a page…  (⌘K / Ctrl-K)" />
      <Sidebar view={view} onNavigate={navigate} onOpenSearch={() => setCmdkOpen(true)} onLogout={noAuthMode ? undefined : () => { clearApiKey(); clearSession(); setAuthed(false); }} />
      <div className="main">
        {view === 'dashboard' && <DashboardView onOpenScanRequests={openScanRequests} onOpenVulnerabilities={openVulnerabilities} onOpenHosts={openHosts} />}
        {view === 'hosts' && <HostsView initialFilters={hostFilters} onSelectHost={(id) => { setSelectedHostId(id); setView('host-detail'); }} />}
        {view === 'host-detail' && <HostDetailView key={selectedHostId} hostId={selectedHostId} onBack={() => setView('hosts')} onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'packages' && <PackagesView onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'containers' && <ContainersView />}
        {view === 'cve-search' && <CveSearchView />}
        {view === 'scans' && <ScansView initialRequestFilters={scanRequestFilters} />}
        {view === 'rbac' && <RBACView />}
        {view === 'users' && <UsersView />}
        {view === 'tokens' && <ApiTokensView />}
        {view === 'audit' && <AuditLogView />}
        {view === 'vulns' && <VulnsView initialFilters={vulnerabilityFilters} onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'vuln-detail' && <VulnDetailView key={selectedVuln?.id || ''} vuln={selectedVuln} onBack={() => setView('vulns')} />}
        {view === 'schedules' && <SchedulesView />}
        {view === 'asset-groups' && <AssetGroupsView />}
        {view === 'trends' && <TrendsView />}
        {view === 'reports' && <ReportsView />}
        {view === 'notifications' && <NotificationsView />}
        {view === 'topology' && <TopologyView onSelectHost={(id) => { setSelectedHostId(id); setView('host-detail'); }} />}
        {view === 'ai-triage' && <AiTriageView onSelectVuln={(v) => { setSelectedVuln(v); setView('vuln-detail'); }} />}
        {view === 'ai-approvals' && <AiApprovalsView />}
      </div>
    </div>
  );
}

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [apiKeyInput, setApiKeyInput] = useState('');
  const [error, setError] = useState('');
  const [showApiKey, setShowApiKey] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleLogin = async () => {
    if (!username || !password) return;
    setLoading(true);
    setError('');
    try {
      const result = await api.login(username, password);
      setSession(result.token);
      onLogin();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleApiKeyLogin = () => {
    if (!apiKeyInput) return;
    setApiKey(apiKeyInput);
    onLogin();
  };

  return (
    <div className="login-wrapper">
      <div className="login-card">
        <h2>Bongsu</h2>
        <div className="login-subtitle">Package Vulnerability Monitor</div>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
          autoFocus
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') handleLogin(); }}
        />
        {error && <div className="login-error">{error}</div>}
        <button
          className="login-btn"
          onClick={handleLogin}
          disabled={loading || !username || !password}
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
        <div className="login-divider">
          <span>or</span>
        </div>
        {showApiKey ? (
          <>
            <input
              type="password"
              placeholder="API Key"
              value={apiKeyInput}
              onChange={(e) => setApiKeyInput(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') handleApiKeyLogin(); }}
            />
            <button
              className="login-btn login-btn-secondary"
              onClick={handleApiKeyLogin}
              disabled={!apiKeyInput}
            >
              Connect with API Key
            </button>
          </>
        ) : (
          <button
            className="login-btn login-btn-secondary"
            onClick={() => setShowApiKey(true)}
          >
            Use API Key
          </button>
        )}
      </div>
    </div>
  );
}

function ChangePasswordPanel({ onClose }: { onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!current || !next) { setMsg('All fields are required'); return; }
    if (next !== confirm) { setMsg('New passwords do not match'); return; }
    setBusy(true);
    setMsg('');
    try {
      await api.changePassword(current, next);
      setMsg('Password changed');
      setCurrent(''); setNext(''); setConfirm('');
      window.setTimeout(onClose, 1200);
    } catch (err) {
      setMsg(err instanceof Error ? err.message : 'Password change failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); onClose(); } }} style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>Change Password</div>
      <input type="password" placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} autoComplete="current-password" />
      <input type="password" placeholder="New password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" />
      <input type="password" placeholder="Confirm new password" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="new-password" />
      <div style={{ display: 'flex', gap: '0.5rem' }}>
        <button type="submit" className="filter-btn" disabled={busy}>{busy ? 'Saving...' : 'Save'}</button>
        <button type="button" onClick={onClose}>Cancel</button>
      </div>
      {msg && <div style={{ fontSize: '0.75rem', color: msg === 'Password changed' ? 'var(--low)' : 'var(--critical)' }}>{msg}</div>}
    </form>
  );
}

// NAV_GROUPS is the single source of truth for primary navigation, shared by the
// sidebar and the command palette. Order reflects the redesign's IA priority:
// Overview -> Security -> Inventory -> Topology -> Administration.
const NAV_GROUPS: { label: string; items: [View, string, string][] }[] = [
  { label: 'Overview', items: [
    ['dashboard', 'Dashboard', 'dashboard'],
    ['trends', 'Trends', 'trends'],
    ['reports', 'Reports', 'reports'],
  ] },
  { label: 'Security', items: [
    ['vulns', 'Vulnerabilities', 'vulnerabilities'],
    ['cve-search', 'CVE Search', 'cve-search'],
    ['ai-triage', 'AI Triage', 'ai-triage'],
    ['scans', 'Scan History', 'scans'],
  ] },
  { label: 'Inventory', items: [
    ['hosts', 'Hosts', 'hosts'],
    ['packages', 'Packages', 'packages'],
    ['containers', 'Containers', 'containers'],
    ['asset-groups', 'Asset Groups', 'asset-groups'],
  ] },
  { label: 'Topology', items: [
    ['topology', 'Topology', 'topology'],
  ] },
  { label: 'Administration', items: [
    ['users', 'Users', 'users'],
    ['tokens', 'API Tokens', 'tokens'],
    ['rbac', 'RBAC', 'rbac'],
    ['audit', 'Audit Log', 'audit'],
    ['ai-approvals', 'AI Approvals', 'ai-approvals'],
    ['schedules', 'Schedules', 'schedules'],
    ['notifications', 'Notifications', 'notifications'],
  ] },
];

// Routing: the set of valid views and the list each detail view falls back to
// when its URL is loaded directly (no in-memory selection).
const ALL_VIEWS = new Set<View>(['dashboard', 'hosts', 'host-detail', 'packages', 'containers', 'vulns', 'vuln-detail', 'scans', 'audit', 'rbac', 'cve-search', 'schedules', 'asset-groups', 'trends', 'reports', 'notifications', 'topology', 'users', 'tokens', 'ai-triage', 'ai-approvals']);
const DETAIL_FALLBACK: Partial<Record<View, View>> = { 'host-detail': 'hosts', 'vuln-detail': 'vulns' };

function viewFromHash(): View {
  const h = getHashView() as View;
  if (!ALL_VIEWS.has(h)) return 'dashboard';
  return DETAIL_FALLBACK[h] ?? h;
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  const next = theme === 'dark' ? 'light' : 'dark';
  return (
    <button
      type="button"
      className="theme-toggle"
      onClick={toggle}
      title={`Switch to ${next} theme`}
      aria-label={`Switch to ${next} theme`}
    >
      <span className="nav-icon"><Icon name={theme === 'dark' ? 'sun' : 'moon'} size={16} /></span>
      <span>{theme === 'dark' ? 'Light mode' : 'Dark mode'}</span>
    </button>
  );
}

function Sidebar({ view, onNavigate, onLogout, onOpenSearch }: { view: View; onNavigate: (v: View) => void; onLogout?: () => void; onOpenSearch?: () => void }) {
  const [me, setMe] = useState<{ username: string; role: string } | null>(null);
  const [showPw, setShowPw] = useState(false);
  useEffect(() => {
    if (!onLogout) return;
    api.authMe().then(r => setMe(r.user ? { username: r.user.username, role: r.user.role } : null)).catch(() => setMe(null));
  }, [onLogout]);
  const groups = NAV_GROUPS;
  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <h1><span className="brand-icon"><BeaconMark size={22} /></span> Bongsu</h1>
      </div>
      {onOpenSearch && (
        <button type="button" className="sidebar-search" onClick={onOpenSearch} aria-label="Open command palette">
          <span className="nav-icon"><Icon name="cve-search" size={15} /></span>
          <span className="sidebar-search-label">Search</span>
          <kbd className="sidebar-search-kbd">⌘K</kbd>
        </button>
      )}
      <nav>
        {groups.map(group => (
          <div className="nav-group" key={group.label}>
            <div className="nav-group-label">{group.label}</div>
            {group.items.map(([v, label, icon]) => (
              <a key={v} className={view === v ? 'active' : ''} href="#" onClick={(e) => { e.preventDefault(); onNavigate(v); }}>
                <span className="nav-icon"><Icon name={icon} size={17} /></span>
                {label}
              </a>
            ))}
          </div>
        ))}
      </nav>
      {onLogout && <LiveIndicator />}
      <ThemeToggle />
      {onLogout && showPw && <ChangePasswordPanel onClose={() => setShowPw(false)} />}
      {onLogout && (
        <div className="sidebar-footer">
          {me && (
            <button
              type="button"
              className="user-chip"
              title="Change password"
              onClick={() => setShowPw(s => !s)}
            >
              <span className="user-avatar">{me.username.slice(0, 1).toUpperCase()}</span>
              <span className="user-meta">
                <span className="user-name">{me.username}</span>
                <span className="user-role">{me.role}</span>
              </span>
              <Icon name="settings" size={15} className="user-chip-gear" />
            </button>
          )}
          <a href="#" className="logout" onClick={(e) => { e.preventDefault(); onLogout(); }}>
            <span className="nav-icon"><Icon name="logout" size={16} /></span> Logout
          </a>
        </div>
      )}
    </div>
  );
}

function DashboardView({ onOpenScanRequests, onOpenVulnerabilities, onOpenHosts }: { onOpenScanRequests: (filters: ScanRequestFilters) => void; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void; onOpenHosts: (filters: HostFilters) => void }) {
  const [stats, setStats] = useState<Stats | null>(null);
  const [statsError, setStatsError] = useState('');
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [securityDbConfigured, setSecurityDbConfigured] = useState(false);
  const [cveSources, setCveSources] = useState<CveSourceStat[]>([]);
  const [cveRematchPolicy, setCveRematchPolicy] = useState<CveRematchPolicy | null>(null);
  const [cveAffectedIndex, setCveAffectedIndex] = useState<HealthStatus['cve_affected_package_index'] | null>(null);
  const [cveReferenceIndex, setCveReferenceIndex] = useState<HealthStatus['cve_reference_key_index'] | CveDbStatsResponse['reference_key_index'] | null>(null);
  const [cveEpssMerge, setCveEpssMerge] = useState<CveEpssMergeStats | null>(null);
  const [cveDbQuality, setCveDbQuality] = useState<CveDbQuality | null>(null);
  const [cveStatsMeta, setCveStatsMeta] = useState<Pick<CveDbStatsResponse, 'cache_status' | 'generated_at' | 'durations_ms' | 'osv_ecosystems' | 'osv_ecosystems_error'> | null>(null);
  const [installerStatus, setInstallerStatus] = useState<InstallerStatus | null>(null);
  const [securityDbStatus, setSecurityDbStatus] = useState<SecurityDbOperationalStatus | null>(null);
  const [agentFleetStatus, setAgentFleetStatus] = useState<AgentFleetStatus | null>(null);
  const [dashboardHosts, setDashboardHosts] = useState<Host[]>([]);
  const [agentCounts, setAgentCounts] = useState<Record<string, number>>({});
  const [totalPkgs, setTotalPkgs] = useState(0);
  const [ownerSummary, setOwnerSummary] = useState<VulnSummaryRow[]>([]);
  const [teamSummary, setTeamSummary] = useState<VulnSummaryRow[]>([]);
  const [environmentSummary, setEnvironmentSummary] = useState<VulnSummaryRow[]>([]);
  const [criticalitySummary, setCriticalitySummary] = useState<VulnSummaryRow[]>([]);
  const [trendRange, setTrendRange] = useState('30');
  const [trendRows, setTrendRows] = useState<VulnTrendRow[]>([]);
  const [scanRows, setScanRows] = useState<ScanActivityRow[]>([]);
  const [chartsLoading, setChartsLoading] = useState(true);
  const [updating, setUpdating] = useState(false);
  const [updateMsg, setUpdateMsg] = useState('');
  const [rematching, setRematching] = useState(false);
  const [rematchMsg, setRematchMsg] = useState('');
  const [rematchMinQuality, setRematchMinQuality] = useState('');
  const [rematchCandidateLimit, setRematchCandidateLimit] = useState('');
  const [cvssRecalcBusy, setCvssRecalcBusy] = useState(false);
  const [cvssRecalcMsg, setCvssRecalcMsg] = useState('');
  const [securityRecalcBusy, setSecurityRecalcBusy] = useState(false);
  const [securityRecalcMsg, setSecurityRecalcMsg] = useState('');
  const [retentionMsg, setRetentionMsg] = useState('');
  const [retentionBusy, setRetentionBusy] = useState(false);
  const [securityBundleMsg, setSecurityBundleMsg] = useState('');
  const [securityBundleBusy, setSecurityBundleBusy] = useState(false);
  const [securityBundleIncludeTrivy, setSecurityBundleIncludeTrivy] = useState(true);
  const applyCveStats = useCallback((r: CveDbStatsResponse) => {
    setCveSources(r.sources || []);
    setCveRematchPolicy(r.rematch_policy || null);
    setCveAffectedIndex(r.affected_package_index || null);
    setCveEpssMerge(r.epss_merge || null);
    setCveReferenceIndex(r.reference_key_index || null);
    setCveDbQuality(r.cve_db_quality || null);
    setCveStatsMeta({ cache_status: r.cache_status, generated_at: r.generated_at, durations_ms: r.durations_ms, osv_ecosystems: r.osv_ecosystems, osv_ecosystems_error: r.osv_ecosystems_error });
  }, []);
  const applySecurityDbStatus = useCallback((r: SecurityDbOperationalStatus) => {
    setSecurityDbStatus(r);
    setSecurityDbConfigured(!!r.security_db?.configured);
    if (r.cve_affected_package_index) setCveAffectedIndex(r.cve_affected_package_index);
    if (r.cve_reference_key_index) setCveReferenceIndex(r.cve_reference_key_index);
    if (r.cve_db_quality) setCveDbQuality(r.cve_db_quality);
  }, []);
  const refreshSecurityDbStatus = useCallback(() => {
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
  }, [applySecurityDbStatus]);

  const loadStats = useCallback(() => {
    setStatsError('');
    api.stats().then(setStats).catch((e) => setStatsError(e instanceof Error ? e.message : 'Failed to load stats'));
  }, []);
  useEffect(() => { loadStats(); }, [loadStats]);
  // Live KPI refresh: when a low-frequency aggregate event arrives over SSE,
  // refetch the (RBAC-scoped, server-cached) stats + fleet rather than the
  // server pushing a snapshot — so scoped viewers never receive global counts.
  // finding.new is intentionally excluded (it bursts; scan.completed covers it).
  const reloadLiveKpis = useCallback(() => {
    loadStats();
    api.agentFleetStatus().then(r => { setAgentFleetStatus(r); if (r.installer) setInstallerStatus(r.installer); }).catch(() => {});
  }, [loadStats]);
  useEffect(() => {
    const agg = new Set(['scan.completed', 'scan.failed', 'agent.online', 'agent.offline', 'secdb.updated']);
    return subscribeLiveBus((e) => { if (agg.has(e.type)) reloadLiveKpis(); });
  }, [reloadLiveKpis]);
  useEffect(() => {
    api.rawHealth().then(h => {
      setHealth(h);
      setSecurityDbConfigured(!!h.security_db?.configured);
      setCveAffectedIndex(h.cve_affected_package_index || null);
      setCveDbQuality(h.cve_db_quality || null);
    }).catch(() => {});
    refreshSecurityDbStatus();
  }, [updating, refreshSecurityDbStatus]);
  useEffect(() => {
    if (!health?.cve_reference_index_rebuild?.running && !health?.cve_affected_index_rebuild?.running) return;
    const timer = window.setInterval(() => {
      api.rawHealth().then(h => {
        setHealth(h);
        setSecurityDbConfigured(!!h.security_db?.configured);
        setCveAffectedIndex(h.cve_affected_package_index || null);
        setCveDbQuality(h.cve_db_quality || null);
      }).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [health?.cve_reference_index_rebuild?.running, health?.cve_affected_index_rebuild?.running, applyCveStats, refreshSecurityDbStatus]);
  useEffect(() => {
    api.cveDbStats().then(applyCveStats).catch(() => {});
    api.installerStatus().then(setInstallerStatus).catch(() => {});
    api.securityDbStatus().then(applySecurityDbStatus).catch(() => {});
    api.agentFleetStatus().then(r => {
      setAgentFleetStatus(r);
      if (r.installer) setInstallerStatus(r.installer);
    }).catch(() => {});
    api.packages({ limit: '1' }).then(r => setTotalPkgs(r.total)).catch(() => {});
    api.hosts().then(items => {
      setDashboardHosts(items || []);
      setAgentCounts(items.reduce((acc, h) => {
        const status = h.agent_status || 'unknown';
        acc[status] = (acc[status] || 0) + 1;
        return acc;
      }, {} as Record<string, number>));
    }).catch(() => {});
    api.vulnSummary({ group_by: 'owner' }).then(r => setOwnerSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'team' }).then(r => setTeamSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'environment' }).then(r => setEnvironmentSummary(r.items || [])).catch(() => {});
    api.vulnSummary({ group_by: 'criticality' }).then(r => setCriticalitySummary(r.items || [])).catch(() => {});
  }, [applyCveStats]);

  useEffect(() => {
    let active = true;
    setChartsLoading(true);
    Promise.all([
      api.vulnTrends({ days: trendRange }).catch(() => ({ items: [] as VulnTrendRow[] })),
      api.scanActivity({ days: trendRange }).catch(() => ({ days: 0, items: [] as ScanActivityRow[] })),
    ]).then(([t, s]) => {
      if (!active) return;
      setTrendRows(t.items || []);
      setScanRows(s.items || []);
      setChartsLoading(false);
    });
    return () => { active = false; };
  }, [trendRange]);

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
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Security source sync failed or is not configured');
    }
    setUpdating(false);
  };

  const handleAffectedIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveAffectedIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Affected package index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Affected package index rebuild is already running');
      } else {
        setCveAffectedIndex(r.index || null);
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Affected package index rebuilt: ${(r.indexed || 0).toLocaleString()} entries${duration}`);
      }
      if (r.affected_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_affected_index_rebuild: r.affected_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Affected package index rebuild failed');
    }
    setUpdating(false);
  };

  const handleReferenceIndexRebuild = async () => {
    setUpdating(true);
    setUpdateMsg('');
    try {
      const r = await api.rebuildCveReferenceIndex();
      if (r.status === 'queued') {
        setUpdateMsg('Reference key index rebuild queued');
      } else if (r.status === 'running') {
        setUpdateMsg('Reference key index rebuild is already running');
      } else {
        const duration = r.duration_ms ? ` in ${(r.duration_ms / 1000).toFixed(1)}s` : '';
        setUpdateMsg(`Reference key index rebuilt: ${(r.indexed || 0).toLocaleString()} keys${duration}`);
      }
      if (r.reference_index_rebuild) {
        setHealth(prev => ({ ...(prev || {} as HealthStatus), cve_reference_index_rebuild: r.reference_index_rebuild }));
      }
      api.rawHealth().then(setHealth).catch(() => {});
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setUpdateMsg('Reference key index rebuild failed');
    }
    setUpdating(false);
  };

  const handleRematch = async () => {
    setRematching(true);
    setRematchMsg('');
    try {
      const minQuality = Number(rematchMinQuality);
      const candidateLimit = Number(rematchCandidateLimit);
      const body: { min_source_matchable_percent?: number; candidate_limit?: number } = {};
      if (Number.isFinite(minQuality) && minQuality > 0) body.min_source_matchable_percent = minQuality;
      if (Number.isFinite(candidateLimit) && candidateLimit > 0) body.candidate_limit = Math.floor(candidateLimit);
      const r = await api.rematchCVEs(body);
      const qualityMsg = minQuality > 0 ? ` with source quality >= ${minQuality}%` : '';
      const limitMsg = candidateLimit > 0 ? `, candidate limit ${Math.floor(candidateLimit).toLocaleString()}` : '';
      const limitedMsg = r.limited ? `, limited at ${r.candidate_limit.toLocaleString()} candidates` : '';
      const scanned = r.scanned_candidates || r.matched + r.skipped;
      const scannedMsg = r.scanned_candidates ? ` from ${r.scanned_candidates.toLocaleString()} scanned candidates` : '';
      const skippedPct = scanned > 0 ? `, ${(r.skipped * 100 / scanned).toFixed(1)}% skipped` : '';
      const sourceMsg = r.eligible_sources !== undefined ? `, ${r.eligible_sources.toLocaleString()} eligible sources${r.excluded_sources ? `, ${r.excluded_sources.toLocaleString()} excluded` : ''}` : '';
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setRematchMsg(`Matched ${r.matched.toLocaleString()} packages${scannedMsg}${qualityMsg}${limitMsg}, found ${r.new_vulns.toLocaleString()} new vulnerabilities (${r.skipped.toLocaleString()} skipped${skippedPct}${limitedMsg}${sourceMsg}${revisionMsg})`);
      api.stats().then(setStats).catch(() => {});
    } catch {
      setRematchMsg('Rematch failed (check server logs)');
    }
    setRematching(false);
  };

  const minQualityForDisplay = Number.parseFloat(rematchMinQuality);
  const sourceBelowQuality = (s: CveSourceStat) =>
    Number.isFinite(minQualityForDisplay) && minQualityForDisplay > 0 && (s.matchable_percent || 0) < minQualityForDisplay;
  const cveTotalRecords = cveSources.reduce((sum, s) => sum + (s.count || 0), 0);
  const cveTotalMatchable = cveSources.reduce((sum, s) => sum + (s.matchable || 0), 0);
  const cveMatchablePercent = cveTotalRecords > 0 ? (cveTotalMatchable * 100) / cveTotalRecords : 0;
  const cveRematchEligibleCount = cveRematchPolicy?.eligible_sources ?? cveSources.filter(s => s.rematch_eligible !== false).length;
  const cveRematchExcludedCount = cveRematchPolicy?.excluded_sources ?? cveSources.filter(s => s.rematch_eligible === false).length;
  const cveRematchPolicyText = cveRematchPolicy
    ? `${cveRematchPolicy.sources?.length ? `${cveRematchPolicy.sources.length} allowlisted` : 'all sources'}, min ${(cveRematchPolicy.min_source_matchable_percent || 0).toFixed(1)}%`
    : 'policy pending';
  const epssMergeCoverage = cveEpssMerge?.non_epss_coverage_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssUniverseCoverage = cveEpssMerge?.epss_universe_match_percent ?? cveEpssMerge?.merge_coverage_percent ?? 0;
  const epssMergeColor = !cveEpssMerge || cveEpssMerge.epss_cves === 0
    ? 'var(--medium)'
    : epssMergeCoverage < 90
      ? 'var(--high)'
      : 'var(--low)';
  const cveAffectedIndexIndexedOnly = cveAffectedIndex?.summary_mode === 'indexed-only';
  const cveAffectedIndexUnhealthy = !!(cveAffectedIndex?.stale || (cveAffectedIndex?.orphans || 0) > 0 || (cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 || cveAffectedIndex?.error);
  const cveAffectedIndexColor = cveAffectedIndexUnhealthy ? 'var(--high)' : cveAffectedIndexIndexedOnly ? 'var(--medium)' : 'var(--low)';
  const affectedRebuild = health?.cve_affected_index_rebuild;
  const affectedRebuildLast = affectedRebuild?.last_result;
  const affectedRebuildRunning = !!affectedRebuild?.running;
  const affectedRebuildColor = affectedRebuildRunning
    ? 'var(--medium)'
    : affectedRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : affectedRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveReferenceIndexUnhealthy = !!(!cveReferenceIndex || cveReferenceIndex.stale || (cveReferenceIndex.orphans || 0) > 0 || (cveReferenceIndex.coverage_percent ?? 0) < 90);
  const cveReferenceIndexColor = cveReferenceIndexUnhealthy ? 'var(--high)' : 'var(--low)';
  const referenceRebuild = health?.cve_reference_index_rebuild;
  const referenceRebuildLast = referenceRebuild?.last_result;
  const referenceRebuildRunning = !!referenceRebuild?.running;
  const referenceRebuildColor = referenceRebuildRunning
    ? 'var(--medium)'
    : referenceRebuildLast?.status === 'error'
      ? 'var(--critical)'
      : referenceRebuildLast?.status === 'ok'
        ? 'var(--low)'
        : 'var(--text-muted)';
  const cveQualityStatus = cveDbQuality?.status || 'pending';
  const cveQualityColor = cveQualityStatus === 'degraded'
    ? 'var(--critical)'
    : cveQualityStatus === 'warning' || cveQualityStatus === 'pending'
      ? 'var(--medium)'
      : 'var(--low)';
  const cveQualityWarnings = cveDbQuality?.warnings || [];
  const securityDbWarnings = securityDbStatus?.warnings || [];
  const securityDbActions = securityDbStatus?.recommended_actions || [];
  const securitySourceRegistry = securityDbStatus?.security_sources || [];
  const securitySourceRegistryOk = securitySourceRegistry.filter(s => s.enabled && s.last_status === 'ok' && (s.record_count || 0) > 0).length;
  const securitySourceRegistryEnabled = securitySourceRegistry.filter(s => s.enabled).length;
  const securitySourceRegistryRecords = securitySourceRegistry.reduce((sum, s) => sum + (s.record_count || 0), 0);
  const latestSecuritySourceRegistry = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_sync_finished_at) return latest;
    if (!latest?.last_sync_finished_at) return source;
    return new Date(source.last_sync_finished_at).getTime() > new Date(latest.last_sync_finished_at).getTime() ? source : latest;
  }, null);
  const latestSecuritySourceExport = securitySourceRegistry.reduce<typeof securitySourceRegistry[number] | null>((latest, source) => {
    if (!source.last_exported_at) return latest;
    if (!latest?.last_exported_at) return source;
    return new Date(source.last_exported_at).getTime() > new Date(latest.last_exported_at).getTime() ? source : latest;
  }, null);
  const securitySourceRegistryBroken = !!securityDbStatus?.security_sources_error || securitySourceRegistry.some(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error));
  const securityDbExportStatus = securityDbStatus?.security_db_export;
  const latestSecuritySourceDataUpdate = securityDbExportStatus?.latest_source_update_at;
  const latestSecuritySourceRegistryTime = latestSecuritySourceRegistry?.last_sync_finished_at;
  const latestSecuritySourceDisplay = latestSecuritySourceDataUpdate && (!latestSecuritySourceRegistryTime || new Date(latestSecuritySourceDataUpdate).getTime() > new Date(latestSecuritySourceRegistryTime).getTime())
    ? { label: 'data', source: 'cve rows', at: latestSecuritySourceDataUpdate }
    : latestSecuritySourceRegistryTime
      ? { label: 'registry', source: latestSecuritySourceRegistry?.id || 'source', at: latestSecuritySourceRegistryTime }
      : null;
  const securityDbExportStale = securityDbExportStatus?.status === 'stale' || securityDbExportStatus?.status === 'never';
  const securitySourceRegistryColor = securitySourceRegistryBroken
    ? 'var(--critical)'
    : securityDbExportStale
      ? 'var(--medium)'
    : securitySourceRegistry.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const cveStatsCacheStatus = cveStatsMeta?.cache_status || 'unknown';
  const cveStatsGeneratedAt = cveStatsMeta?.generated_at ? new Date(cveStatsMeta.generated_at).toLocaleString() : 'not loaded';
  const cveStatsDuration = cveStatsMeta?.durations_ms?.total;
  const osvEcosystems = cveStatsMeta?.osv_ecosystems || [];
  const osvEcosystemRows = osvEcosystems.reduce((sum, eco) => sum + (eco.indexed_rows || 0), 0);
  const oldestOsvEcosystem = osvEcosystems.reduce<typeof osvEcosystems[number] | null>((oldest, eco) => {
    const at = eco.raw_last_update || eco.last_update;
    const oldestAt = oldest ? (oldest.raw_last_update || oldest.last_update) : null;
    if (!at) return oldest;
    if (!oldestAt) return eco;
    return new Date(at).getTime() < new Date(oldestAt).getTime() ? eco : oldest;
  }, null);
  const osvEcosystemColor = cveStatsMeta?.osv_ecosystems_error
    ? 'var(--high)'
    : osvEcosystems.length > 0
      ? 'var(--low)'
      : 'var(--medium)';
  const weakestCveSource = cveSources.reduce<CveSourceStat | null>((worst, source) =>
    !worst || (source.matchable_percent ?? 0) < (worst.matchable_percent ?? 0) ? source : worst, null);
  const latestCveSource = cveSources.reduce<CveSourceStat | null>((latest, source) => {
    if (!source.last_update) return latest;
    if (!latest?.last_update) return source;
    return new Date(source.last_update).getTime() > new Date(latest.last_update).getTime() ? source : latest;
  }, null);
  const latestSecurityDbSource = latestCveSource?.last_update
    ? { source: latestCveSource.source, last_update: latestCveSource.last_update }
    : health?.security_db_freshness?.latest_source && health.security_db_freshness.latest_last_update
      ? { source: health.security_db_freshness.latest_source, last_update: health.security_db_freshness.latest_last_update }
      : null;
  const osvCveSource = cveSources.find(source => source.source.toLowerCase() === 'osv') || null;
  const staleCveSources = health?.security_db_freshness?.stale_sources || [];
  const missingCveSources = health?.security_db_freshness?.missing_sources || [];
  const staleCveSourceByName = new Map(staleCveSources.map(s => [s.source.toLowerCase(), s]));
  const staleCveSourceCount = staleCveSources.length;
  const cveSourceAlertCount = staleCveSourceCount + missingCveSources.length;
  const oldestCveAgeDays = health?.security_db_freshness?.oldest_age_seconds
    ? health.security_db_freshness.oldest_age_seconds / 86400
    : 0;
  const securityDbFreshnessStatus = health?.security_db_freshness?.status || '';
  const effectiveSecurityDbStatus = health?.security_db?.effective_status || securityDbFreshnessStatus;
  const securitySourcesReady = !!health?.security_db?.configured && (
    health?.security_db?.status === 'ok' ||
    effectiveSecurityDbStatus === 'ok'
  );
  const securitySourcesLabel = !health?.security_db?.configured
    ? 'not configured'
    : securitySourcesReady
      ? 'ok'
      : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatus = !securityDbConfigured
    ? 'not configured'
    : health?.security_db?.running
      ? 'syncing'
      : securityDbStatus?.status === 'warning'
        ? 'warning'
      : health?.security_db_freshness?.stale
        ? 'stale'
        : securityDbStatus?.status === 'degraded'
          ? 'degraded'
        : effectiveSecurityDbStatus === 'ok'
          ? 'ok'
          : effectiveSecurityDbStatus || health?.security_db?.status || 'unknown';
  const cveDbStatusColor = !securityDbConfigured || cveDbStatus === 'stale'
    ? 'var(--critical)'
    : cveDbStatus === 'degraded'
      ? 'var(--critical)'
    : cveDbStatus === 'syncing' || cveDbStatus === 'unknown' || cveDbStatus === 'warning'
      ? 'var(--medium)'
      : 'var(--low)';
  const securitySyncNext = health?.security_db?.next_sync && !health.security_db.next_sync.startsWith('0001-')
    ? new Date(health.security_db.next_sync).toLocaleString()
    : '';
  const securitySyncLast = health?.security_db?.last_attempt && !health.security_db.last_attempt.startsWith('0001-')
    ? new Date(health.security_db.last_attempt).toLocaleString()
    : '';
  const securitySyncStatus = health?.security_db?.running
    ? 'syncing'
    : effectiveSecurityDbStatus === 'ok'
      ? 'ok'
    : health?.security_db?.status === 'never' && latestSecurityDbSource?.last_update
      ? 'waiting'
      : health?.security_db?.status || '-';
  const securitySyncDetail = securitySyncLast
    ? `last sync ${securitySyncLast}`
    : health?.security_db?.effective_last_sync
      ? `effective ${effectiveSecurityDbStatus || 'unknown'} from ${(health.security_db.effective_source || 'source').toUpperCase()} ${new Date(health.security_db.effective_last_sync).toLocaleString()}`
    : latestSecurityDbSource?.last_update
      ? `latest source ${latestSecurityDbSource.source.toUpperCase()} ${new Date(latestSecurityDbSource.last_update).toLocaleString()}`
      : securitySyncNext
        ? `next ${securitySyncNext}`
        : `interval ${health?.security_db?.interval || '-'}`;
  const cveFreshnessColor = missingCveSources.length > 0 || staleCveSourceCount > 0 || health?.security_db_freshness?.stale ? 'var(--critical)' : 'var(--low)';
  const cveMatchableColor = cveMatchablePercent < 50 && cveTotalRecords > 0
    ? 'var(--critical)'
    : cveMatchablePercent < 80 && cveTotalRecords > 0
      ? 'var(--medium)'
      : 'var(--low)';
  const lastRecalc = health?.security_recalculation?.last_result;
  const lastManualRematch = health?.cve_db_rematch?.last_result;
  const lastAutoRescan = health?.security_db_auto_rescan?.last_result;
  const lastSecurityBundleImport = securityDbStatus?.security_db_bundle_import?.last_result;
  const lastRecalcLimited = !!lastRecalc?.rematch_limited;
  const lastManualRematchLimited = !!lastManualRematch?.limited;
  const lastRecalcColor = lastRecalc?.status === 'error'
    ? 'var(--critical)'
    : lastRecalcLimited
      ? 'var(--high)'
    : lastRecalc?.status === 'ok'
      ? 'var(--low)'
      : 'var(--medium)';
  const lastRecalcTitle = lastRecalcLimited
    ? `Rematch hit candidate limit ${lastRecalc?.rematch_candidate_limit || 0}`
    : lastRecalc?.errors?.length ? lastRecalc.errors.join('\n') : lastRecalc?.reason || '';
  const lastManualRematchColor = lastManualRematch?.status === 'error'
    ? 'var(--critical)'
    : lastManualRematchLimited
      ? 'var(--high)'
      : lastManualRematch?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const lastAutoRescanColor = lastAutoRescan?.status === 'error'
    ? 'var(--critical)'
    : lastAutoRescan?.status === 'disabled'
      ? 'var(--medium)'
      : lastAutoRescan?.status === 'ok'
        ? 'var(--low)'
        : 'var(--medium)';
  const rescanProgress = stats?.security_db_rescan_progress || {};
  const rescanCompletePercent = Number(rescanProgress.complete_percent || 0);
  const rescanProgressColor = (rescanProgress.failed || 0) > 0
    ? 'var(--critical)'
    : (rescanProgress.open || 0) > 0
      ? 'var(--medium)'
      : (rescanProgress.total || 0) > 0
        ? 'var(--low)'
        : 'var(--text-muted)';
  const scanCoverage = stats?.security_db_scan_coverage || {};
  const scanCoveragePercent = Number(scanCoverage.coverage_percent || 0);
  const scanCoverageColor = (scanCoverage.stale_hosts || 0) > 0 || (scanCoverage.unknown_hosts || 0) > 0
    ? 'var(--medium)'
    : (scanCoverage.current_hosts || 0) > 0
      ? 'var(--low)'
      : 'var(--text-muted)';
  const triageActiveCounts = stats?.triage_active_counts || {};
  const triageExpiringSoonCounts = stats?.triage_expiring_soon_counts || {};
  const suppressedTriageCount = ['accepted_risk', 'false_positive', 'fixed', 'ignored']
    .reduce((sum, status) => sum + (triageActiveCounts[status] || 0), 0);
  const triageExpiringSoonTotal = Object.values(triageExpiringSoonCounts).reduce((sum, count) => sum + count, 0);
  const effectiveAgentCounts = stats?.agent_status_counts || agentCounts;
  const effectiveInventoryCounts = stats?.inventory_status_counts || {};
  const inventoryCoveragePercent = stats?.inventory_coverage_percent ?? 0;
  const inventoryFreshPercent = stats?.inventory_fresh_percent ?? 0;
  const agentFleetWarnings = agentFleetStatus?.warnings || [];
  const agentFleetActions = agentFleetStatus?.recommended_actions || [];
  const agentVersionDriftCounts = agentFleetStatus?.agent_version_drift_counts || stats?.agent_version_drift_counts || {};
  const latestAgentVersion = agentFleetStatus?.latest_agent_version || stats?.latest_agent_version || installerStatus?.agent?.version || '';
  const currentAgentCount = agentVersionDriftCounts.current ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version === latestAgentVersion).length : 0);
  const outdatedAgentCount = agentVersionDriftCounts.outdated ?? (latestAgentVersion ? dashboardHosts.filter(h => h.agent_version && h.agent_version !== latestAgentVersion).length : 0);
  const unknownAgentVersionCount = agentVersionDriftCounts.unknown ?? dashboardHosts.filter(h => !h.agent_version).length;
  const agentFleetOutdatedPercent = agentFleetStatus?.outdated_percent ?? (dashboardHosts.length ? (outdatedAgentCount / dashboardHosts.length) * 100 : 0);
  const inventoryCoverageColor = inventoryCoveragePercent < 70
    ? 'var(--critical)'
    : inventoryCoveragePercent < 90
      ? 'var(--medium)'
      : 'var(--low)';

  const handleCvssRecalc = async () => {
    setCvssRecalcBusy(true);
    setCvssRecalcMsg('');
    try {
      const r = await api.recalcCveCVSS();
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setCvssRecalcMsg(`Recalculated ${r.updated.toLocaleString()} CVSS records${revisionMsg}`);
      api.cveDbStats().then(applyCveStats).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setCvssRecalcMsg('CVSS recalculation failed or requires admin API key');
    }
    setCvssRecalcBusy(false);
  };

  const handleSecurityRecalc = async () => {
    setSecurityRecalcBusy(true);
    setSecurityRecalcMsg('');
    try {
      const r = await api.recalculateSecurityDB({ reason: 'manual dashboard recalculation' });
      const revisionMsg = r.security_db_revision ? `, DB rev ${r.security_db_revision}` : r.security_db_revision_error ? ', DB revision unavailable' : '';
      setSecurityRecalcMsg(`Security recalculation ${r.status}${revisionMsg}`);
      api.rawHealth().then(setHealth).catch(() => {});
      refreshSecurityDbStatus();
    } catch {
      setSecurityRecalcMsg('Security recalculation queue failed or requires admin API key');
    }
    setSecurityRecalcBusy(false);
  };

  const openCurrentDBRescans = (status: string, stale?: boolean) => {
    const revision = stats?.security_db_revision || health?.security_db_revision || '';
    if (!revision) return;
    onOpenScanRequests({ status, scan_type: 'security-db-update', security_db_revision: revision, ...(stale ? { stale: 'true' } : {}) });
  };

  const handleRetentionPrune = async (dryRun: boolean) => {
    setRetentionBusy(true);
    setRetentionMsg('');
    try {
      const r = await api.pruneRetention({ dry_run: dryRun });
      const inventoryRows = r.packages + r.vulnerabilities + r.containers + r.users + r.processes + r.ports;
      const affected = r.scans + inventoryRows + r.scan_requests + r.audit_logs;
      const scanCutoff = r.scan_cutoff ? new Date(r.scan_cutoff).toLocaleString() : `${r.scan_days}d`;
      const requestCutoff = r.request_cutoff ? new Date(r.request_cutoff).toLocaleString() : `${r.request_days}d`;
      const auditCutoff = r.audit_cutoff ? new Date(r.audit_cutoff).toLocaleString() : `${r.audit_days}d`;
      setRetentionMsg(`${dryRun ? 'Dry run' : 'Pruned'}: ${affected.toLocaleString()} records (${r.scans} scans before ${scanCutoff}, ${inventoryRows} inventory rows, ${r.scan_requests} requests before ${requestCutoff}, ${r.audit_logs} audit logs before ${auditCutoff})`);
    } catch {
      setRetentionMsg('Retention prune failed or requires admin API key');
    }
    setRetentionBusy(false);
  };

  const handleSecurityBundleExport = async () => {
    setSecurityBundleBusy(true);
    setSecurityBundleMsg('Preparing bundle on the server — the full CVE DB is packaged and checksummed before the download starts, which takes roughly 30–90 seconds. The download begins automatically when ready...');
    try {
      await api.exportSecurityDBBundle(securityBundleIncludeTrivy);
      setSecurityBundleMsg(`Exported airgap bundle${securityBundleIncludeTrivy ? ' with Trivy DB when available' : ' without Trivy DB'}`);
    } catch {
      setSecurityBundleMsg('Security DB bundle export failed or requires admin API key');
    }
    setSecurityBundleBusy(false);
  };

  const handleSecurityBundleImport = async (file?: File) => {
    if (!file) return;
    setSecurityBundleBusy(true);
    setSecurityBundleMsg(`Uploading ${file.name}…`);
    try {
      const r = await api.importSecurityDBBundle(file);
      // The import runs in the background (the upload streams ~170MB and the DB
      // replace + index rebuild take several minutes), so the upload returns a
      // "started" acknowledgement and we poll the security DB status for the
      // result instead of holding the request open.
      const records = typeof r.bundle_cve_records === 'number' ? `~${r.bundle_cve_records.toLocaleString()} CVE records` : 'the bundle';
      setSecurityBundleMsg(`Import started in the background (${records}). This takes several minutes; the dashboard updates automatically when it completes.`);
      const startedAt = Date.now();
      const poll = setInterval(() => {
        if (Date.now() - startedAt > 30 * 60 * 1000) { clearInterval(poll); setSecurityBundleBusy(false); return; }
        api.securityDbStatus().then(st => {
          const last = st?.security_db_bundle_import?.last_result;
          const status = last?.status;
          if (status === 'ok') {
            clearInterval(poll);
            const imp = typeof last?.imported === 'number' ? last.imported.toLocaleString() : '';
            setSecurityBundleMsg(`Imported ${imp} CVE records${last?.trivy_db_loaded ? ' and Trivy DB' : ''}; recalculation started`);
            api.rawHealth().then(h => { setHealth(h); setSecurityDbConfigured(!!h.security_db?.configured); }).catch(() => {});
            api.cveDbStats().then(applyCveStats).catch(() => {});
            api.stats().then(setStats).catch(() => {});
            refreshSecurityDbStatus();
            setSecurityBundleBusy(false);
          } else if (status === 'error') {
            clearInterval(poll);
            setSecurityBundleMsg(`Bundle import failed: ${last?.message || last?.error || 'see audit log'}`);
            setSecurityBundleBusy(false);
          }
        }).catch(() => {});
      }, 5000);
    } catch {
      setSecurityBundleMsg('Security DB bundle import failed or requires admin API key');
      setSecurityBundleBusy(false);
    }
  };

  // ── Ops console derived data ────────────────────────────────────────────────
  const trendTotals = trendRows.map(r => r.total_vulns);
  const lastTrend = trendRows[trendRows.length - 1];
  // delta vs ~7 days ago within the loaded series (or earliest available point)
  const deltaAt = (sel: (r: VulnTrendRow) => number): number | null => {
    if (trendRows.length < 2) return null;
    const idx = Math.max(0, trendRows.length - 1 - 7);
    const ref = trendRows[idx];
    if (!lastTrend || !ref || ref === lastTrend) return null;
    return sel(lastTrend) - sel(ref);
  };
  const totalDelta = deltaAt(r => r.total_vulns);
  const critDelta = deltaAt(r => r.critical_count);
  const exploitedDelta = deltaAt(r => r.exploited_count);
  const sparkSlice = (sel: (r: VulnTrendRow) => number) => trendRows.slice(-14).map(sel);
  const enoughHistory = trendRows.length >= 2;
  const enoughScans = scanRows.length >= 2;

  const sevCounts = stats?.active_risk_level_counts || {};
  const donutSegments = [
    { label: 'Critical', value: sevCounts.critical || 0, color: '#f04444' },
    { label: 'High', value: sevCounts.high || 0, color: '#f07830' },
    { label: 'Medium', value: sevCounts.medium || 0, color: '#e0b020' },
    { label: 'Low', value: sevCounts.low || 0, color: '#30c060' },
  ];

  if (!stats) return statsError ? <LoadError message={statsError} onRetry={loadStats} /> : <Loading />;

  return (
    <>
      <section className="product-intro">
        <div>
          <div className="eyebrow">Self-hosted vulnerability watchtower</div>
          <h1>bongsu</h1>
          <p>
            Named after 봉수대, the Korean signal-fire watchtower, Bongsu gathers package evidence from hosts and running containers,
            separates OS packages from code libraries, and matches them against CVSS-aware vulnerability databases.
          </p>
        </div>
        <div className="install-box">
          <div className="label">One-line agent install</div>
          <code>curl -fsSL -H "X-Install-Token: $BONGSU_INSTALL_TOKEN" "{window.location.origin}/api/install.sh" | sudo bash</code>
          {installerStatus && (
            <div style={{ marginTop: '0.75rem', display: 'flex', flexWrap: 'wrap', gap: '0.375rem' }}>
              <span className="badge" style={{ color: installerStatus.ready ? 'var(--low)' : 'var(--critical)' }}>
                installer {installerStatus.ready ? 'ready' : 'not ready'}
              </span>
              <span className="badge" style={{ color: installerStatus.agent.ready ? 'var(--low)' : 'var(--critical)' }}>
                agent {installerStatus.agent.ready ? (installerStatus.agent.version || `${Math.round((installerStatus.agent.bytes || 0) / 1024 / 1024)}MB`) : installerStatus.agent.error || 'missing'}
              </span>
              <span className="badge" style={{ color: installerStatus.trivy.ready ? 'var(--low)' : 'var(--medium)' }}>
                trivy {installerStatus.trivy.ready ? `${Math.round((installerStatus.trivy.bytes || 0) / 1024 / 1024)}MB` : installerStatus.trivy.error || 'optional'}
              </span>
            </div>
          )}
          {agentFleetWarnings.length > 0 && (
            <div style={{ marginTop: '0.5rem', color: 'var(--medium)', fontSize: '0.8125rem' }}>
              Agent fleet: {agentFleetWarnings.slice(0, 2).join('; ')}{agentFleetWarnings.length > 2 ? `; +${agentFleetWarnings.length - 2} more` : ''}
            </div>
          )}
          {agentFleetActions.length > 0 && (
            <div style={{ marginTop: '0.25rem', color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
              Action: {agentFleetActions[0]}
            </div>
          )}
        </div>
      </section>

      {/* ── Operations console ──────────────────────────────────────────────── */}
      <div className="console-head">
        <div>
          <h2 className="console-title">Operations Console</h2>
          <div className="console-sub">Fleet vulnerability posture and scan activity</div>
        </div>
        <RangeSwitcher value={trendRange} onChange={setTrendRange} />
      </div>

      <div className="kpi-grid">
        <KpiCard
          label="Total Findings"
          value={(lastTrend?.total_vulns ?? stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}
          accent="var(--primary)"
          delta={totalDelta}
          spark={sparkSlice(r => r.total_vulns)}
          onClick={() => onOpenVulnerabilities({})}
        />
        <KpiCard
          label="Critical Risk"
          value={(stats.active_risk_level_counts?.critical || 0).toLocaleString()}
          accent="var(--critical)"
          delta={critDelta}
          spark={sparkSlice(r => r.critical_count)}
          sparkColor="#f04444"
          onClick={() => onOpenVulnerabilities({ riskLevel: 'critical' })}
        />
        <KpiCard
          label="Exploited"
          value={(lastTrend?.exploited_count || 0).toLocaleString()}
          accent="var(--high)"
          delta={exploitedDelta}
          spark={sparkSlice(r => r.exploited_count)}
          sparkColor="#f07830"
          onClick={() => onOpenVulnerabilities({ exploitedOnly: true })}
        />
        <KpiCard
          label="SLA Overdue"
          value={(stats.overdue_sla_count || 0).toLocaleString()}
          accent="var(--medium)"
          sub={<>C {stats.overdue_sla_risk_counts?.critical || 0} · H {stats.overdue_sla_risk_counts?.high || 0}</>}
          onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
        />
        <KpiCard
          label="Hosts"
          value={(stats.total_hosts || 0).toLocaleString()}
          accent="var(--low)"
          sub={<>{(lastTrend?.host_count ?? stats.total_hosts) || 0} reporting</>}
          onClick={() => onOpenHosts({})}
        />
      </div>

      <div className="console-charts">
        <div className="card chart-card chart-card-wide">
          <div className="card-header">
            <h2>Findings over time</h2>
            <span className="chart-legend">
              {SEV_KEYS.map(s => (
                <span key={s.key} className="chart-legend-item"><span className="chart-legend-dot" style={{ background: s.raw }} />{s.label}</span>
              ))}
            </span>
          </div>
          <div className="chart-body">
            {chartsLoading ? <Loading /> : enoughHistory ? <StackedAreaChart rows={trendRows} /> : <EmptyState message="Not enough history yet — charts appear after 2+ days of snapshots." />}
          </div>
        </div>
        <div className="card chart-card">
          <div className="card-header"><h2>Severity distribution</h2></div>
          <div className="chart-body">
            {donutSegments.reduce((s, x) => s + x.value, 0) > 0
              ? <DonutChart segments={donutSegments} />
              : <EmptyState message="No active findings." />}
          </div>
        </div>
      </div>

      <div className="card chart-card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <h2>Scan activity ({trendRange}d)</h2>
          <span className="chart-legend">
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#7c6cf0' }} />Completed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#e0b020' }} />Degraded</span>
            <span className="chart-legend-item"><span className="chart-legend-dot" style={{ background: '#f04444' }} />Failed</span>
            <span className="chart-legend-item"><span className="chart-legend-dot chart-legend-line" />Packages</span>
          </span>
        </div>
        <div className="chart-body">
          {chartsLoading ? <Loading /> : enoughScans ? <BarSeries rows={scanRows} /> : <EmptyState message="Not enough scan activity yet." />}
        </div>
      </div>

      <div className="stats-grid">
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Total Hosts</div>
          <div className="value">{stats.total_hosts}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Active Findings</div>
          <div className="value" style={{ color: 'var(--high)' }}>{(stats.active_vulnerabilities ?? stats.total_vulnerabilities).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--text-secondary)' }} />
          <div className="label">Raw Vulnerability Rows</div>
          <div className="value">{stats.total_vulnerabilities.toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Critical Risk</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.active_risk_level_counts?.critical || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk</div>
          <div className="value" style={{ color: 'var(--high)' }}>{stats.active_risk_level_counts?.high || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Medium Risk</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.active_risk_level_counts?.medium || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Low Risk</div>
          <div className="value" style={{ color: 'var(--low)' }}>{stats.active_risk_level_counts?.low || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">SLA Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue actionable vulnerabilities"
          >
            {stats.overdue_sla_count || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            C {stats.overdue_sla_risk_counts?.critical || 0} / H {stats.overdue_sla_risk_counts?.high || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">High Risk Overdue</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ overdueOnly: true, riskLevel: 'high' })}
            style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open overdue high-risk vulnerabilities"
          >
            {stats.overdue_sla_risk_counts?.high || 0}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Medium {stats.overdue_sla_risk_counts?.medium || 0} / Low {stats.overdue_sla_risk_counts?.low || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: suppressedTriageCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Suppressed Findings</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: suppressedTriageCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings"
          >
            {suppressedTriageCount}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Accepted {triageActiveCounts.accepted_risk || 0} / FP {triageActiveCounts.false_positive || 0}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)' }} />
          <div className="label">Expiring Exceptions</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenVulnerabilities({ triageStatus: 'accepted_risk' })}
            style={{ color: triageExpiringSoonTotal ? 'var(--high)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open accepted-risk findings with expiry dates"
          >
            {triageExpiringSoonTotal}
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            Next {stats.triage_expiring_soon_days || 14}d, accepted {triageExpiringSoonCounts.accepted_risk || 0}
          </div>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--low)' }} />
          <div className="label">Agents Online</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'online' })}
            style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open online hosts"
          >
            {effectiveAgentCounts.online || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Agents Stale</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'stale' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open stale hosts"
          >
            {effectiveAgentCounts.stale || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Agents Offline</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_status: 'offline' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open offline hosts"
          >
            {effectiveAgentCounts.offline || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: outdatedAgentCount || unknownAgentVersionCount ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Agent Version Drift</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ agent_version_state: 'outdated' })}
            style={{ color: outdatedAgentCount ? 'var(--medium)' : 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts running an older agent than the installer binary"
          >
            {outdatedAgentCount}
          </button>
          <div className="mono" style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>
            current {currentAgentCount} / unknown {unknownAgentVersionCount}{agentFleetStatus ? ` / ${agentFleetOutdatedPercent.toFixed(1)}% outdated` : ''}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: inventoryCoverageColor }} />
          <div className="label">SBOM Coverage</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenHosts({ inventory_status: 'none' })}
            style={{ color: inventoryCoverageColor, background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open hosts without completed or degraded inventory scans"
          >
            {inventoryCoveragePercent.toFixed(1)}%
          </button>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {stats.inventory_covered_hosts || 0} / {stats.total_hosts} hosts, {inventoryFreshPercent.toFixed(1)}% fresh
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Tracked Packages</div>
          <div className="value">{(stats.inventory_latest_packages ?? totalPkgs).toLocaleString()}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
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
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'healthy' })} style={{ color: 'var(--low)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.healthy || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Degraded SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'degraded' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.degraded || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'stale' })} style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.stale || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--high)' }} />
          <div className="label">Empty SBOM</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'empty' })} style={{ color: 'var(--high)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.empty || 0}</button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">No Completed Scan</div>
          <button type="button" className="value" onClick={() => onOpenHosts({ inventory_status: 'none' })} style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}>{effectiveInventoryCounts.none || 0}</button>
        </div>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Pending</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.pending || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Scan Requests Claimed</div>
          <div className="value">{stats.scan_request_counts?.claimed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Scan Requests Failed</div>
          <div className="value" style={{ color: 'var(--critical)' }}>{stats.scan_request_counts?.failed || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Scan Requests Degraded</div>
          <div className="value" style={{ color: 'var(--medium)' }}>{stats.scan_request_counts?.degraded || 0}</div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Stale Pending Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'pending', stale: 'true' })}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open pending scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Stale Claimed Requests</div>
          <button
            type="button"
            className="value"
            onClick={() => onOpenScanRequests({ status: 'claimed', stale: 'true' })}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: 'pointer' }}
            title="Open claimed scan requests older than the configured timeout"
          >
            {stats.scan_request_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">Current DB Rescan Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ background: 'transparent', border: 0, padding: 0, color: 'var(--text)', cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Stale Pending</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('pending', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale pending security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.pending || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Stale Claimed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('claimed', true)}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open stale claimed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_stale_counts?.claimed || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--medium)' }} />
          <div className="label">Current DB Rescan Degraded</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('degraded')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--medium)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open degraded security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.degraded || 0}
          </button>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--critical)' }} />
          <div className="label">Current DB Rescan Failed</div>
          <button
            type="button"
            className="value"
            onClick={() => openCurrentDBRescans('failed')}
            disabled={!(stats?.security_db_revision || health?.security_db_revision)}
            style={{ color: 'var(--critical)', background: 'transparent', border: 0, padding: 0, cursor: stats?.security_db_revision || health?.security_db_revision ? 'pointer' : 'default' }}
            title="Open failed security DB rescans for the current revision"
          >
            {stats.security_db_rescan_request_counts?.failed || 0}
          </button>
        </div>
        <div className="stat-card" title={rescanProgress.revision ? `Revision ${rescanProgress.revision}` : 'Current security DB revision'}>
          <div className="accent-bar" style={{ background: rescanProgressColor }} />
          <div className="label">Current DB Rescan Done</div>
          <div className="value" style={{ color: rescanProgressColor }}>{rescanCompletePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(rescanProgress.terminal || 0).toLocaleString()} done, {(rescanProgress.open || 0).toLocaleString()} open of {(rescanProgress.total || 0).toLocaleString()}
          </div>
        </div>
        <div className="stat-card" title={scanCoverage.revision ? `Latest completed/degraded scan revision coverage for ${scanCoverage.revision}` : 'Latest completed/degraded scan revision coverage'}>
          <div className="accent-bar" style={{ background: scanCoverageColor }} />
          <div className="label">Current DB Scan Coverage</div>
          <div className="value" style={{ color: scanCoverageColor }}>{scanCoveragePercent.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(scanCoverage.current_hosts || 0).toLocaleString()} current, {((scanCoverage.stale_hosts || 0) + (scanCoverage.unknown_hosts || 0)).toLocaleString()} stale/unknown
          </div>
        </div>
      </div>
      <div className="db-status-bar" style={{ marginTop: '1.5rem' }}>
        <h3>Vulnerability Database</h3>
        <span className={`status-dot ${health?.trivy_db_ready ? 'ready' : 'not-ready'}`}>
          Trivy: {health?.trivy_db?.status || (health?.trivy_db_ready ? 'ok' : 'not loaded')}
        </span>
        {health?.security_db && (
          <span className={`status-dot ${securitySourcesReady ? 'ready' : 'not-ready'}`} title={health.security_db.status_detail || ''}>
            Sources: {securitySourcesLabel}{health.security_db.status === 'never' && health.security_db.effective_status === 'ok' ? ' (persisted)' : ''}
          </span>
        )}
        {health?.security_recalculation && (
          <span className={`status-dot ${health.security_recalculation.running || health.security_recalculation.pending ? 'not-ready' : 'ready'}`} title={health.security_recalculation.pending_reason || ''}>
            Recalc: {health.security_recalculation.running ? 'running' : health.security_recalculation.pending ? 'queued' : 'idle'}
          </span>
        )}
        {health?.security_db_freshness && (
          <span
            className={`status-dot ${health.security_db_freshness.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={health.security_db_freshness.oldest_source ? `Oldest source: ${health.security_db_freshness.oldest_source}` : ''}
          >
            DB fresh: {health.security_db_freshness.status}
          </span>
        )}
        {health?.security_db_revision && (
          <span className="mono" title="Current merged security database revision" style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            DB rev: {health.security_db_revision}
          </span>
        )}
        {lastSecurityBundleImport && (
          <span
            className={`status-dot ${lastSecurityBundleImport.status === 'ok' ? 'ready' : 'not-ready'}`}
            title={lastSecurityBundleImport.bundle_created_at ? `Bundle created ${new Date(lastSecurityBundleImport.bundle_created_at).toLocaleString()}` : lastSecurityBundleImport.message || lastSecurityBundleImport.error || ''}
          >
            Bundle import: {lastSecurityBundleImport.status === 'ok'
              ? `${lastSecurityBundleImport.bundle_source_count ?? '-'} sources${lastSecurityBundleImport.security_db_revision ? `, rev ${lastSecurityBundleImport.security_db_revision}` : ''}`
              : lastSecurityBundleImport.stage || lastSecurityBundleImport.status}
          </span>
        )}
        {(health?.trivy_db_last_update || health?.trivy_db?.last_update) && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
            Trivy updated: {new Date(health.trivy_db_last_update || health.trivy_db?.last_update || '').toLocaleString()}
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
        <input
          className="compact-input"
          type="number"
          min="1"
          step="10000"
          value={rematchCandidateLimit}
          onChange={(e) => setRematchCandidateLimit(e.target.value)}
          placeholder={`Limit ${cveRematchPolicy?.candidate_limit?.toLocaleString() || 'default'}`}
          title="Maximum CVE-package candidates to evaluate for this manual rematch"
          style={{ width: '11rem', marginLeft: '0.5rem' }}
        />
        <button
          className="update-btn"
          onClick={handleRematch}
          disabled={rematching}
          style={{ marginLeft: '0.5rem' }}
        >
          {rematching ? 'Matching...' : 'Rematch CVEs'}
        </button>
        <button
          className="update-btn"
          onClick={handleCvssRecalc}
          disabled={cvssRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {cvssRecalcBusy ? 'Recalculating...' : 'Recalc CVSS'}
        </button>
        <button
          className="update-btn"
          onClick={handleSecurityRecalc}
          disabled={securityRecalcBusy}
          style={{ marginLeft: '0.5rem' }}
        >
          {securityRecalcBusy ? 'Queueing...' : 'Full Recalc'}
        </button>
        <button
          className="update-btn"
          onClick={handleAffectedIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Affected Index
        </button>
        <button
          className="update-btn"
          onClick={handleReferenceIndexRebuild}
          disabled={updating}
          style={{ marginLeft: '0.5rem' }}
        >
          Rebuild Reference Index
        </button>
      </div>
      <div className="stats-grid" style={{ marginTop: '1rem' }}>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">CVE DB Status</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{cveDbStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {health?.security_db_revision ? `rev ${health.security_db_revision}` : `${cveSources.length || 0} sources tracked`}
          </div>
          <div style={{ color: cveStatsCacheStatus === 'stale' ? 'var(--medium)' : 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
            stats {cveStatsCacheStatus}{cveStatsDuration !== undefined ? ` · ${cveStatsDuration}ms` : ''} · {cveStatsGeneratedAt}
          </div>
          {osvCveSource?.last_update && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              OSV updated {new Date(osvCveSource.last_update).toLocaleString()}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveQualityColor }} />
          <div className="label">CVE DB Quality</div>
          <div className="value" style={{ color: cveQualityColor }}>{cveQualityStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveDbQuality?.warning_count || 0).toLocaleString()} warnings, {(cveDbQuality?.temporary_placeholders || 0).toLocaleString()} temp IDs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveDbStatusColor }} />
          <div className="label">Security Sync</div>
          <div className="value" style={{ color: cveDbStatusColor }}>{securitySyncStatus}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securitySyncDetail}
          </div>
          {securitySyncNext && securitySyncStatus !== 'syncing' && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              next {securitySyncNext}
            </div>
          )}
        </div>
        <div className="stat-card" title={latestSecuritySourceDisplay ? `Latest ${latestSecuritySourceDisplay.label} update ${new Date(latestSecuritySourceDisplay.at).toLocaleString()}` : securityDbStatus?.security_sources_error || ''}>
          <div className="accent-bar" style={{ background: securitySourceRegistryColor }} />
          <div className="label">Source Registry</div>
          <div className="value" style={{ color: securitySourceRegistryColor }}>
            {securitySourceRegistry.length ? `${securitySourceRegistryOk}/${securitySourceRegistryEnabled || securitySourceRegistry.length}` : '-'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {securityDbStatus?.security_sources_error
              ? 'registry status unavailable'
              : securitySourceRegistry.length
                ? `${securitySourceRegistryRecords.toLocaleString()} records tracked`
                : 'waiting for source registry'}
          </div>
          {latestSecuritySourceDisplay && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              latest {latestSecuritySourceDisplay.source} {new Date(latestSecuritySourceDisplay.at).toLocaleString()}
            </div>
          )}
          {latestSecuritySourceExport?.last_exported_at && (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {latestSecuritySourceExport.id} {new Date(latestSecuritySourceExport.last_exported_at).toLocaleString()}
            </div>
          )}
          {securityDbExportStale && (
            <div style={{ color: 'var(--medium)', fontSize: '0.75rem', marginTop: '0.25rem' }}>
              export {securityDbExportStatus?.status}{securityDbExportStatus?.outdated_source_count ? `, ${securityDbExportStatus.outdated_source_count} changed` : ''}
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: 'var(--primary)' }} />
          <div className="label">CVE DB Records</div>
          <div className="value">{cveTotalRecords.toLocaleString()}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveSources.length || 0} merged sources
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveMatchableColor }} />
          <div className="label">CVE Matchable</div>
          <div className="value" style={{ color: cveMatchableColor }}>{cveTotalRecords ? cveMatchablePercent.toFixed(1) : '0.0'}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveTotalMatchable.toLocaleString()} records with ecosystem/range data
          </div>
        </div>
        <div className="stat-card" title={oldestOsvEcosystem?.last_update ? `Oldest OSV raw source ${oldestOsvEcosystem.ecosystem} updated ${new Date(oldestOsvEcosystem.raw_last_update || oldestOsvEcosystem.last_update).toLocaleString()}${oldestOsvEcosystem.indexed_last_update ? `, index rebuilt ${new Date(oldestOsvEcosystem.indexed_last_update).toLocaleString()}` : ''}` : cveStatsMeta?.osv_ecosystems_error || ''}>
          <div className="accent-bar" style={{ background: osvEcosystemColor }} />
          <div className="label">OSV Ecosystems</div>
          <div className="value" style={{ color: osvEcosystemColor }}>{osvEcosystems.length || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveStatsMeta?.osv_ecosystems_error
              ? 'ecosystem stats delayed'
              : oldestOsvEcosystem
                ? `${osvEcosystemRows.toLocaleString()} rows, ${oldestOsvEcosystem.ecosystem} raw oldest`
                : 'waiting for OSV index stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveAffectedIndexColor }} />
          <div className="label">Affected Index</div>
          <div className="value" style={{ color: cveAffectedIndexColor }}>{cveAffectedIndexIndexedOnly ? 'indexed' : cveAffectedIndex?.stale ? 'stale' : `${(cveAffectedIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveAffectedIndexIndexedOnly
              ? `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} indexed CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`
              : `${(cveAffectedIndex?.indexed_cves || 0).toLocaleString()} / ${(cveAffectedIndex?.matchable_cves || 0).toLocaleString()} CVEs, ${(cveAffectedIndex?.orphans || 0).toLocaleString()} orphans`}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: affectedRebuildColor }} />
          <div className="label">Affected Rebuild</div>
          <div className="value" style={{ color: affectedRebuildColor }}>
            {affectedRebuildRunning ? 'running' : affectedRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {affectedRebuildRunning
              ? `${Math.round((affectedRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : affectedRebuildLast?.finished_at
                ? `${(affectedRebuildLast.indexed || 0).toLocaleString()} entries, ${(affectedRebuildLast.duration_ms || 0) > 0 ? `${((affectedRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveReferenceIndexColor }} />
          <div className="label">Reference Index</div>
          <div className="value" style={{ color: cveReferenceIndexColor }}>{cveReferenceIndex?.stale ? 'stale' : `${(cveReferenceIndex?.coverage_percent ?? 0).toFixed(1)}%`}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveReferenceIndex?.count || 0).toLocaleString()} keys, {(cveReferenceIndex?.canonical_cves || 0).toLocaleString()} canonical CVEs
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: referenceRebuildColor }} />
          <div className="label">Reference Rebuild</div>
          <div className="value" style={{ color: referenceRebuildColor }}>
            {referenceRebuildRunning ? 'running' : referenceRebuildLast?.status || 'idle'}
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {referenceRebuildRunning
              ? `${Math.round((referenceRebuild?.duration_ms || 0) / 1000)}s elapsed`
              : referenceRebuildLast?.finished_at
                ? `${(referenceRebuildLast.indexed || 0).toLocaleString()} keys, ${(referenceRebuildLast.duration_ms || 0) > 0 ? `${((referenceRebuildLast.duration_ms || 0) / 1000).toFixed(1)}s` : 'duration pending'}`
                : 'no recent rebuild'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: epssMergeColor }} />
          <div className="label">EPSS Merge</div>
          <div className="value" style={{ color: epssMergeColor }}>{epssMergeCoverage.toFixed(1)}%</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {(cveEpssMerge?.non_epss_cves_with_epss || 0).toLocaleString()} / {(cveEpssMerge?.non_epss_cves || 0).toLocaleString()} local CVEs, {epssUniverseCoverage.toFixed(1)}% EPSS universe
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: weakestCveSource && (weakestCveSource.matchable_percent ?? 0) < 50 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Weakest CVE Source</div>
          <div className="value">{weakestCveSource ? weakestCveSource.source.toUpperCase() : '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {weakestCveSource ? `${(weakestCveSource.matchable_percent ?? 0).toFixed(1)}% matchable` : 'waiting for source stats'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }} />
          <div className="label">Rematch Eligible Sources</div>
          <div className="value" style={{ color: cveRematchExcludedCount > 0 ? 'var(--medium)' : 'var(--low)' }}>{cveRematchEligibleCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {cveRematchExcludedCount} excluded, {cveRematchPolicyText}
          </div>
        </div>
        <div className="stat-card" title={lastRecalcTitle}>
          <div className="accent-bar" style={{ background: lastRecalcColor }} />
          <div className="label">Last Recalculation</div>
          <div className="value" style={{ color: lastRecalcColor }}>{lastRecalc?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastRecalc?.finished_at
              ? lastRecalcLimited
                ? `limited at ${(lastRecalc.rematch_candidates || 0).toLocaleString()} matches, ${(lastRecalc.rematch_scanned_candidates || 0).toLocaleString()} scanned`
                : `${new Date(lastRecalc.finished_at).toLocaleString()} · ${lastRecalc.rematch_new_vulns || 0} new · ${(lastRecalc.stale_rematch_scanned || 0).toLocaleString()} cleaned${lastRecalc.rematch_eligible_sources !== undefined ? ` · ${lastRecalc.rematch_eligible_sources} src` : ''}`
              : 'waiting for audit result'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: lastManualRematchColor }} />
          <div className="label">Manual Rematch</div>
          <div className="value" style={{ color: lastManualRematchColor }}>{lastManualRematch?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastManualRematch?.finished_at
              ? `${(lastManualRematch.matched || 0).toLocaleString()} matches, ${(lastManualRematch.scanned_candidates || 0).toLocaleString()} scanned${lastManualRematch.eligible_sources !== undefined ? ` · ${lastManualRematch.eligible_sources} src` : ''}`
              : 'no manual run yet'}
          </div>
        </div>
        <div className="stat-card" title={lastAutoRescan?.error || lastAutoRescan?.reason || ''}>
          <div className="accent-bar" style={{ background: lastAutoRescanColor }} />
          <div className="label">Auto Rescan Queue</div>
          <div className="value" style={{ color: lastAutoRescanColor }}>{lastAutoRescan?.status || '-'}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {lastAutoRescan?.finished_at
              ? `${(lastAutoRescan.queued || 0).toLocaleString()} queued, ${(lastAutoRescan.already_pending || 0).toLocaleString()} pending of ${(lastAutoRescan.eligible || 0).toLocaleString()} hosts`
              : 'waiting for DB update'}
          </div>
        </div>
        <div className="stat-card">
          <div className="accent-bar" style={{ background: cveFreshnessColor }} />
          <div className="label">CVE Source Alerts</div>
          <div className="value" style={{ color: cveFreshnessColor }}>{cveSourceAlertCount}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
            {missingCveSources.length ? `missing ${missingCveSources.join(', ')}` : health?.security_db_freshness?.oldest_source ? `${health.security_db_freshness.oldest_source} oldest, ${oldestCveAgeDays.toFixed(1)}d` : 'freshness pending'}
          </div>
        </div>
      </div>
      {health?.trivy_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Trivy DB: {health.trivy_db.last_error}</div>}
      {health?.security_db?.last_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security sources: {health.security_db.last_error}</div>}
      {health?.security_db_revision_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB revision: {health.security_db_revision_error}</div>}
      {health?.security_db_freshness?.error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security DB freshness: {health.security_db_freshness.error}</div>}
      {securityDbWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityDbStatus?.status === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>Security DB: {securityDbWarnings.slice(0, 3).join('; ')}{securityDbWarnings.length > 3 ? `; +${securityDbWarnings.length - 3} more` : ''}</div>}
      {securityDbActions.length > 0 && <div style={{ marginTop: '0.25rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>Action: {securityDbActions.slice(0, 2).join('; ')}</div>}
      {securityDbStatus?.security_sources_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Security source registry: {securityDbStatus.security_sources_error}</div>}
      {securitySourceRegistryBroken && !securityDbStatus?.security_sources_error && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>
          Source registry attention: {securitySourceRegistry.filter(s => s.enabled && (s.last_status !== 'ok' || (s.record_count || 0) === 0 || s.last_error)).slice(0, 5).map(s => `${s.id} ${s.last_status}${s.record_count ? ` (${s.record_count.toLocaleString()})` : ''}`).join(', ')}
        </div>
      )}
      {cveQualityWarnings.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cveQualityStatus === 'degraded' ? 'var(--critical)' : 'var(--medium)' }}>CVE DB quality: {cveQualityWarnings.slice(0, 3).join(', ')}{cveQualityWarnings.length > 3 ? `, +${cveQualityWarnings.length - 3} more` : ''}</div>}
      {cveStatsMeta?.osv_ecosystems_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>OSV ecosystem stats: {cveStatsMeta.osv_ecosystems_error}</div>}
      {cveAffectedIndex?.detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index detailed stats delayed; showing indexed-only health snapshot.</div>}
      {cveDbQuality?.affected_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Affected index quality: {cveDbQuality.affected_index_detail_error}</div>}
      {cveDbQuality?.reference_index_detail_error && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--medium)' }}>Reference index quality: {cveDbQuality.reference_index_detail_error}</div>}
      {cveEpssMerge && cveEpssMerge.epss_cves > 0 && cveEpssMerge.enriched_records === 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>EPSS source is loaded but no non-EPSS CVE rows are enriched.</div>}
      {cveAffectedIndex?.stale && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index is older than matchable CVE rows. Rebuild the index before trusting rematch coverage.</div>}
      {(cveAffectedIndex?.missing_matchable_sources?.length || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index missing matchable sources: {cveAffectedIndex?.missing_matchable_sources?.join(', ')}</div>}
      {(cveAffectedIndex?.orphans || 0) > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Affected index orphan rows: {(cveAffectedIndex?.orphans || 0).toLocaleString()}</div>}
      {lastRecalcLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>CVE rematch hit candidate limit: {(lastRecalc?.rematch_candidates || 0).toLocaleString()} / {(lastRecalc?.rematch_candidate_limit || 0).toLocaleString()} matches, {(lastRecalc?.rematch_scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {lastManualRematchLimited && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--high)' }}>Manual CVE rematch hit candidate limit: {(lastManualRematch?.matched || 0).toLocaleString()} / {(lastManualRematch?.candidate_limit || 0).toLocaleString()} matches, {(lastManualRematch?.scanned_candidates || 0).toLocaleString()} raw candidates scanned</div>}
      {missingCveSources.length > 0 && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--critical)' }}>Missing CVE sources: {missingCveSources.join(', ')}</div>}
      {health?.security_db_freshness?.oldest_last_update && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: 'var(--text-muted)' }}>
          Oldest CVE source: {health.security_db_freshness.oldest_source || '-'} updated {new Date(health.security_db_freshness.oldest_last_update).toLocaleString()}
        </div>
      )}
      {updateMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: updateMsg.includes('fail') ? 'var(--critical)' : 'var(--low)' }}>{updateMsg}</div>}
      {rematchMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: rematchMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{rematchMsg}</div>}
      {cvssRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: cvssRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{cvssRecalcMsg}</div>}
      {securityRecalcMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityRecalcMsg.includes('fail') ? 'var(--critical)' : '#4ade80' }}>{securityRecalcMsg}</div>}
      <div className="db-status-bar" style={{ marginTop: '1rem' }}>
        <h3>Airgap Security Bundle</h3>
        <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Export outside, import inside air-gapped environments</span>
        <label style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 'auto', fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
          <input type="checkbox" checked={securityBundleIncludeTrivy} onChange={(e) => setSecurityBundleIncludeTrivy(e.target.checked)} />
          Include Trivy DB
        </label>
        <button className="update-btn" onClick={handleSecurityBundleExport} disabled={securityBundleBusy} style={{ marginLeft: '0.5rem' }}>
          Export Bundle
        </button>
        <label className="update-btn" style={{ marginLeft: '0.5rem', cursor: securityBundleBusy ? 'default' : 'pointer', opacity: securityBundleBusy ? 0.6 : 1 }}>
          Import Bundle
          <input
            type="file"
            accept=".tar.gz,.tgz,application/gzip"
            disabled={securityBundleBusy}
            onChange={(e) => {
              const file = e.target.files?.[0];
              e.currentTarget.value = '';
              handleSecurityBundleImport(file);
            }}
            style={{ display: 'none' }}
          />
        </label>
      </div>
      {securityBundleMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8125rem', color: securityBundleMsg.includes('failed') ? 'var(--critical)' : 'var(--text-muted)' }}>{securityBundleMsg}</div>}
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
      {(ownerSummary.length > 0 || teamSummary.length > 0 || environmentSummary.length > 0 || criticalitySummary.length > 0) && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem', marginTop: '1rem' }}>
          <SummaryTable title="Owner Remediation Queue" groupBy="owner" rows={ownerSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Team Remediation Queue" groupBy="team" rows={teamSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Environment Risk Queue" groupBy="environment" rows={environmentSummary} onOpenVulnerabilities={onOpenVulnerabilities} />
          <SummaryTable title="Criticality Risk Queue" groupBy="criticality" rows={criticalitySummary} onOpenVulnerabilities={onOpenVulnerabilities} />
        </div>
      )}
      {cveSources.length > 0 && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>CVE Database Sources</h2></div>
          <table>
            <thead><tr><th>Source</th><th>Records</th><th>Matchable</th><th>Matchable %</th><th>Rematch</th><th>Ecosystem</th><th>Fixed</th><th>Ranges</th><th>CVSS</th><th>Last Update</th></tr></thead>
            <tbody>
              {cveSources.map(s => {
                const belowQuality = sourceBelowQuality(s);
                const excludedByPolicy = s.rematch_eligible === false;
                const staleSource = staleCveSourceByName.get(s.source.toLowerCase());
                const rowWarn = belowQuality || excludedByPolicy || staleSource;
                return (
                  <tr key={s.source} style={rowWarn ? { background: staleSource ? 'rgba(248, 113, 113, 0.08)' : 'rgba(224, 176, 32, 0.08)' } : undefined}>
                    <td>
                      <span style={{ fontWeight: 600 }}>{s.source.toUpperCase()}</span>
                      {staleSource && <span className="badge" title={staleSource.last_update ? `last update ${new Date(staleSource.last_update).toLocaleString()}` : 'missing last update'} style={{ marginLeft: 6, color: 'var(--critical)' }}>stale</span>}
                      {belowQuality && <span className="badge" style={{ marginLeft: 6, color: 'var(--medium)' }}>below gate</span>}
                      {excludedByPolicy && <span className="badge" title={s.rematch_exclusion || ''} style={{ marginLeft: 6, color: 'var(--medium)' }}>policy excluded</span>}
                    </td>
                    <td className="mono">{s.count.toLocaleString()}</td>
                    <td className="mono">{(s.matchable || 0).toLocaleString()}</td>
                    <td className="mono" style={{ color: belowQuality || excludedByPolicy ? 'var(--medium)' : undefined }}>{(s.matchable_percent ?? 0).toFixed(1)}%</td>
                    <td>
                      <span className="badge" title={s.rematch_exclusion || ''} style={{ color: excludedByPolicy ? 'var(--medium)' : 'var(--low)' }}>
                        {excludedByPolicy ? 'excluded' : 'eligible'}
                      </span>
                    </td>
                    <td className="mono">{(s.with_ecosystem || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_fixed || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_ranges || 0).toLocaleString()}</td>
                    <td className="mono">{(s.with_cvss || 0).toLocaleString()}</td>
                    <td className="mono" style={{ fontSize: '0.8125rem', color: staleSource ? 'var(--critical)' : undefined }}>
                      {s.last_update ? new Date(s.last_update).toLocaleString() : '-'}
                      {staleSource?.age_seconds !== undefined && <div style={{ fontSize: '0.75rem' }}>{formatAge(staleSource.age_seconds)} old</div>}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="info-card" style={{ marginTop: '1.5rem' }}>
        <div className="info-header">
          <div className="info-icon">🏔</div>
          <div>
            <h3>Bongsu</h3>
            <p>
              Bongsu is named after a Korean signal-fire watchtower. It centralizes package evidence from hosts and containers,
              then matches that inventory against CVSS-aware vulnerability databases.
            </p>
            <p>
              Agents collect package inventories periodically. The server stores host, container, image, and package context so operators
              can inspect findings by host, package, container, and vulnerability.
            </p>
            <div className="info-links">
              <span><strong>Hosts</strong> - registered systems and SBOM state</span>
              <span><strong>Packages</strong> - package search and CVSS ordering</span>
              <span><strong>Vulnerabilities</strong> - CVE detail, triage, and filtering</span>
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

function SummaryTable({ title, groupBy, rows, onOpenVulnerabilities }: { title: string; groupBy: 'owner' | 'team' | 'environment' | 'criticality'; rows: VulnSummaryRow[]; onOpenVulnerabilities: (filters: VulnerabilityFilters) => void }) {
  const topRows = rows.slice(0, 8);
  const openRow = (row: VulnSummaryRow, extra?: VulnerabilityFilters) => {
    onOpenVulnerabilities({ [groupBy]: row.group, ...extra });
  };
  return (
    <div className="card">
      <div className="card-header"><h2>{title}</h2></div>
      <table>
        <thead>
          <tr><th>Group</th><th>Total</th><th>Critical Risk</th><th>High Risk</th><th>Overdue</th></tr>
        </thead>
        <tbody>
          {topRows.map(row => (
            <tr key={row.group}>
              <td><button type="button" className="link-button" onClick={() => openRow(row)}>{row.group}</button></td>
              <td className="mono"><button type="button" className="link-button mono" onClick={() => openRow(row)}>{row.total.toLocaleString()}</button></td>
              <td className="mono" style={{ color: 'var(--critical)', fontWeight: row.risk?.critical ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'critical' })}>{row.risk?.critical || 0}</button></td>
              <td className="mono" style={{ color: 'var(--high)', fontWeight: row.risk?.high ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { riskLevel: 'high' })}>{row.risk?.high || 0}</button></td>
              <td className="mono" style={{ color: row.overdue ? 'var(--critical)' : 'var(--text-muted)', fontWeight: row.overdue ? 700 : 400 }}><button type="button" className="link-button mono" onClick={() => openRow(row, { overdueOnly: true })}>{row.overdue || 0}</button></td>
            </tr>
          ))}
          {topRows.length === 0 && <tr className="empty-row"><td colSpan={5}>No findings</td></tr>}
        </tbody>
      </table>
    </div>
  );
}


function HostDetailView({ hostId, onBack, onSelectVuln }: { hostId: string; onBack: () => void; onSelectVuln?: (v: Vuln) => void }) {
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

function VulnsView({ initialFilters, onSelectVuln }: { initialFilters?: VulnerabilityFilters; onSelectVuln: (v: Vuln) => void }) {
  const [vulns, setVulns] = useState<Vuln[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [severity, setSeverity] = useState('');
  const [triageStatus, setTriageStatus] = useState(initialFilters?.triageStatus || '');
  const [assignee, setAssignee] = useState('');
  const [findingSource, setFindingSource] = useState('');
  const [riskLevel, setRiskLevel] = useState(initialFilters?.riskLevel || '');
  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [pkgQuery, setPkgQuery] = useState('');
  const [sortBy, setSortBy] = useState('risk_score');
  const [sortDesc, setSortDesc] = useState(true);
  const [loading, setLoading] = useState(true);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostMeta, setHostMeta] = useState<Record<string, Host>>({});
  const [hostIds, setHostIds] = useState<string[]>([]);
  const [containers, setContainers] = useState<string[]>([]);
  const [findingSources, setFindingSources] = useState<string[]>([]);
  const [owner, setOwner] = useState(initialFilters?.owner || '');
  const [team, setTeam] = useState(initialFilters?.team || '');
  const [environment, setEnvironment] = useState(initialFilters?.environment || '');
  const [criticality, setCriticality] = useState(initialFilters?.criticality || '');
  const [showNoFix, setShowNoFix] = useState(false);
  const [showMismatch, setShowMismatch] = useState(false);
  const [overdueOnly, setOverdueOnly] = useState(!!initialFilters?.overdueOnly);
  const [exploitedOnly, setExploitedOnly] = useState(!!initialFilters?.exploitedOnly);
  const [minEpss, setMinEpss] = useState('');
  const [vulnId, setVulnId] = useState('');
  const [vEcosystem, setVEcosystem] = useState('');
  const [vPkgType, setVPkgType] = useState('');
  const [minCvss, setMinCvss] = useState('');
  const [maxCvss, setMaxCvss] = useState('');
  const [hasFix, setHasFix] = useState('');
  const [affectedFor, setAffectedFor] = useState<string | null>(null);
  const [exportMsg, setExportMsg] = useState('');
  const [loadError, setLoadError] = useState('');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkStatus, setBulkStatus] = useState('');
  const [bulkAssignee, setBulkAssignee] = useState('');
  const [bulkBusy, setBulkBusy] = useState(false);
  const [bulkMsg, setBulkMsg] = useState('');
  const [editAssigneeId, setEditAssigneeId] = useState('');
  const [editAssigneeVal, setEditAssigneeVal] = useState('');
  const [editAssigneeBusy, setEditAssigneeBusy] = useState(false);
  const loadSeq = useRef(0);
  const limit = 50;

  const load = useCallback((p: number, sev: string, triage: string, asg: string, source: string, risk: string, overdue: boolean, exploited: boolean, epss: string, hId: string, cont: string, own: string, tm: string, env: string, crit: string, pq: string, sBy: string, sDesc: boolean, sNoFix: boolean, sMismatch: boolean, adv: { vulnId: string; ecosystem: string; pkgType: string; minCvss: string; maxCvss: string; hasFix: string }) => {
    const seq = ++loadSeq.current;
    setLoading(true);
    setLoadError('');
    const params: Record<string, string> = { limit: String(limit), offset: String(p * limit) };
    if (adv.vulnId) params.vuln_id = adv.vulnId;
    if (adv.ecosystem) params.ecosystem = adv.ecosystem;
    if (adv.pkgType) params.pkg_type = adv.pkgType;
    if (adv.minCvss) params.min_cvss = adv.minCvss;
    if (adv.maxCvss) params.max_cvss = adv.maxCvss;
    if (adv.hasFix) params.has_fix = adv.hasFix;
    if (sev) params.severity = sev;
    if (triage) params.triage_status = triage;
    if (asg) params.assignee = asg;
    if (source) params.finding_source = source;
    if (risk) params.risk_level = risk;
    if (overdue) params.overdue = 'true';
    if (exploited) params.exploited = 'true';
    const minEpssParam = epssParam(epss);
    if (minEpssParam) params.min_epss = minEpssParam;
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
      .then(r => { if (seq !== loadSeq.current) return; setVulns(r.items || []); setTotal(r.total); setPage(p); setLoading(false); setSelectedIds(new Set()); setEditAssigneeId(''); })
      .catch((e) => { if (seq !== loadSeq.current) return; setLoadError(e instanceof Error ? e.message : 'Failed to load vulnerabilities'); setLoading(false); });
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
      setFindingSources(f.finding_sources || []);
    }).catch(() => {});
  }, []);

  const vadv = { vulnId, ecosystem: vEcosystem, pkgType: vPkgType, minCvss, maxCvss, hasFix };

  useEffect(() => { load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv); }, [load, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, showNoFix, showMismatch, vEcosystem, vPkgType, hasFix]);

  const handleSearch = () => { load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : col === 'risk_score' || col === 'cvss_score' || col === 'severity' || col === 'exploited' || col === 'epss_score' || col === 'epss_percentile';
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, col, nextDesc, showNoFix, showMismatch, vadv);
  };


  const badgeClass = (sev: string) => `badge badge-${sev.toLowerCase()}`;
  const epssParam = (epss: string) => {
    const n = Number(epss);
    if (!Number.isFinite(n) || n <= 0) return '';
    return String(Math.min(n, 100) / 100);
  };
  const currentExportParams = (format: 'csv' | 'json') => {
    const params: Record<string, string> = { format };
    if (severity) params.severity = severity;
    if (triageStatus) params.triage_status = triageStatus;
    if (assignee) params.assignee = assignee;
    if (findingSource) params.finding_source = findingSource;
    if (riskLevel) params.risk_level = riskLevel;
    if (overdueOnly) params.overdue = 'true';
    if (exploitedOnly) params.exploited = 'true';
    const minEpssParam = epssParam(minEpss);
    if (minEpssParam) params.min_epss = minEpssParam;
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

  const toggleSelect = (id: string) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };
  const allSelected = vulns.length > 0 && vulns.every(v => selectedIds.has(v.id));
  const toggleSelectAll = () => {
    setSelectedIds(prev => {
      if (vulns.length > 0 && vulns.every(v => prev.has(v.id))) {
        const next = new Set(prev);
        vulns.forEach(v => next.delete(v.id));
        return next;
      }
      const next = new Set(prev);
      vulns.forEach(v => next.add(v.id));
      return next;
    });
  };
  const reloadCurrent = () => load(page, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv);
  const applyBulkTriage = async () => {
    const targets = vulns.filter(v => selectedIds.has(v.id));
    if (targets.length === 0 || !bulkStatus) return;
    setBulkBusy(true);
    let done = 0;
    let failed = 0;
    for (const v of targets) {
      setBulkMsg(`Applying ${done + 1}/${targets.length}...`);
      try {
        await api.triageVulnerability({
          vulnerability_id: v.vulnerability_id,
          host_id: v.host_id,
          pkg_name: v.pkg_name,
          status: bulkStatus,
          assignee: bulkAssignee,
        });
      } catch {
        failed++;
      }
      done++;
    }
    setBulkBusy(false);
    setBulkMsg(failed ? `Applied ${done - failed}/${targets.length} (${failed} failed)` : `Applied to ${done} finding${done === 1 ? '' : 's'}`);
    reloadCurrent();
  };
  const startEditAssignee = (v: Vuln) => {
    setEditAssigneeId(v.id);
    setEditAssigneeVal(v.triage_assignee || '');
  };
  const saveEditAssignee = async (v: Vuln) => {
    setEditAssigneeBusy(true);
    try {
      await api.triageVulnerability({
        vulnerability_id: v.vulnerability_id,
        host_id: v.host_id,
        pkg_name: v.pkg_name,
        status: v.triage_status || 'open',
        assignee: editAssigneeVal,
      });
      setVulns(prev => prev.map(x => x.id === v.id ? { ...x, triage_assignee: editAssigneeVal } : x));
      setEditAssigneeId('');
    } catch {
      // keep editor open on failure
    }
    setEditAssigneeBusy(false);
  };

  const owners = Array.from(new Set(Object.values(hostMeta).map(h => h.owner || '').filter(Boolean))).sort();
  const teams = Array.from(new Set(Object.values(hostMeta).map(h => h.team || '').filter(Boolean))).sort();
  const environments = Array.from(new Set(Object.values(hostMeta).map(h => h.environment || '').filter(Boolean))).sort();
  const criticalities = Array.from(new Set(Object.values(hostMeta).map(h => h.criticality || '').filter(Boolean))).sort();
  const clearFilters = () => {
    setSeverity('');
    setTriageStatus('');
    setAssignee('');
    setFindingSource('');
    setRiskLevel('');
    setHostId('');
    setContainer('');
    setOwner('');
    setTeam('');
    setEnvironment('');
    setCriticality('');
    setPkgQuery('');
    setShowNoFix(false);
    setShowMismatch(false);
    setOverdueOnly(false);
    setExploitedOnly(false);
    setMinEpss('');
    setVulnId('');
    setVEcosystem('');
    setVPkgType('');
    setMinCvss('');
    setMaxCvss('');
    setHasFix('');
  };
  const activeFilters = [
    severity && `Severity: ${severity}`,
    triageStatus && `Status: ${triageStatus.replace('_', ' ')}`,
    assignee && `Assignee: ${assignee}`,
    findingSource && `Source: ${findingSourceLabel(findingSource)}`,
    riskLevel && `Risk: ${riskLevel}`,
    overdueOnly && 'Overdue',
    exploitedOnly && 'CISA KEV',
    minEpss && `EPSS >= ${minEpss}%`,
    hostId && `Host: ${hostMap[hostId] || hostId}`,
    container && `Container: ${container}`,
    owner && `Owner: ${owner}`,
    team && `Team: ${team}`,
    environment && `Environment: ${environment}`,
    criticality && `Criticality: ${criticality}`,
    pkgQuery && `Package: ${pkgQuery}`,
    vulnId && `CVE: ${vulnId}`,
    vEcosystem && `Ecosystem: ${vEcosystem}`,
    vPkgType && `Pkg Type: ${vPkgType}`,
    minCvss && `CVSS >= ${minCvss}`,
    maxCvss && `CVSS <= ${maxCvss}`,
    hasFix === 'yes' && 'Fix available',
    hasFix === 'no' && 'No fix available',
    showNoFix && 'No fix info',
    showMismatch && 'Wrong ecosystem',
  ].filter(Boolean) as string[];

  const cols: [string, string][] = [
    ['risk_score', 'Risk'], ['exploited', 'KEV'], ['epss_score', 'EPSS'], ['vulnerability_id', 'CVE'], ['severity', 'Severity'], ['cvss_score', 'CVSS'],
    ['pkg_name', 'Package'], ['owner', 'Owner'], ['environment', 'Env'], ['container', 'Container'], ['pkg_type', 'Pkg Type'],
    ['installed_version', 'Installed'], ['fixed_version', 'Fixed'], ['due_at', 'Due'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Vulnerabilities</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
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
          <input
            type="text"
            placeholder="Assignee (or 'unassigned')"
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            style={{ minWidth: 170 }}
            title="Filter by triage assignee; use 'unassigned' for findings without an assignee"
          />
          <select value={findingSource} onChange={(e) => setFindingSource(e.target.value)}>
            <option value="">All Sources</option>
            {(findingSources.length ? findingSources : ['scanner', 'cve-db']).map(s => (
              <option key={s} value={s}>{findingSourceLabel(s)}</option>
            ))}
          </select>
          <select value={riskLevel} onChange={(e) => setRiskLevel(e.target.value)}>
            <option value="">All Risk</option>
            <option value="critical">Critical Risk</option>
            <option value="high">High Risk</option>
            <option value="medium">Medium Risk</option>
            <option value="low">Low Risk</option>
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
          <input
            type="text"
            placeholder="CVE id (e.g. CVE-2024)"
            value={vulnId}
            onChange={(e) => setVulnId(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 170 }}
            title="Filter by vulnerability id substring, e.g. CVE-2024 or DEBIAN-"
          />
          <input
            type="text"
            placeholder="Ecosystem..."
            value={vEcosystem}
            onChange={(e) => setVEcosystem(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 130 }}
            title="Ecosystem, e.g. pypi/npm/debian/rhel/alpine"
            list="vuln-ecosystem-list"
          />
          <datalist id="vuln-ecosystem-list">
            <option value="pypi" /><option value="npm" /><option value="debian" /><option value="rhel" /><option value="alpine" />
            <option value="go" /><option value="maven" /><option value="cargo" /><option value="gem" /><option value="nuget" />
          </datalist>
          <input
            type="text"
            placeholder="Pkg type..."
            value={vPkgType}
            onChange={(e) => setVPkgType(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 120 }}
            title="Package type"
          />
          <select value={hasFix} onChange={(e) => setHasFix(e.target.value)} title="Fix availability">
            <option value="">All Fixes</option>
            <option value="yes">Has fix</option>
            <option value="no">No fix</option>
          </select>
          <input
            type="number"
            min="0"
            max="10"
            step="0.1"
            placeholder="Min CVSS"
            value={minCvss}
            onChange={(e) => setMinCvss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 100 }}
            title="Minimum CVSS score"
          />
          <input
            type="number"
            min="0"
            max="10"
            step="0.1"
            placeholder="Max CVSS"
            value={maxCvss}
            onChange={(e) => setMaxCvss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 100 }}
            title="Maximum CVSS score"
          />
          <input
            type="number"
            min="0"
            max="100"
            step="1"
            placeholder="Min EPSS %"
            value={minEpss}
            onChange={(e) => setMinEpss(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ width: 115 }}
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="No fix info" checked={showNoFix} onChange={setShowNoFix} />
            <CheckboxField label="Wrong ecosystem" checked={showMismatch} onChange={setShowMismatch} />
            <CheckboxField label="Overdue" checked={overdueOnly} onChange={setOverdueOnly} />
            <CheckboxField label="CISA KEV" checked={exploitedOnly} onChange={setExploitedOnly} />
          </div>
          <div className="filter-actions">
            <span className="result-count">{exportMsg || `${total.toLocaleString()} results`}</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
            <button className="btn btn-secondary" onClick={() => exportVulns('csv')}>Export CSV</button>
            <button className="btn btn-secondary" onClick={() => exportVulns('json')}>Export JSON</button>
          </div>
        </div>
        {activeFilters.length > 0 && (
          <div className="active-filters">
            {activeFilters.map(f => <span key={f} className="filter-chip">{f}</span>)}
            <button type="button" className="filter-clear" onClick={clearFilters}>Clear Filters</button>
          </div>
        )}
      </div>
      {selectedIds.size > 0 && (
        <div className="card" style={{ marginBottom: '1rem', padding: '0.75rem 1rem', display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <strong style={{ whiteSpace: 'nowrap' }}>{selectedIds.size} selected</strong>
          <select value={bulkStatus} onChange={(e) => setBulkStatus(e.target.value)} disabled={bulkBusy}>
            <option value="">Set status...</option>
            <option value="open">Open</option>
            <option value="in_progress">In Progress</option>
            <option value="accepted_risk">Accepted Risk</option>
            <option value="false_positive">False Positive</option>
            <option value="fixed">Fixed</option>
            <option value="ignored">Ignored</option>
          </select>
          <input
            type="text"
            placeholder="Assignee (optional)"
            value={bulkAssignee}
            onChange={(e) => setBulkAssignee(e.target.value)}
            disabled={bulkBusy}
            style={{ minWidth: 170 }}
          />
          <button className="btn btn-primary" onClick={applyBulkTriage} disabled={bulkBusy || !bulkStatus}>
            {bulkBusy ? 'Applying...' : 'Apply to selected'}
          </button>
          <button type="button" className="btn btn-secondary" onClick={() => { setSelectedIds(new Set()); setBulkMsg(''); }} disabled={bulkBusy}>Clear selection</button>
          {bulkMsg && <span className="result-count">{bulkMsg}</span>}
        </div>
      )}
      <div className="card">
        {loading ? <Loading /> : loadError ? <LoadError message={loadError} onRetry={handleSearch} /> : (
          <table>
            <thead>
              <tr>
                <th style={{ width: 28 }}><input type="checkbox" checked={allSelected} onChange={toggleSelectAll} title="Select all on page" /></th>
                <th>Host</th>
                <th>Status</th>
                <th>Source</th>
                {cols.map(([key, label]) => (
                  <SortHeader key={key} col={key} label={label} sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                ))}
                <th>Assignee</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map(v => (
                <tr key={v.id} style={{ cursor: 'pointer' }} onClick={() => onSelectVuln(v)}>
                  <td onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
                    <input type="checkbox" checked={selectedIds.has(v.id)} onChange={() => toggleSelect(v.id)} />
                  </td>
                  <td><span className="host-link">{hostMap[v.host_id] || v.host_id.slice(0, 8)}</span></td>
                  <td><span className="badge">{(v.triage_status || 'open').replace('_', ' ')}</span></td>
                  <td>
                    <span className="badge" title={(v.advisory_sources || []).length ? `Advisory: ${(v.advisory_sources || []).join(', ')}` : ''}>{findingSourceLabel(v.finding_source)}</span>
                    {(v.advisory_sources || []).length > 0 && <div className="mono" style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>{(v.advisory_sources || []).slice(0, 2).join(', ')}</div>}
                    {(v.advisory_evidence || []).length > 0 && <div className="mono" style={{ fontSize: '0.625rem', color: '#22c55e', marginTop: 2 }}>{(v.advisory_evidence || []).length} verified</div>}
                  </td>
                  <td className="mono" style={{ fontWeight: 700, color: riskLevelColor(v.risk_level) }}>
                    {v.risk_score ? v.risk_score.toFixed(1) : '-'}
                    <div style={{ fontSize: '0.625rem', textTransform: 'uppercase', color: riskLevelColor(v.risk_level) }}>{riskLevelLabel(v.risk_level)}</div>
                  </td>
                  <td>{v.exploited ? <span className="badge badge-critical">KEV</span> : <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono" style={{ color: (v.epss_score || 0) >= 0.5 ? 'var(--critical)' : (v.epss_score || 0) >= 0.1 ? 'var(--high)' : 'var(--text-muted)' }}>
                    {v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : '-'}
                  </td>
                  <td className="mono">
                    <span className="host-link" style={{ color: 'var(--primary)' }}>{v.vulnerability_id}</span>
                    <button
                      className="btn btn-secondary btn-sm"
                      style={{ marginLeft: 6, height: '1.25rem', padding: '0 6px', fontSize: '0.625rem' }}
                      title="Show hosts & containers affected by this CVE"
                      onClick={(e) => { e.stopPropagation(); setAffectedFor(v.vulnerability_id); }}
                    >
                      assets
                    </button>
                  </td>
                  <td><span className={badgeClass(v.severity)}>{v.severity}</span></td>
                  <td className="mono" style={{ color: v.cvss_score >= 9 ? 'var(--critical)' : v.cvss_score >= 7 ? 'var(--high)' : v.cvss_score >= 4 ? 'var(--medium)' : 'inherit', fontWeight: 600 }}>{v.cvss_score > 0 ? v.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{v.pkg_name}</td>
                  <td>{v.host_owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{v.host_environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono">{v.container || '(host)'}</td>
                  <td className="mono">{v.pkg_type || v.ecosystem || '-'}</td>
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
                  <td className="mono" style={{ color: v.overdue ? 'var(--critical)' : 'var(--text-muted)' }} title={v.due_at ? `Due ${formatDateOnly(v.due_at)}` : ''}>
                    {formatDateOnly(v.due_at)}
                  </td>
                  <td onClick={(e) => e.stopPropagation()} style={{ cursor: 'default' }}>
                    {editAssigneeId === v.id ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                        <input
                          type="text"
                          autoFocus
                          value={editAssigneeVal}
                          onChange={(e) => setEditAssigneeVal(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') saveEditAssignee(v); if (e.key === 'Escape') setEditAssigneeId(''); }}
                          disabled={editAssigneeBusy}
                          style={{ width: 110 }}
                        />
                        <button className="filter-btn" onClick={() => saveEditAssignee(v)} disabled={editAssigneeBusy} style={{ padding: '2px 6px' }}>✓</button>
                        <button type="button" className="filter-clear" onClick={() => setEditAssigneeId('')} disabled={editAssigneeBusy} style={{ padding: '2px 6px' }}>✕</button>
                      </span>
                    ) : (
                      <span
                        className="host-link"
                        title="Click to set assignee"
                        onClick={() => startEditAssignee(v)}
                        style={{ color: v.triage_assignee ? 'inherit' : 'var(--text-muted)' }}
                      >
                        {v.triage_assignee || '—'}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
              {vulns.length === 0 && <tr className="empty-row"><td colSpan={19}>No vulnerabilities match the current filters — try widening severity, risk, or clearing the search above.</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, severity, triageStatus, assignee, findingSource, riskLevel, overdueOnly, exploitedOnly, minEpss, hostId, container, owner, team, environment, criticality, pkgQuery, sortBy, sortDesc, showNoFix, showMismatch, vadv)} />
      </div>
      {affectedFor && <AffectedAssetsModal vulnerabilityId={affectedFor} onClose={() => setAffectedFor(null)} />}
    </>
  );
}

function AffectedAssetsModal({ vulnerabilityId, onClose }: { vulnerabilityId: string; onClose: () => void }) {
  const [data, setData] = useState<AffectedAssetsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    fetchAffectedAssets(vulnerabilityId, 500)
      .then(r => { if (active) { setData(r); setLoading(false); } })
      .catch(e => { if (active) { setError(e instanceof Error ? e.message : 'Failed to load affected assets'); setLoading(false); } });
    return () => { active = false; };
  }, [vulnerabilityId]);

  const assets = data?.assets || [];

  return (
    <Modal
      onClose={onClose}
      title={<>
        Affected assets — <span className="mono" style={{ color: 'var(--primary)' }}>{vulnerabilityId}</span>
        {data && <span style={{ color: 'var(--text-muted)', fontWeight: 400, marginLeft: 10, fontSize: '0.8125rem' }}>{data.total} asset{data.total === 1 ? '' : 's'}</span>}
      </>}
    >
      <>
          {loading ? <Loading label="Loading affected assets..." /> : error ? (
            <LoadError message={error} />
          ) : assets.length === 0 ? (
            <EmptyState message="No affected assets found" />
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Asset</th>
                  <th>Container / Image</th>
                  <th>Package</th>
                  <th>Pkg Type</th>
                  <th>Installed → Fixed</th>
                  <th>Severity</th>
                  <th>CVSS</th>
                  <th>Owner</th>
                  <th>Env</th>
                </tr>
              </thead>
              <tbody>
                {assets.map((a, i) => (
                  <tr key={`${a.host_id}-${a.container}-${a.pkg_name}-${i}`}>
                    <td>{a.hostname || a.host_id.slice(0, 8)}</td>
                    <td><span className="badge">{a.asset_type || (a.container ? 'container' : 'host')}</span></td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {a.container || a.image_name
                        ? <>{a.container || '-'}{a.image_name ? <div style={{ color: 'var(--text-muted)' }}>{a.image_name}</div> : null}</>
                        : <span style={{ color: 'var(--text-muted)' }}>(host)</span>}
                    </td>
                    <td className="mono">{a.pkg_name}</td>
                    <td className="mono">{a.pkg_type || '-'}</td>
                    <td className="mono" style={{ fontSize: '0.75rem' }}>
                      {a.installed_version || '-'}
                      {a.fixed_version
                        ? <span style={{ color: 'var(--low)', fontWeight: 600 }}> → {a.fixed_version}</span>
                        : <span style={{ color: 'var(--text-muted)' }}> → no fix</span>}
                    </td>
                    <td><span className={`badge badge-${(a.severity || 'unknown').toLowerCase()}`}>{a.severity || '-'}</span></td>
                    <td className="mono" style={{ color: severityColor(a.severity), fontWeight: 600 }}>{a.cvss_score > 0 ? a.cvss_score.toFixed(1) : '-'}</td>
                    <td>{a.owner || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                    <td>{a.environment || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
      </>
    </Modal>
  );
}

// AiAnalysisBody renders a stored VulnAnalysis: badges, confidence, reasoning,
// a model/provider footer, and an Apply action for actionable recommendations.
function AiAnalysisBody({ analysis, onApply, applyMsg, applying }: {
  analysis: VulnAnalysis;
  onApply?: () => void;
  applyMsg?: string;
  applying?: boolean;
}) {
  const actionable = analysis.recommended_action === 'false_positive' || analysis.recommended_action === 'accept_risk';
  return (
    <>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', marginBottom: '0.75rem' }}>
        <Badge tone={recommendedActionTone(analysis.recommended_action)}>{recommendedActionLabel(analysis.recommended_action)}</Badge>
        <Badge tone={riskLevelTone(analysis.risk_level)} dot>{analysis.risk_level || 'unknown'} risk</Badge>
        {analysis.auto_applied && <Badge tone="accent">auto-applied</Badge>}
      </div>
      <table style={{ marginBottom: '0.75rem' }}>
        <tbody>
          <tr><td style={{ color: 'var(--text-muted)', width: 160 }}>Exploitability</td><td className="mono">{analysis.exploitability || '-'}</td></tr>
          <tr><td style={{ color: 'var(--text-muted)' }}>Confidence</td><td className="mono">{Math.round((analysis.confidence || 0) * 100)}%</td></tr>
          <tr><td style={{ color: 'var(--text-muted)' }}>Likely false positive</td><td className="mono">{analysis.likely_false_positive ? 'Yes' : 'No'}</td></tr>
        </tbody>
      </table>
      {analysis.reasoning && (
        <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.875rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '0.75rem' }}>{analysis.reasoning}</div>
      )}
      {onApply && actionable && (
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <button className="btn btn-primary btn-sm" onClick={onApply} disabled={applying}>{applying ? 'Applying...' : 'Apply'}</button>
          {applyMsg && <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>{applyMsg}</span>}
        </div>
      )}
      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }} className="mono">
        {analysis.model || '-'} · {analysis.provider || '-'} · updated {formatDateTime(analysis.updated_at)}
      </div>
    </>
  );
}

// AiAssessmentCard fetches and renders the AI assessment for a single
// vulnerability finding. It degrades gracefully when the LLM is not
// configured and never throws into the surrounding detail page.
function AiAssessmentCard({ vuln }: { vuln: Vuln }) {
  const [llm, setLlm] = useState<LLMStatus | null>(null);
  const [llmLoaded, setLlmLoaded] = useState(false);
  const [analysis, setAnalysis] = useState<VulnAnalysis | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState('');
  const [applying, setApplying] = useState(false);
  const [applyMsg, setApplyMsg] = useState('');

  const params = useMemo(() => ({
    vulnerability_id: vuln.vulnerability_id,
    ...(vuln.pkg_name ? { pkg_name: vuln.pkg_name } : {}),
    ...(vuln.host_id ? { host_id: vuln.host_id } : {}),
  }), [vuln.vulnerability_id, vuln.pkg_name, vuln.host_id]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    setAnalysis(null);
    setApplyMsg('');
    api.llmStatus()
      .then(status => {
        if (!active) return;
        setLlm(status);
        setLlmLoaded(true);
        if (!status.enabled) { setLoading(false); return; }
        return api.vulnAnalysis(params)
          .then(r => { if (active) setAnalysis(isVulnAnalysis(r) ? r : null); })
          .finally(() => { if (active) setLoading(false); });
      })
      .catch(() => {
        // Treat an unreachable/failed status check as "not configured" rather
        // than breaking the vuln detail page.
        if (active) { setLlmLoaded(true); setLoading(false); }
      });
    return () => { active = false; };
  }, [params]);

  const runAnalyze = async () => {
    setRunning(true);
    setError('');
    try {
      const r = await api.vulnAnalysis({ ...params, analyze: true });
      setAnalysis(isVulnAnalysis(r) ? r : null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'AI analysis is not configured');
    } finally {
      setRunning(false);
    }
  };

  const applyAnalysis = async () => {
    if (!analysis) return;
    setApplying(true);
    setApplyMsg('');
    try {
      const r = await api.applyVulnAnalysis(analysis.id);
      setApplyMsg(`applied as ${r.triage_status}`);
    } catch (err) {
      setApplyMsg(err instanceof Error ? err.message : 'Apply failed');
    } finally {
      setApplying(false);
    }
  };

  const disabled = llmLoaded && (!llm || !llm.enabled);

  return (
    <div className="card ai-card" style={{ marginBottom: '1rem', padding: '1rem' }}>
      <h3 style={{ margin: '0 0 0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <Icon name="ai-triage" size={16} /> AI Assessment
      </h3>
      {!llmLoaded || loading ? (
        <Loading label="Loading AI assessment..." />
      ) : disabled ? (
        <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>AI analysis not configured</div>
      ) : analysis ? (
        <AiAnalysisBody analysis={analysis} onApply={applyAnalysis} applyMsg={applyMsg} applying={applying} />
      ) : (
        <div>
          <button className="btn btn-primary btn-sm" onClick={runAnalyze} disabled={running}>
            {running ? 'Analyzing...' : 'Analyze with AI'}
          </button>
          {error && <span style={{ marginLeft: '0.75rem', color: 'var(--critical)', fontSize: '0.8125rem' }}>{error}</span>}
        </div>
      )}
    </div>
  );
}

function VulnDetailView({ vuln, onBack }: { vuln: Vuln | null; onBack: () => void }) {
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [triageStatus, setTriageStatus] = useState(vuln?.triage_status || 'open');
  const [triageReason, setTriageReason] = useState(vuln?.triage_reason || '');
  const [triageAssignee, setTriageAssignee] = useState(vuln?.triage_assignee || '');
  const [triageComment, setTriageComment] = useState(vuln?.triage_comment || '');
  const [triageExpiresAt, setTriageExpiresAt] = useState(dateInputValue(vuln?.triage_expires_at));
  const [triageScope, setTriageScope] = useState<'finding' | 'host' | 'global'>('finding');
  const [triageMsg, setTriageMsg] = useState('');

  // Escape returns to the vulnerability list (unless typing in a field).
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
    setTriageAssignee(vuln?.triage_assignee || '');
    setTriageComment(vuln?.triage_comment || '');
    setTriageExpiresAt(dateInputValue(vuln?.triage_expires_at));
    setTriageMsg('');
  }, [vuln]);

  if (!vuln) return <div>No vulnerability selected</div>;

  const badgeClass = `badge badge-${vuln.severity.toLowerCase()}`;
  const sevColor = severityColor(vuln.severity);
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
        assignee: triageAssignee,
        expires_at: triageExpiresAt ? `${triageExpiresAt}T00:00:00Z` : null,
      });
      setTriageMsg('Saved');
    } catch (err) {
      setTriageMsg(err instanceof Error ? err.message : 'Save failed');
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
          <div className="label">Risk Score</div>
          <div className="value" style={{ color: (vuln.risk_score || 0) >= 80 ? 'var(--critical)' : (vuln.risk_score || 0) >= 60 ? 'var(--high)' : (vuln.risk_score || 0) >= 40 ? 'var(--medium)' : 'inherit' }}>
            {vuln.risk_score ? vuln.risk_score.toFixed(1) : '-'}
          </div>
          <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: riskLevelColor(vuln.risk_level) }}>{riskLevelLabel(vuln.risk_level)} Risk</div>
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
          <div className="label">Source</div>
          <div style={{ fontSize: '0.875rem' }}>{findingSourceLabel(vuln.finding_source)}</div>
          {(vuln.advisory_sources || []).length > 0 && (
            <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
              {(vuln.advisory_sources || []).join(', ')}
            </div>
          )}
          {(vuln.advisory_evidence || []).length > 0 && (
            <div style={{ fontSize: '0.75rem', color: '#22c55e', marginTop: '0.25rem' }}>
              {(vuln.advisory_evidence || []).length} verified advisories
            </div>
          )}
        </div>
        <div className="stat-card">
          <div className="label">CISA KEV</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.exploited ? <span className="badge badge-critical">Known exploited</span> : '-'}</div>
        </div>
        <div className="stat-card">
          <div className="label">EPSS</div>
          <div style={{ fontSize: '0.875rem' }}>{vuln.epss_score ? `${(vuln.epss_score * 100).toFixed(1)}%` : '-'}</div>
          {vuln.epss_percentile ? <div className="mono" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>p{(vuln.epss_percentile * 100).toFixed(1)}</div> : null}
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
            {formatDateOnly(vuln.due_at)}
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
          <input type="text" placeholder="Assignee (담당자)" value={triageAssignee} onChange={(e) => setTriageAssignee(e.target.value)} title="Assignee responsible for remediation" />
          <input type="date" value={triageExpiresAt} onChange={(e) => setTriageExpiresAt(e.target.value)} title="Triage expiry date" />
          {triageExpiresAt && <button className="btn btn-secondary btn-sm" onClick={() => setTriageExpiresAt('')}>Clear Expiry</button>}
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

      <AiAssessmentCard vuln={vuln} />

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
            <tr><td style={{ color: 'var(--text-muted)' }}>Asset Type</td><td className="mono">{vuln.asset_type || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Package Type</td><td className="mono">{vuln.pkg_type || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Ecosystem</td><td className="mono">{vuln.ecosystem || '-'}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Advisory Sources</td><td className="mono">{(vuln.advisory_sources || []).length ? (vuln.advisory_sources || []).join(', ') : '-'}</td></tr>
            {vuln.image_name && <tr><td style={{ color: 'var(--text-muted)' }}>Image</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.image_name}</td></tr>}
            {vuln.image_id && <tr><td style={{ color: 'var(--text-muted)' }}>Image ID</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.image_id}</td></tr>}
            {vuln.container_id && <tr><td style={{ color: 'var(--text-muted)' }}>Container ID</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.container_id}</td></tr>}
            {vuln.target && <tr><td style={{ color: 'var(--text-muted)' }}>Target</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.target}</td></tr>}
            <tr><td style={{ color: 'var(--text-muted)' }}>Installed Version</td><td className="mono">{vuln.installed_version}</td></tr>
            <tr><td style={{ color: 'var(--text-muted)' }}>Fixed Version</td><td className="mono" style={{ color: vuln.fixed_version ? 'var(--low)' : 'var(--critical)', fontWeight: 600 }}>{vuln.fixed_version || 'No fix available'}</td></tr>
            {vuln.pkg_path && <tr><td style={{ color: 'var(--text-muted)' }}>Path</td><td className="mono" style={{ fontSize: '0.8125rem' }}>{vuln.pkg_path}</td></tr>}
          </tbody>
        </table>
      </div>

      {(vuln.advisory_evidence || []).length > 0 && (
        <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
          <h3 style={{ margin: '0 0 0.75rem' }}>Advisory Evidence</h3>
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Ecosystem</th>
                <th>Fixed</th>
                <th>CVSS</th>
                <th>EPSS</th>
                <th>Title</th>
              </tr>
            </thead>
            <tbody>
              {(vuln.advisory_evidence || []).map((e, idx) => (
                <tr key={`${e.source}-${idx}`}>
                  <td><span className="badge">{e.source}</span></td>
                  <td className="mono">{e.ecosystem || '-'}</td>
                  <td className="mono">{e.fixed_version || '-'}</td>
                  <td className="mono">{e.cvss_score ? e.cvss_score.toFixed(1) : '-'}</td>
                  <td className="mono">{e.epss_score ? `${(e.epss_score * 100).toFixed(1)}%` : '-'}</td>
                  <td style={{ maxWidth: 420, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.title || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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





// ── Topology (typed asset knowledge graph) ──────────────────────────────────



