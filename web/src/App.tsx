import React, { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import { useTheme } from './hooks/useTheme';
import { LiveIndicator } from './components/LiveIndicator';
import { subscribeLiveBus } from './hooks/useLiveEvents';
import { DashboardView } from './views/DashboardView';
import { CommandPalette, type CommandItem } from './components/CommandPalette';
import { DataTable, type Column } from './components/DataTable';
import { getHashView, setHashView } from './hooks/useHashRoute';
import { verCmp } from './lib/version';
import { type SeverityTone, findingSourceLabel, riskLevelLabel, riskLevelColor, recommendedActionLabel, recommendedActionTone, riskLevelTone, isVulnAnalysis, aiPolicyModeTone, aiPolicyModeBlurb, aiApprovalStatusTone, aiActionLabel, aiProposedSummary, strField, SEVERITY_ORDER, severityColor, agentStatusColor } from './lib/severity';
import { formatDateTime, formatDateTimeFull, formatDateOnly, fmtCount, shortDate, niceMax, formatAge, dateInputValue } from './lib/format';
import { type ScanRequestFilters, type VulnerabilityFilters, type HostFilters } from './lib/viewTypes';
import { parseCvssVector } from './lib/cvss';
import { Icon, BeaconMark } from './components/Icon';
import { Loading, LoadError, EmptyState, SortHeader, Badge, toneColor } from './components/primitives';
import { StackedAreaChart, BarSeries, DonutChart, Sparkline, KpiCard, SEV_KEYS } from './components/charts';
import { RangeSwitcher, CheckboxField, Modal, Pager } from './components/controls';
import { renderFactValue, FactsCard } from './components/FactsCard';
import { CvssTooltip } from './components/CvssTooltip';
import { AiAssessmentCard } from './components/AiAssessmentCard';
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
import { IntelView } from './views/IntelView';
import { PackagesView } from './views/PackagesView';
import { AssetGroupsView } from './views/AssetGroupsView';
import { CveSearchView } from './views/CveSearchView';
import { HostsView } from './views/HostsView';
import { HostDetailView } from './views/HostDetailView';
import { ReportsView } from './views/ReportsView';
import { TopologyView } from './views/TopologyView';
import { VulnDetailView } from './views/VulnDetailView';
import { VulnsView } from './views/VulnsView';
import { api, setApiKey, getApiKey, clearApiKey, setSession, getSession, clearSession, hasAuth, onAuthFailure, type Host, type UserAccount, type ProcessSnapshot, type PortInfo, type Vuln, type Pkg, type Stats, type FilterOptions, type Scan, type ScanRequest, type HealthStatus, type CveDbEntry, type CveAffectedPackage, type CveReferenceGroupSummary, type CveDbStatsResponse, type CveSourceStat, type CveRematchPolicy, type CveEpssMergeStats, type CveDbQuality, type InstallerStatus, type SecurityDbOperationalStatus, type AgentFleetStatus, type ContainerAsset, type VulnSummaryRow, type AuditLog, type AccessSubject, type AccessPolicy, type AccessControlStatus, type ScheduledScan, type AssetGroup, type AssetGroupDetail, type VulnTrendRow, type ScanActivityRow, type VulnTrendSummary, type AtRiskHost, type Recommendation, type PostureComparison, type ExecutiveSummary, type SLAComplianceReport, type RiskBreakdownRow, type NotificationRule, type NotificationLogEntry, type GraphNodeType, type GraphNode, type GraphNeighborhood, type GraphSchema, type GraphOverview, type BlastRadiusRollup, type ExposedService, type ImageExposure, type OrgExposure, type OrgExposureRow, type RemediationRow, type CveGraphInfo, type LocalUser, type ApiToken, type LLMStatus, type VulnAnalysis, type AIPolicyStatus, type AIApproval } from './api';





// renderFactValue formats an arbitrary JSON fact value for display: scalars
// inline, string arrays as comma lists, arrays of objects as compact rows, and
// nested objects as an indented key/value block.



// ── Shared formatting helpers ────────────────────────────────────────────────
// One date/time format used across every view: local "YYYY-MM-DD HH:mm".


type View = 'dashboard' | 'hosts' | 'packages' | 'containers' | 'vulns' | 'vuln-detail' | 'scans' | 'audit' | 'rbac' | 'host-detail' | 'cve-search' | 'schedules' | 'asset-groups' | 'trends' | 'reports' | 'notifications' | 'topology' | 'users' | 'tokens' | 'ai-triage' | 'ai-approvals' | 'intel';


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
        {view === 'intel' && <IntelView />}
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
    ['intel', 'Intelligence', 'ai-triage'],
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







// AiAnalysisBody renders a stored VulnAnalysis: badges, confidence, reasoning,
// a model/provider footer, and an Apply action for actionable recommendations.

// AiAssessmentCard fetches and renders the AI assessment for a single
// vulnerability finding. It degrades gracefully when the LLM is not
// configured and never throws into the surrounding detail page.






// ── Topology (typed asset knowledge graph) ──────────────────────────────────



