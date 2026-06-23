import React, { useCallback,useEffect,useRef,useState } from 'react';
import { api, getApiKey, getSession, type Vuln, type FilterOptions, type Host } from '../api';
import { type VulnerabilityFilters } from '../lib/viewTypes';
import { Loading, LoadError, SortHeader, EmptyState } from '../components/primitives';
import { Pager, CheckboxField, Modal } from '../components/controls';
import { CvssTooltip } from '../components/CvssTooltip';
import { findingSourceLabel, riskLevelColor, riskLevelLabel, severityColor } from '../lib/severity';
import { formatDateOnly } from '../lib/format';
import { verCmp } from '../lib/version';

export function VulnsView({ initialFilters, onSelectVuln }: { initialFilters?: VulnerabilityFilters; onSelectVuln: (v: Vuln) => void }) {
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
