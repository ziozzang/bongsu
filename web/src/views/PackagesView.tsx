import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import { api, type Pkg, type Host, type FilterOptions, type Vuln } from '../api';
import { Loading, SortHeader } from '../components/primitives';
import { Pager, CheckboxField } from '../components/controls';
import { CvssTooltip } from '../components/CvssTooltip';
import { formatDateOnly, formatDateTimeFull } from '../lib/format';

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

export function PackagesView({ onSelectVuln }: { onSelectVuln?: (v: Vuln) => void }) {
  const [pkgs, setPkgs] = useState<Pkg[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const loadSeq = useRef(0);
  const [filterOpts, setFilterOpts] = useState<FilterOptions | null>(null);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});

  const [hostId, setHostId] = useState('');
  const [container, setContainer] = useState('');
  const [lang, setLang] = useState('');
  const [source, setSource] = useState('');
  const [query, setQuery] = useState('');
  const [version, setVersion] = useState('');
  const [ecosystem, setEcosystem] = useState('');
  const [arch, setArch] = useState('');
  const [assetType, setAssetType] = useState('');
  const [hasVulns, setHasVulns] = useState(false);
  const [minCvss, setMinCvss] = useState('');
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

  const load = useCallback((p: number, hId: string, cont: string, langLabel: string, src: string, q: string, sBy: string, sDesc: boolean, adv: { version: string; ecosystem: string; arch: string; assetType: string; hasVulns: boolean; minCvss: string }) => {
    const seq = ++loadSeq.current;
    setLoading(true);
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (hId) params.host_id = hId;
    if (cont) params.container = cont;
    if (src) params.source = src;
    if (q) params.q = q;
    if (adv.version) params.version = adv.version;
    if (adv.ecosystem) params.ecosystem = adv.ecosystem;
    if (adv.arch) params.arch = adv.arch;
    if (adv.assetType) params.asset_type = adv.assetType;
    if (adv.hasVulns) params.has_vulns = 'true';
    if (adv.minCvss) params.min_cvss = adv.minCvss;
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
        if (seq !== loadSeq.current) return;
        setPkgs(items);
        setTotal(types.length > 1 ? items.length : r.total);
        setPage(p);
        setLoading(false);
      })
      .catch(() => { if (seq === loadSeq.current) setLoading(false); });
  }, [filterOpts]);

  const adv = { version, ecosystem, arch, assetType, hasVulns, minCvss };

  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); }, [filterOpts]);
  useEffect(() => { if (filterOpts) load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); }, [hostId, container, lang, source, ecosystem, arch, assetType, hasVulns]);

  const handleSearch = () => { load(0, hostId, container, lang, source, query, sortBy, sortDesc, adv); };
  const handleKeyDown = (e: React.KeyboardEvent) => { if (e.key === 'Enter') handleSearch(); };

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : false;
    setSortBy(col);
    setSortDesc(nextDesc);
    load(0, hostId, container, lang, source, query, col, nextDesc, adv);
  };


  const cols: [string, string][] = [
    ['name', 'Name'], ['version', 'Version'], ['pkg_type', 'Type'],
    ['max_cvss', 'CVSS'], ['vuln_count', 'Vulns'],
    ['container', 'Container'], ['source', 'Source'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Packages</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
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
          <input
            type="text"
            placeholder="Version (exact)..."
            value={version}
            onChange={(e) => setVersion(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 140 }}
            title="Exact installed version"
          />
          <input
            type="text"
            placeholder="Ecosystem (pypi, npm...)"
            value={ecosystem}
            onChange={(e) => setEcosystem(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 150 }}
            title="Ecosystem, e.g. pypi/npm/debian/rhel/alpine"
            list="pkg-ecosystem-list"
          />
          <datalist id="pkg-ecosystem-list">
            <option value="pypi" /><option value="npm" /><option value="debian" /><option value="rhel" /><option value="alpine" />
            <option value="go" /><option value="maven" /><option value="cargo" /><option value="gem" /><option value="nuget" />
          </datalist>
          <input
            type="text"
            placeholder="Arch..."
            value={arch}
            onChange={(e) => setArch(e.target.value)}
            onKeyDown={handleKeyDown}
            style={{ minWidth: 90 }}
            title="Package architecture, e.g. x86_64, amd64, noarch"
          />
          <select value={assetType} onChange={(e) => setAssetType(e.target.value)} title="Asset type">
            <option value="">All Asset Types</option>
            <option value="host">Host</option>
            <option value="container">Container</option>
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
            style={{ width: 110 }}
            title="Minimum CVSS score"
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Has vulnerabilities" checked={hasVulns} onChange={setHasVulns} />
          </div>
          <div className="filter-actions">
            <span className="result-count">{total.toLocaleString()} packages</span>
            <button className="btn btn-primary" onClick={handleSearch}>Search</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr>
                <th>Host</th>
                {cols.map(([key, label]) => (
                  <SortHeader key={key} col={key} label={label} sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
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
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(p.created_at)}>{formatDateOnly(p.created_at)}</td>
                </tr>
              ))}
              {pkgs.length === 0 && <tr className="empty-row"><td colSpan={10}>No packages match — adjust the host, source, or search filters above, or run a scan to collect inventory.</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, hostId, container, lang, source, query, sortBy, sortDesc, adv)} />
      </div>
    </>
  );
}


