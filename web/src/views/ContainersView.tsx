import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api, type ContainerAsset, type Host } from '../api';
import { renderFactValue } from '../components/FactsCard';
import { Loading, SortHeader } from '../components/primitives';
import { Pager } from '../components/controls';
import { formatDateTime, formatDateTimeFull, fmtCount } from '../lib/format';

export function ContainersView() {
  const [containers, setContainers] = useState<ContainerAsset[]>([]);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [hostMap, setHostMap] = useState<Record<string, string>>({});
  const [hostIPMap, setHostIPMap] = useState<Record<string, string>>({});
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);
  const [expandedFacts, setExpandedFacts] = useState('');
  const loadSeq = useRef(0);

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
    const seq = ++loadSeq.current;
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
        if (seq !== loadSeq.current) return;
        setContainers(r.items || []);
        setTotal(r.total || 0);
        setPage(p);
        setLoading(false);
      })
      .catch(() => { if (seq === loadSeq.current) setLoading(false); });
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


  const runtimes = Array.from(new Set(['docker', 'containerd', 'podman', ...containers.map(c => c.runtime).filter(Boolean)])).sort();
  const states = Array.from(new Set(['running', 'exited', 'created', 'paused', 'restarting', 'dead', ...containers.map(c => c.state).filter(Boolean)])).sort();
  const cols: [string, string][] = [
    ['name', 'Name'], ['state', 'State'], ['runtime', 'Runtime'],
    ['image_name', 'Image'], ['container_id', 'Container ID'],
    ['vulnerability_count', 'Findings'], ['critical_count', 'Critical'], ['high_count', 'High'], ['max_cvss', 'Max CVSS'], ['package_count', 'Packages'],
    ['started_at', 'Started'],
  ];

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Containers</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
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
          <div className="filter-actions">
            <span className="result-count">{total.toLocaleString()} containers</span>
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
                <th>Labels</th>
                <th>Image ID</th>
                <th>Scan</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {containers.map(c => (
                <React.Fragment key={c.id}>
                <tr>
                  <td><span className="host-link" title={`IP: ${hostIPMap[c.host_id] || ''}`}>{hostMap[c.host_id] || c.host_id}</span></td>
                  <td
                    className="mono"
                    style={{ cursor: c.facts ? 'pointer' : 'default' }}
                    title={c.facts ? 'Show container OS facts' : ''}
                    onClick={() => c.facts && setExpandedFacts(e => (e === c.id ? '' : c.id))}
                  >{c.facts ? (expandedFacts === c.id ? '▾ ' : '▸ ') : ''}{c.name || '-'}</td>
                  <td><span className="badge">{c.state || '-'}</span></td>
                  <td>{c.runtime || '-'}</td>
                  <td className="mono" title={c.image_name}>{c.image_name || '-'}</td>
                  <td className="mono" title={c.container_id}>{c.container_id ? c.container_id.slice(0, 16) : '-'}</td>
                  <td className="mono" style={{ color: c.vulnerability_count ? 'var(--high)' : 'var(--text-muted)', fontWeight: c.vulnerability_count ? 700 : 400 }}>{c.vulnerability_count || 0}</td>
                  <td className="mono" style={{ color: c.critical_count ? 'var(--critical)' : 'var(--text-muted)', fontWeight: c.critical_count ? 700 : 400 }}>{c.critical_count || 0}</td>
                  <td className="mono" style={{ color: c.high_count ? 'var(--high)' : 'var(--text-muted)', fontWeight: c.high_count ? 700 : 400 }}>{c.high_count || 0}</td>
                  <td className="mono" style={{ color: (c.max_cvss || 0) >= 9 ? 'var(--critical)' : (c.max_cvss || 0) >= 7 ? 'var(--high)' : 'var(--text-muted)' }}>{c.max_cvss ? c.max_cvss.toFixed(1) : '-'}</td>
                  <td className="mono">{fmtCount(c.package_count)}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(c.started_at)}>{formatDateTime(c.started_at)}</td>
                  <td className="mono" title={c.labels_redacted ? 'Labels hidden by default; use include_labels=true in the API for raw labels' : ''}>{c.label_count || 0}</td>
                  <td className="mono" title={c.image_id}>{c.image_id ? c.image_id.replace(/^sha256:/, '').slice(0, 18) : '-'}</td>
                  <td className="mono" title={c.latest_scan_id || c.scan_id}>{(c.latest_scan_id || c.scan_id || '').slice(0, 8) || '-'}</td>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(c.created_at)}>{formatDateTime(c.created_at)}</td>
                </tr>
                {expandedFacts === c.id && c.facts && (
                  <tr>
                    <td colSpan={16} style={{ background: 'var(--bg)', padding: '0.75rem 1.5rem' }}>
                      {renderFactValue(c.facts)}
                    </td>
                  </tr>
                )}
                </React.Fragment>
              ))}
              {containers.length === 0 && <tr className="empty-row"><td colSpan={16}>No containers reported yet — agents collect running containers automatically unless started with -skip-containers.</td></tr>}
            </tbody>
          </table>
        )}
        <Pager page={page} limit={limit} total={total} onPage={(p) => load(p, hostId, runtime, state, image, query, sortBy, sortDesc)} />
      </div>
    </>
  );
}
