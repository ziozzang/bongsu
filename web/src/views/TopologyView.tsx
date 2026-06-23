import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { api, type GraphNode, type GraphNodeType, type GraphNeighborhood, type GraphOverview, type GraphSchema, type BlastRadiusRollup, type CveGraphInfo, type ExposedService, type ImageExposure, type OrgExposure, type OrgExposureRow, type RemediationRow } from '../api';
import { Loading, LoadError, EmptyState } from '../components/primitives';
import { severityColor } from '../lib/severity';

const GRAPH_NODE_COLORS: Record<GraphNodeType, string> = {
  host: '#7c6cf0',      // primary violet
  container: '#3aa0e0', // blue
  package: '#30c060',   // green
  service: '#e0b020',   // amber
  cve: '#f04444',       // red
  group: '#c060d0',     // magenta
  process: '#e07050',   // coral
  image: '#20b0a0',     // teal
  team: '#a070e0',      // periwinkle
  environment: '#d09030', // ochre
};

const GRAPH_MAX_NODES = 60;

function graphNodeColor(n: GraphNode): string {
  if (n.type === 'cve') {
    const sev = String(n.attrs?.severity ?? '');
    if (sev) return severityColor(sev);
  }
  return GRAPH_NODE_COLORS[n.type] || 'var(--text-muted)';
}

function graphNodeTitle(n: GraphNode): string {
  const parts = [`${n.type}: ${n.label}`];
  const sev = String(n.attrs?.severity ?? '');
  if (sev) parts.push(`severity ${sev}`);
  const cvss = Number(n.attrs?.cvss_score ?? 0);
  if (cvss > 0) parts.push(`CVSS ${cvss.toFixed(1)}`);
  const env = String(n.attrs?.environment ?? '');
  if (env) parts.push(`env ${env}`);
  return parts.join(' · ');
}

// GraphCanvas renders a GraphNeighborhood as a pure-SVG radial node-link diagram
// (no external deps). The root sits at the center; the remaining nodes are
// grouped by type and distributed across concentric rings.
function GraphCanvas({ data, onNodeClick }: { data: GraphNeighborhood; onNodeClick: (n: GraphNode) => void }) {
  const cx = 400;
  const cy = 260;

  const layout = useMemo(() => {
    // Cap rendered nodes for readability, preferring high-CVSS nodes.
    const rootKey = `${data.root.type}|${data.root.id}`;
    const others = data.nodes.filter(n => `${n.type}|${n.id}` !== rootKey);
    const sorted = [...others].sort((a, b) => Number(b.attrs?.cvss_score ?? 0) - Number(a.attrs?.cvss_score ?? 0));
    const shown = sorted.slice(0, GRAPH_MAX_NODES);
    const hiddenCount = sorted.length - shown.length;

    // Group by node type so each type occupies its own arc.
    const byType = new Map<GraphNodeType, GraphNode[]>();
    shown.forEach(n => {
      const list = byType.get(n.type) || [];
      list.push(n);
      byType.set(n.type, list);
    });

    const pos = new Map<string, { x: number; y: number }>();
    pos.set(rootKey, { x: cx, y: cy });

    const types = Array.from(byType.keys());
    const ringStep = 110;
    types.forEach((t, ti) => {
      const list = byType.get(t) || [];
      const radius = ringStep * (ti + 1);
      // Offset each ring's starting angle so labels do not stack vertically.
      const startAngle = (ti * Math.PI) / 6;
      list.forEach((n, i) => {
        const angle = startAngle + (i / Math.max(1, list.length)) * Math.PI * 2;
        pos.set(`${n.type}|${n.id}`, {
          x: cx + radius * Math.cos(angle),
          y: cy + radius * Math.sin(angle),
        });
      });
    });

    const drawn = [data.root, ...shown];
    const drawnKeys = new Set(drawn.map(n => `${n.type}|${n.id}`));
    const edges = data.edges.filter(e =>
      drawnKeys.has(`${e.src_type}|${e.src_id}`) && drawnKeys.has(`${e.dst_type}|${e.dst_id}`),
    );

    return { pos, drawn, edges, hiddenCount, rootKey };
  }, [data]);

  const usedTypes = useMemo(() => {
    const set = new Set<GraphNodeType>();
    layout.drawn.forEach(n => set.add(n.type));
    return Array.from(set);
  }, [layout]);

  return (
    <div className="graph-canvas">
      <svg viewBox="0 0 800 520" width="100%" height={480} role="img" aria-label="Asset relationship graph">
        {layout.edges.map((e, i) => {
          const a = layout.pos.get(`${e.src_type}|${e.src_id}`);
          const b = layout.pos.get(`${e.dst_type}|${e.dst_id}`);
          if (!a || !b) return null;
          return (
            <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="graph-edge">
              <title>{e.rel}</title>
            </line>
          );
        })}
        {layout.drawn.map(n => {
          const p = layout.pos.get(`${n.type}|${n.id}`);
          if (!p) return null;
          const isRoot = `${n.type}|${n.id}` === layout.rootKey;
          const r = isRoot ? 16 : 9;
          const color = graphNodeColor(n);
          const label = n.label.length > 22 ? n.label.slice(0, 21) + '…' : n.label;
          return (
            <g
              key={`${n.type}|${n.id}`}
              className="graph-node"
              transform={`translate(${p.x}, ${p.y})`}
              onClick={() => onNodeClick(n)}
              role="button"
              tabIndex={0}
              onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); onNodeClick(n); } }}
            >
              <title>{graphNodeTitle(n)}</title>
              <circle r={r} fill={color} stroke={isRoot ? 'var(--text)' : 'var(--bg)'} strokeWidth={isRoot ? 2 : 1.5} />
              <text x={0} y={r + 13} textAnchor="middle" className="graph-node-label">{label}</text>
            </g>
          );
        })}
      </svg>
      <div className="graph-footer">
        <div className="graph-legend">
          {usedTypes.map(t => (
            <span key={t} className="graph-legend-item">
              <span className="graph-legend-dot" style={{ background: GRAPH_NODE_COLORS[t] }} />
              {t}
            </span>
          ))}
        </div>
        {(layout.hiddenCount > 0 || data.truncated) && (
          <span className="graph-truncated">
            {layout.hiddenCount > 0 ? `+${layout.hiddenCount} more (truncated)` : 'results truncated'}
          </span>
        )}
      </div>
    </div>
  );
}

type TopologyFocus =
  | { kind: 'blast'; id: string }
  | { kind: 'host'; id: string }
  | { kind: 'group'; id: string };

type TopologySection = 'overview' | 'attack-surface' | 'images' | 'remediation' | 'ownership' | 'blast';

const TOPOLOGY_SECTIONS: { key: TopologySection; label: string }[] = [
  { key: 'overview', label: 'Overview' },
  { key: 'attack-surface', label: 'Attack Surface' },
  { key: 'images', label: 'Images' },
  { key: 'remediation', label: 'Remediation' },
  { key: 'ownership', label: 'Ownership' },
  { key: 'blast', label: 'Blast Radius' },
];

export function TopologyView({ onSelectHost }: { onSelectHost: (id: string) => void }) {
  const [section, setSection] = useState<TopologySection>('overview');

  const [schema, setSchema] = useState<GraphSchema | null>(null);
  const [overview, setOverview] = useState<GraphOverview | null>(null);
  const [overviewError, setOverviewError] = useState('');

  const [cveInput, setCveInput] = useState('');
  const [rollup, setRollup] = useState<BlastRadiusRollup | null>(null);
  const [cveInfo, setCveInfo] = useState<CveGraphInfo | null>(null);

  const [graph, setGraph] = useState<GraphNeighborhood | null>(null);
  const [trail, setTrail] = useState<{ focus: TopologyFocus; label: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const loadOverview = useCallback(() => {
    setOverviewError('');
    Promise.all([
      api.graphOverview(),
      api.graphSchema(),
    ]).then(([ov, sc]) => {
      setOverview(ov);
      setSchema(sc);
    }).catch((err) => setOverviewError(err?.message || 'Failed to load graph overview'));
  }, []);

  useEffect(() => { loadOverview(); }, [loadOverview]);

  const focusHost = useCallback((id: string, label: string, append: boolean) => {
    setLoading(true);
    setError('');
    api.graphHost(id)
      .then((g) => {
        setGraph(g);
        setRollup(null);
        setTrail(prev => append ? [...prev, { focus: { kind: 'host', id }, label }] : [{ focus: { kind: 'host', id }, label }]);
        setLoading(false);
      })
      .catch((err) => { setError(err?.message || 'Failed to load host neighborhood'); setLoading(false); });
  }, []);

  const focusGroup = useCallback((id: string, label: string, append: boolean) => {
    setLoading(true);
    setError('');
    api.graphGroup(id)
      .then((g) => {
        setGraph(g);
        setRollup(null);
        setTrail(prev => append ? [...prev, { focus: { kind: 'group', id }, label }] : [{ focus: { kind: 'group', id }, label }]);
        setLoading(false);
      })
      .catch((err) => { setError(err?.message || 'Failed to load group neighborhood'); setLoading(false); });
  }, []);

  const analyzeCve = useCallback((rawId: string) => {
    const id = rawId.trim();
    if (!id) return;
    setLoading(true);
    setError('');
    setCveInfo(null);
    api.graphBlastRadius(id)
      .then((res) => {
        setRollup(res.rollup);
        setGraph(res.graph);
        setTrail([{ focus: { kind: 'blast', id }, label: id }]);
        setLoading(false);
      })
      .catch((err) => { setError(err?.message || 'Blast-radius analysis failed'); setLoading(false); });
    api.graphCve(id).then(setCveInfo).catch(() => setCveInfo(null));
  }, []);

  const handleNodeClick = useCallback((n: GraphNode) => {
    if (n.type === 'host') focusHost(n.id, n.label, true);
    else if (n.type === 'group') focusGroup(n.id, n.label, true);
    else if (n.type === 'cve') analyzeCve(n.id);
  }, [focusHost, focusGroup, analyzeCve]);

  const jumpToCrumb = useCallback((idx: number) => {
    const target = trail[idx];
    if (!target) return;
    setTrail(prev => prev.slice(0, idx + 1));
    setLoading(true);
    setError('');
    const f = target.focus;
    if (f.kind === 'blast') {
      api.graphCve(f.id).then(setCveInfo).catch(() => setCveInfo(null));
    } else {
      setCveInfo(null);
    }
    const req = f.kind === 'blast'
      ? api.graphBlastRadius(f.id).then(r => { setRollup(r.rollup); return r.graph; })
      : f.kind === 'host'
        ? api.graphHost(f.id).then(g => { setRollup(null); return g; })
        : api.graphGroup(f.id).then(g => { setRollup(null); return g; });
    req
      .then((g) => { setGraph(g); setLoading(false); })
      .catch((err) => { setError(err?.message || 'Failed to load neighborhood'); setLoading(false); });
  }, [trail]);

  const current = trail.length ? trail[trail.length - 1].focus : null;
  const rootHostId = graph && graph.root.type === 'host' ? graph.root.id : '';

  return (
    <>
      <h1 style={{ marginBottom: '1rem' }}>Topology</h1>

      <div className="topo-tabs" role="tablist" aria-label="Topology sections" style={{ marginBottom: '1.25rem' }}>
        {TOPOLOGY_SECTIONS.map(s => (
          <button
            key={s.key}
            type="button"
            role="tab"
            aria-selected={section === s.key}
            className={section === s.key ? 'active' : ''}
            onClick={() => setSection(s.key)}
          >
            {s.label}
          </button>
        ))}
      </div>

      {section === 'overview' && (
        overviewError ? (
          <div className="card"><LoadError message={overviewError} onRetry={loadOverview} /></div>
        ) : !overview || !schema ? (
          <div className="card"><Loading label="Loading graph overview..." /></div>
        ) : (
          <>
            <div className="stats-grid">
              {schema.node_types.map(nt => (
                <div className="stat-card" key={nt.type} title={nt.description}>
                  <div className="accent-bar" style={{ background: GRAPH_NODE_COLORS[nt.type] || 'var(--primary)' }} />
                  <div className="label">{nt.label}</div>
                  <div className="value" style={{ color: GRAPH_NODE_COLORS[nt.type] }}>{(overview.nodes[nt.type] || 0).toLocaleString()}</div>
                </div>
              ))}
            </div>
            <div className="card" style={{ padding: '0.75rem 1rem' }}>
              <div className="graph-edge-stats">
                {schema.relations.map(rel => (
                  <span key={rel.rel} className="graph-edge-stat" title={rel.description}>
                    <span className="graph-edge-stat-label">{rel.rel.replace(/_/g, ' ')}</span>
                    <span className="graph-edge-stat-value">{(overview.edges[rel.rel] || 0).toLocaleString()}</span>
                  </span>
                ))}
              </div>
            </div>
          </>
        )
      )}

      {section === 'attack-surface' && <AttackSurfaceSection onSelectHost={onSelectHost} />}
      {section === 'images' && <ImagesSection />}
      {section === 'remediation' && <RemediationSection />}
      {section === 'ownership' && <OwnershipSection />}

      {section === 'blast' && (
        <>
          <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
            <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}><h2>Blast-Radius Explorer</h2></div>
            <div className="filters">
              <input
                type="text"
                placeholder="CVE ID (e.g. CVE-2024-3094)"
                value={cveInput}
                onChange={(e) => setCveInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') analyzeCve(cveInput); }}
                style={{ minWidth: 240 }}
              />
              <button className="btn btn-primary" onClick={() => analyzeCve(cveInput)} disabled={loading || !cveInput.trim()}>
                {loading ? 'Analyzing...' : 'Analyze'}
              </button>
            </div>
          </div>

          {error && <div className="card" style={{ marginBottom: '1rem' }}><LoadError message={error} /></div>}

          {loading && <div className="card" style={{ marginBottom: '1rem' }}><Loading label="Loading topology..." /></div>}

          {/* Blast-radius rollup */}
          {!loading && rollup && current?.kind === 'blast' && (
            rollup.host_count === 0 ? (
              <div className="card" style={{ marginBottom: '1rem' }}>
                <EmptyState message="No assets in your scope are exposed to this CVE." />
              </div>
            ) : (
              <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
                <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
                  <h2 style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                    {rollup.vulnerability_id}{rollup.title ? ` — ${rollup.title}` : ''}
                    {(rollup.known_exploited || cveInfo?.known_exploited) && <span className="badge kev-badge">KEV — Known Exploited</span>}
                  </h2>
                </div>
                {cveInfo && (cveInfo.aliases.length > 0 || cveInfo.epss_score > 0) && (
                  <div className="topo-cve-meta">
                    {cveInfo.epss_score > 0 && (
                      <span className="topo-cve-meta-item"><span className="topo-cve-meta-label">EPSS</span> {(cveInfo.epss_score * 100).toFixed(1)}%</span>
                    )}
                    {cveInfo.aliases.length > 0 && (
                      <span className="topo-cve-meta-item">
                        <span className="topo-cve-meta-label">Aliases</span>{' '}
                        {cveInfo.aliases.slice(0, 10).join(', ')}
                        {cveInfo.aliases.length > 10 ? ` +${cveInfo.aliases.length - 10} more` : ''}
                      </span>
                    )}
                  </div>
                )}
                <div className="stats-grid">
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: severityColor(rollup.severity) }} />
                    <div className="label">Severity</div>
                    <div className="value" style={{ fontSize: '1rem' }}>
                      <span className="badge" style={{ color: severityColor(rollup.severity) }}>{rollup.severity || 'UNKNOWN'}</span>
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: 'var(--high)' }} />
                    <div className="label">CVSS</div>
                    <div className="value">{rollup.cvss_score > 0 ? rollup.cvss_score.toFixed(1) : '-'}</div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: 'var(--medium)' }} />
                    <div className="label">EPSS</div>
                    <div className="value">{rollup.epss_score > 0 ? (rollup.epss_score * 100).toFixed(1) + '%' : '-'}</div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: rollup.known_exploited ? 'var(--critical)' : 'var(--unknown)' }} />
                    <div className="label">Exploited</div>
                    <div className="value" style={{ fontSize: '1rem' }}>
                      {rollup.known_exploited
                        ? <span className="badge kev-badge">KEV</span>
                        : <span className="badge" style={{ color: 'var(--text-muted)' }}>No</span>}
                    </div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: GRAPH_NODE_COLORS.host }} />
                    <div className="label">Hosts</div>
                    <div className="value" style={{ color: GRAPH_NODE_COLORS.host }}>{rollup.host_count.toLocaleString()}</div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: GRAPH_NODE_COLORS.container }} />
                    <div className="label">Containers</div>
                    <div className="value" style={{ color: GRAPH_NODE_COLORS.container }}>{rollup.container_count.toLocaleString()}</div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: GRAPH_NODE_COLORS.package }} />
                    <div className="label">Packages</div>
                    <div className="value" style={{ color: GRAPH_NODE_COLORS.package }}>{rollup.package_count.toLocaleString()}</div>
                  </div>
                  <div className="stat-card">
                    <div className="accent-bar" style={{ background: GRAPH_NODE_COLORS.group }} />
                    <div className="label">Groups</div>
                    <div className="value" style={{ color: GRAPH_NODE_COLORS.group }}>{rollup.group_count.toLocaleString()}</div>
                  </div>
                </div>
                <div className="graph-breakdowns">
                  <GraphBreakdown title="By Severity" data={rollup.by_severity} />
                  <GraphBreakdown title="By Environment" data={rollup.by_environment} />
                  <GraphBreakdown title="By Criticality" data={rollup.by_criticality} />
                </div>
              </div>
            )
          )}

          {/* C + D. Focus graph + drill-down */}
          {!loading && graph && !(rollup && current?.kind === 'blast' && rollup.host_count === 0) && (
            <div className="card" style={{ padding: '1rem' }}>
              <div className="graph-toolbar">
                <nav className="graph-breadcrumb" aria-label="Topology focus">
                  {trail.map((c, i) => (
                    <React.Fragment key={`${c.focus.kind}|${c.focus.id}|${i}`}>
                      {i > 0 && <span className="graph-breadcrumb-sep">/</span>}
                      {i === trail.length - 1 ? (
                        <span className="graph-breadcrumb-current">{c.label}</span>
                      ) : (
                        <a href="#" onClick={(e) => { e.preventDefault(); jumpToCrumb(i); }}>{c.label}</a>
                      )}
                    </React.Fragment>
                  ))}
                </nav>
                {rootHostId && (
                  <button className="btn btn-secondary btn-sm" onClick={() => onSelectHost(rootHostId)}>
                    Open host detail
                  </button>
                )}
              </div>
              <GraphCanvas data={graph} onNodeClick={handleNodeClick} />
            </div>
          )}

          {!loading && !graph && !error && !rollup && (
            <div className="card">
              <EmptyState message="Enter a CVE ID above to map its blast radius, then click hosts, groups, or CVEs in the graph to drill down." />
            </div>
          )}
        </>
      )}
    </>
  );
}

// AttackSurfaceSection lists network-exposed listening services, ranked by host
// risk. Rows for KEV-affected or high crit/high hosts get a subtle tint.
function AttackSurfaceSection({ onSelectHost }: { onSelectHost: (id: string) => void }) {
  const [services, setServices] = useState<ExposedService[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.graphExposure()
      .then(r => { setServices(r.services || []); setTotal(r.total); setLoading(false); })
      .catch(e => { setError(e instanceof Error ? e.message : 'Failed to load exposed services'); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="card"><Loading label="Loading exposed services..." /></div>;
  if (error) return <div className="card"><LoadError message={error} onRetry={load} /></div>;
  const rows = services || [];

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
        <h2>Attack Surface</h2>
        <span className="muted-caption">{total.toLocaleString()} network-exposed listening service{total === 1 ? '' : 's'}, ranked by host risk</span>
      </div>
      {rows.length === 0 ? (
        <EmptyState message="No network-exposed listening services in scope." />
      ) : (
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Address:Port</th>
              <th>Protocol</th>
              <th>Service</th>
              <th>Process</th>
              <th>User</th>
              <th>Host Crit/High</th>
              <th>KEV</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((s, i) => {
              const tint = s.host_known_exploited ? 'topo-row-kev' : s.host_critical_high > 0 ? 'topo-row-risk' : '';
              return (
                <tr key={`${s.host_id}|${s.address}|${s.port}|${s.protocol}|${i}`} className={tint}>
                  <td><span className="host-link" onClick={() => onSelectHost(s.host_id)} title={`${s.environment || '-'} · ${s.criticality || '-'}`}>{s.hostname || s.host_id}</span></td>
                  <td className="mono">{s.address}:{s.port}</td>
                  <td className="mono">{s.protocol || '-'}</td>
                  <td>{s.service_name || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }} title={s.cmdline}>{s.process_name || '-'}{s.pid > 0 ? ` (pid ${s.pid})` : ''}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.process_user || '-'}</td>
                  <td style={{ color: s.host_critical_high > 0 ? severityColor('CRITICAL') : 'var(--text-muted)', fontWeight: 600 }}>{s.host_critical_high.toLocaleString()}</td>
                  <td>{s.host_known_exploited && <span className="badge kev-badge">KEV</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ImagesSection lists container images in scope with their exposure rollups.
function ImagesSection() {
  const [images, setImages] = useState<ImageExposure[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.graphImages()
      .then(r => { setImages(r.images || []); setTotal(r.total); setLoading(false); })
      .catch(e => { setError(e instanceof Error ? e.message : 'Failed to load images'); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="card"><Loading label="Loading container images..." /></div>;
  if (error) return <div className="card"><LoadError message={error} onRetry={load} /></div>;
  const rows = images || [];

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
        <h2>Container Images</h2>
        <span className="muted-caption">{total.toLocaleString()} image{total === 1 ? '' : 's'} in scope</span>
      </div>
      {rows.length === 0 ? (
        <EmptyState message="No container images in scope — images appear here once container inventories are ingested." />
      ) : (
        <table>
          <thead>
            <tr>
              <th>Image</th>
              <th>Hosts</th>
              <th>Containers</th>
              <th>Packages</th>
              <th>CVEs</th>
              <th>Crit/High</th>
              <th>Max CVSS</th>
              <th>KEV</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((im, i) => {
              const shortDigest = im.digest ? im.digest.replace(/^sha256:/, '').slice(0, 12) : '';
              return (
                <tr key={`${im.digest || im.image_name}|${i}`} className={im.known_exploited ? 'topo-row-kev' : im.critical_high > 0 ? 'topo-row-risk' : ''}>
                  <td className="mono" style={{ fontSize: '0.8125rem' }} title={im.digest}>{im.image_name || shortDigest || '-'}</td>
                  <td>{im.host_count.toLocaleString()}</td>
                  <td>{im.container_count.toLocaleString()}</td>
                  <td>{im.package_count.toLocaleString()}</td>
                  <td>{im.cve_count.toLocaleString()}</td>
                  <td style={{ color: im.critical_high > 0 ? severityColor('CRITICAL') : 'var(--text-muted)', fontWeight: 600 }}>{im.critical_high.toLocaleString()}</td>
                  <td className="mono" style={{ color: severityColor(cvssSeverity(im.max_cvss)), fontWeight: 600 }}>{im.max_cvss > 0 ? im.max_cvss.toFixed(1) : '-'}</td>
                  <td>{im.known_exploited && <span className="badge kev-badge">KEV</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </div>
  );
}

// RemediationSection lists the highest-leverage package upgrades first.
function RemediationSection() {
  const [rows, setRows] = useState<RemediationRow[] | null>(null);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.graphRemediation()
      .then(r => { setRows(r.remediations || []); setTotal(r.total); setLoading(false); })
      .catch(e => { setError(e instanceof Error ? e.message : 'Failed to load remediations'); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="card"><Loading label="Loading remediations..." /></div>;
  if (error) return <div className="card"><LoadError message={error} onRetry={load} /></div>;
  const items = rows || [];

  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}>
        <h2>Top Fixes</h2>
        <span className="muted-caption">{total.toLocaleString()} remediation{total === 1 ? '' : 's'}</span>
      </div>
      <p className="muted-caption" style={{ marginTop: 0 }}>Upgrading one package clears these CVEs across these hosts — highest leverage first.</p>
      {items.length === 0 ? (
        <EmptyState message="No fixable packages in scope — nothing to remediate right now." />
      ) : (
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Upgrade to</th>
              <th>Fixes CVEs</th>
              <th>Hosts</th>
              <th>Crit/High</th>
              <th>Max CVSS</th>
              <th>KEV</th>
            </tr>
          </thead>
          <tbody>
            {items.map((r, i) => (
              <tr key={`${r.package_name}|${r.ecosystem}|${r.fixed_version}|${i}`} className={r.known_exploited ? 'topo-row-kev' : r.critical_high > 0 ? 'topo-row-risk' : ''}>
                <td>
                  <span className="mono">{r.package_name}</span>
                  {r.ecosystem && <span className="badge" style={{ marginLeft: 6, color: 'var(--text-muted)' }}>{r.ecosystem}</span>}
                </td>
                <td className="mono">{r.fixed_version || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                <td style={{ fontWeight: 600 }}>{r.cve_count.toLocaleString()}</td>
                <td>{r.host_count.toLocaleString()}</td>
                <td style={{ color: r.critical_high > 0 ? severityColor('CRITICAL') : 'var(--text-muted)', fontWeight: 600 }}>{r.critical_high.toLocaleString()}</td>
                <td className="mono" style={{ color: severityColor(cvssSeverity(r.max_cvss)), fontWeight: 600 }}>{r.max_cvss > 0 ? r.max_cvss.toFixed(1) : '-'}</td>
                <td>{r.known_exploited && <span className="badge kev-badge">KEV</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// OwnershipSection shows host exposure broken down by team, environment, and
// criticality with a simple inline bar for the critical/high count.
function OwnershipSection() {
  const [org, setOrg] = useState<OrgExposure | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError('');
    api.graphOrg()
      .then(o => { setOrg(o); setLoading(false); })
      .catch(e => { setError(e instanceof Error ? e.message : 'Failed to load ownership breakdown'); setLoading(false); });
  }, []);
  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="card"><Loading label="Loading ownership breakdown..." /></div>;
  if (error) return <div className="card"><LoadError message={error} onRetry={load} /></div>;
  if (!org) return <div className="card"><EmptyState message="No ownership data available." /></div>;

  return (
    <div className="topo-ownership-grid">
      <OwnershipCard title="By Team" rows={org.by_team} />
      <OwnershipCard title="By Environment" rows={org.by_environment} />
      <OwnershipCard title="By Criticality" rows={org.by_criticality} />
    </div>
  );
}

function OwnershipCard({ title, rows }: { title: string; rows: OrgExposureRow[] }) {
  const max = rows.reduce((m, r) => Math.max(m, r.critical_high), 0);
  return (
    <div className="card" style={{ padding: '1rem' }}>
      <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}><h2>{title}</h2></div>
      {rows.length === 0 ? (
        <EmptyState message="No data" />
      ) : (
        <div className="topo-own-list">
          {rows.map((r, i) => (
            <div className="topo-own-row" key={`${r.key}|${i}`}>
              <div className="topo-own-head">
                <span className="topo-own-key">{r.key || 'unknown'}</span>
                <span className="topo-own-ch" style={{ color: r.critical_high > 0 ? severityColor('CRITICAL') : 'var(--text-muted)' }}>{r.critical_high.toLocaleString()}</span>
              </div>
              <div className="topo-own-bar-track">
                <div className="topo-own-bar-fill" style={{ width: `${max > 0 ? Math.max(2, (r.critical_high / max) * 100) : 0}%` }} />
              </div>
              <div className="topo-own-meta">
                {r.host_count.toLocaleString()} host{r.host_count === 1 ? '' : 's'}
                {r.known_exploited_hosts > 0 && <span className="topo-own-kev"> · {r.known_exploited_hosts.toLocaleString()} KEV host{r.known_exploited_hosts === 1 ? '' : 's'}</span>}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// cvssSeverity maps a numeric CVSS score to a severity bucket for coloring.
function cvssSeverity(score: number): string {
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'UNKNOWN';
}

function GraphBreakdown({ title, data }: { title: string; data: Record<string, number> }) {
  const entries = Object.entries(data || {}).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  return (
    <div className="graph-breakdown">
      <div className="graph-breakdown-title">{title}</div>
      {entries.length === 0 ? (
        <div className="graph-breakdown-empty">—</div>
      ) : (
        entries.map(([k, v]) => (
          <div className="graph-breakdown-row" key={k}>
            <span className="graph-breakdown-key">{k || 'unknown'}</span>
            <span className="graph-breakdown-count">{v.toLocaleString()}</span>
          </div>
        ))
      )}
    </div>
  );
}
