import React, { useState, useEffect, useCallback, useRef } from 'react';
import { api, type CveDbEntry, type CveAffectedPackage, type CveReferenceGroupSummary } from '../api';
import { Loading, LoadError, EmptyState, SortHeader } from '../components/primitives';
import { Pager, CheckboxField } from '../components/controls';
import { formatDateOnly } from '../lib/format';

export function CveSearchView() {
  const [results, setResults] = useState<{items: CveDbEntry[]; total: number}>({items: [], total: 0});
  const [query, setQuery] = useState('');
  const [referenceKey, setReferenceKey] = useState('');
  const [severity, setSeverity] = useState('');
  const [source, setSource] = useState('');
  const [sources, setSources] = useState<string[]>([]);
  const [minCvss, setMinCvss] = useState('');
  const [minEpss, setMinEpss] = useState('');
  const [minEpssPercentile, setMinEpssPercentile] = useState('');
  const [matchableOnly, setMatchableOnly] = useState(false);
  const [includePrioritySources, setIncludePrioritySources] = useState(false);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [error, setError] = useState('');
  const [page, setPage] = useState(0);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [indexedAffected, setIndexedAffected] = useState<Record<string, { loading?: boolean; error?: string; items?: CveAffectedPackage[]; total?: number }>>({});
  const [referenceGroups, setReferenceGroups] = useState<Record<string, { loading?: boolean; error?: string; data?: CveReferenceGroupSummary }>>({});
  const [sortBy, setSortBy] = useState('published_date');
  const [sortDesc, setSortDesc] = useState(true);
  const initialSearchStarted = useRef(false);
  const limit = 50;

  const doSearch = useCallback((p: number, sBy?: string, sDesc?: boolean, refKeyOverride?: string) => {
    setLoading(true);
    setError('');
    const sb = sBy ?? sortBy;
    const sd = sDesc ?? sortDesc;
    const refKey = refKeyOverride ?? referenceKey;
    const params: Record<string, string> = {
      limit: String(limit),
      offset: String(p * limit),
    };
    if (query.trim()) params.q = query.trim();
    if (refKey.trim()) params.reference_key = refKey.trim();
    if (severity) params.severity = severity;
    if (source) params.source = source;
    if (minCvss) params.min_cvss = minCvss;
    if (minEpss) params.min_epss = minEpss;
    if (minEpssPercentile) params.min_epss_percentile = minEpssPercentile;
    if (matchableOnly) params.matchable = 'true';
    if (includePrioritySources) params.include_priority_sources = 'true';
    params.sort_by = sb;
    params.sort_order = sd ? 'desc' : 'asc';
    api.cveDbSearch(params)
      .then(r => {
        setResults({items: r.items || [], total: r.total});
        setPage(p);
        setSearched(true);
        setLoading(false);
      })
      .catch((err) => {
        setError(err?.message || 'CVE database search failed');
        setSearched(true);
        setLoading(false);
      });
  }, [query, referenceKey, severity, source, minCvss, minEpss, minEpssPercentile, matchableOnly, includePrioritySources, sortBy, sortDesc]);

  useEffect(() => {
    api.cveDbSources().then(data => {
      setSources(data.sources || []);
    }).catch((err) => setError(err?.message || 'CVE source list failed'));
  }, []);

  useEffect(() => {
    if (initialSearchStarted.current) return;
    initialSearchStarted.current = true;
    doSearch(0, 'published_date', true);
  }, [doSearch]);

  const badge = (s: string) => "badge badge-" + (s || "unknown").toLowerCase();
  const cvssClr = (n: number) => n >= 9 ? "var(--critical)" : n >= 7 ? "var(--high)" : n >= 4 ? "var(--medium)" : "inherit";

  const loadIndexedAffected = (entry: CveDbEntry, offset = 0) => {
    setIndexedAffected(prev => ({ ...prev, [entry.id]: { ...(prev[entry.id] || {}), loading: true, error: '' } }));
    api.cveDbAffectedPackages(entry.id, { limit: '200', offset: String(offset) })
      .then(r => setIndexedAffected(prev => ({
        ...prev,
        [entry.id]: {
          items: offset > 0 ? [...(prev[entry.id]?.items || []), ...(r.items || [])] : (r.items || []),
          total: r.total,
        },
      })))
      .catch(err => setIndexedAffected(prev => ({ ...prev, [entry.id]: { ...(prev[entry.id] || {}), loading: false, error: err?.message || 'Indexed affected packages failed' } })));
  };

  const loadReferenceGroup = (key: string) => {
    if (!key || referenceGroups[key]?.data || referenceGroups[key]?.loading) return;
    setReferenceGroups(prev => ({ ...prev, [key]: { ...(prev[key] || {}), loading: true, error: '' } }));
    api.cveDbReferenceGroup({ key, limit: '10' })
      .then(data => setReferenceGroups(prev => ({ ...prev, [key]: { data } })))
      .catch(err => setReferenceGroups(prev => ({ ...prev, [key]: { loading: false, error: err?.message || 'Reference group summary failed' } })));
  };

  const toggleExpand = (entry: CveDbEntry) => {
    setExpanded(prev => prev === entry.id ? null : entry.id);
    if ((entry.matchable_affected_count || 0) > 0 && !indexedAffected[entry.id]) {
      loadIndexedAffected(entry, 0);
    }
    const groupKey = entry.reference_group_key || (entry.reference_keys || []).find(key => key.startsWith('cve:')) || (entry.reference_keys || [])[0];
    if (groupKey) loadReferenceGroup(groupKey);
  };

  const formatDate = (d: string | null | undefined) => formatDateOnly(d);

  const toggleSort = (col: string) => {
    const nextDesc = sortBy === col ? !sortDesc : true;
    setSortBy(col);
    setSortDesc(nextDesc);
    doSearch(0, col, nextDesc);
  };

  const searchReferenceGroup = (key: string) => {
    setReferenceKey(key);
    doSearch(0, sortBy, sortDesc, key);
  };

  const parseJson = (raw: string | null | undefined): any[] => {
    if (!raw) return [];
    try { return JSON.parse(raw); } catch { return []; }
  };
  const affectedPackageFixedVersions = (pkg: any): string[] => {
    const out: string[] = [];
    const seen = new Set<string>();
    const add = (v: unknown) => {
      if (typeof v !== 'string') return;
      const fixed = v.trim();
      if (!fixed || seen.has(fixed)) return;
      seen.add(fixed);
      out.push(fixed);
    };
    if (Array.isArray(pkg?.fixed)) pkg.fixed.forEach(add);
    if (Array.isArray(pkg?.ranges)) {
      pkg.ranges.forEach((range: any) => {
        if (Array.isArray(range?.events)) range.events.forEach((event: any) => add(event?.fixed));
      });
    }
    return out;
  };
  const affectedPackageTarget = (pkg: any, entry: CveDbEntry): string => {
    const target = typeof pkg?.ecosystem === 'string' && pkg.ecosystem.trim() ? pkg.ecosystem : entry.ecosystem;
    return typeof target === 'string' ? target.trim() : '';
  };
  const isPriorityFeed = (entry: CveDbEntry): boolean => entry.source === 'epss' || entry.source === 'cisa-kev';
  const isMatchableAffectedPackage = (pkg: any, entry: CveDbEntry): boolean =>
    typeof pkg?.name === 'string' && pkg.name.trim() !== '' &&
    affectedPackageTarget(pkg, entry) !== '' &&
    affectedPackageFixedVersions(pkg).length > 0;

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>CVE Search</h1>

      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="filters">
          <input
            type="text"
            placeholder="CVE, package, ecosystem, keyword..."
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doSearch(0); }}
            style={{ minWidth: 220 }}
          />
          <input
            type="text"
            placeholder="Reference group"
            value={referenceKey}
            onChange={e => setReferenceKey(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') doSearch(0); }}
            style={{ minWidth: 190 }}
          />
          <select value={severity} onChange={e => setSeverity(e.target.value)}>
            <option value="">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={source} onChange={e => setSource(e.target.value)}>
            <option value="">{includePrioritySources ? 'All Sources' : 'Advisory Sources'}</option>
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
          <input
            type="number"
            placeholder="Min EPSS"
            value={minEpss}
            onChange={e => setMinEpss(e.target.value)}
            min="0" max="1" step="0.01"
            style={{ width: 90 }}
          />
          <input
            type="number"
            placeholder="Min EPSS %ile"
            value={minEpssPercentile}
            onChange={e => setMinEpssPercentile(e.target.value)}
            min="0" max="1" step="0.01"
            style={{ width: 120 }}
          />
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Matchable only" checked={matchableOnly} onChange={setMatchableOnly} />
            <CheckboxField label="Include priority feeds" checked={includePrioritySources} onChange={setIncludePrioritySources} />
          </div>
          <div className="filter-actions">
            {searched && <span className="result-count">{results.total.toLocaleString()} results</span>}
            <button className="btn btn-primary" onClick={() => doSearch(0)} disabled={loading}>{loading ? 'Searching...' : 'Search'}</button>
          </div>
        </div>
      </div>

      {error && <div className="card"><LoadError message={error} onRetry={() => doSearch(0)} /></div>}

      {!searched && !loading && !error && (
        <div className="card">
          <EmptyState message="Search the CVE database by CVE ID, affected package, ecosystem, keyword, severity, source, or minimum CVSS score." />
        </div>
      )}

      {loading && <div className="card"><Loading label="Searching..." /></div>}

      {searched && !loading && (
        <div className="card">
          <table>
            <thead>
              <tr>
                <SortHeader col="vulnerability_id" label="CVE ID" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <SortHeader col="severity" label="Severity" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <SortHeader col="cvss_score" label="CVSS" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <SortHeader col="epss_score" label="EPSS" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <SortHeader col="source" label="Source" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <th>Match</th>
                <SortHeader col="title" label="Title" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
                <SortHeader col="published_date" label="Published" sortBy={sortBy} sortDesc={sortDesc} onSort={toggleSort} />
              </tr>
            </thead>
            <tbody>
              {results.items.map(entry => {
                const isExpanded = expanded === entry.id;
                const prods = parseJson(entry.affected_products);
                const refs = parseJson(entry.references);
                const priorityFeed = isPriorityFeed(entry);
                const groupKey = entry.reference_group_key || (entry.reference_keys || []).find(key => key.startsWith('cve:')) || (entry.reference_keys || [])[0];
                const groupSummary = groupKey ? referenceGroups[groupKey] : undefined;

                return (
                  <React.Fragment key={entry.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
                      onClick={() => toggleExpand(entry)}
                    >
                      <td className="mono">
                        <span className="host-link" style={{ color: 'var(--primary)' }}>
                          {entry.vulnerability_id}
                        </span>
                        {(entry.reference_group_total || 0) > 0 && (
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginTop: 3 }}>
                            <span className="badge" style={{ color: '#22c55e' }}>
                              group {entry.reference_group_total}
                            </span>
                            {entry.reference_group_key && (
                              <span className="badge" style={{ color: 'var(--text-muted)' }}>
                                {entry.reference_group_key}
                              </span>
                            )}
                            <span className="badge" style={{ color: 'var(--text-muted)' }}>
                              {entry.reference_group_sources || 0} src
                            </span>
                            <span className="badge" style={{ color: (entry.reference_group_matchable || 0) > 0 ? '#22c55e' : 'var(--text-muted)' }}>
                              {entry.reference_group_matchable || 0} match
                            </span>
                          </div>
                        )}
                        {entry.reference_group_status === 'unavailable' && (
                          <div className="badge" style={{ marginTop: 3, color: 'var(--medium)' }}>
                            group summary unavailable
                          </div>
                        )}
                      </td>
                      <td>
                        <span className={badge(entry.severity)}>
                          {entry.severity || '-'}
                        </span>
                      </td>
                      <td className="mono" style={{ fontWeight: 600, color: cvssClr(entry.cvss_score) }}>
                        {entry.cvss_score > 0 ? entry.cvss_score.toFixed(1) : '-'}
                      </td>
                      <td className="mono" style={{ color: (entry.epss_score || 0) >= 0.5 ? 'var(--critical)' : (entry.epss_score || 0) >= 0.1 ? 'var(--high)' : 'var(--text-muted)' }}>
                        {entry.epss_score ? `${(entry.epss_score * 100).toFixed(1)}%` : '-'}
                      </td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        {entry.source}
                        {priorityFeed && (
                          <span className="badge" style={{ marginLeft: '0.375rem', color: 'var(--medium)' }}>priority</span>
                        )}
                      </td>
                      <td>
                        <span className="badge" style={{ color: entry.matchable ? '#22c55e' : priorityFeed ? 'var(--medium)' : 'var(--text-muted)' }}>
                          {entry.matchable ? 'matchable' : priorityFeed ? 'priority' : 'reference'}
                        </span>
                        {(entry.matchable_affected_count || 0) > 0 && (
                          <div className="mono" style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>
                            {entry.matchable_affected_count} affected
                          </div>
                        )}
                        {!entry.matchable && entry.matchability_reason && (
                          <div style={{ fontSize: '0.625rem', color: 'var(--text-muted)', marginTop: 2 }}>
                            {entry.matchability_reason}
                          </div>
                        )}
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
                        <td colSpan={8} style={{ background: 'var(--surface)', padding: '1rem 1.5rem' }}>
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
                          {(entry.reference_keys || []).length > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Reference Groups</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {(entry.reference_keys || []).slice(0, 20).map(key => (
                                  <button
                                    key={key}
                                    className="badge"
                                    style={{ marginRight: '0.375rem', marginBottom: '0.25rem', color: key.startsWith('cve:') ? '#22c55e' : 'var(--text-muted)', cursor: 'pointer' }}
                                    onClick={e => {
                                      e.preventDefault();
                                      e.stopPropagation();
                                      searchReferenceGroup(key);
                                    }}
                                  >
                                    {key}
                                  </button>
                                ))}
                              </div>
                            </div>
                          )}
                          {groupKey && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Group Context</strong>
                              {groupSummary?.loading && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem', marginTop: '0.25rem' }}>Loading...</div>}
                              {groupSummary?.error && <div style={{ color: 'var(--critical)', fontSize: '0.8125rem', marginTop: '0.25rem' }}>{groupSummary.error}</div>}
                              {groupSummary?.data && (
                                <div style={{ marginTop: '0.25rem', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 4, padding: '0.5rem 0.75rem' }}>
                                  <div className="mono" style={{ fontSize: '0.75rem', marginBottom: '0.375rem' }}>
                                    {groupSummary.data.key} · {groupSummary.data.total.toLocaleString()} records · {groupSummary.data.matchable.toLocaleString()} matchable
                                  </div>
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginBottom: '0.375rem' }}>
                                    {(groupSummary.data.sources || []).slice(0, 8).map(b => (
                                      <span key={b.name} className="badge">{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                  </div>
                                  {(groupSummary.data.source_groups || []).length > 0 && (
                                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem', marginBottom: '0.375rem' }}>
                                      {(groupSummary.data.source_groups || []).slice(0, 8).map(b => (
                                        <span key={b.name} className="badge" style={{ color: '#22c55e' }}>{b.name}: {b.count.toLocaleString()}</span>
                                      ))}
                                    </div>
                                  )}
                                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.25rem' }}>
                                    {(groupSummary.data.categories || []).slice(0, 6).map(b => (
                                      <span key={b.name} className="badge" style={{ color: 'var(--text-muted)' }}>{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                    {(groupSummary.data.ecosystems || []).slice(0, 6).map(b => (
                                      <span key={b.name} className="badge" style={{ color: 'var(--text-muted)' }}>{b.name}: {b.count.toLocaleString()}</span>
                                    ))}
                                  </div>
                                  {(groupSummary.data.affected_packages || []).length > 0 && (
                                    <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                                      <strong style={{ fontSize: '0.75rem' }}>Group Match Evidence</strong>
                                      <span className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                        showing {(groupSummary.data.affected_packages || []).length.toLocaleString()} of {(groupSummary.data.affected_package_total || 0).toLocaleString()}
                                      </span>
                                      <div style={{ marginTop: '0.375rem', display: 'grid', gap: '0.25rem' }}>
                                        {(groupSummary.data.affected_packages || []).slice(0, 10).map((item, idx) => (
                                          <div key={`${item.cve_id}-${item.package_name}-${item.ecosystem}-${item.fixed_version}-${idx}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(7rem, 1fr) minmax(8rem, 1.2fr) minmax(6rem, 0.8fr) minmax(5rem, 0.8fr) minmax(7rem, 1fr)', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                            <span className="mono" style={{ color: 'var(--text)' }}>{item.vulnerability_id}</span>
                                            <span style={{ fontWeight: 600, color: 'var(--text)' }}>{item.package_name}</span>
                                            <span className="mono">{item.ecosystem}</span>
                                            <span>{item.source || '-'}</span>
                                            <span className="mono" style={{ color: '#22c55e' }}>Fixed {item.fixed_version}</span>
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                  {(groupSummary.data.items || []).length > 0 && (
                                    <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                                      <strong style={{ fontSize: '0.75rem' }}>Grouped Evidence</strong>
                                      <div style={{ marginTop: '0.375rem', display: 'grid', gap: '0.25rem' }}>
                                        {(groupSummary.data.items || []).slice(0, 8).map(item => {
                                          const itemPriority = isPriorityFeed(item);
                                          return (
                                            <div key={item.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(8rem, 1.4fr) minmax(6rem, 0.8fr) minmax(7rem, 1fr) minmax(6rem, 1fr) auto minmax(7rem, 1fr) auto auto', gap: '0.5rem', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                              <span className="mono" style={{ color: 'var(--text)' }}>{item.vulnerability_id}</span>
                                              <span>{item.source || '-'}</span>
                                              <span>{item.category || '-'}</span>
                                              <span className="mono">{item.ecosystem || '-'}</span>
                                              <span className="badge" style={{ color: item.matchable ? '#22c55e' : itemPriority ? 'var(--medium)' : 'var(--text-muted)' }}>
                                                {item.matchable ? 'matchable' : itemPriority ? 'priority' : 'reference'}
                                              </span>
                                              <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                                {item.matchability_reason || ''}
                                              </span>
                                              <span className="mono" style={{ color: cvssClr(item.cvss_score), justifySelf: 'end' }}>
                                                CVSS {item.cvss_score > 0 ? item.cvss_score.toFixed(1) : '-'}
                                              </span>
                                              <span className="mono" style={{ justifySelf: 'end' }}>
                                                EPSS {item.epss_score ? `${(item.epss_score * 100).toFixed(1)}%` : '-'}
                                              </span>
                                            </div>
                                          );
                                        })}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          )}
                          {(entry.matchable_affected_count || 0) > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Indexed Match Evidence</strong>
                              <span className="mono" style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                showing {(indexedAffected[entry.id]?.items || []).length.toLocaleString()} of {((indexedAffected[entry.id]?.total ?? entry.matchable_affected_count) || 0).toLocaleString()}
                              </span>
                              <div style={{ marginTop: '0.25rem' }}>
                                {indexedAffected[entry.id]?.loading && <div style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>Loading...</div>}
                                {indexedAffected[entry.id]?.error && <div style={{ color: 'var(--critical)', fontSize: '0.8125rem' }}>{indexedAffected[entry.id]?.error}</div>}
                                {(indexedAffected[entry.id]?.items || []).map((item, idx) => (
                                  <div key={`${item.package_name}-${item.ecosystem}-${item.fixed_version}-${idx}`} style={{ background: 'var(--bg)', padding: '0.4rem 0.75rem', borderRadius: 4, border: '1px solid var(--border)', marginBottom: '0.25rem' }}>
                                    <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{item.package_name}</span>
                                    <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{item.ecosystem}</span>
                                    <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '1px 6px', borderRadius: 3, fontWeight: 600, marginLeft: '0.5rem' }}>Fixed: {item.fixed_version}</span>
                                  </div>
                                ))}
                                {((indexedAffected[entry.id]?.items || []).length < (indexedAffected[entry.id]?.total || 0)) && (
                                  <button
                                    style={{ marginTop: '0.25rem' }}
                                    disabled={indexedAffected[entry.id]?.loading}
                                    onClick={e => {
                                      e.stopPropagation();
                                      loadIndexedAffected(entry, (indexedAffected[entry.id]?.items || []).length);
                                    }}
                                  >
                                    Load More
                                  </button>
                                )}
                              </div>
                            </div>
                          )}
                          {prods.length > 0 && (
                            <div style={{ marginBottom: '0.75rem' }}>
                              <strong style={{ fontSize: '0.8125rem' }}>Affected Packages</strong>
                              <div style={{ marginTop: '0.25rem' }}>
                                {prods.slice(0, 20).map((pkg: any, idx: number) => {
                                  const fixedArr = affectedPackageFixedVersions(pkg);
                                  const lastFixed = fixedArr.length > 0 ? fixedArr[fixedArr.length - 1] : '';
                                  const target = affectedPackageTarget(pkg, entry);
                                  const matchablePkg = isMatchableAffectedPackage(pkg, entry);
                                  return (
                                    <div key={idx} style={{ background: 'var(--bg)', padding: '0.4rem 0.75rem', borderRadius: 4, border: '1px solid var(--border)', marginBottom: '0.25rem' }}>
                                      <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{pkg.name || 'unknown'}</span>
                                      {target && (
                                        <span style={{ fontSize: '0.6875rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{target}</span>
                                      )}
                                      {lastFixed && (
                                        <span style={{ fontSize: '0.6875rem', color: '#22c55e', background: 'rgba(34,197,94,0.1)', padding: '1px 6px', borderRadius: 3, fontWeight: 600, marginLeft: '0.5rem' }}>
                                          Fixed: {lastFixed}
                                        </span>
                                      )}
                                      <span style={{ fontSize: '0.6875rem', color: matchablePkg ? '#22c55e' : 'var(--text-muted)', marginLeft: '0.5rem' }}>
                                        {matchablePkg ? 'used for matching' : 'reference only'}
                                      </span>
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
                <tr className="empty-row"><td colSpan={8}>No results found</td></tr>
              )}
            </tbody>
          </table>
          {results.total > limit && (
            <Pager page={page} limit={limit} total={results.total} onPage={doSearch} />
          )}
        </div>
      )}
    </>
  );
}
