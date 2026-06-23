import React, { useState, useEffect, useCallback } from 'react';
import { api, type AssetGroup, type AssetGroupDetail, type Host } from '../api';
import { Loading } from '../components/primitives';

export function AssetGroupsView() {
  const [items, setItems] = useState<AssetGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [groupType, setGroupType] = useState('static');
  const [ruleExpr, setRuleExpr] = useState('');
  const [msg, setMsg] = useState('');
  const [allHosts, setAllHosts] = useState<Host[]>([]);
  const [expandedId, setExpandedId] = useState('');
  const [detail, setDetail] = useState<AssetGroupDetail | null>(null);
  const [addHostId, setAddHostId] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.assetGroups()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { api.hosts().then(hs => setAllHosts(hs || [])).catch(() => {}); }, []);

  const loadDetail = useCallback((id: string) => {
    api.assetGroup(id).then(setDetail).catch(() => setDetail(null));
  }, []);

  const toggleExpand = (id: string) => {
    if (expandedId === id) { setExpandedId(''); setDetail(null); return; }
    setExpandedId(id);
    setDetail(null);
    setAddHostId('');
    loadDetail(id);
  };

  const handleAddHost = async (groupId: string) => {
    if (!addHostId) return;
    setMsg('');
    try {
      await api.addHostToAssetGroup(groupId, addHostId);
      setAddHostId('');
      loadDetail(groupId);
      load();
    } catch {
      setMsg('Failed to add host to group');
    }
  };

  const handleRemoveHost = async (groupId: string, hostId: string) => {
    setMsg('');
    try {
      await api.removeHostFromAssetGroup(groupId, hostId);
      loadDetail(groupId);
      load();
    } catch {
      setMsg('Failed to remove host from group');
    }
  };

  const handleCreate = async () => {
    if (!name) return;
    setMsg('');
    try {
      await api.createAssetGroup({ name, description, rule_type: groupType, rule_expr: groupType === 'dynamic' ? ruleExpr : '' });
      setMsg('Asset group created');
      setName('');
      setDescription('');
      setRuleExpr('');
      load();
    } catch {
      setMsg('Failed to create asset group');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteAssetGroup(id);
      setMsg('Asset group deleted');
      load();
    } catch {
      setMsg('Failed to delete asset group');
    }
  };

  const handleScan = async (id: string) => {
    setMsg('');
    try {
      await api.triggerAssetGroupScan(id);
      setMsg('Asset group scan triggered');
    } catch {
      setMsg('Failed to trigger asset group scan');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Asset Groups</h1>
      <div className="card" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 1rem' }}><h2>Create Asset Group</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input type="text" placeholder="Description" value={description} onChange={(e) => setDescription(e.target.value)} />
          <select value={groupType} onChange={(e) => setGroupType(e.target.value)}>
            <option value="static">Static</option>
            <option value="dynamic">Dynamic</option>
          </select>
          {groupType === 'dynamic' && <input type="text" placeholder="Rule expression" value={ruleExpr} onChange={(e) => setRuleExpr(e.target.value)} style={{ minWidth: 260 }} />}
          <button className="filter-btn" onClick={handleCreate}>Create</button>
          {msg && <span style={{ color: msg.includes('Failed') ? 'var(--critical)' : 'var(--low)', fontSize: '0.8125rem' }}>{msg}</span>}
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Description</th><th>Type</th><th>Rule</th><th>Hosts</th><th></th><th></th></tr>
            </thead>
            <tbody>
              {items.map(g => (
                <React.Fragment key={g.id}>
                <tr style={{ cursor: 'pointer' }} onClick={() => toggleExpand(g.id)}>
                  <td>{expandedId === g.id ? '▾ ' : '▸ '}{g.name}</td>
                  <td>{g.description || '-'}</td>
                  <td><span className="badge">{g.rule_type}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{g.rule_expr || '-'}</td>
                  <td className="mono">{g.host_count || 0}</td>
                  <td><button className="update-btn" onClick={(e) => { e.stopPropagation(); handleScan(g.id); }}>Scan</button></td>
                  <td><button className="delete-btn" onClick={(e) => { e.stopPropagation(); handleDelete(g.id); }}>Delete</button></td>
                </tr>
                {expandedId === g.id && (
                  <tr>
                    <td colSpan={7} style={{ background: 'var(--bg)', padding: '0.75rem 1rem' }}>
                      {!detail ? <span style={{ color: 'var(--text-muted)' }}>Loading members...</span> : (
                        <>
                          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center', marginBottom: (detail.host_ids || []).length ? '0.5rem' : 0 }}>
                            {(detail.host_ids || []).map(hid => (
                              <span key={hid} className="badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '0.35rem' }}>
                                {allHosts.find(h => h.id === hid)?.hostname || hid}
                                {g.rule_type === 'static' && (
                                  <button className="delete-btn" style={{ padding: '0 0.3rem', fontSize: '0.7rem' }} onClick={() => handleRemoveHost(g.id, hid)}>x</button>
                                )}
                              </span>
                            ))}
                            {(detail.host_ids || []).length === 0 && <span style={{ color: 'var(--text-muted)' }}>No member hosts</span>}
                          </div>
                          {g.rule_type === 'static' && (
                            <div className="filters" style={{ margin: 0 }}>
                              <select value={addHostId} onChange={(e) => setAddHostId(e.target.value)}>
                                <option value="">Add host...</option>
                                {allHosts.filter(h => !(detail.host_ids || []).includes(h.id)).map(h => (
                                  <option key={h.id} value={h.id}>{h.hostname || h.id}</option>
                                ))}
                              </select>
                              <button className="filter-btn" disabled={!addHostId} onClick={() => handleAddHost(g.id)}>Add Host</button>
                            </div>
                          )}
                        </>
                      )}
                    </td>
                  </tr>
                )}
                </React.Fragment>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No asset groups yet — use the form above to create a static group or a dynamic group with a rule expression to organize hosts.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
