import { useState, useEffect, useCallback } from 'react';
import { api, type ScheduledScan } from '../api';
import { Loading } from '../components/primitives';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function SchedulesView() {
  const [items, setItems] = useState<ScheduledScan[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [cronExpr, setCronExpr] = useState('');
  const [scanType, setScanType] = useState('full');
  const [msg, setMsg] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    api.schedules()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!name || !cronExpr) return;
    setMsg('');
    try {
      await api.createSchedule({ name, cron_expr: cronExpr, scan_type: 'manual', packages_only: scanType === 'packages_only' });
      setMsg('Schedule created');
      setName('');
      setCronExpr('');
      load();
    } catch {
      setMsg('Failed to create schedule');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteSchedule(id);
      setMsg('Schedule deleted');
      load();
    } catch {
      setMsg('Failed to delete schedule');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Schedules</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create Schedule</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <input type="text" placeholder="Cron expression (e.g. 0 2 * * *)" value={cronExpr} onChange={(e) => setCronExpr(e.target.value)} style={{ minWidth: 260 }} />
          <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
            <option value="full">Full Scan</option>
            <option value="packages_only">Packages Only</option>
          </select>
          <div className="filter-actions">
            {msg && <span className="result-count" style={{ color: msg.includes('Failed') ? 'var(--critical)' : 'var(--low)' }}>{msg}</span>}
            <button className="btn btn-primary" onClick={handleCreate}>Create</button>
          </div>
        </div>
      </div>
      <div className="card">
        {loading ? <Loading /> : (
          <table>
            <thead>
              <tr><th>Name</th><th>Cron</th><th>Scan Type</th><th>Enabled</th><th>Last Run</th><th>Next Run</th><th></th></tr>
            </thead>
            <tbody>
              {items.map(s => (
                <tr key={s.id}>
                  <td>{s.name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{s.cron_expr}</td>
                  <td>{s.packages_only ? 'packages_only' : s.scan_type}</td>
                  <td><span className="badge" style={{ color: s.enabled ? 'var(--low)' : 'var(--medium)' }}>{s.enabled ? 'yes' : 'no'}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }} title={formatDateTimeFull(s.last_run)}>{formatDateTime(s.last_run)}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }} title={formatDateTimeFull(s.next_run)}>{formatDateTime(s.next_run)}</td>
                  <td><button className="btn btn-danger btn-sm" onClick={() => handleDelete(s.id)}>Delete</button></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={7}>No scheduled scans yet — use the Create Schedule form above with a cron expression (e.g. 0 2 * * *) to run recurring scans.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}

