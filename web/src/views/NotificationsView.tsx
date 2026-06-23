import { useState, useEffect, useCallback } from 'react';
import { api, type NotificationRule, type NotificationLogEntry } from '../api';
import { Loading } from '../components/primitives';
import { CheckboxField } from '../components/controls';
import { formatDateTime, formatDateTimeFull } from '../lib/format';

export function NotificationsView() {
  const [items, setItems] = useState<NotificationRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [name, setName] = useState('');
  const [triggerEvent, setTriggerEvent] = useState('scan.completed');
  const [minSeverity, setMinSeverity] = useState('CRITICAL');
  const [channelType, setChannelType] = useState('webhook');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');
  const [emailTo, setEmailTo] = useState('');
  const [emailSubjectPrefix, setEmailSubjectPrefix] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [msg, setMsg] = useState('');
  const [logEntries, setLogEntries] = useState<NotificationLogEntry[]>([]);
  const [showLog, setShowLog] = useState(false);

  const load = useCallback(() => {
    setLoading(true);
    api.notificationRules()
      .then(r => { setItems(r.items || []); setLoading(false); })
      .catch(() => { setItems([]); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const handleCreate = async () => {
    if (!name) return;
    setMsg('');
    const channelConfig: Record<string, string> = {};
    if (channelType === 'webhook') {
      if (!webhookUrl.trim()) { setMsg('Webhook URL is required'); return; }
      channelConfig.url = webhookUrl.trim();
      if (webhookSecret.trim()) channelConfig.secret = webhookSecret.trim();
    } else if (channelType === 'email') {
      if (!emailTo.trim()) { setMsg('Recipient email is required'); return; }
      channelConfig.to = emailTo.trim();
      if (emailSubjectPrefix.trim()) channelConfig.subject_prefix = emailSubjectPrefix.trim();
    }
    try {
      await api.createNotificationRule({ name, trigger_event: triggerEvent, min_severity: minSeverity, channel_type: channelType, channel_config: channelConfig, enabled });
      setMsg('Notification rule created');
      setName('');
      setWebhookUrl(''); setWebhookSecret(''); setEmailTo(''); setEmailSubjectPrefix('');
      load();
    } catch (err) {
      setMsg(err instanceof Error ? `Failed to create rule: ${err.message}` : 'Failed to create notification rule');
    }
  };

  const handleDelete = async (id: string) => {
    setMsg('');
    try {
      await api.deleteNotificationRule(id);
      setMsg('Notification rule deleted');
      load();
    } catch {
      setMsg('Failed to delete notification rule');
    }
  };

  const handleTest = async (id: string) => {
    setMsg('');
    try {
      await api.testNotificationRule(id);
      setMsg('Test notification sent');
    } catch {
      setMsg('Failed to send test notification');
    }
  };

  const handleLoadLog = async () => {
    if (showLog) { setShowLog(false); return; }
    try {
      const r = await api.notificationLog({ limit: '20' });
      setLogEntries(r.items || []);
      setShowLog(true);
    } catch {
      setMsg('Failed to load notification log');
    }
  };

  return (
    <>
      <h1 style={{ marginBottom: '1.5rem' }}>Notifications</h1>
      <div className="card filter-bar" style={{ marginBottom: '1rem', padding: '1rem' }}>
        <div className="card-header" style={{ margin: '-1rem -1rem 0' }}><h2>Create Notification Rule</h2></div>
        <div className="filters">
          <input type="text" placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select value={triggerEvent} onChange={(e) => setTriggerEvent(e.target.value)}>
            <option value="scan.completed">Scan Completed</option>
            <option value="vulnerability.discovered">Vulnerability Discovered</option>
            <option value="security_db.updated">Security DB Updated</option>
          </select>
          <select value={minSeverity} onChange={(e) => setMinSeverity(e.target.value)}>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
          <select value={channelType} onChange={(e) => setChannelType(e.target.value)}>
            <option value="webhook">Webhook</option>
            <option value="email">Email</option>
            <option value="log">Log</option>
          </select>
          {channelType === 'webhook' && (
            <>
              <input type="text" placeholder="Webhook URL" value={webhookUrl} onChange={(e) => setWebhookUrl(e.target.value)} style={{ minWidth: 240 }} />
              <input type="text" placeholder="HMAC secret (optional)" value={webhookSecret} onChange={(e) => setWebhookSecret(e.target.value)} />
            </>
          )}
          {channelType === 'email' && (
            <>
              <input type="text" placeholder="Recipients (comma-separated)" value={emailTo} onChange={(e) => setEmailTo(e.target.value)} style={{ minWidth: 240 }} />
              <input type="text" placeholder="Subject prefix (optional)" value={emailSubjectPrefix} onChange={(e) => setEmailSubjectPrefix(e.target.value)} />
            </>
          )}
        </div>
        <div className="filter-controls-row">
          <div className="check-group">
            <CheckboxField label="Enabled" checked={enabled} onChange={setEnabled} />
          </div>
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
              <tr><th>Name</th><th>Trigger Event</th><th>Min Severity</th><th>Channel</th><th>Enabled</th><th>Last Triggered</th><th></th><th></th></tr>
            </thead>
            <tbody>
              {items.map(r => (
                <tr key={r.id}>
                  <td>{r.name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{r.trigger_event}</td>
                  <td><span className="badge">{r.min_severity || '-'}</span></td>
                  <td>{r.channel_type}</td>
                  <td><span className="badge" style={{ color: r.enabled ? 'var(--low)' : 'var(--medium)' }}>{r.enabled ? 'yes' : 'no'}</span></td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }} title={formatDateTimeFull(r.last_triggered)}>{formatDateTime(r.last_triggered)}</td>
                  <td><button className="btn btn-secondary btn-sm" onClick={() => handleTest(r.id)}>Test</button></td>
                  <td><button className="btn btn-danger btn-sm" onClick={() => handleDelete(r.id)}>Delete</button></td>
                </tr>
              ))}
              {items.length === 0 && <tr className="empty-row"><td colSpan={8}>No notification rules yet — use the form above to send new-finding alerts to a webhook, email, or the log.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
      <div style={{ marginTop: '1rem' }}>
        <button className="btn btn-secondary" onClick={handleLoadLog}>{showLog ? 'Hide Log' : 'Show Log'}</button>
      </div>
      {showLog && (
        <div className="card" style={{ marginTop: '1rem' }}>
          <div className="card-header"><h2>Notification Log</h2></div>
          <table>
            <thead>
              <tr><th>Time</th><th>Rule</th><th>Event</th><th>Channel</th><th>Status</th><th>Error</th></tr>
            </thead>
            <tbody>
              {logEntries.map(e => (
                <tr key={e.id}>
                  <td className="mono" style={{ fontSize: '0.75rem' }} title={formatDateTimeFull(e.created_at)}>{formatDateTime(e.created_at)}</td>
                  <td>{e.rule_name}</td>
                  <td className="mono" style={{ fontSize: '0.8125rem' }}>{e.trigger_event}</td>
                  <td>{e.channel_type}</td>
                  <td><span className="badge">{e.status}</span></td>
                  <td style={{ fontSize: '0.8125rem', color: e.error_message ? 'var(--critical)' : 'var(--text-muted)' }}>{e.error_message || '-'}</td>
                </tr>
              ))}
              {logEntries.length === 0 && <tr className="empty-row"><td colSpan={6}>No notifications sent yet — entries appear here once a rule fires. Use Test on a rule to generate one.</td></tr>}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
