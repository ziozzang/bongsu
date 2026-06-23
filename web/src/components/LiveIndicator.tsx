import { useState } from 'react';
import { useLiveEvents, type LiveEvent } from '../hooks/useLiveEvents';

function eventLabel(e: LiveEvent): string {
  const p = e.payload ?? {};
  const host = (p.hostname as string) || (p.host_id as string) || '';
  switch (e.type) {
    case 'scan.completed':
      return `Scan completed — ${host}`;
    case 'scan.failed':
      return `Scan failed — ${host}`;
    case 'agent.offline':
      return `Agent offline — ${host}`;
    case 'agent.online':
      return `Agent back online — ${host}`;
    case 'finding.new_critical':
      return `New critical — ${(p.cve as string) ?? host}`;
    case 'finding.new_high':
      return `New high — ${(p.cve as string) ?? host}`;
    case 'secdb.updated':
      return 'Security DB updated';
    case 'rescan.progress':
      return `Rescan ${(p.percent as number) ?? ''}%`;
    case 'sla.breach':
      return `SLA breach — ${host}`;
    default:
      return e.type;
  }
}

// LiveIndicator shows the live-monitoring connection state and a popover of the
// most recent events (the real-time activity feed). It owns one SSE subscription
// for the whole app via useLiveEvents.
export function LiveIndicator() {
  const [open, setOpen] = useState(false);
  const { connected, events } = useLiveEvents({ max: 30 });
  return (
    <div className="live-indicator">
      <button
        type="button"
        className="live-toggle"
        onClick={() => setOpen((o) => !o)}
        title={connected ? 'Live monitoring connected' : 'Live monitoring reconnecting…'}
        aria-label="Live activity"
      >
        <span className={'live-dot' + (connected ? ' on' : '')} aria-hidden="true" />
        <span className="live-toggle-label">Live</span>
        {events.length > 0 && <span className="live-count">{events.length}</span>}
      </button>
      {open && (
        <div className="live-feed" role="log" aria-label="Recent activity">
          <div className="live-feed-header">Activity · {connected ? 'live' : 'reconnecting…'}</div>
          {events.length === 0 && <div className="live-empty">No recent events</div>}
          {events.map((e) => (
            <div key={e.id} className={'live-item sev-' + (e.severity || 'info')}>
              <span className="live-item-dot" aria-hidden="true" />
              <span className="live-item-label">{eventLabel(e)}</span>
              <span className="live-item-time">{new Date(e.occurred_at).toLocaleTimeString()}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
