import { useEffect, useRef, useState } from 'react';
import { getApiKey, getSession } from '../api';

export interface LiveEvent {
  id: number;
  type: string;
  scope_key?: string;
  payload?: Record<string, unknown>;
  severity?: string;
  occurred_at: string;
}

// All event types the server may emit; used as the listener set when the caller
// doesn't narrow with `types`.
export const LIVE_EVENT_TYPES = [
  'scan.completed',
  'scan.failed',
  'finding.new_critical',
  'finding.new_high',
  'agent.online',
  'agent.offline',
  'secdb.updated',
  'rescan.progress',
  'sla.breach',
  'kpi.snapshot',
];

// useLiveEvents subscribes to the server's SSE feed (GET /api/events/stream),
// keeping a rolling buffer of recent events and the connection state. It
// reconnects with exponential backoff and resumes from the last seen event id
// (?since=) so a dropped connection replays what it missed. EventSource cannot
// set headers, so the auth token is passed as ?access_token=.
export function useLiveEvents(opts?: { types?: string[]; onEvent?: (e: LiveEvent) => void; max?: number }) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const onEventRef = useRef(opts?.onEvent);
  onEventRef.current = opts?.onEvent;
  const max = opts?.max ?? 50;
  const typesKey = (opts?.types ?? []).join(',');

  useEffect(() => {
    let closed = false;
    let reconnectTimer: number | undefined;
    let es: EventSource | null = null;
    const lastId = { current: '' };
    let retry = 0;
    const types = typesKey ? typesKey.split(',') : LIVE_EVENT_TYPES;

    const connect = () => {
      if (closed) return;
      const token = getApiKey() || getSession();
      const params = new URLSearchParams();
      if (typesKey) params.set('types', typesKey);
      if (lastId.current) params.set('since', lastId.current);
      if (token) params.set('access_token', token);
      es = new EventSource(`/api/events/stream?${params.toString()}`);
      es.onopen = () => {
        setConnected(true);
        retry = 0;
      };
      const handle = (ev: MessageEvent) => {
        if (ev.lastEventId) lastId.current = ev.lastEventId;
        try {
          const data = JSON.parse(ev.data) as LiveEvent;
          onEventRef.current?.(data);
          setEvents((prev) => [data, ...prev].slice(0, max));
        } catch {
          /* ignore malformed frame */
        }
      };
      types.forEach((t) => es!.addEventListener(t, handle as EventListener));
      es.onerror = () => {
        setConnected(false);
        es?.close();
        if (closed) return;
        const delay = Math.min(1000 * 2 ** retry++, 30000);
        reconnectTimer = window.setTimeout(connect, delay);
      };
    };
    connect();
    return () => {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      es?.close();
    };
  }, [typesKey, max]);

  return { connected, events };
}
