import React from 'react';

// Single stroke-based inline SVG icon system + brand mark, extracted from
// App.tsx (UI decomposition). No external icon dependency.
const ICON_PATHS: Record<string, React.ReactNode> = {
  dashboard: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /></>,
  hosts: <><rect x="3" y="4" width="18" height="6" rx="1.5" /><rect x="3" y="14" width="18" height="6" rx="1.5" /><path d="M7 7h.01M7 17h.01" /></>,
  packages: <><path d="M21 8v8a1.5 1.5 0 0 1-.8 1.3l-7 3.8a1.5 1.5 0 0 1-1.4 0l-7-3.8A1.5 1.5 0 0 1 3 16V8a1.5 1.5 0 0 1 .8-1.3l7-3.8a1.5 1.5 0 0 1 1.4 0l7 3.8A1.5 1.5 0 0 1 21 8Z" /><path d="m3.3 7 8.7 4.7L20.7 7M12 21.8V11.7" /></>,
  containers: <><path d="m12 2 9 4.9-9 4.9-9-4.9L12 2Z" /><path d="m3 12 9 4.9 9-4.9M3 17l9 4.9 9-4.9" /></>,
  vulnerabilities: <><path d="M12 3 5 6v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V6l-7-3Z" /><path d="M12 9v3.5M12 16h.01" /></>,
  'cve-search': <><circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" /></>,
  scans: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8" /><path d="M3 4v4h4M12 8v4l3 2" /></>,
  rbac: <><circle cx="8" cy="8" r="3.5" /><path d="m12.5 11 7 7M16 14l2.5-2.5M18.5 16.5 21 14" /></>,
  users: <><circle cx="9" cy="8" r="3.5" /><path d="M3 20a6 6 0 0 1 12 0" /><path d="M16 4.5a3.5 3.5 0 0 1 0 7M21 20a6 6 0 0 0-4-5.6" /></>,
  tokens: <><circle cx="8" cy="14" r="4" /><path d="m11 11 8-8M16 3h4v4M15 7l2 2" /></>,
  audit: <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z" /><path d="M14 3v5h5M9 13h6M9 17h6" /></>,
  schedules: <><rect x="3" y="4" width="18" height="17" rx="2" /><path d="M16 2v4M8 2v4M3 9h18" /><circle cx="12" cy="15" r="2.5" /><path d="M12 14v1.2l.8.8" /></>,
  'asset-groups': <><path d="M4 7a2 2 0 0 1 2-2h3.5l2 2.5H18a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V7Z" /></>,
  topology: <><circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="18" r="2.5" /><circle cx="19" cy="18" r="2.5" /><path d="M10.5 7 6.5 16M13.5 7l4 9M7 18h10" /></>,
  trends: <><path d="m3 17 6-6 4 4 8-8" /><path d="M17 7h4v4" /></>,
  reports: <><path d="M3 3v18h18" /><rect x="7" y="11" width="3" height="6" rx="0.5" /><rect x="12.5" y="7" width="3" height="10" rx="0.5" /><rect x="18" y="13" width="3" height="4" rx="0.5" /></>,
  notifications: <><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9Z" /><path d="M13.7 21a2 2 0 0 1-3.4 0" /></>,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /><path d="m16 17 5-5-5-5M21 12H9" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1A2 2 0 1 1 7 4.5l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1Z" /></>,
  // misc icons used in the console
  alert: <><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 2" /></>,
  flame: <><path d="M12 3c1 3 4 5 4 9a4 4 0 0 1-8 0c0-2 1-3 2-4 .5 1.5 2 2 2 3.5" /></>,
  check: <><path d="M20 6 9 17l-5-5" /></>,
  arrow: <><path d="M5 12h14M13 6l6 6-6 6" /></>,
  'ai-triage': <><path d="M12 3l1.6 4.2L18 9l-4.4 1.8L12 15l-1.6-4.2L6 9l4.4-1.8L12 3Z" /><path d="M18 14l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8.8-2Z" /></>,
  'ai-approvals': <><path d="M12 3 5 6v5c0 4 3 6.5 7 8 4-1.5 7-4 7-8V6l-7-3Z" /><path d="m9 11 2 2 4-4" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z" /></>,
};

export function Icon({ name, size = 16, className, strokeWidth = 1.5, style }: { name: string; size?: number; className?: string; strokeWidth?: number; style?: React.CSSProperties }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      style={style}
    >
      {ICON_PATHS[name] || ICON_PATHS.dashboard}
    </svg>
  );
}

// Compact 22px beacon-tower brand mark (signal-fire watchtower).
export function BeaconMark({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <defs>
        <linearGradient id="beacon-grad" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fff3e0" />
          <stop offset="1" stopColor="#ffd9a8" />
        </linearGradient>
      </defs>
      <path d="M32 10 C36 18 40 20 40 27 a8 8 0 0 1 -16 0 c0-5 4-8 5-13 1 4 3 5 3 8 a3 3 0 0 0 0-12Z" fill="url(#beacon-grad)" />
      <rect x="26" y="38" width="12" height="14" rx="2" fill="rgba(255,255,255,0.85)" />
      <rect x="20" y="52" width="24" height="4" rx="2" fill="rgba(255,255,255,0.85)" />
    </svg>
  );
}
