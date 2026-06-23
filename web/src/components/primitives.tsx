import React from 'react';
import { type SeverityTone } from '../lib/severity';

// Small shared presentational primitives extracted from App.tsx: load/error/
// empty states, the sortable table header, and the Badge (with tone color).
export function Loading({ label = 'Loading...' }: { label?: string }) {
  return (
    <div className="state-block">
      <div className="spinner" />
      <span>{label}</span>
    </div>
  );
}

export function LoadError({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="state-block state-error">
      <span>{message}</span>
      {onRetry && <button className="btn btn-secondary btn-sm" onClick={onRetry}>Retry</button>}
    </div>
  );
}

// EmptyState renders the standard "no results" message for an empty list/table.
export function EmptyState({ message = 'No results found' }: { message?: string }) {
  return <div className="state-block">{message}</div>;
}

// SortHeader: a sortable <th> with a clear, clickable affordance. The active
// column shows a solid ▲/▼ arrow; inactive columns show a dimmed ↕ hint.
export function SortHeader({ col, label, sortBy, sortDesc, onSort }: {
  col: string; label: React.ReactNode; sortBy: string; sortDesc: boolean; onSort: (col: string) => void;
}) {
  const active = sortBy === col;
  return (
    <th
      className={`clickable sort-th${active ? ' sort-active' : ''}`}
      onClick={() => onSort(col)}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSort(col); } }}
      role="button"
      tabIndex={0}
      aria-sort={active ? (sortDesc ? 'descending' : 'ascending') : 'none'}
      style={{ userSelect: 'none' }}
    >
      {label}
      <span className={`sort-ind${active ? ' active' : ''}`} aria-hidden="true">{active ? (sortDesc ? '▼' : '▲') : '↕'}</span>
    </th>
  );
}

export function toneColor(tone: SeverityTone): string {
  switch (tone) {
    case 'critical': return 'var(--critical)';
    case 'high': return 'var(--high)';
    case 'medium': return 'var(--medium)';
    case 'low': return 'var(--low)';
    case 'accent': return 'var(--primary)';
    case 'unknown': return 'var(--unknown)';
    default: return 'var(--text-muted)';
  }
}
export function Badge({ tone = 'neutral', dot, children, title }: { tone?: SeverityTone; dot?: boolean; children: React.ReactNode; title?: string }) {
  const color = toneColor(tone);
  return (
    <span className="badge2" title={title} style={{ color, background: `color-mix(in srgb, ${color} 14%, transparent)` }}>
      {dot && <span className="badge2-dot" style={{ background: color }} />}
      {children}
    </span>
  );
}
