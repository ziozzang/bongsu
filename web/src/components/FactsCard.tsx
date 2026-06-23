import React, { useState } from 'react';

// Renders unstructured host/container facts JSONB. Extracted from App.tsx.
export function renderFactValue(value: unknown): React.ReactNode {
  if (value === null || value === undefined) return <span style={{ color: 'var(--text-muted)' }}>-</span>;
  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={{ color: 'var(--text-muted)' }}>none</span>;
    if (value.every(v => typeof v !== 'object' || v === null)) {
      return <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-word' }}>{value.join(', ')}</span>;
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
        {value.map((v, i) => <div key={i} style={{ borderLeft: '2px solid var(--border)', paddingLeft: '0.5rem' }}>{renderFactValue(v)}</div>)}
      </div>
    );
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    return (
      <table style={{ width: '100%' }}>
        <tbody>
          {entries.map(([k, v]) => (
            <tr key={k}>
              <td style={{ color: 'var(--text-muted)', fontSize: '0.78rem', verticalAlign: 'top', whiteSpace: 'nowrap', paddingRight: '0.75rem', width: '1%' }}>{k}</td>
              <td style={{ fontSize: '0.8rem' }}>{renderFactValue(v)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  return <span className="mono" style={{ fontSize: '0.78rem', wordBreak: 'break-word' }}>{String(value)}</span>;
}

// FactsCard renders the unstructured host/container facts JSONB as a set of
// collapsible sections, one per top-level fact key (cpu, memory, dmi, ...).
export function FactsCard({ title, facts, collectedAt }: { title: string; facts?: Record<string, unknown>; collectedAt?: string | null }) {
  const sections = facts ? Object.entries(facts) : [];
  const [open, setOpen] = useState<Record<string, boolean>>({});
  if (sections.length === 0) return null;
  return (
    <div className="card" style={{ marginBottom: '1rem' }}>
      <div className="card-header">
        <h2>{title}</h2>
        {collectedAt && <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem' }}>collected {new Date(collectedAt).toLocaleString()}</span>}
      </div>
      <div style={{ padding: '0.5rem 1rem 1rem' }}>
        {sections.sort((a, b) => a[0].localeCompare(b[0])).map(([key, val]) => {
          const isOpen = open[key] ?? (key === 'os_release' || key === 'memory');
          return (
            <div key={key} style={{ borderBottom: '1px solid var(--border)', padding: '0.4rem 0' }}>
              <div
                style={{ cursor: 'pointer', fontWeight: 600, fontSize: '0.8125rem', display: 'flex', gap: '0.4rem', userSelect: 'none' }}
                onClick={() => setOpen(o => ({ ...o, [key]: !isOpen }))}
              >
                <span style={{ color: 'var(--text-muted)' }}>{isOpen ? '▾' : '▸'}</span>{key}
              </div>
              {isOpen && <div style={{ marginTop: '0.35rem', paddingLeft: '1rem' }}>{renderFactValue(val)}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

