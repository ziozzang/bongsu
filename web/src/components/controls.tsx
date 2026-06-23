import React, { useRef, useEffect } from 'react';

// Shared interactive controls extracted from App.tsx: range switcher,
// checkbox field, modal dialog (focus-trapped, Esc-closable), and pager.
export function RangeSwitcher({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <div className="range-switcher" role="tablist">
      {['14', '30', '90'].map(d => (
        <button key={d} type="button" role="tab" aria-selected={value === d} className={value === d ? 'active' : ''} onClick={() => onChange(d)}>{d}d</button>
      ))}
    </div>
  );
}

// CheckboxField is the single clickable checkbox+label control used across all
// filter bars and forms (replaces ad-hoc inline-styled <label> wrappers).
export function CheckboxField({ label, checked, onChange, title, disabled }: { label: string; checked: boolean; onChange: (checked: boolean) => void; title?: string; disabled?: boolean }) {
  return (
    <label className="checkbox-field" title={title}>
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

// Modal is the shared dialog shell: consistent backdrop, header with title + X,
// Escape-to-close, and a scrollable body.
export function Modal({ title, onClose, children, width }: { title: React.ReactNode; onClose: () => void; children: React.ReactNode; width?: string }) {
  const modalRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    // Move focus into the dialog on open; restore to the trigger on close.
    const prevFocus = document.activeElement as HTMLElement | null;
    modalRef.current?.focus();
    return () => {
      window.removeEventListener('keydown', onKey);
      if (prevFocus && typeof prevFocus.focus === 'function') prevFocus.focus();
    };
  }, [onClose]);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        ref={modalRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        tabIndex={-1}
        onClick={(e) => e.stopPropagation()}
        style={width ? { width } : undefined}
      >
        <div className="modal-header">
          <h2>{title}</h2>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close" title="Close (Esc)">×</button>
        </div>
        <div className="modal-body">{children}</div>
      </div>
    </div>
  );
}

export function Pager({ page, limit, total, onPage }: { page: number; limit: number; total: number; onPage: (p: number) => void }) {
  return (
    <div className="pagination" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginTop: '0.75rem' }}>
      <button disabled={page === 0} onClick={() => onPage(page - 1)}>Prev</button>
      <span style={{ color: 'var(--text-muted)', fontSize: '0.8125rem' }}>
        Page {page + 1} / {Math.max(1, Math.ceil(total / limit))} ({total.toLocaleString()} items)
      </span>
      <button disabled={(page + 1) * limit >= total} onClick={() => onPage(page + 1)}>Next</button>
    </div>
  );
}
