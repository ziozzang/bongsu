import React, { useEffect, useMemo, useRef, useState } from 'react';

// A command item is anything the palette can jump to or run. Kept generic so the
// palette has no dependency on the app's View type or icon system — the caller
// supplies labels, optional pre-rendered icons, and the action to run.
export interface CommandItem {
  id: string;
  label: string;
  group?: string;
  keywords?: string;
  icon?: React.ReactNode;
  run: () => void;
}

// CommandPalette is a ⌘K/Ctrl-K overlay: type to filter, ↑/↓ to move, Enter to
// run, Esc/backdrop to close. Open/close state is owned by the caller.
export function CommandPalette({
  open,
  onClose,
  items,
  placeholder,
}: {
  open: boolean;
  onClose: () => void;
  items: CommandItem[];
  placeholder?: string;
}) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActive(0);
      const t = setTimeout(() => inputRef.current?.focus(), 0);
      return () => clearTimeout(t);
    }
  }, [open]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return items;
    return items.filter((it) =>
      `${it.label} ${it.group ?? ''} ${it.keywords ?? ''}`.toLowerCase().includes(q),
    );
  }, [items, query]);

  useEffect(() => {
    setActive(0);
  }, [query]);

  if (!open) return null;

  const choose = (it?: CommandItem) => {
    if (it) {
      it.run();
      onClose();
    }
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, filtered.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      choose(filtered[active]);
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  return (
    <div className="cmdk-backdrop" onClick={onClose} role="presentation">
      <div
        className="cmdk"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
      >
        <input
          ref={inputRef}
          className="cmdk-input"
          value={query}
          placeholder={placeholder ?? 'Jump to a page…'}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKey}
          aria-label="Command search"
        />
        <ul className="cmdk-list" role="listbox" aria-label="Commands">
          {filtered.length === 0 && <li className="cmdk-empty">No matches</li>}
          {filtered.map((it, i) => (
            <li
              key={it.id}
              role="option"
              aria-selected={i === active}
              className={'cmdk-item' + (i === active ? ' active' : '')}
              onMouseEnter={() => setActive(i)}
              onClick={() => choose(it)}
            >
              {it.icon && <span className="cmdk-icon">{it.icon}</span>}
              <span className="cmdk-label">{it.label}</span>
              {it.group && <span className="cmdk-group">{it.group}</span>}
            </li>
          ))}
        </ul>
        <div className="cmdk-hint">
          <kbd>↑</kbd><kbd>↓</kbd> navigate <kbd>↵</kbd> open <kbd>esc</kbd> close
        </div>
      </div>
    </div>
  );
}
