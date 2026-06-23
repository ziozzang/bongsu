import React from 'react';

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  // render defaults to String((row as any)[key]); supply for formatted/JSX cells.
  render?: (row: T) => React.ReactNode;
  // sortKey enables a sortable header for this column (handled by the caller via onSort).
  sortKey?: string;
  align?: 'left' | 'right' | 'center';
  className?: string;
  width?: string | number;
  // headerTitle is a tooltip on the header cell.
  headerTitle?: string;
}

export interface SortState {
  by: string;
  desc: boolean;
}

// DataTable is the one table primitive for the dashboard: it owns the sortable
// header affordance and the loading / error / empty states so every list view
// renders them identically. It reuses the existing table CSS classes (table,
// sort-th, sort-ind, empty-row), so it is a visual drop-in for the hand-rolled
// tables it replaces. Data fetching, pagination and sorting logic stay with the
// caller (most views page on the server); DataTable just renders.
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  sort,
  onSort,
  loading,
  error,
  onRetry,
  empty,
  onRowClick,
  rowClassName,
  stickyHeader,
}: {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  sort?: SortState;
  onSort?: (sortKey: string) => void;
  loading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  empty?: React.ReactNode;
  onRowClick?: (row: T) => void;
  rowClassName?: (row: T) => string | undefined;
  stickyHeader?: boolean;
}) {
  const span = columns.length;
  const cellStyle = (c: Column<T>): React.CSSProperties => ({
    textAlign: c.align,
    width: c.width,
  });

  return (
    <table className={'data-table' + (stickyHeader ? ' sticky-header' : '')}>
      <thead>
        <tr>
          {columns.map((c) => {
            const sortable = !!c.sortKey && !!onSort;
            const active = sortable && sort?.by === c.sortKey;
            if (!sortable) {
              return (
                <th key={c.key} style={cellStyle(c)} title={c.headerTitle}>
                  {c.header}
                </th>
              );
            }
            return (
              <th
                key={c.key}
                className={'clickable sort-th' + (active ? ' sort-active' : '')}
                style={{ ...cellStyle(c), userSelect: 'none' }}
                title={c.headerTitle}
                role="button"
                tabIndex={0}
                aria-sort={active ? (sort?.desc ? 'descending' : 'ascending') : 'none'}
                onClick={() => onSort!(c.sortKey!)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    onSort!(c.sortKey!);
                  }
                }}
              >
                {c.header}
                <span className={'sort-ind' + (active ? ' active' : '')} aria-hidden="true">
                  {active ? (sort?.desc ? '▼' : '▲') : '↕'}
                </span>
              </th>
            );
          })}
        </tr>
      </thead>
      <tbody>
        {loading && (
          <tr className="empty-row">
            <td colSpan={span}>
              <span className="dt-spinner" aria-hidden="true" /> Loading…
            </td>
          </tr>
        )}
        {!loading && error && (
          <tr className="empty-row">
            <td colSpan={span}>
              <span className="dt-error">{error}</span>
              {onRetry && (
                <button type="button" className="btn btn-sm btn-secondary dt-retry" onClick={onRetry}>
                  Retry
                </button>
              )}
            </td>
          </tr>
        )}
        {!loading && !error && rows.length === 0 && (
          <tr className="empty-row">
            <td colSpan={span}>{empty ?? 'No results'}</td>
          </tr>
        )}
        {!loading &&
          !error &&
          rows.map((row, i) => (
            <tr
              key={rowKey(row, i)}
              className={rowClassName?.(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              style={onRowClick ? { cursor: 'pointer' } : undefined}
            >
              {columns.map((c) => (
                <td key={c.key} className={c.className} style={{ textAlign: c.align }}>
                  {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
      </tbody>
    </table>
  );
}
