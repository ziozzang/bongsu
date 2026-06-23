// Date and number formatting helpers, extracted verbatim from App.tsx
// (UI decomposition). Pure, locale-aware where it doesn't break alignment.

function pad2(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}

// "YYYY-MM-DD HH:MM" in local time; '-' for empty, raw string if unparseable.
export function formatDateTime(value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '-';
  const dt = new Date(value);
  if (isNaN(dt.getTime())) return typeof value === 'string' ? value : '-';
  return `${dt.getFullYear()}-${pad2(dt.getMonth() + 1)}-${pad2(dt.getDate())} ${pad2(dt.getHours())}:${pad2(dt.getMinutes())}`;
}

// Full precision (with seconds) for hover tooltips.
export function formatDateTimeFull(value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '-';
  const dt = new Date(value);
  if (isNaN(dt.getTime())) return typeof value === 'string' ? value : '-';
  return `${formatDateTime(value)}:${pad2(dt.getSeconds())}`;
}

// Date-only local "YYYY-MM-DD".
export function formatDateOnly(value?: string | number | null): string {
  if (value === undefined || value === null || value === '') return '-';
  const dt = new Date(value);
  if (isNaN(dt.getTime())) return typeof value === 'string' ? value : '-';
  return `${dt.getFullYear()}-${pad2(dt.getMonth() + 1)}-${pad2(dt.getDate())}`;
}

// Thousands-grouped integer; counts > 999 always get separators.
export function fmtCount(n?: number | null): string {
  if (n === undefined || n === null || !Number.isFinite(n)) return '0';
  return n.toLocaleString();
}

// Short "Mon D" label for chart axes from a YYYY-MM-DD string.
export function shortDate(d: string): string {
  const dt = new Date(d + 'T00:00:00');
  if (isNaN(dt.getTime())) return d;
  return dt.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

// Round a max value up to a "nice" axis bound (1/2/5 × 10^n).
export function niceMax(v: number): number {
  if (v <= 0) return 1;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  const norm = v / pow;
  const step = norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10;
  return step * pow;
}
