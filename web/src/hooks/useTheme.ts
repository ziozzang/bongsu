import { useCallback, useEffect, useState } from 'react';

// Theme controls the [data-theme] attribute on <html>, which selects the
// semantic token palette defined in index.css. Dark is the product default;
// light is opt-in and persisted per browser.
export type Theme = 'dark' | 'light';

const STORAGE_KEY = 'bongsu-theme';

export function getInitialTheme(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    /* localStorage unavailable (private mode) — fall through to system default */
  }
  if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-color-scheme: light)').matches) {
    return 'light';
  }
  return 'dark';
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute('data-theme', theme);
}

// useTheme keeps React state, the <html data-theme> attribute, and localStorage
// in sync. Call applyTheme(getInitialTheme()) once at boot (main.tsx) to avoid a
// flash of the wrong palette before React mounts.
export function useTheme() {
  const [theme, setTheme] = useState<Theme>(getInitialTheme);

  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch {
      /* ignore persistence failures */
    }
  }, [theme]);

  const toggle = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  return { theme, setTheme, toggle };
}
