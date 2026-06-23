// Minimal, zero-dependency hash routing. The dashboard is a single page whose
// "view" now lives in the URL (#/vulns, #/hosts, …) so pages are deep-linkable
// and the browser back/forward buttons work — the chief weakness of the previous
// useState<View>-only navigation. Detail views (host-detail/vuln-detail) need an
// in-memory selection, so a direct load of their URL falls back to the list.

export function getHashView(): string {
  return window.location.hash.replace(/^#\/?/, '').split('/')[0] || '';
}

export function setHashView(view: string): void {
  const target = '#/' + view;
  if (window.location.hash !== target) {
    window.location.hash = target;
  }
}
