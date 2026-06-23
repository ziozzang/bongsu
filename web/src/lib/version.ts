// Version comparison for package versions across ecosystems. Handles numeric
// segments, epoch prefixes (1:2.3), a leading v, and common pre-release markers
// (alpha/beta/rc/~/snapshot/…), ranking a pre-release below its release.
// Extracted verbatim from App.tsx as the first lib/ module of the UI decomposition.

const preReleaseMarkers = ['dev', 'snapshot', 'preview', 'pre', 'alpha', 'beta', 'rc'];

export const verCmp = (a: string, b: string): number => {
  const pa = versionSegments(a);
  const pb = versionSegments(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na - nb;
  }
  const aPre = isPreReleaseVersion(a);
  const bPre = isPreReleaseVersion(b);
  if (aPre && !bPre) return -1;
  if (!aPre && bPre) return 1;
  if (aPre && bPre) return comparePreRelease(a, b);
  return 0;
};

export function versionSegments(v: string): number[] {
  const clean = stripPreReleaseSuffix(v.trim().replace(/^v?/, '').replace(/^[0-9]+:/, ''));
  return clean.split(/[^0-9]+/).filter(Boolean).map((p) => Number.parseInt(p, 10)).filter((n) => Number.isFinite(n));
}

export function isPreReleaseVersion(v: string): boolean {
  const clean = v.toLowerCase().split('+')[0];
  return clean.includes('~') || preReleaseMarkers.some((m) => clean.includes(m));
}

function stripPreReleaseSuffix(v: string): string {
  const low = v.toLowerCase();
  let cut = low.includes('+') ? low.indexOf('+') : v.length;
  const tilde = low.indexOf('~');
  if (tilde >= 0 && tilde < cut) cut = tilde;
  preReleaseMarkers.forEach((marker) => {
    const idx = low.indexOf(marker);
    if (idx >= 0 && idx < cut) cut = idx;
  });
  return v.slice(0, cut).replace(/[-_.]+$/, '');
}

function comparePreRelease(a: string, b: string): number {
  const [ar, an] = preReleaseRank(a);
  const [br, bn] = preReleaseRank(b);
  if (ar !== br) return ar - br;
  return an - bn;
}

function preReleaseRank(v: string): [number, number] {
  const clean = v.toLowerCase().split('+')[0];
  for (let i = 0; i < preReleaseMarkers.length; i++) {
    const marker = preReleaseMarkers[i];
    if (clean.includes(marker)) return [i + 1, preReleaseNumber(clean, marker)];
  }
  if (clean.includes('~')) return [0, preReleaseNumber(clean, '~')];
  return [preReleaseMarkers.length + 1, 0];
}

function preReleaseNumber(v: string, marker: string): number {
  const idx = v.indexOf(marker);
  if (idx < 0) return 0;
  const match = v.slice(idx + marker.length).match(/\d+/);
  return match ? Number.parseInt(match[0], 10) : 0;
}
