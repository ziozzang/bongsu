const API_BASE = '/api';

let apiKey = localStorage.getItem('bongsu_api_key') || '';
let onUnauthorized: (() => void) | null = null;

export function setApiKey(key: string) {
  apiKey = key;
  localStorage.setItem('bongsu_api_key', key);
}

export function clearApiKey() {
  apiKey = '';
  localStorage.removeItem('bongsu_api_key');
}

export function getApiKey(): string {
  return apiKey;
}

export function onAuthFailure(cb: () => void) {
  onUnauthorized = cb;
}

async function request<T>(path: string, params?: Record<string, string>, method?: string): Promise<T> {
  const url = new URL(API_BASE + path, window.location.origin);
  if (params && method !== 'DELETE') {
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.set(k, v);
    });
  }

  const headers: Record<string, string> = {};
  if (apiKey) headers['X-API-Key'] = apiKey;

  const res = await fetch(url.toString(), { method: method || 'GET', headers });
  if (res.status === 401) {
    clearApiKey();
    if (onUnauthorized) onUnauthorized();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function requestJSON<T>(path: string, body: unknown): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(API_BASE + path, { method: 'POST', headers, body: JSON.stringify(body) });
  if (res.status === 401) {
    clearApiKey();
    if (onUnauthorized) onUnauthorized();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export interface Host {
  id: string;
  hostname: string;
  ip_address: string;
  os_name: string;
  os_version: string;
  kernel: string;
  arch: string;
  cpu_model: string;
  cpu_cores: number;
  memory_mb: number;
  agent_version: string;
  last_seen: string;
  vuln_counts?: Record<string, number>;
}

export interface Vuln {
  id: string;
  vulnerability_id: string;
  severity: string;
  title: string;
  description: string;
  pkg_name: string;
  pkg_path: string;
  installed_version: string;
  fixed_version: string;
  cvss_score: number;
  cvss_vector: string;
  primary_url: string;
  host_id: string;
  container: string;
}

export interface Pkg {
  id: string;
  name: string;
  version: string;
  arch: string;
  pkg_type: string;
  source: string;
  container: string;
  host_id: string;
  file_path: string;
  target: string;
  max_cvss: number;
  vuln_count: number;
  created_at: string;
}

export interface FilterOptions {
  host_ids: string[];
  containers: string[];
  pkg_types: string[];
  sources: string[];
}

export interface Stats {
  total_hosts: number;
  total_vulnerabilities: number;
  severity_counts: Record<string, number>;
}

export interface HealthStatus {
  status: string;
  trivy_db_ready: boolean;
  trivy_db_last_update?: string;
  web_auth: boolean;
  security_db?: {
    configured: boolean;
    running: boolean;
    status: string;
    last_error: string;
    interval: string;
  };
}

export interface CveSourceStat {
  source: string;
  count: number;
  last_update: string | null;
}

export interface Scan {
  id: string;
  host_id: string;
  scan_type: string;
  status: string;
  started_at: string;
  finished_at: string | null;
  created_at: string;
}

export interface CveDbEntry {
  id: string;
  vulnerability_id: string;
  source: string;
  severity: string;
  cvss_score: number;
  cvss_vector: string;
  title: string;
  description: string;
  published_date: string | null;
  modified_date: string | null;
  affected_products: string;
  references: string;
}

export const api = {
  hosts: () => request<Host[]>('/hosts'),
  host: (id: string) => request<Host>(`/hosts/${id}`),
  hostPackages: (id: string, limit: number, offset: number) =>
    request<{ items: Pkg[]; total: number }>(`/hosts/${id}/packages`, { limit: String(limit), offset: String(offset) }),
  hostVulnCounts: (id: string) => request<Record<string, number>>(`/hosts/${id}/vuln-counts`),
  vulnerabilities: (params: { host_id?: string; severity?: string; min_cvss?: string; pkg_name?: string; container?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Vuln[]; total: number }>('/vulnerabilities', params),
  vulnFilters: () => request<{ host_ids: string[]; containers: string[] }>('/vulnerabilities/filters'),
  cveSearch: (params: { q?: string; pkg_name?: string; severity?: string; min_cvss?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Vuln[]; total: number }>('/cve-search', params),
  cveDbSearch: (params: { q?: string; severity?: string; source?: string; min_cvss?: string; limit?: string; offset?: string }) =>
    request<{ items: CveDbEntry[]; total: number }>('/cve-db/search', params),
  cveDbSources: () => request<string[]>('/admin/cve-db/sources'),
  cveDbStats: () => request<{ sources: CveSourceStat[] }>('/cve-db/stats'),
  packages: (params: { host_id?: string; container?: string; pkg_type?: string; source?: string; q?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Pkg[]; total: number }>('/packages', params),
  packageFilters: () => request<FilterOptions>('/packages/filters'),
  packageVulns: (id: string) => request<Vuln[]>(`/packages/${id}/vulnerabilities`),
  scans: (params: { host_id?: string; limit?: string; offset?: string }) =>
    request<{ items: Scan[]; total: number }>('/scans', params),
  createScanRequest: (body: { host_id?: string; requested_by?: string; scan_type?: string; packages_only?: boolean; reason?: string }) =>
    requestJSON<{ id: string; status: string }>('/scan-requests', body),
  stats: () => request<Stats>('/stats'),
  rawHealth: () => request<HealthStatus>('/health'),
  deleteScan: (id: string) => request<{status: string}>(`/scans/${id}`, undefined, 'DELETE'),
  updateTrivyDB: () => request<{status: string; message: string; trivy_db_ready: boolean; last_update: string}>('/admin/trivy-db/update', undefined, 'POST'),
  updateSecurityDB: () => request<{status: string; security_db: HealthStatus['security_db']}>('/admin/security-db/update', undefined, 'POST'),
  rematchCVEs: () => request<{matched: number; new_vulns: number; skipped: number}>('/admin/cve-db/rematch', undefined, 'POST'),
};
