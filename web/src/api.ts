const API_BASE = '/api';

let apiKey = localStorage.getItem('bongsu_api_key') || '';
let onUnauthorized: (() => void) | null = null;

async function responseError(res: Response): Promise<Error> {
  const text = (await res.text()).trim();
  return new Error(text || `HTTP ${res.status}`);
}

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
  if (!res.ok) throw await responseError(res);
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
  if (!res.ok) throw await responseError(res);
  return res.json();
}

async function requestEmpty<T>(path: string, method: string): Promise<T> {
  const headers: Record<string, string> = {};
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(API_BASE + path, { method, headers });
  if (res.status === 401) {
    clearApiKey();
    if (onUnauthorized) onUnauthorized();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw await responseError(res);
  return res.json();
}

async function download(path: string, filename: string, params?: Record<string, string>): Promise<void> {
  const headers: Record<string, string> = {};
  if (apiKey) headers['X-API-Key'] = apiKey;
  const url = new URL(API_BASE + path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.set(k, v);
    });
  }
  const res = await fetch(url.toString(), { headers });
  if (res.status === 401) {
    clearApiKey();
    if (onUnauthorized) onUnauthorized();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw await responseError(res);
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = objectUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(objectUrl);
}

async function uploadForm<T>(path: string, form: FormData): Promise<T> {
  const headers: Record<string, string> = {};
  if (apiKey) headers['X-API-Key'] = apiKey;
  const res = await fetch(API_BASE + path, { method: 'POST', headers, body: form });
  if (res.status === 401) {
    clearApiKey();
    if (onUnauthorized) onUnauthorized();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw await responseError(res);
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
  agent_token_set?: boolean;
  owner?: string;
  team?: string;
  environment?: string;
  criticality?: string;
  tags?: string;
  last_seen: string;
  agent_status?: string;
  last_seen_age_seconds?: number;
  vuln_counts?: Record<string, number>;
  active_vuln_counts?: Record<string, number>;
  latest_inventory?: {
    latest_scan_id?: string;
    latest_scan_status?: string;
    latest_scan_at?: string | null;
    latest_package_count: number;
    latest_vulnerability_count: number;
    latest_container_count: number;
  };
}

export interface Vuln {
  id: string;
  vulnerability_id: string;
  severity: string;
  title: string;
  description: string;
  pkg_name: string;
  asset_type?: string;
  pkg_type?: string;
  ecosystem?: string;
  container_id?: string;
  image_name?: string;
  image_id?: string;
  target?: string;
  pkg_path: string;
  installed_version: string;
  fixed_version: string;
  cvss_score: number;
  cvss_vector: string;
  primary_url: string;
  finding_source?: string;
  advisory_sources?: string[];
  advisory_evidence?: AdvisoryEvidence[];
  host_id: string;
  host_owner?: string;
  host_team?: string;
  host_environment?: string;
  host_criticality?: string;
  exploited: boolean;
  epss_score?: number;
  epss_percentile?: number;
  risk_score?: number;
  risk_level?: string;
  container: string;
  triage_status: string;
  triage_reason: string;
  triage_comment: string;
  triage_expires_at?: string | null;
  triage_updated_by: string;
  triage_updated_at?: string | null;
  sla_days: number;
  due_at?: string | null;
  overdue: boolean;
}

export interface AdvisoryEvidence {
  source: string;
  category?: string;
  ecosystem?: string;
  severity?: string;
  cvss_score?: number;
  epss_score?: number;
  fixed_version?: string;
  title?: string;
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

export interface ContainerAsset {
  id: string;
  scan_id: string;
  host_id: string;
  runtime: string;
  container_id: string;
  name: string;
  image_name: string;
  image_id: string;
  image_digest?: string;
  state: string;
  labels?: string;
  started_at?: string | null;
  package_count: number;
  vulnerability_count: number;
  critical_count: number;
  high_count: number;
  max_cvss: number;
  created_at: string;
}

export interface FilterOptions {
  host_ids: string[];
  containers: string[];
  pkg_types: string[];
  sources: string[];
  finding_sources?: string[];
}

export interface Stats {
  total_hosts: number;
  total_vulnerabilities: number;
  severity_counts: Record<string, number>;
  agent_status_counts?: Record<string, number>;
  inventory_status_counts?: Record<string, number>;
  inventory_covered_hosts?: number;
  inventory_coverage_percent?: number;
  inventory_fresh_hosts?: number;
  inventory_fresh_percent?: number;
  inventory_latest_packages?: number;
  inventory_latest_vulnerabilities?: number;
  inventory_latest_containers?: number;
  active_vulnerabilities?: number;
  active_severity_counts?: Record<string, number>;
  active_risk_level_counts?: Record<string, number>;
  overdue_sla_count?: number;
  overdue_sla_risk_counts?: Record<string, number>;
  triage_active_counts?: Record<string, number>;
  triage_expired_counts?: Record<string, number>;
  triage_expiring_soon_counts?: Record<string, number>;
  triage_expiring_soon_days?: number;
  scan_request_counts?: Record<string, number>;
  scan_request_stale_counts?: Record<string, number>;
  security_db_revision?: string;
  security_db_rescan_request_counts?: Record<string, number>;
}

export interface VulnSummaryRow {
  group: string;
  total: number;
  overdue: number;
  severity: Record<string, number>;
  risk?: Record<string, number>;
}

export interface HealthStatus {
  status: string;
  trivy_db_ready: boolean;
  trivy_db_last_update?: string;
  security_db_revision?: string;
  security_db_revision_error?: string;
  security_db_freshness?: {
    status: string;
    stale: boolean;
    source_count?: number;
    required_sources?: string[];
    missing_sources?: string[];
    max_age_hours?: number;
    oldest_source?: string;
    oldest_last_update?: string;
    oldest_age_seconds?: number;
    stale_sources?: Array<{
      source: string;
      last_update?: string;
      age_seconds?: number;
    }>;
    error?: string;
  };
  trivy_db?: {
    ready: boolean;
    last_update?: string;
    status: string;
    last_error?: string;
  };
  web_auth: boolean;
  security_recalculation?: {
    running: boolean;
    pending: boolean;
    pending_reason?: string;
    last_result?: {
      status: string;
      finished_at?: string;
      reason?: string;
      cvss_updated?: number;
      findings_enriched?: number;
      stale_rematch_removed?: number;
      rematch_candidates?: number;
      rematch_scanned_candidates?: number;
      rematch_new_vulns?: number;
      rematch_skipped?: number;
      rematch_limited?: boolean;
      rematch_candidate_limit?: number;
      rematch_eligible_sources?: number;
      rematch_excluded_sources?: number;
      rematch_source_policy?: Record<string, { eligible?: boolean; reason?: string }>;
      severity_normalized?: number;
      errors?: string[];
    };
  };
  cve_db_rematch?: {
    last_result?: {
      status: string;
      finished_at?: string;
      matched?: number;
      new_vulns?: number;
      skipped?: number;
      scanned_candidates?: number;
      candidate_limit?: number;
      limited?: boolean;
      eligible_sources?: number;
      excluded_sources?: number;
      source_policy?: Record<string, { eligible?: boolean; reason?: string }>;
      security_db_revision?: string;
      security_db_revision_error?: string;
    };
  };
  cve_affected_package_index?: {
    count?: number;
    source_count?: number;
    indexed_cves?: number;
    matchable_cves?: number;
    coverage_percent?: number;
    missing_matchable_sources?: string[];
    last_update?: string;
    latest_matchable_update?: string;
    stale?: boolean;
    orphans?: number;
    error?: string;
  };
  security_db?: {
    configured: boolean;
    running: boolean;
    status: string;
    last_error: string;
    interval: string;
    last_sync?: string;
    last_attempt?: string;
    next_sync?: string;
  };
}

export interface CveSourceStat {
  source: string;
  count: number;
  matchable: number;
  matchable_percent?: number;
  with_ecosystem: number;
  with_fixed: number;
  with_ranges: number;
  with_cvss: number;
  last_update: string | null;
  rematch_eligible?: boolean;
  rematch_exclusion?: string;
}

export interface CveRematchPolicy {
  sources?: string[];
  min_source_matchable_percent?: number;
  candidate_limit?: number;
  eligible_sources?: number;
  excluded_sources?: number;
}

export interface CveEpssMergeStats {
  epss_records: number;
  epss_cves: number;
  matched_cves: number;
  unmatched_cves: number;
  enriched_records: number;
  enriched_cves: number;
  enriched_source_count: number;
  merge_coverage_percent: number;
}

export interface CveDbStatsResponse {
  generated_at?: string;
  security_db_revision?: string;
  security_db_revision_error?: string;
  source_count?: number;
  total_records?: number;
  total_matchable?: number;
  total_matchable_percent?: number;
  affected_package_index?: {
    count: number;
    source_count: number;
    indexed_cves?: number;
    matchable_cves?: number;
    coverage_percent?: number;
    missing_matchable_sources?: string[];
    last_update?: string;
    latest_matchable_update?: string;
    stale?: boolean;
    orphans: number;
  };
  affected_package_index_error?: string;
  epss_merge?: CveEpssMergeStats;
  epss_merge_error?: string;
  sources: CveSourceStat[];
  rematch_policy?: CveRematchPolicy;
}

export interface Scan {
  id: string;
  host_id: string;
  scan_type: string;
  status: string;
  error_summary?: string;
  package_count?: number;
  vulnerability_count?: number;
  container_count?: number;
  packages_added?: number;
  packages_removed?: number;
  packages_changed?: number;
  started_at: string;
  finished_at: string | null;
  created_at: string;
}

export interface ScanRequest {
  id: string;
  host_id?: string;
  requested_by?: string;
  scan_type: string;
  packages_only: boolean;
  reason?: string;
  security_db_revision?: string;
  status: string;
  error_message?: string;
  claimed_by_host_id?: string;
  claimed_at?: string | null;
  request_age_seconds?: number;
  claim_age_seconds?: number;
  request_stale?: boolean;
  claim_stale?: boolean;
  completed_at?: string | null;
  created_at: string;
}

export interface AuditLog {
  id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  status: string;
  ip_address: string;
  user_agent: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface AccessSubject {
  id: string;
  subject_type: string;
  external_id: string;
  display_name: string;
  created_at: string;
  updated_at: string;
}

export interface AccessPolicy {
  id: string;
  subject_id: string;
  subject_type: string;
  subject_external_id: string;
  resource_type: string;
  resource_id: string;
  permission: string;
  created_at: string;
}

export interface CveDbEntry {
  id: string;
  vulnerability_id: string;
  source: string;
  category?: string;
  ecosystem?: string;
  severity: string;
  cvss_score: number;
  cvss_vector: string;
  epss_score?: number;
  epss_percentile?: number;
  matchable?: boolean;
  title: string;
  description: string;
  published_date: string | null;
  modified_date: string | null;
  affected_products: string;
  references: string;
  raw_data?: string;
  updated_at?: string;
}

export interface RetentionPruneResult {
  dry_run: boolean;
  scan_days: number;
  request_days: number;
  audit_days: number;
  scan_cutoff: string;
  request_cutoff: string;
  audit_cutoff: string;
  scans: number;
  packages: number;
  vulnerabilities: number;
  containers: number;
  users: number;
  processes: number;
  ports: number;
  scan_requests: number;
  audit_logs: number;
}

export const api = {
  hosts: (params?: { agent_status?: string; inventory_status?: string }) => request<Host[]>('/hosts', params),
  host: (id: string) => request<Host>(`/hosts/${id}`),
  updateHostMetadata: (id: string, body: { owner?: string; team?: string; environment?: string; criticality?: string; tags?: string }) =>
    requestJSON<Host>(`/hosts/${id}/metadata`, body),
  resetHostAgentToken: (id: string) =>
    requestEmpty<{ status: string }>(`/hosts/${id}/agent-token/reset`, 'POST'),
  hostPackages: (id: string, limit: number, offset: number) =>
    request<{ items: Pkg[]; total: number }>(`/hosts/${id}/packages`, { limit: String(limit), offset: String(offset) }),
  exportHostSBOM: (id: string, hostname: string, format = 'cyclonedx') =>
    download(`/hosts/${id}/sbom`, `${hostname || id}-${format === 'spdx' ? 'spdx.json' : 'cyclonedx.json'}`, { format }),
  hostVulnCounts: (id: string) => request<Record<string, number>>(`/hosts/${id}/vuln-counts`),
  vulnerabilities: (params: { host_id?: string; severity?: string; triage_status?: string; finding_source?: string; risk_level?: string; overdue?: string; exploited?: string; min_epss?: string; min_epss_percentile?: string; min_cvss?: string; pkg_name?: string; container?: string; owner?: string; team?: string; environment?: string; criticality?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Vuln[]; total: number }>('/vulnerabilities', params),
  exportVulnerabilities: (params: { host_id?: string; severity?: string; triage_status?: string; finding_source?: string; risk_level?: string; overdue?: string; exploited?: string; min_epss?: string; min_epss_percentile?: string; pkg_name?: string; container?: string; owner?: string; team?: string; environment?: string; criticality?: string; sort_by?: string; sort_order?: string; show_no_fix?: string; show_mismatch?: string; format?: string }) =>
    download('/vulnerabilities/export', `bongsu-vulnerabilities.${params.format === 'json' ? 'json' : 'csv'}`, params),
  vulnFilters: () => request<FilterOptions>('/vulnerabilities/filters'),
  vulnSummary: (params: { group_by?: string }) =>
    request<{ group_by?: string; items: VulnSummaryRow[] }>('/vuln-summary', params),
  cveSearch: (params: { q?: string; pkg_name?: string; severity?: string; min_cvss?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Vuln[]; total: number }>('/cve-search', params),
  cveDbSearch: (params: { q?: string; severity?: string; source?: string; min_cvss?: string; min_epss?: string; min_epss_percentile?: string; matchable?: string; include_priority_sources?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: CveDbEntry[]; total: number }>('/cve-db/search', params),
  cveDbSources: () => request<{ sources: string[] }>('/cve-db/sources'),
  cveDbStats: () => request<CveDbStatsResponse>('/cve-db/stats'),
  packages: (params: { host_id?: string; container?: string; pkg_type?: string; source?: string; q?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Pkg[]; total: number }>('/packages', params),
  containers: (params: { host_id?: string; runtime?: string; state?: string; image?: string; q?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: ContainerAsset[]; total: number }>('/containers', params),
  packageFilters: () => request<FilterOptions>('/packages/filters'),
  packageVulns: (id: string) => request<Vuln[]>(`/packages/${id}/vulnerabilities`),
  triageVulnerability: (body: { vulnerability_id: string; host_id?: string; pkg_name?: string; status: string; reason?: string; comment?: string; expires_at?: string | null }) =>
    requestJSON<{ id: string; status: string }>('/vulnerabilities/triage', body),
  scans: (params: { host_id?: string; limit?: string; offset?: string }) =>
    request<{ items: Scan[]; total: number }>('/scans', params),
  scanRequests: (params: { host_id?: string; status?: string; scan_type?: string; security_db_revision?: string; stale?: string; limit?: string; offset?: string }) =>
    request<{ items: ScanRequest[]; total: number }>('/scan-requests', params),
  createScanRequest: (body: { host_id?: string; requested_by?: string; scan_type?: string; packages_only?: boolean; reason?: string }) =>
    requestJSON<{ id: string; status: string }>('/scan-requests', body),
  cancelScanRequest: (id: string) => request<{status: string}>(`/scan-requests/${id}/cancel`, undefined, 'POST'),
  requeueScanRequest: (id: string, body?: { message?: string }) =>
    requestJSON<{status: string}>(`/scan-requests/${id}/requeue`, body || {}),
  requeueFilteredScanRequests: (body: { host_id?: string; status?: string; scan_type?: string; security_db_revision?: string; message?: string }) =>
    requestJSON<{ status: string; requeued: number }>('/scan-requests/requeue-filtered', body),
  requeueStaleScanRequests: (body?: { timeout_minutes?: number }) =>
    requestJSON<{ status: string; requeued: number; cancelled_duplicates: number; timeout_minutes: number }>('/scan-requests/requeue-stale', body || {}),
  stats: () => request<Stats>('/stats'),
  rawHealth: () => request<HealthStatus>('/health'),
  deleteScan: (id: string, force = false) => request<{status: string}>(`/scans/${id}`, force ? { force: 'true' } : undefined, 'DELETE'),
  auditLogs: (params: { actor_type?: string; actor_id?: string; action?: string; resource_type?: string; resource_id?: string; status?: string; created_from?: string; created_to?: string; limit?: string; offset?: string }) =>
    request<{ items: AuditLog[]; total: number }>('/admin/audit-logs', params),
  rbacSubjects: () => request<{ items: AccessSubject[] }>('/admin/rbac/subjects'),
  rbacPolicies: (params?: { subject_external_id?: string }) =>
    request<{ items: AccessPolicy[] }>('/admin/rbac/policies', params),
  upsertRbacSubject: (body: { subject_type?: string; external_id: string; display_name?: string }) =>
    requestJSON<{ status: string }>('/admin/rbac/subjects', body),
  deleteRbacSubject: (id: string) => requestEmpty<{ status: string }>(`/admin/rbac/subjects/${encodeURIComponent(id)}`, 'DELETE'),
  upsertRbacPolicy: (body: { subject_id?: string; subject_external_id?: string; resource_type: string; resource_id?: string; permission?: string }) =>
    requestJSON<{ status: string }>('/admin/rbac/policies', body),
  deleteRbacPolicy: (id: string) => requestEmpty<{ status: string }>(`/admin/rbac/policies/${encodeURIComponent(id)}`, 'DELETE'),
  updateTrivyDB: () => request<{status: string; message: string; trivy_db_ready: boolean; last_update: string}>('/admin/trivy-db/update', undefined, 'POST'),
  updateSecurityDB: () => request<{status: string; security_db: HealthStatus['security_db']}>('/admin/security-db/update', undefined, 'POST'),
  recalculateSecurityDB: (body?: { reason?: string }) =>
    requestJSON<{status: string; reason: string; security_recalculation?: HealthStatus['security_recalculation']; security_db_revision?: string; security_db_revision_error?: string}>('/admin/security-db/recalculate', body || {}),
  exportSecurityDBBundle: (includeTrivy = true) =>
    download('/admin/security-db/export', 'bongsu-security-db-bundle.tar.gz', { include_trivy: includeTrivy ? 'true' : 'false' }),
  importSecurityDBBundle: (file: File) => {
    const form = new FormData();
    form.append('bundle', file);
    return uploadForm<{ status: string; imported: number; trivy_db_loaded: boolean }>('/admin/security-db/import', form);
  },
  rematchCVEs: (body?: { sources?: string[]; min_source_matchable_percent?: number; candidate_limit?: number }) =>
    requestJSON<{matched: number; new_vulns: number; skipped: number; scanned_candidates?: number; candidate_limit: number; limited: boolean; eligible_sources?: number; excluded_sources?: number; source_policy?: Record<string, { eligible?: boolean; reason?: string }>; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/rematch', body || {}),
  rebuildCveAffectedIndex: () =>
    request<{status: string; indexed: number; index?: CveDbStatsResponse['affected_package_index']; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/affected-index/rebuild', undefined, 'POST'),
  recalcCveCVSS: () =>
    request<{status: string; updated: number; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/recalc-cvss', undefined, 'POST'),
  pruneRetention: (body: { dry_run: boolean; scan_days?: number; request_days?: number; audit_days?: number }) =>
    requestJSON<RetentionPruneResult>('/admin/retention/prune', body),
};
