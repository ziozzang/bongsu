const API_BASE = '/api';

let apiKey = localStorage.getItem('bongsu_api_key') || '';
let sessionToken = localStorage.getItem('bongsu_session') || '';
let onUnauthorized: (() => void) | null = null;

async function responseError(res: Response): Promise<Error> {
  const text = (await res.text()).trim();
  return new Error(text || `HTTP ${res.status}`);
}

function handleUnauthorized(): Error {
  if (apiKey || sessionToken) {
    clearApiKey();
    clearSession();
    if (onUnauthorized) onUnauthorized();
  }
  return new Error('Unauthorized');
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

export function setSession(token: string) {
  sessionToken = token;
  localStorage.setItem('bongsu_session', token);
}

export function clearSession() {
  sessionToken = '';
  localStorage.removeItem('bongsu_session');
}

export function getSession(): string {
  return sessionToken;
}

export function hasAuth(): boolean {
  return apiKey !== '' || sessionToken !== '';
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
  if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;

  const res = await fetch(url.toString(), { method: method || 'GET', headers });
  if (res.status === 401) {
    throw handleUnauthorized();
  }
  if (!res.ok) throw await responseError(res);
  return res.json();
}

async function requestCveDbStats(): Promise<CveDbStatsResponse> {
  const res = await fetch(API_BASE + '/cve-db/stats', { headers: apiHeaders() });
  if (res.status === 401) {
    throw handleUnauthorized();
  }
  if (!res.ok) throw await responseError(res);
  const body = await res.json() as CveDbStatsResponse;
  body.cache_status = res.headers.get('X-Bongsu-Cache') || undefined;
  return body;
}

function apiHeaders(extra?: Record<string, string>): Record<string, string> {
  const headers: Record<string, string> = { ...(extra || {}) };
  if (apiKey) headers['X-API-Key'] = apiKey;
  if (sessionToken) headers['Authorization'] = `Bearer ${sessionToken}`;
  return headers;
}

async function requestJSON<T>(path: string, body: unknown): Promise<T> {
  const headers = apiHeaders({ 'Content-Type': 'application/json' });
  const res = await fetch(API_BASE + path, { method: 'POST', headers, body: JSON.stringify(body) });
  if (res.status === 401) {
    throw handleUnauthorized();
  }
  if (!res.ok) throw await responseError(res);
  return res.json();
}

async function requestEmpty<T>(path: string, method: string): Promise<T> {
  const headers = apiHeaders();
  const res = await fetch(API_BASE + path, { method, headers });
  if (res.status === 401) {
    throw handleUnauthorized();
  }
  if (!res.ok) throw await responseError(res);
  return res.json();
}

async function download(path: string, filename: string, params?: Record<string, string>): Promise<void> {
  const headers = apiHeaders();
  const url = new URL(API_BASE + path, window.location.origin);
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.set(k, v);
    });
  }
  const res = await fetch(url.toString(), { headers });
  if (res.status === 401) {
    throw handleUnauthorized();
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
    throw handleUnauthorized();
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

export interface UserAccount {
  id: string;
  scan_id: string;
  host_id: string;
  username: string;
  uid: number;
  gid: number;
  home_dir: string;
  shell: string;
}

export interface ProcessSnapshot {
  id: string;
  scan_id: string;
  host_id: string;
  pid: number;
  name: string;
  cmdline: string;
  user: string;
  cpu_usage: number;
  mem_usage: number;
}

export interface PortInfo {
  id: string;
  scan_id: string;
  host_id: string;
  name: string;
  port: number;
  protocol: string;
  address: string;
  pid: number;
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
  latest_scan_id?: string;
  host_id: string;
  runtime: string;
  container_id: string;
  name: string;
  image_name: string;
  image_id: string;
  image_digest?: string;
  state: string;
  labels?: string;
  label_count: number;
  labels_redacted?: boolean;
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
  agent_version_counts?: Record<string, number>;
  agent_version_drift_counts?: Record<string, number>;
  latest_agent_version?: string;
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
  security_db_rescan_stale_counts?: Record<string, number>;
  security_db_rescan_progress?: {
    revision?: string;
    total?: number;
    open?: number;
    terminal?: number;
    succeeded?: number;
    failed?: number;
    cancelled?: number;
    complete_percent?: number;
    healthy_percent?: number;
  };
  security_db_scan_coverage?: {
    revision?: string;
    total_hosts?: number;
    current_hosts?: number;
    stale_hosts?: number;
    unknown_hosts?: number;
    no_scan_hosts?: number;
    coverage_percent?: number;
  };
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
    latest_source?: string;
    latest_last_update?: string;
    latest_age_seconds?: number;
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
      stale_rematch_scanned?: number;
      stale_rematch_batches?: number;
      stale_rematch_batch_size?: number;
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
  security_db_auto_rescan?: {
    last_result?: {
      status: string;
      finished_at?: string;
      reason?: string;
      recalculation_status?: string;
      eligible?: number;
      queued?: number;
      already_pending?: number;
      security_db_revision?: string;
      last_seen_hours?: number;
      error?: string;
      stage?: string;
    };
  };
  cve_reference_index_rebuild?: {
    running?: boolean;
    started_at?: string;
    duration_ms?: number;
    last_result?: {
      status?: string;
      indexed?: number;
      duration_ms?: number;
      finished_at?: string;
      error?: string;
      security_db_revision?: string;
      security_db_revision_error?: string;
    };
  };
  cve_affected_index_rebuild?: {
    running?: boolean;
    started_at?: string;
    duration_ms?: number;
    last_result?: {
      status?: string;
      indexed?: number;
      duration_ms?: number;
      finished_at?: string;
      error?: string;
      index_count?: number;
      index_sources?: number;
      index_coverage_percent?: number;
      index_orphans?: number;
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
    summary_mode?: string;
    detail_error?: string;
    fallback_error?: string;
  };
  cve_reference_key_index?: {
    count?: number;
    indexed_cves?: number;
    total_cves?: number;
    canonical_cves?: number;
    vendor_keys?: number;
    repository_keys?: number;
    coverage_percent?: number;
    last_update?: string;
    latest_cve_update?: string;
    stale?: boolean;
    orphans?: number;
    error?: string;
  };
  cve_db_quality?: CveDbQuality;
  security_db?: {
    configured: boolean;
    running: boolean;
    status: string;
    status_detail?: string;
    last_error: string;
    interval: string;
    last_sync?: string;
    last_attempt?: string;
    next_sync?: string;
    last_sync_persisted?: string;
    persisted_latest_source?: string;
    persisted_latest_update?: string;
    persisted_status?: string;
    persisted_missing_sources?: string[];
    persisted_stale_sources?: string[];
    effective_status?: string;
    effective_last_sync?: string;
    effective_source?: string;
    effective_age_seconds?: number;
  };
}

export interface SecuritySourceStatus {
  id: string;
  name: string;
  kind: string;
  category: string;
  ecosystems: string[];
  enabled: boolean;
  update_interval_seconds: number;
  last_sync_started_at?: string;
  last_sync_finished_at?: string;
  last_exported_at?: string;
  last_status: string;
  last_error: string;
  record_count: number;
  updated_at: string;
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

export interface CveOsvEcosystemStat {
  ecosystem: string;
  indexed_rows: number;
  matchable_cves: number;
  last_update: string | null;
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
  non_epss_cves?: number;
  non_epss_cves_with_epss?: number;
  non_epss_coverage_percent?: number;
  enriched_records: number;
  enriched_cves: number;
  enriched_source_count: number;
  epss_universe_match_percent?: number;
  merge_coverage_percent: number;
}

export interface CveDbQuality {
  status?: string;
  warnings?: string[];
  warning_count?: number;
  total_records?: number;
  total_matchable?: number;
  eligible_sources?: number;
  excluded_sources?: number;
  temporary_placeholders?: number;
  empty_vulnerability_ids?: number;
  empty_sources?: number;
  affected_index_coverage_percent?: number;
  affected_index_orphans?: number;
  affected_index_stale?: boolean;
  affected_index_summary_mode?: string;
  affected_index_indexed_cves?: number;
  affected_index_records?: number;
  affected_index_detail_error?: string;
  reference_index_coverage_percent?: number;
  reference_index_orphans?: number;
  reference_index_stale?: boolean;
  reference_index_summary_mode?: string;
  reference_index_indexed_cves?: number;
  reference_index_records?: number;
  reference_index_detail_error?: string;
  epss_merge_coverage_percent?: number;
  epss_non_epss_coverage_percent?: number;
  placeholder_stats_error?: string;
  affected_index_error?: string;
  reference_index_error?: string;
  epss_merge_error?: string;
}

export interface CveDbStatsResponse {
  generated_at?: string;
  cache_status?: string;
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
  reference_key_index?: {
    count: number;
    indexed_cves?: number;
    total_cves?: number;
    canonical_cves?: number;
    vendor_keys?: number;
    repository_keys?: number;
    coverage_percent?: number;
    last_update?: string;
    latest_cve_update?: string;
    stale?: boolean;
    orphans: number;
  };
  reference_key_index_error?: string;
  epss_merge?: CveEpssMergeStats;
  epss_merge_error?: string;
  cve_db_quality?: CveDbQuality;
  cve_db_quality_error?: string;
  durations_ms?: Record<string, number>;
  sources: CveSourceStat[];
  osv_ecosystems?: CveOsvEcosystemStat[];
  osv_ecosystems_error?: string;
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

export interface AccessControlStatus {
  status: string;
  generated_at: string;
  warnings?: string[];
  stats: {
    subject_count: number;
    policy_count: number;
    user_subject_count: number;
    group_subject_count: number;
    read_policy_count: number;
    write_policy_count: number;
    admin_policy_count: number;
    export_policy_count: number;
    wildcard_policy_count: number;
    orphan_policy_count: number;
  };
  auth?: {
    web_auth_enabled: boolean;
    viewer_key_count: number;
    oidc_configured: boolean;
    oidc_jwks_configured: boolean;
    oidc_admin_user_count: number;
    oidc_admin_group_count: number;
    trusted_identity_configured: boolean;
    trusted_user_header_configured: boolean;
    trusted_groups_header_configured: boolean;
    trusted_proxy_cidr_count: number;
    trusted_admin_user_count: number;
    trusted_admin_group_count: number;
    trusted_identity_admin_configured: boolean;
  };
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
  matchable_affected_count?: number;
  matchability_reason?: string;
  reference_group_total?: number;
  reference_group_matchable?: number;
  reference_group_sources?: number;
  reference_group_status?: string;
  reference_group_key?: string;
  title: string;
  description: string;
  published_date: string | null;
  modified_date: string | null;
  affected_products: string;
  references: string;
  reference_keys?: string[];
  raw_data?: string;
  updated_at?: string;
}

export interface CveAffectedPackage {
  cve_id: string;
  vulnerability_id: string;
  source: string;
  package_name: string;
  ecosystem: string;
  fixed_version: string;
  affected_product: string;
  updated_at: string;
}

export interface CveReferenceGroupBucket {
  name: string;
  count: number;
}

export interface CveReferenceGroupSummary {
  key: string;
  total: number;
  matchable: number;
  affected_package_total?: number;
  sources: CveReferenceGroupBucket[];
  categories: CveReferenceGroupBucket[];
  ecosystems: CveReferenceGroupBucket[];
  source_groups: CveReferenceGroupBucket[];
  reference_keys: string[];
  items: CveDbEntry[];
  affected_packages?: CveAffectedPackage[];
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

export interface InstallerBinaryStatus {
  name: string;
  ready: boolean;
  path?: string;
  version?: string;
  bytes?: number;
  sha256?: string;
  error?: string;
}

export interface InstallerStatus {
  ready: boolean;
  install_token_configured: boolean;
  agent: InstallerBinaryStatus;
  trivy: InstallerBinaryStatus;
}

export interface SecurityDbOperationalStatus {
  status: string;
  warnings?: string[];
  recommended_actions?: string[];
  security_sources?: SecuritySourceStatus[];
  security_sources_error?: string;
  security_db?: HealthStatus['security_db'];
  security_db_freshness?: HealthStatus['security_db_freshness'];
  security_db_export?: {
    status: string;
    source_count?: number;
    data_source_count?: number;
    latest_exported_at?: string;
    latest_source_update_at?: string;
    outdated_source_count?: number;
    outdated_sources?: Array<{
      source: string;
      last_source_update_at?: string;
      last_data_update_at?: string;
      last_sync_finished_at?: string;
      last_exported_at?: string;
      lag_seconds?: number;
    }>;
  };
  security_db_export_data_error?: string;
  security_db_revision?: string;
  security_db_revision_error?: string;
  security_recalculation?: HealthStatus['security_recalculation'];
  security_db_bundle_import?: {
    last_result?: {
      status: string;
      finished_at?: string;
      stage?: string;
      message?: string;
      imported?: number;
      trivy_db_loaded?: boolean;
      security_db_revision?: string;
      bundle_created_at?: string;
      bundle_source_count?: number;
      bundle_cve_records?: number;
      bundle_trivy_db_included?: boolean;
      error?: string;
    };
  };
  cve_db_quality?: CveDbQuality;
  cve_affected_package_index?: HealthStatus['cve_affected_package_index'];
  cve_reference_key_index?: HealthStatus['cve_reference_key_index'];
}

export interface AgentFleetStatus {
  status: string;
  total_hosts?: number;
  outdated_percent?: number;
  warnings?: string[];
  recommended_actions?: string[];
  agent_status_counts?: Record<string, number>;
  agent_version_counts?: Record<string, number>;
  agent_version_drift_counts?: Record<string, number>;
  scan_request_stale_counts?: Record<string, number>;
  security_db_revision?: string;
  security_db_rescan_request_counts?: Record<string, number>;
  security_db_rescan_stale_counts?: Record<string, number>;
  security_db_rescan_progress?: Stats['security_db_rescan_progress'];
  security_db_scan_coverage?: Stats['security_db_scan_coverage'];
  latest_agent_version?: string;
  installer?: InstallerStatus;
}

// Phase 3: Fleet Management

export interface ScheduledScan {
  id: string;
  name: string;
  cron_expr: string;
  scan_type: string;
  enabled: boolean;
  host_filter: string;
  packages_only: boolean;
  last_run: string | null;
  next_run: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetGroup {
  id: string;
  name: string;
  description: string;
  rule_type: string;
  rule_expr: string;
  host_count: number;
  created_at: string;
  updated_at: string;
}

export interface AssetGroupDetail extends AssetGroup {
  hosts: Host[];
}

// Phase 4: Intelligence & Reports

export interface VulnTrendRow {
  date: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface VulnTrendSummary {
  current_total: number;
  previous_total: number;
  delta: number;
  delta_percent: number;
  trend_direction: string;
}

export interface AtRiskHost {
  host_id: string;
  hostname: string;
  total_vulns: number;
  critical_count: number;
  high_count: number;
  exploited_count: number;
  overdue_count: number;
  max_risk_score: number;
}

export interface Recommendation {
  type: string;
  severity: string;
  count: number;
  message: string;
}

export interface PostureComparison {
  current_total: number;
  previous_total: number;
  delta: number;
  delta_percent: number;
  trend_direction: string;
  current_date: string;
  previous_date: string;
}

export interface ExecutiveSummary {
  generated_at: string;
  total_hosts: number;
  host_coverage_percent: number;
  active_vulnerabilities: number;
  severity_counts: Record<string, number>;
  risk_level_counts: Record<string, number>;
  exploited_count: number;
  overdue_sla_count: number;
  sla_compliance_percent: number;
  trend_direction: string;
  trend_delta: number;
  top_risk_hosts: AtRiskHost[];
}

export interface SLASevStats {
  total: number;
  overdue: number;
  compliance_percent: number;
}

export interface SLAComplianceReport {
  generated_at: string;
  overall_compliance_percent: number;
  by_severity: Record<string, SLASevStats>;
  overdue_by_owner: { owner: string; overdue: number; total: number }[];
}

export interface RiskBreakdownRow {
  group: string;
  total: number;
  severity_counts: Record<string, number>;
  risk_level_counts: Record<string, number>;
}

export interface NotificationRule {
  id: string;
  name: string;
  trigger_event: string;
  min_severity: string;
  min_risk_level: string;
  channel_type: string;
  channel_config: Record<string, string>;
  host_filter: string;
  enabled: boolean;
  last_triggered: string | null;
  created_at: string;
  updated_at: string;
}

export interface NotificationLogEntry {
  id: string;
  rule_id: string;
  rule_name: string;
  trigger_event: string;
  channel_type: string;
  status: string;
  error_message: string;
  created_at: string;
}

export const api = {
  login: (username: string, password: string) => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (apiKey) headers['X-API-Key'] = apiKey;
    return fetch(API_BASE + '/auth/login', {
      method: 'POST',
      headers,
      body: JSON.stringify({ username, password }),
    }).then(async (res) => {
      if (!res.ok) throw await responseError(res);
      return res.json() as Promise<{ token: string; user: { id: string; username: string; role: string }; expires: string }>;
    });
  },
  logout: () => {
    const headers = apiHeaders();
    return fetch(API_BASE + '/auth/logout', { method: 'POST', headers }).then(async (res) => {
      if (!res.ok && res.status !== 401) throw await responseError(res);
      return res.json() as Promise<{ status: string }>;
    }).finally(() => {
      clearSession();
    });
  },
  authMe: () => request<{ user: { id: string; username: string; role: string } }>('/auth/me'),
  changePassword: (currentPassword: string, newPassword: string) =>
    requestJSON<{ status: string }>('/auth/change-password', { current_password: currentPassword, new_password: newPassword }),
  hosts: (params?: { agent_status?: string; inventory_status?: string; agent_version_state?: string }) => request<Host[]>('/hosts', params),
  host: (id: string) => request<Host>(`/hosts/${id}`),
  deleteHost: (id: string) =>
    requestEmpty<{ status: string }>(`/hosts/${id}`, 'DELETE'),
  updateHostMetadata: (id: string, body: { owner?: string; team?: string; environment?: string; criticality?: string; tags?: string }) =>
    requestJSON<Host>(`/hosts/${id}/metadata`, body),
  resetHostAgentToken: (id: string) =>
    requestEmpty<{ status: string }>(`/hosts/${id}/agent-token/reset`, 'POST'),
  hostPackages: (id: string, limit: number, offset: number) =>
    request<{ items: Pkg[]; total: number }>(`/hosts/${id}/packages`, { limit: String(limit), offset: String(offset) }),
  hostUsers: (id: string, limit: number, offset: number) =>
    request<{ items: UserAccount[]; total: number }>(`/hosts/${id}/users`, { limit: String(limit), offset: String(offset) }),
  hostProcesses: (id: string, limit: number, offset: number) =>
    request<{ items: ProcessSnapshot[]; total: number }>(`/hosts/${id}/processes`, { limit: String(limit), offset: String(offset) }),
  hostPorts: (id: string, limit: number, offset: number) =>
    request<{ items: PortInfo[]; total: number }>(`/hosts/${id}/ports`, { limit: String(limit), offset: String(offset) }),
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
  cveDbSearch: (params: { q?: string; reference_key?: string; severity?: string; source?: string; min_cvss?: string; min_epss?: string; min_epss_percentile?: string; matchable?: string; include_priority_sources?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: CveDbEntry[]; total: number }>('/cve-db/search', params),
  cveDbReferenceGroup: (params: { key: string; limit?: string }) =>
    request<CveReferenceGroupSummary>('/cve-db/reference-group', params),
  cveDbAffectedPackages: (id: string, params?: { limit?: string; offset?: string }) =>
    request<{ items: CveAffectedPackage[]; total: number; limit?: number; offset?: number }>(`/cve-db/${id}/affected-packages`, params),
  cveDbSources: () => request<{ sources: string[] }>('/cve-db/sources'),
  cveDbStats: requestCveDbStats,
  packages: (params: { host_id?: string; container?: string; pkg_type?: string; source?: string; q?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
    request<{ items: Pkg[]; total: number }>('/packages', params),
  containers: (params: { host_id?: string; runtime?: string; state?: string; image?: string; q?: string; include_labels?: string; sort_by?: string; sort_order?: string; limit?: string; offset?: string }) =>
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
  installerStatus: () => request<InstallerStatus>('/admin/installer/status'),
  securityDbStatus: () => request<SecurityDbOperationalStatus>('/admin/security-db/status'),
  agentFleetStatus: () => request<AgentFleetStatus>('/admin/agent-fleet/status'),
  deleteScan: (id: string, force = false) => request<{status: string}>(`/scans/${id}`, force ? { force: 'true' } : undefined, 'DELETE'),
  auditLogs: (params: { actor_type?: string; actor_id?: string; action?: string; resource_type?: string; resource_id?: string; status?: string; created_from?: string; created_to?: string; limit?: string; offset?: string }) =>
    request<{ items: AuditLog[]; total: number }>('/admin/audit-logs', params),
  rbacSubjects: () => request<{ items: AccessSubject[] }>('/admin/rbac/subjects'),
  rbacStatus: () => request<AccessControlStatus>('/admin/rbac/status'),
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
    return uploadForm<{
      status: string;
      imported: number;
      trivy_db_loaded: boolean;
      security_db_revision?: string;
      bundle_created_at?: string;
      bundle_source_count?: number;
      bundle_cve_records?: number;
      bundle_trivy_db_included?: boolean;
    }>('/admin/security-db/import', form);
  },
  rematchCVEs: (body?: { sources?: string[]; min_source_matchable_percent?: number; candidate_limit?: number }) =>
    requestJSON<{matched: number; new_vulns: number; skipped: number; scanned_candidates?: number; candidate_limit: number; limited: boolean; eligible_sources?: number; excluded_sources?: number; source_policy?: Record<string, { eligible?: boolean; reason?: string }>; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/rematch', body || {}),
  rebuildCveAffectedIndex: () =>
    request<{status: string; indexed?: number; duration_ms?: number; index?: CveDbStatsResponse['affected_package_index']; affected_index_rebuild?: HealthStatus['cve_affected_index_rebuild']; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/affected-index/rebuild', { async: 'true' }, 'POST'),
  rebuildCveReferenceIndex: () =>
    request<{status: string; indexed?: number; duration_ms?: number; reference_index_rebuild?: HealthStatus['cve_reference_index_rebuild']; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/reference-index/rebuild', { async: 'true' }, 'POST'),
  recalcCveCVSS: () =>
    request<{status: string; updated: number; security_db_revision?: string; security_db_revision_error?: string}>('/admin/cve-db/recalc-cvss', undefined, 'POST'),
  pruneRetention: (body: { dry_run: boolean; scan_days?: number; request_days?: number; audit_days?: number }) =>
    requestJSON<RetentionPruneResult>('/admin/retention/prune', body),

  // Phase 3: Fleet Management
  schedules: () => request<{ items: ScheduledScan[] }>('/admin/schedules'),
  createSchedule: (body: { name: string; cron_expr: string; scan_type?: string; host_filter?: string; packages_only?: boolean; enabled?: boolean }) =>
    requestJSON<ScheduledScan>('/admin/schedules', body),
  schedule: (id: string) => request<ScheduledScan>(`/admin/schedules/${id}`),
  updateSchedule: (id: string, body: { name?: string; cron_expr?: string; scan_type?: string; host_filter?: string; packages_only?: boolean; enabled?: boolean }) =>
    requestJSON<ScheduledScan>(`/admin/schedules/${id}`, body),
  deleteSchedule: (id: string) => requestEmpty<{ status: string }>(`/admin/schedules/${id}`, 'DELETE'),

  assetGroups: () => request<{ items: AssetGroup[] }>('/asset-groups'),
  createAssetGroup: (body: { name: string; description?: string; rule_type?: string; rule_expr?: string }) =>
    requestJSON<AssetGroup>('/asset-groups', body),
  assetGroup: (id: string) => request<AssetGroupDetail>(`/asset-groups/${id}`),
  deleteAssetGroup: (id: string) => requestEmpty<{ status: string }>(`/asset-groups/${id}`, 'DELETE'),
  addHostToAssetGroup: (id: string, hostId: string) =>
    requestJSON<{ status: string }>(`/asset-groups/${id}/hosts`, { host_id: hostId }),
  removeHostFromAssetGroup: (id: string, hostId: string) =>
    requestEmpty<{ status: string }>(`/asset-groups/${id}/hosts/${hostId}`, 'DELETE'),
  triggerAssetGroupScan: (id: string) =>
    requestJSON<{ status: string; scan_request_id: string }>(`/asset-groups/${id}/scan`, {}),

  // Phase 4: Intelligence & Reports
  vulnTrends: (params?: { host_id?: string; days?: string }) =>
    request<{ items: VulnTrendRow[] }>('/vuln-trends', params),
  vulnTrendSummary: (params?: { host_id?: string; days?: string }) =>
    request<VulnTrendSummary>('/vuln-trends/summary', params),
  topRiskHosts: (params?: { limit?: string }) =>
    request<{ items: AtRiskHost[] }>('/intelligence/top-risk', params),
  recommendations: () => request<{ items: Recommendation[] }>('/intelligence/recommendations'),
  vulnPosture: (params?: { days?: string }) =>
    request<PostureComparison>('/intelligence/posture', params),

  executiveSummary: () => request<ExecutiveSummary>('/reports/executive-summary'),
  riskBreakdown: (params?: { group_by?: string }) =>
    request<{ group_by: string; items: RiskBreakdownRow[] }>('/reports/risk-breakdown', params),
  slaCompliance: () => request<SLAComplianceReport>('/reports/sla-compliance'),
  exportReport: (params?: { format?: string; type?: string }) =>
    download('/reports/export', `bongsu-report.${params?.format === 'csv' ? 'csv' : 'json'}`, params),

  notificationRules: () => request<{ items: NotificationRule[] }>('/admin/notification-rules'),
  createNotificationRule: (body: { name: string; trigger_event: string; min_severity?: string; min_risk_level?: string; channel_type?: string; channel_config?: Record<string, string>; host_filter?: string; enabled?: boolean }) =>
    requestJSON<NotificationRule>('/admin/notification-rules', body),
  notificationRule: (id: string) => request<NotificationRule>(`/admin/notification-rules/${id}`),
  updateNotificationRule: (id: string, body: Partial<NotificationRule>) =>
    requestJSON<NotificationRule>(`/admin/notification-rules/${id}`, body),
  deleteNotificationRule: (id: string) => requestEmpty<{ status: string }>(`/admin/notification-rules/${id}`, 'DELETE'),
  testNotificationRule: (id: string) =>
    requestJSON<{ status: string; message: string }>(`/admin/notification-rules/${id}/test`, {}),
  notificationLog: (params?: { rule_id?: string; limit?: string; offset?: string }) =>
    request<{ items: NotificationLogEntry[]; total: number }>('/admin/notification-log', params),
};
