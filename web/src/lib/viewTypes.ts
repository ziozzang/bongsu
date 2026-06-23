// Cross-view filter types, shared between the App shell (which holds the active
// filter state and threads it as a view prop) and the views that render them.
export type ScanRequestFilters = { status?: string; scan_type?: string; security_db_revision?: string; stale?: string };
export type VulnerabilityFilters = { overdueOnly?: boolean; exploitedOnly?: boolean; riskLevel?: string; triageStatus?: string; owner?: string; team?: string; environment?: string; criticality?: string };
export type HostFilters = { agent_status?: string; inventory_status?: string; agent_version_state?: string };
