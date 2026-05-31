package models

import (
	"encoding/json"
	"time"
)

type Host struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	IPAddress    string    `json:"ip_address"`
	OSName       string    `json:"os_name"`
	OSVersion    string    `json:"os_version"`
	Kernel       string    `json:"kernel"`
	Arch         string    `json:"arch"`
	CPUModel     string    `json:"cpu_model"`
	CPUCores     int       `json:"cpu_cores"`
	MemoryMB     int64     `json:"memory_mb"`
	AgentVersion string    `json:"agent_version"`
	Owner        string    `json:"owner,omitempty"`
	Team         string    `json:"team,omitempty"`
	Environment  string    `json:"environment,omitempty"`
	Criticality  string    `json:"criticality,omitempty"`
	Tags         string    `json:"tags,omitempty"`
	LastSeen     time.Time `json:"last_seen"`
	AgentStatus  string    `json:"agent_status,omitempty"`
	LastSeenAgeS int64     `json:"last_seen_age_seconds,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

type Scan struct {
	ID              string     `json:"id"`
	HostID          string     `json:"host_id"`
	ScanType        string     `json:"scan_type"` // "daily", "manual"
	Status          string     `json:"status"`    // "running", "completed", "degraded", "failed"
	PackageCount    int        `json:"package_count,omitempty"`
	VulnCount       int        `json:"vulnerability_count,omitempty"`
	ContainerCount  int        `json:"container_count,omitempty"`
	PackagesAdded   int        `json:"packages_added,omitempty"`
	PackagesRemoved int        `json:"packages_removed,omitempty"`
	PackagesChanged int        `json:"packages_changed,omitempty"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type ScanRequest struct {
	ID                 string     `json:"id"`
	HostID             string     `json:"host_id,omitempty"`
	RequestedBy        string     `json:"requested_by,omitempty"`
	ScanType           string     `json:"scan_type"`
	PackagesOnly       bool       `json:"packages_only"`
	Reason             string     `json:"reason,omitempty"`
	SecurityDBRevision string     `json:"security_db_revision,omitempty"`
	Status             string     `json:"status"`
	ErrorMessage       string     `json:"error_message,omitempty"`
	ClaimedByHostID    string     `json:"claimed_by_host_id,omitempty"`
	ClaimedAt          *time.Time `json:"claimed_at,omitempty"`
	RequestAgeS        int64      `json:"request_age_seconds,omitempty"`
	ClaimAgeS          int64      `json:"claim_age_seconds,omitempty"`
	RequestStale       bool       `json:"request_stale,omitempty"`
	ClaimStale         bool       `json:"claim_stale,omitempty"`
	CompletedAt        *time.Time `json:"completed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
}

type AuditLog struct {
	ID           string          `json:"id"`
	ActorType    string          `json:"actor_type"`
	ActorID      string          `json:"actor_id"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Status       string          `json:"status"`
	IPAddress    string          `json:"ip_address"`
	UserAgent    string          `json:"user_agent"`
	Metadata     json.RawMessage `json:"metadata"`
	CreatedAt    time.Time       `json:"created_at"`
}

type AccessSubject struct {
	ID          string    `json:"id"`
	SubjectType string    `json:"subject_type"`
	ExternalID  string    `json:"external_id"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type AccessPolicy struct {
	ID                string    `json:"id"`
	SubjectID         string    `json:"subject_id"`
	SubjectType       string    `json:"subject_type"`
	SubjectExternalID string    `json:"subject_external_id"`
	ResourceType      string    `json:"resource_type"`
	ResourceID        string    `json:"resource_id"`
	Permission        string    `json:"permission"`
	CreatedAt         time.Time `json:"created_at"`
}

type Package struct {
	ID          string    `json:"id"`
	ScanID      string    `json:"scan_id"`
	HostID      string    `json:"host_id"`
	AssetType   string    `json:"asset_type"`
	AssetID     string    `json:"asset_id,omitempty"`
	Source      string    `json:"source"`
	Container   string    `json:"container,omitempty"`
	ContainerID string    `json:"container_id,omitempty"`
	ImageName   string    `json:"image_name,omitempty"`
	ImageID     string    `json:"image_id,omitempty"`
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Arch        string    `json:"arch,omitempty"`
	PkgType     string    `json:"pkg_type"`
	Ecosystem   string    `json:"ecosystem,omitempty"`
	PURL        string    `json:"purl,omitempty"`
	SrcName     string    `json:"src_name,omitempty"`
	FilePath    string    `json:"file_path,omitempty"`
	LayerID     string    `json:"layer_id,omitempty"`
	Target      string    `json:"target,omitempty"`
	MaxCVSS     float64   `json:"max_cvss"`
	VulnCount   int       `json:"vuln_count"`
	CreatedAt   time.Time `json:"created_at"`
}

type Vulnerability struct {
	ID              string     `json:"id"`
	PackageID       string     `json:"package_id"`
	ScanID          string     `json:"scan_id"`
	HostID          string     `json:"host_id"`
	VulnerabilityID string     `json:"vulnerability_id"`
	Severity        string     `json:"severity"`
	Title           string     `json:"title,omitempty"`
	Description     string     `json:"description,omitempty"`
	PkgName         string     `json:"pkg_name"`
	PkgType         string     `json:"pkg_type,omitempty"`
	Ecosystem       string     `json:"ecosystem,omitempty"`
	PkgPath         string     `json:"pkg_path,omitempty"`
	InstalledVer    string     `json:"installed_version"`
	FixedVersion    string     `json:"fixed_version,omitempty"`
	CVSSScore       float64    `json:"cvss_score,omitempty"`
	CVSSVector      string     `json:"cvss_vector,omitempty"`
	PrimaryURL      string     `json:"primary_url,omitempty"`
	Container       string     `json:"container,omitempty"`
	LayerID         string     `json:"layer_id,omitempty"`
	FindingSource   string     `json:"finding_source,omitempty"`
	HostOwner       string     `json:"host_owner,omitempty"`
	HostTeam        string     `json:"host_team,omitempty"`
	HostEnvironment string     `json:"host_environment,omitempty"`
	HostCriticality string     `json:"host_criticality,omitempty"`
	TriageStatus    string     `json:"triage_status"`
	TriageReason    string     `json:"triage_reason,omitempty"`
	TriageComment   string     `json:"triage_comment,omitempty"`
	TriageExpiresAt *time.Time `json:"triage_expires_at,omitempty"`
	TriageUpdatedBy string     `json:"triage_updated_by,omitempty"`
	TriageUpdatedAt *time.Time `json:"triage_updated_at,omitempty"`
	SLADays         int        `json:"sla_days,omitempty"`
	DueAt           *time.Time `json:"due_at,omitempty"`
	Overdue         bool       `json:"overdue"`
	CreatedAt       time.Time  `json:"created_at"`
}

type VulnerabilityTriage struct {
	ID              string     `json:"id"`
	VulnerabilityID string     `json:"vulnerability_id"`
	HostID          string     `json:"host_id,omitempty"`
	PkgName         string     `json:"pkg_name,omitempty"`
	Status          string     `json:"status"`
	Reason          string     `json:"reason,omitempty"`
	Comment         string     `json:"comment,omitempty"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	UpdatedBy       string     `json:"updated_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type UserAccount struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	HostID   string `json:"host_id"`
	Username string `json:"username"`
	UID      int    `json:"uid"`
	GID      int    `json:"gid"`
	HomeDir  string `json:"home_dir"`
	Shell    string `json:"shell"`
}

type ProcessSnapshot struct {
	ID       string  `json:"id"`
	ScanID   string  `json:"scan_id"`
	HostID   string  `json:"host_id"`
	PID      int     `json:"pid"`
	Name     string  `json:"name"`
	Cmdline  string  `json:"cmdline"`
	User     string  `json:"user"`
	CPUUsage float64 `json:"cpu_usage"`
	MemUsage float64 `json:"mem_usage"`
}

type PortInfo struct {
	ID       string `json:"id"`
	ScanID   string `json:"scan_id"`
	HostID   string `json:"host_id"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Address  string `json:"address"`
	PID      int    `json:"pid"`
}

type ContainerAsset struct {
	ID          string     `json:"id"`
	ScanID      string     `json:"scan_id"`
	HostID      string     `json:"host_id"`
	Runtime     string     `json:"runtime"`
	ContainerID string     `json:"container_id"`
	Name        string     `json:"name"`
	ImageName   string     `json:"image_name"`
	ImageID     string     `json:"image_id"`
	ImageDigest string     `json:"image_digest,omitempty"`
	State       string     `json:"state"`
	Labels      string     `json:"labels,omitempty"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type ScanReport struct {
	Host       Host              `json:"host"`
	ScanType   string            `json:"scan_type"`
	ScanID     string            `json:"scan_id"`
	Errors     []string          `json:"errors,omitempty"`
	Containers []ContainerAsset  `json:"containers"`
	Packages   []Package         `json:"packages"`
	Vulns      []Vulnerability   `json:"vulnerabilities"`
	Users      []UserAccount     `json:"users"`
	Processes  []ProcessSnapshot `json:"processes"`
	Ports      []PortInfo        `json:"ports"`
	Timestamp  time.Time         `json:"timestamp"`
}

type CveEntry struct {
	ID               string     `json:"id"`
	VulnerabilityID  string     `json:"vulnerability_id"`
	Source           string     `json:"source"`
	Category         string     `json:"category,omitempty"`
	Ecosystem        string     `json:"ecosystem,omitempty"`
	Severity         string     `json:"severity"`
	CVSSScore        float64    `json:"cvss_score"`
	CVSSVector       string     `json:"cvss_vector"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	PublishedDate    *time.Time `json:"published_date,omitempty"`
	ModifiedDate     *time.Time `json:"modified_date,omitempty"`
	AffectedProducts string     `json:"affected_products"`
	References       string     `json:"references"`
	RawData          string     `json:"raw_data"`
	UpdatedAt        time.Time  `json:"updated_at"`
}
