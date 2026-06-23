package db

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// findingKeySep is the field separator used when hashing a finding's identity.
// It is a control byte (US, 0x1f) that cannot appear in any of the normalized
// identity fields, so the concatenation is unambiguous. The SQL backfill in
// migration 065 MUST use the identical recipe (E'\x1f' separator, same per-field
// normalization) or Go-computed and DB-backfilled keys would diverge.
const findingKeySep = "\x1f"

// FindingIdentity is the stable, scan-independent identity of a vulnerability
// finding: a given CVE affecting a given package at a given path on a given host.
// installed_version is deliberately NOT part of the identity — a version bump is
// a state change on the same finding (so triage survives upgrades), not a new
// finding. scan_id / package_id are likewise excluded (they are per-scan).
type FindingIdentity struct {
	HostID          string
	PkgName         string
	PkgPath         string
	VulnerabilityID string
}

// normalizeFindingPkgPath maps an empty container/layer path to a sentinel so a
// host-level package (no path) is distinct from, and stable against, a path that
// merely arrives empty in one scan.
func normalizeFindingPkgPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "__HOST__"
	}
	return p
}

// ComputeFindingKey returns the stable SHA-256 fingerprint (hex) for a finding.
// Recipe (must match migration 065's SQL backfill exactly):
//
//	sha256( lower(trim(host_id)) ⋮ lower(trim(pkg_name)) ⋮
//	        normalize(pkg_path)  ⋮ trim(vulnerability_id) )
//
// host_id and pkg_name are lowercased; pkg_path is case-preserving (paths are
// case-sensitive); vulnerability_id is case-preserving (CVE/advisory IDs are
// conventionally upper but compared verbatim) and only trimmed.
func ComputeFindingKey(id FindingIdentity) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(id.HostID)),
		strings.ToLower(strings.TrimSpace(id.PkgName)),
		normalizeFindingPkgPath(id.PkgPath),
		strings.TrimSpace(id.VulnerabilityID),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, findingKeySep)))
	return hex.EncodeToString(sum[:])
}
