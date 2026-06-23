package db

import "testing"

func TestComputeFindingKey(t *testing.T) {
	base := FindingIdentity{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "", VulnerabilityID: "CVE-2024-1234"}

	t.Run("known vector matches the SQL backfill recipe", func(t *testing.T) {
		// Locked against PostgreSQL pgcrypto digest() (migration 065). If this
		// changes, the Go ingest and the SQL backfill have diverged.
		const want = "7bd889a4a62e40e94b0d5ec8631fcba90cca8c8a2f4c93ff3de25cb86a84180b"
		if got := ComputeFindingKey(base); got != want {
			t.Fatalf("finding key drifted from the SQL recipe:\n got  %s\n want %s", got, want)
		}
	})

	t.Run("host_id and pkg_name are case/space-insensitive", func(t *testing.T) {
		noisy := FindingIdentity{HostID: " host-1 ", PkgName: " openssl ", PkgPath: "", VulnerabilityID: "CVE-2024-1234"}
		if ComputeFindingKey(noisy) != ComputeFindingKey(base) {
			t.Fatal("normalization must make host/pkg case+whitespace irrelevant")
		}
	})

	t.Run("installed_version is NOT part of identity (survives upgrades)", func(t *testing.T) {
		// FindingIdentity has no version field by construction; assert that the
		// same identity yields one key regardless of any version a caller tracks
		// separately — a package upgrade is a state change, not a new finding.
		again := FindingIdentity{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "", VulnerabilityID: "CVE-2024-1234"}
		if ComputeFindingKey(again) != ComputeFindingKey(base) {
			t.Fatal("identity must be version-independent")
		}
	})

	t.Run("empty path and host-level sentinel are stable", func(t *testing.T) {
		// "" and whitespace both normalize to the __HOST__ sentinel, so a package
		// whose path arrives empty in one scan keeps its key.
		ws := FindingIdentity{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "   ", VulnerabilityID: "CVE-2024-1234"}
		if ComputeFindingKey(ws) != ComputeFindingKey(base) {
			t.Fatal("blank path must normalize to the host-level sentinel")
		}
	})

	t.Run("distinct path, pkg, host, or CVE produce distinct keys", func(t *testing.T) {
		variants := []FindingIdentity{
			{HostID: "Host-2", PkgName: "OpenSSL", PkgPath: "", VulnerabilityID: "CVE-2024-1234"},
			{HostID: "Host-1", PkgName: "libcurl", PkgPath: "", VulnerabilityID: "CVE-2024-1234"},
			{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "/app", VulnerabilityID: "CVE-2024-1234"},
			{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "", VulnerabilityID: "CVE-2024-9999"},
		}
		baseKey := ComputeFindingKey(base)
		seen := map[string]bool{baseKey: true}
		for _, v := range variants {
			k := ComputeFindingKey(v)
			if seen[k] {
				t.Fatalf("identity collision: %+v hashed to an already-seen key", v)
			}
			seen[k] = true
		}
	})

	t.Run("CVE id case is preserved (advisory IDs compared verbatim)", func(t *testing.T) {
		lower := FindingIdentity{HostID: "Host-1", PkgName: "OpenSSL", PkgPath: "", VulnerabilityID: "cve-2024-1234"}
		if ComputeFindingKey(lower) == ComputeFindingKey(base) {
			t.Fatal("vulnerability_id case must be significant")
		}
	})
}
