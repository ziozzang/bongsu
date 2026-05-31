package db

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func TestClassifySecuritySource(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		affected string
		category string
		eco      string
	}{
		{"osv pypi", "osv", `[{"name":"django","ecosystem":"PyPI"}]`, "code-library", "PyPI"},
		{"osv debian", "osv", `[{"name":"openssl","ecosystem":"Debian"}]`, "os-package", "Debian"},
		{"nvd fallback", "nvd", `[]`, "general-cve", ""},
		{"custom fallback", "internal", ``, "custom", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			category, eco := ClassifySecuritySource(tt.source, tt.affected)
			if category != tt.category || eco != tt.eco {
				t.Fatalf("got (%q, %q), want (%q, %q)", category, eco, tt.category, tt.eco)
			}
		})
	}
}

func TestCompatibleSecurityCandidateSeparatesEcosystems(t *testing.T) {
	affected := `[
		{"name":"foo","ecosystem":"PyPI","fixed":["1.2.3"]},
		{"name":"foo","ecosystem":"npm","fixed":["4.5.6"]},
		{"name":"foo","ecosystem":"Debian","fixed":["1.0-2"]}
	]`

	got, ok := compatibleSecurityCandidate("foo", "npm", "npm", "4.5.5", "code-library", "", affected)
	if !ok {
		t.Fatal("npm candidate should match")
	}
	if got.Fixed[0] != "4.5.6" {
		t.Fatalf("fixed = %q, want npm fixed version", got.Fixed[0])
	}

	got, ok = compatibleSecurityCandidate("foo", "python-pkg", "PyPI", "1.2.2", "code-library", "", affected)
	if !ok {
		t.Fatal("PyPI candidate should match")
	}
	if got.Fixed[0] != "1.2.3" {
		t.Fatalf("fixed = %q, want PyPI fixed version", got.Fixed[0])
	}

	got, ok = compatibleSecurityCandidate("foo", "debian", "Debian", "1.0-1", "os-package", "", affected)
	if !ok {
		t.Fatal("Debian candidate should match")
	}
	if got.Fixed[0] != "1.0-2" {
		t.Fatalf("fixed = %q, want Debian fixed version", got.Fixed[0])
	}
}

func TestCompatibleSecurityCandidateMatchesUbuntuAsUbuntu(t *testing.T) {
	affected := `[{"name":"openssl","ecosystem":"Ubuntu","fixed":["3.0.13-0ubuntu3.6"]}]`
	if _, ok := compatibleSecurityCandidate("openssl", "ubuntu", "Ubuntu", "3.0.13-0ubuntu3.5", "os-package", "Ubuntu", affected); !ok {
		t.Fatal("Ubuntu package should match Ubuntu advisory")
	}
	if _, ok := compatibleSecurityCandidate("openssl", "ubuntu", "Debian", "3.0.13-0ubuntu3.5", "os-package", "Ubuntu", affected); ok {
		t.Fatal("Ubuntu advisory must not match package recorded as Debian")
	}
}

func TestCompatibleSecurityCandidateRejectsWeakOrWrongCandidates(t *testing.T) {
	noFixed := `[{"name":"foo","ecosystem":"npm"}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "4.5.5", "code-library", "", noFixed); ok {
		t.Fatal("candidate without fixed version should not match")
	}

	wrongEco := `[{"name":"foo","ecosystem":"PyPI","fixed":["1.2.3"]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "4.5.5", "code-library", "", wrongEco); ok {
		t.Fatal("PyPI advisory should not match npm package with same name")
	}

	ambiguous := `[{"name":"foo","fixed":["1.2.3"]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "4.5.5", "general-cve", "", ambiguous); ok {
		t.Fatal("candidate without ecosystem should not match")
	}
}

func TestCompatibleSecurityCandidateChecksAffectedRanges(t *testing.T) {
	affected := `[{"name":"foo","ecosystem":"npm","fixed":["2.0.0"],"ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "code-library", "", affected); !ok {
		t.Fatal("installed version inside affected range should match")
	}
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "2.0.0", "code-library", "", affected); ok {
		t.Fatal("fixed installed version should not match")
	}
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "0.9.9", "code-library", "", affected); ok {
		t.Fatal("version before introduced should not match")
	}
}

func TestCompatibleSecurityCandidateUsesRangeFixedVersion(t *testing.T) {
	affected := `[{"name":"foo","ecosystem":"npm","ranges":[{"type":"SEMVER","events":[{"introduced":"1.0.0"},{"fixed":"2.0.0"}]}]}]`
	got, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.5.0", "code-library", "", affected)
	if !ok {
		t.Fatal("range-only fixed event should be matchable")
	}
	fixed := fixedVersions(got)
	if len(fixed) != 1 || fixed[0] != "2.0.0" {
		t.Fatalf("fixed versions = %#v, want 2.0.0", fixed)
	}
}

func TestVersionInRangeHandlesMultipleIntervals(t *testing.T) {
	events := []affectedRangeEvent{
		{Introduced: "0"},
		{Fixed: "1.0.0"},
		{Introduced: "2.0.0"},
		{Fixed: "3.0.0"},
	}
	tests := []struct {
		version string
		want    bool
	}{
		{"0.5.0", true},
		{"1.5.0", false},
		{"2.5.0", true},
		{"3.0.0", false},
	}
	for _, tt := range tests {
		if got := versionInRange(tt.version, events); got != tt.want {
			t.Fatalf("versionInRange(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestCompareVersionsTreatsPrereleaseBelowRelease(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"1.0.0-alpha.1", "1.0.0", -1},
		{"1.0.0-alpha.1", "1.0.0-beta.1", -1},
		{"1.0.0-beta.2", "1.0.0-beta.1", 1},
		{"2.0.0-rc.1", "2.0.0", -1},
		{"2.0.0~rc1", "2.0.0", -1},
		{"2.0.0~beta1", "2.0.0~rc1", -1},
		{"1.0.0", "1.0.0-beta.1", 1},
		{"1.0.0", "1.0.0", 0},
	}
	for _, tt := range tests {
		got, ok := compareVersions(tt.a, tt.b)
		if !ok {
			t.Fatalf("compareVersions(%q, %q) not comparable", tt.a, tt.b)
		}
		if got != tt.want {
			t.Fatalf("compareVersions(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}

	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.0.0-rc.1", "code-library", "", `[{"name":"foo","ecosystem":"npm","fixed":["1.0.0"]}]`); !ok {
		t.Fatal("pre-release installed version should remain affected until the final fixed release")
	}
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.0.0", "code-library", "", `[{"name":"foo","ecosystem":"npm","fixed":["1.0.0"]}]`); ok {
		t.Fatal("final fixed release should not remain affected")
	}
	if _, ok := compatibleSecurityCandidate("openssl", "ubuntu", "Ubuntu", "3.0.13-0ubuntu3.6~rc1", "os-package", "Ubuntu", `[{"name":"openssl","ecosystem":"Ubuntu","fixed":["3.0.13-0ubuntu3.6"]}]`); !ok {
		t.Fatal("distribution pre-release build should remain affected until the final fixed package")
	}
}

func TestCalcCvssScoreVersions(t *testing.T) {
	tests := []struct {
		name   string
		vector string
		want   float64
	}{
		{"v2", "AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5},
		{"v31", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := calcCvssScore(tt.vector)
			if got != tt.want {
				t.Fatalf("score = %.1f, want %.1f", got, tt.want)
			}
		})
	}
}

func TestApplyVulnerabilitySLA(t *testing.T) {
	v := models.Vulnerability{
		Severity:     "HIGH",
		TriageStatus: "open",
		CreatedAt:    time.Now().Add(-31 * 24 * time.Hour),
	}
	ApplyVulnerabilitySLA(&v)
	if v.SLADays != 30 {
		t.Fatalf("sla days = %d", v.SLADays)
	}
	if v.DueAt == nil {
		t.Fatal("due_at should be set")
	}
	if !v.Overdue {
		t.Fatal("high finding older than SLA should be overdue")
	}

	v.TriageStatus = "accepted_risk"
	ApplyVulnerabilitySLA(&v)
	if v.Overdue {
		t.Fatal("accepted risk should not be overdue")
	}
}

func TestContainerSortExprAllowlist(t *testing.T) {
	if got := containerSortExpr("image_name", true); got != "c.image_name DESC NULLS LAST" {
		t.Fatalf("sort expr = %q", got)
	}
	if got := containerSortExpr("c.name; DROP TABLE container_assets", false); got != "c.created_at ASC NULLS LAST" {
		t.Fatalf("unsafe sort expr should fall back, got %q", got)
	}
}

func TestAppendUnique(t *testing.T) {
	items := []string{"host-1"}
	items = appendUnique(items, "host-1")
	items = appendUnique(items, "host-2")
	items = appendUnique(items, "")
	if len(items) != 2 || items[0] != "host-1" || items[1] != "host-2" {
		t.Fatalf("appendUnique produced %#v", items)
	}
}

func TestVulnSummaryGroupExprAllowlist(t *testing.T) {
	if got := vulnSummaryGroupExpr("team"); got != "COALESCE(NULLIF(h.team, ''), '(unassigned)')" {
		t.Fatalf("team group expr = %q", got)
	}
	if got := vulnSummaryGroupExpr("owner; DROP TABLE hosts"); got != "COALESCE(NULLIF(h.owner, ''), '(unassigned)')" {
		t.Fatalf("unsafe group expr should fall back to owner, got %q", got)
	}
}

func TestParseAssetGroupRef(t *testing.T) {
	tests := []struct {
		ref       string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{"team:platform", "team", "platform", true},
		{"environment=prod", "environment", "prod", true},
		{"tag:service=api", "tag", "service=api", true},
		{"missing-separator", "", "", false},
		{"owner:", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			key, value, ok := parseAssetGroupRef(tt.ref)
			if key != tt.wantKey || value != tt.wantValue || ok != tt.wantOK {
				t.Fatalf("got (%q, %q, %v), want (%q, %q, %v)", key, value, ok, tt.wantKey, tt.wantValue, tt.wantOK)
			}
		})
	}
}

func TestPackageIdentitySQLExcludesVersion(t *testing.T) {
	got := packageIdentitySQL("current", "previous")
	if !strings.Contains(got, "current.name") || !strings.Contains(got, "previous.name") {
		t.Fatalf("identity SQL missing package name: %s", got)
	}
	if strings.Contains(got, ".version") {
		t.Fatalf("identity SQL must exclude version so upgrades become changes: %s", got)
	}
}

func TestQueueSecurityDBRescanInsertSQLUsesAtomicDedupe(t *testing.T) {
	got := queueSecurityDBRescanInsertSQL()
	for _, want := range []string{
		"ON CONFLICT (host_id)",
		"host_id <> ''",
		"scan_type='security-db-update'",
		"status IN ('pending','claimed')",
		"DO NOTHING",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rescan insert SQL missing %q: %s", want, got)
		}
	}
}

func TestLatestScansIncludesDegradedInventory(t *testing.T) {
	if !strings.Contains(latestScansSub, "status IN ('completed','degraded')") {
		t.Fatalf("latest scans must include degraded scans: %s", latestScansSub)
	}
}

func TestDeleteScanProtectsLatestInventory(t *testing.T) {
	got := deleteScanLatestInventorySQL()
	for _, want := range []string{
		"JOIN " + latestScansSub,
		"s.id = $1",
		"s.status IN ('completed','degraded')",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("delete latest inventory guard missing %q: %s", want, got)
		}
	}
}

func TestDeleteScanErrorsAreDistinct(t *testing.T) {
	if ErrLatestInventoryScan == ErrScanNotFound {
		t.Fatal("delete scan guard and not-found errors must be distinct")
	}
}

func TestScanRequestErrorsAreDistinct(t *testing.T) {
	if ErrInvalidScanRequestStatus == ErrScanRequestNotFound || ErrInvalidScanRequestStatus == ErrScanRequestNotActive || ErrScanRequestNotFound == ErrScanRequestNotActive {
		t.Fatal("scan request completion errors must be distinct")
	}
}

func TestUpsertCveEntriesFailsWholeBatchOnAnyInsertError(t *testing.T) {
	fn := "UpsertCveEntriesTx"
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) "+fn)
	if start < 0 {
		t.Fatalf("%s not found", fn)
	}
	next := strings.Index(body[start+1:], "\nfunc ")
	if next < 0 {
		t.Fatalf("%s body end not found", fn)
	}
	body = body[start : start+1+next]
	if !strings.Contains(body, "if firstErr != nil") || strings.Contains(body, "if count == 0 && firstErr != nil") {
		t.Fatalf("%s must reject the whole batch after any row insert error: %s", fn, body)
	}
}

func TestPackagedInstallScriptHardensAgentCredentialFile(t *testing.T) {
	out, err := os.ReadFile("../../../scripts/install-agent.sh")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"umask 077",
		`chmod 600 "$WORK_DIR/config.yaml"`,
		"UMask=0077",
		"ProtectSystem=strict",
		"ReadWritePaths=$WORK_DIR",
		"PrivateTmp=true",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("install-agent.sh hardening missing %q", want)
		}
	}
}

func TestRetentionPruneDoesNotDeleteRunningScans(t *testing.T) {
	got := pruneOldScansCTE()
	if !strings.Contains(got, "status IN ('completed','degraded','failed')") {
		t.Fatalf("retention prune must only target terminal scans: %s", got)
	}
	if strings.Contains(got, "'running'") {
		t.Fatalf("retention prune must not target running scans: %s", got)
	}
	if !strings.Contains(got, "status IN ('completed','degraded')") {
		t.Fatalf("retention prune must still preserve latest usable inventory: %s", got)
	}
}

func TestCveFixedVersionSQLIncludesTopLevelAndRangeEvents(t *testing.T) {
	got := cveFixedVersionSQL("c")
	for _, want := range []string{
		"c.affected_products->0->'fixed'->>0",
		"jsonb_path_query_first(c.affected_products",
		"ranges[*].events[*].fixed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fixed version SQL missing %q: %s", want, got)
		}
	}
}

func TestCveEnrichmentFixedVersionSQLIsPackageAware(t *testing.T) {
	got := cveEnrichmentFixedVersionSQL("c", "v")
	for _, want := range []string{
		"FROM packages p",
		"p.id = v.package_id",
		"lower(ap->>'name')",
		"p.ecosystem",
		"c.ecosystem",
		"jsonb_array_length(c.affected_products) = 1",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("enrichment fixed SQL missing %q: %s", want, got)
		}
	}
}

func TestCvePackageEcosystemMismatchFilterChecksAllAffectedProducts(t *testing.T) {
	got := cvePackageEcosystemMismatchFilter("v")
	for _, want := range []string{
		"jsonb_array_elements",
		"NOT EXISTS",
		"p.id = v.package_id",
		"c.vulnerability_id = v.vulnerability_id",
		"ap->>'ecosystem'",
		"lower(ap->>'name')",
		"p.ecosystem",
		"'ubuntu'",
		"'alpine'",
		"'rpm'",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("ecosystem mismatch filter missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "affected_products->0") {
		t.Fatalf("ecosystem mismatch filter must not inspect only first affected product: %s", got)
	}
}

func TestFixedVersionSQLConditionDoesNotHidePrereleases(t *testing.T) {
	got := fixedVersionSQLCondition("v")
	for _, want := range []string{
		"v.installed_version",
		"v.fixed_version",
		"!~*",
		"alpha",
		"beta",
		"rc",
		"snapshot",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("fixed condition missing %q: %s", want, got)
		}
	}
}

func TestInsertableVulnerabilitiesDropsDanglingRows(t *testing.T) {
	valid := models.Vulnerability{
		ID:              "vuln-1",
		PackageID:       "pkg-1",
		ScanID:          "scan-1",
		HostID:          "host-1",
		VulnerabilityID: "CVE-2026-0001",
	}
	items := insertableVulnerabilities([]models.Vulnerability{
		{ID: "vuln-empty-package", ScanID: "scan-1", HostID: "host-1", VulnerabilityID: "CVE-2026-0002"},
		valid,
		{ID: "vuln-empty-cve", PackageID: "pkg-1", ScanID: "scan-1", HostID: "host-1"},
	})
	if len(items) != 1 || items[0].ID != valid.ID {
		t.Fatalf("insertable vulnerabilities = %#v, want only %s", items, valid.ID)
	}
	if skipped := skippedVulnerabilities([]models.Vulnerability{
		{ID: "vuln-empty-package", ScanID: "scan-1", HostID: "host-1", VulnerabilityID: "CVE-2026-0002"},
		valid,
		{ID: "vuln-empty-cve", PackageID: "pkg-1", ScanID: "scan-1", HostID: "host-1"},
	}); skipped != 2 {
		t.Fatalf("skipped vulnerabilities = %d, want 2", skipped)
	}
}
