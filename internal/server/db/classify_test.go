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

func TestParseAccessSubjectRefSupportsTypedSubjects(t *testing.T) {
	tests := []struct {
		ref     string
		wantTyp string
		wantID  string
	}{
		{"user:alice", "user", "alice"},
		{"group/platform", "group", "platform"},
		{"alice", "", "alice"},
		{"team:platform", "", "team:platform"},
	}
	for _, tt := range tests {
		gotTyp, gotID := parseAccessSubjectRef(tt.ref)
		if gotTyp != tt.wantTyp || gotID != tt.wantID {
			t.Fatalf("parseAccessSubjectRef(%q) = (%q, %q), want (%q, %q)", tt.ref, gotTyp, gotID, tt.wantTyp, tt.wantID)
		}
	}
}

func TestAccessPolicyExternalSubjectResolutionRejectsAmbiguousUntypedRefs(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) resolveAccessSubjectID")
	if start < 0 {
		t.Fatal("resolveAccessSubjectID not found")
	}
	end := strings.Index(body[start:], "func (db *DB) UpsertVulnerabilityTriage")
	if end < 0 {
		t.Fatal("resolveAccessSubjectID end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"parseAccessSubjectRef(subjectExternalID)",
		"len(ids) > 1",
		"is ambiguous",
		"user:%s or group:%s",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("ambiguous subject guard missing %q: %s", want, fn)
		}
	}
}

func TestListAccessPoliciesSupportsTypedSubjectFilter(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) ListAccessPolicies")
	if start < 0 {
		t.Fatal("ListAccessPolicies not found")
	}
	end := strings.Index(body[start:], "func (db *DB) DeleteAccessSubject")
	if end < 0 {
		t.Fatal("ListAccessPolicies end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"parseAccessSubjectRef(subjectExternalID)",
		"s.external_id=$1",
		"s.subject_type=$2",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("typed subject policy filter missing %q: %s", want, fn)
		}
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
		"security_db_revision",
		"ON CONFLICT (host_id)",
		"host_id <> ''",
		"scan_type='security-db-update'",
		"status='pending'",
		"DO UPDATE SET",
		"security_db_revision=EXCLUDED.security_db_revision",
		"RETURNING (xmax = 0) AS inserted",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("rescan insert SQL missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "status IN ('pending','claimed')") {
		t.Fatalf("claimed requests must not suppress follow-up DB update rescans: %s", got)
	}
}

func TestQueueSecurityDBRescansReportsEligibleQueuedAndSkipped(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) QueueSecurityDBRescans")
	if start < 0 {
		t.Fatal("QueueSecurityDBRescans not found")
	}
	end := strings.Index(body[start:], "func queueSecurityDBRescanInsertSQL")
	if end < 0 {
		t.Fatal("QueueSecurityDBRescans end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"SecurityDBRescanQueueResult",
		"securityDBRevision string",
		"result.Eligible++",
		"result.Queued++",
		"result.AlreadyPending++",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("auto-rescan queue accounting missing %q: %s", want, fn)
		}
	}
}

func TestAutoRescanPendingUniqueMigrationAllowsClaimedFollowUp(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/015_pending_auto_rescan_unique.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(migration)
	for _, want := range []string{
		"DROP INDEX IF EXISTS idx_scan_requests_active_security_db_host",
		"idx_scan_requests_pending_security_db_host",
		"status = 'pending'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("pending auto-rescan migration missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "status IN ('pending', 'claimed')") || strings.Contains(body, "status IN ('pending','claimed')") {
		t.Fatalf("pending auto-rescan uniqueness must not include claimed requests: %s", body)
	}
}

func TestListScanRequestsSupportsOperationalFilters(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) ListScanRequests")
	if start < 0 {
		t.Fatal("ListScanRequests not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CountScanRequestsByStatus")
	if end < 0 {
		t.Fatal("ListScanRequests end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"status, scanType, securityDBRevision string",
		"AND scan_type=$%d",
		"AND security_db_revision=$%d",
		"args = append(args, scanType)",
		"args = append(args, securityDBRevision)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request operational filter missing %q: %s", want, fn)
		}
	}
}

func TestGetScanRequestReturnsOperationalFields(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetScanRequest")
	if start < 0 {
		t.Fatal("GetScanRequest not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CountScanRequestsByStatus")
	if end < 0 {
		t.Fatal("GetScanRequest end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"requested_by, scan_type, packages_only, reason, security_db_revision",
		"claimed_by_host_id, claimed_at, completed_at",
		"&r.SecurityDBRevision",
		"&r.ClaimedByHostID",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request lookup missing %q: %s", want, fn)
		}
	}
}

func TestScanRequestSecurityDBRevisionMigration(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/017_scan_request_security_db_revision.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(migration)
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS security_db_revision TEXT NOT NULL DEFAULT ''",
		"idx_scan_requests_security_db_revision",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scan request security DB revision migration missing %q: %s", want, body)
		}
	}
}

func TestStaleSecurityDBRequeueCancelsDuplicateClaimedRequests(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func cancelStaleSecurityDBDuplicates")
	if start < 0 {
		t.Fatal("cancelStaleSecurityDBDuplicates not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CompleteScanRequest")
	if end < 0 {
		t.Fatal("cancelStaleSecurityDBDuplicates end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"row_number() OVER (PARTITION BY sr.host_id",
		"has_pending",
		"stale.rn > 1",
		"pending.status='pending'",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("stale security-db duplicate cleanup missing %q: %s", want, fn)
		}
	}
}

func TestCveSourceQualityRequiresFixedData(t *testing.T) {
	got := cveSourceMatchablePredicateSQL("affected_products", "ecosystem")
	for _, want := range []string{
		"COALESCE(ap->>'name', '') != ''",
		"NULLIF(ap->>'ecosystem', '')",
		"jsonb_typeof(ap->'fixed') = 'array'",
		"jsonb_path_exists(ap, '$.ranges[*].events[*].fixed ? (@ != \"\")')",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("source quality predicate missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "jsonb_array_length(ap->'ranges') > 0") {
		t.Fatalf("source quality must not treat range metadata without fixed events as matchable: %s", got)
	}
}

func TestRematchCVEsSupportsScanScopedMatching(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) RematchCVEs")
	if start < 0 {
		t.Fatal("RematchCVEs not found")
	}
	end := strings.Index(body[start:], "func rematchVulnerabilityKey")
	if end < 0 {
		t.Fatal("RematchCVEs end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"opts.ScanID",
		"opts.CandidateLimit+1",
		"result.Limited = true",
		"matches = matches[:opts.CandidateLimit]",
		"AND p.scan_id =",
		"scanJoin = \"\"",
		"JOIN (%s) ls ON p.scan_id = ls.id",
		"LIMIT %s",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan-scoped rematch missing %q: %s", want, fn)
		}
	}
}

func TestRematchResultExposesSecurityDBRevision(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "type RematchResult struct")
	if start < 0 {
		t.Fatal("RematchResult not found")
	}
	end := strings.Index(body[start:], "type RematchOptions struct")
	if end < 0 {
		t.Fatal("RematchResult end not found")
	}
	typ := body[start : start+end]
	for _, want := range []string{
		"SecurityDBRevision",
		"security_db_revision,omitempty",
		"SecurityDBRevisionError",
		"security_db_revision_error,omitempty",
	} {
		if !strings.Contains(typ, want) {
			t.Fatalf("rematch result revision field missing %q: %s", want, typ)
		}
	}
}

func TestLatestScansIncludesDegradedInventory(t *testing.T) {
	if !strings.Contains(latestScansSub, "status IN ('completed','degraded')") {
		t.Fatalf("latest scans must include degraded scans: %s", latestScansSub)
	}
}

func TestRunMigrationsRecordsAppliedFiles(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) RunMigrations")
	if start < 0 {
		t.Fatal("RunMigrations not found")
	}
	end := strings.Index(body[start:], "func (db *DB) UpsertHost")
	if end < 0 {
		t.Fatal("RunMigrations end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"db.legacySchemaComplete(ctx)",
		"CREATE TABLE IF NOT EXISTS schema_migrations",
		"db.appliedMigrations(ctx)",
		"len(applied) == 0 && legacyInitialized",
		"db.baselineMigrations(ctx, files)",
		"migrationChecksum(data)",
		"checksum mismatch",
		"db.BeginTx(ctx, nil)",
		"INSERT INTO schema_migrations",
		"tx.Commit()",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("RunMigrations tracking missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "log.Printf(\"rematch scan row") {
		t.Fatal("RunMigrations must not log unrelated messages for skipped files")
	}
}

func TestMigrationBaselineRecordsLegacyDatabasesWithoutRerun(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) baselineMigrations")
	if start < 0 {
		t.Fatal("baselineMigrations not found")
	}
	end := strings.Index(body[start:], "func (db *DB) tableExists")
	if end < 0 {
		t.Fatal("tableExists not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"INSERT INTO schema_migrations",
		"ON CONFLICT (filename) DO NOTHING",
		"migrationChecksum(data)",
		"stmt.ExecContext",
		"tx.Commit()",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("baselineMigrations missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "tx.ExecContext(ctx, string(data))") {
		t.Fatal("baselineMigrations must not execute migration SQL")
	}
}

func TestLegacyMigrationBaselineRequiresLatestSchemaMarkers(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) legacySchemaComplete")
	if start < 0 {
		t.Fatal("legacySchemaComplete not found")
	}
	end := strings.Index(body[start:], "func (db *DB) tableExists")
	if end < 0 {
		t.Fatal("tableExists not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		`{table: "hosts"}`,
		`{table: "packages", column: "asset_type"}`,
		`{table: "packages", column: "purl"}`,
		`{table: "vulnerabilities", column: "pkg_path"}`,
		`{table: "vulnerabilities", column: "finding_source"}`,
		`{table: "cve_database", column: "category"}`,
		`{table: "container_assets"}`,
		`{table: "scan_requests", column: "claimed_by_host_id"}`,
		`{table: "scan_requests", column: "security_db_revision"}`,
		`{table: "audit_logs"}`,
		`{table: "vulnerability_triage"}`,
		`{index: "idx_scan_requests_pending_security_db_host"}`,
		`{index: "idx_vulnerabilities_package_scan_vuln"}`,
		`{index: "idx_vulnerabilities_finding_source"}`,
		"db.columnExists",
		"db.indexExists",
		"db.tableExists",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("legacy schema completeness check missing %q: %s", want, fn)
		}
	}
}

func TestVulnerabilityFindingSourceMigration(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/016_vulnerability_finding_source.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(migration)
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS finding_source TEXT NOT NULL DEFAULT 'scanner'",
		"idx_vulnerabilities_finding_source",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("finding source migration missing %q: %s", want, body)
		}
	}
}

func TestStaleRematchedVulnerabilityCleanupOnlyTargetsCveDBFindings(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) RemoveStaleRematchedVulnerabilities")
	if start < 0 {
		t.Fatal("RemoveStaleRematchedVulnerabilities not found")
	}
	end := strings.Index(body[start:], "func cveEnrichmentFixedVersionSQL")
	if end < 0 {
		t.Fatal("RemoveStaleRematchedVulnerabilities end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"DELETE FROM vulnerabilities v",
		"v.finding_source = 'cve-db'",
		"NOT EXISTS",
		"cve_database c",
		"jsonb_array_elements",
		"COALESCE(ap->>'name', '') != ''",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("stale rematch cleanup missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "finding_source != 'scanner'") {
		t.Fatalf("cleanup must target explicit cve-db provenance only: %s", fn)
	}
}

func TestIndexExistsUsesPostgresRegclass(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) indexExists")
	if start < 0 {
		t.Fatal("indexExists not found")
	}
	end := strings.Index(body[start:], "func (db *DB) appliedMigrations")
	if end < 0 {
		t.Fatal("indexExists end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"to_regclass($1) IS NOT NULL",
		`"public."+index`,
		"check index %s",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("indexExists missing %q: %s", want, fn)
		}
	}
}

func TestMigrationChecksumIsStable(t *testing.T) {
	a := migrationChecksum([]byte("select 1;"))
	b := migrationChecksum([]byte("select 1;"))
	c := migrationChecksum([]byte("select 2;"))
	if a == "" || a != b {
		t.Fatalf("migration checksum must be stable, got %q and %q", a, b)
	}
	if a == c {
		t.Fatal("migration checksum must change when migration contents change")
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
	errs := []error{ErrInvalidScanRequestStatus, ErrScanRequestNotFound, ErrScanRequestNotActive, ErrScanRequestClaimMismatch}
	for i := range errs {
		for j := i + 1; j < len(errs); j++ {
			if errs[i] == errs[j] {
				t.Fatal("scan request completion errors must be distinct")
			}
		}
	}
}

func TestScanRequestClaimOwnershipIsTracked(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/014_scan_request_claim_owner.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationBody := string(migration)
	for _, want := range []string{
		"claimed_by_host_id TEXT NOT NULL DEFAULT ''",
		"claimed_by_host_id = host_id",
		"requeued during claimed host ownership migration",
		"idx_scan_requests_claimed_by_host",
	} {
		if !strings.Contains(migrationBody, want) {
			t.Fatalf("scan request claim owner migration missing %q: %s", want, migrationBody)
		}
	}

	dbFile, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(dbFile)
	for _, want := range []string{
		"claimed_by_host_id=$1",
		"claimed_by_host_id=''",
		"CompleteClaimedScanRequest",
		"status='claimed' AND claimed_by_host_id=$4",
		"ErrScanRequestClaimMismatch",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scan request claim ownership handling missing %q", want)
		}
	}
	if !strings.Contains(body, "claimed_by_host_id, claimed_at") {
		t.Fatal("scan request list/claim responses must expose claimed_by_host_id")
	}
}

func TestAgentCompletesScanRequestWithHostID(t *testing.T) {
	reporterFile, err := os.ReadFile("../../agent/reporter/reporter.go")
	if err != nil {
		t.Fatal(err)
	}
	reporterBody := string(reporterFile)
	for _, want := range []string{
		"CompleteScanRequest(id, hostID, status, message string)",
		`"host_id": hostID`,
	} {
		if !strings.Contains(reporterBody, want) {
			t.Fatalf("agent reporter completion missing %q", want)
		}
	}

	agentFile, err := os.ReadFile("../../../cmd/agent/main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(agentFile), `CompleteScanRequest(req.ID, host.ID`) {
		t.Fatal("agent daemon must send host ID when completing scan requests")
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

func TestCveReplacementDeleteHelpersAreTransactional(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"func (db *DB) DeleteCveEntriesBySourceTx",
		"DELETE FROM cve_database WHERE source=$1",
		"func (db *DB) DeleteAllCveEntriesTx",
		"DELETE FROM cve_database",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("cve replacement helper missing %q", want)
		}
	}
}

func TestVulnerabilityFindingsAreUniquePerPackageScanAndCVE(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/013_unique_vulnerability_findings.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationBody := string(migration)
	for _, want := range []string{
		"PARTITION BY package_id, scan_id, vulnerability_id",
		"DELETE FROM vulnerabilities",
		"CREATE UNIQUE INDEX IF NOT EXISTS idx_vulnerabilities_package_scan_vuln",
		"ON vulnerabilities(package_id, scan_id, vulnerability_id)",
	} {
		if !strings.Contains(migrationBody, want) {
			t.Fatalf("unique vulnerability migration missing %q: %s", want, migrationBody)
		}
	}

	dbFile, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(dbFile)
	if strings.Count(body, "ON CONFLICT (package_id, scan_id, vulnerability_id) DO NOTHING") < 2 {
		t.Fatalf("scanner and rematch inserts must ignore duplicate vulnerability findings")
	}
	if !strings.Contains(body, "res.RowsAffected()") {
		t.Fatal("duplicate vulnerability conflicts must be reflected in insert counters")
	}
}

func TestUpdateHostMetadataReportsMissingHosts(t *testing.T) {
	dbFile, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(dbFile)
	start := strings.Index(body, "func (db *DB) UpdateHostMetadata")
	if start < 0 {
		t.Fatal("UpdateHostMetadata not found")
	}
	end := strings.Index(body[start:], "const latestScansSub")
	if end < 0 {
		t.Fatal("UpdateHostMetadata end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"res.RowsAffected()",
		"if n == 0",
		"return sql.ErrNoRows",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("UpdateHostMetadata must report missing hosts with %q: %s", want, fn)
		}
	}
}

func TestRematchVulnerabilityDedupPrefersStrongerCandidate(t *testing.T) {
	current := models.Vulnerability{
		PackageID:       "pkg-1",
		ScanID:          "scan-1",
		VulnerabilityID: "CVE-2026-0001",
		Severity:        "MEDIUM",
		CVSSScore:       5.0,
	}
	candidate := current
	candidate.Severity = "HIGH"
	candidate.CVSSScore = 8.1
	candidate.FixedVersion = "1.2.3"
	candidate.Title = "better"

	if rematchVulnerabilityKey(candidate) != rematchVulnerabilityKey(current) {
		t.Fatal("same package, scan, and CVE must dedupe to the same key")
	}
	if !betterRematchVulnerability(candidate, current) {
		t.Fatal("higher CVSS rematch candidate should replace weaker duplicate")
	}
	if betterRematchVulnerability(current, candidate) {
		t.Fatal("weaker rematch candidate must not replace stronger duplicate")
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

func TestCurrentActionableVulnSQLUsesRemediationFilters(t *testing.T) {
	got := currentActionableVulnSQL()
	for _, want := range []string{
		"COALESCE(vt.status, 'open') IN ('open', 'in_progress')",
		"fixed_version",
		"v.vulnerability_id NOT LIKE 'CGA-%'",
		"v.fixed_version !~ '^[0-9a-f]{40}$'",
		"v.fixed_version IS NOT NULL",
		"SUBSTRING(v.vulnerability_id FROM '^[A-Z]+')",
		"cve_database c",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("current actionable SQL missing %q: %s", want, got)
		}
	}
}

func TestListVulnerabilitiesAlwaysUsesLatestScan(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) ListVulnerabilities")
	if start < 0 {
		t.Fatal("ListVulnerabilities not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetHostVulnCounts")
	if end < 0 {
		t.Fatal("GetHostVulnCounts not found")
	}
	fn := body[start : start+end]
	if !strings.Contains(fn, "JOIN ` + latestScansSub") {
		t.Fatalf("ListVulnerabilities must join latest scans even with host_id filters: %s", fn)
	}
	if strings.Contains(fn, "useLatest :=") {
		t.Fatalf("ListVulnerabilities must not disable latest-scan filtering for host_id filters: %s", fn)
	}
}

func TestListVulnerabilitiesSupportsFindingSourceFilter(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "type VulnFilter")
	if start < 0 {
		t.Fatal("VulnFilter not found")
	}
	end := strings.Index(body[start:], "func (db *DB) ListVulnerabilities")
	if end < 0 {
		t.Fatal("ListVulnerabilities not found")
	}
	filterDef := body[start : start+end]
	if !strings.Contains(filterDef, "FindingSource string") {
		t.Fatalf("VulnFilter missing finding source: %s", filterDef)
	}
	fnStart := start + end
	fnEnd := strings.Index(body[fnStart:], "func (db *DB) GetHostVulnCounts")
	if fnEnd < 0 {
		t.Fatal("GetHostVulnCounts not found")
	}
	fn := body[fnStart : fnStart+fnEnd]
	if !strings.Contains(fn, "COALESCE(v.finding_source, 'scanner')=$") {
		t.Fatalf("finding source filter SQL missing: %s", fn)
	}
}

func TestSearchPackagesAlwaysUsesLatestScan(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) SearchPackages")
	if start < 0 {
		t.Fatal("SearchPackages not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetPackageHostID")
	if end < 0 {
		t.Fatal("GetPackageHostID not found")
	}
	fn := body[start : start+end]
	if !strings.Contains(fn, "JOIN ` + latestScansSub") {
		t.Fatalf("SearchPackages must join latest scans even with host_id filters: %s", fn)
	}
	if strings.Contains(fn, "useLatest :=") {
		t.Fatalf("SearchPackages must not disable latest-scan filtering for host_id filters: %s", fn)
	}
}

func TestPackageVulnJoinUsesActiveFindingFilter(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "var pkgVulnJoin")
	if start < 0 {
		t.Fatal("pkgVulnJoin not found")
	}
	end := strings.Index(body[start:], "const pkgVulnSelect")
	if end < 0 {
		t.Fatal("pkgVulnSelect not found")
	}
	src := body[start : start+end]
	for _, want := range []string{
		"vulnTriageJoin",
		"currentActionableVulnSQL()",
		"MAX(v.cvss_score)",
		"COUNT(*)",
	} {
		if !strings.Contains(src, want) {
			t.Fatalf("package vuln join active filter missing %q: %s", want, src)
		}
	}
}

func TestGetVulnsByPackageIDUsesLatestActiveFindings(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetVulnsByPackageID")
	if start < 0 {
		t.Fatal("GetVulnsByPackageID not found")
	}
	end := strings.Index(body[start:], "const CveCols")
	if end < 0 {
		t.Fatal("CveCols not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"JOIN ` + latestScansSub",
		"currentActionableVulnSQL()",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("package vulnerability details must use latest active findings, missing %q: %s", want, fn)
		}
	}
}

func TestVulnSummaryUsesActiveFindingFilter(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetVulnSummaryByMetadata")
	if start < 0 {
		t.Fatal("GetVulnSummaryByMetadata not found")
	}
	end := strings.Index(body[start:], "func vulnSummaryGroupExpr")
	if end < 0 {
		t.Fatal("vulnSummaryGroupExpr not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"currentActionableVulnSQL()",
		"JOIN ` + latestScansSub",
		"v.host_id = ANY($1)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("vuln summary active filter missing %q: %s", want, fn)
		}
	}
}

func TestFilterOptionsAreHostScopedAndLatestOnly(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	tests := []struct {
		name  string
		start string
		end   string
		wants []string
	}{
		{
			name:  "package filters",
			start: "func (db *DB) GetFilterOptions",
			end:   "func pkgSortExpr",
			wants: []string{
				"hostIDs []string",
				"p.host_id = ANY($1)",
				"+latestScansSub+",
				"SELECT DISTINCT p.host_id",
				"SELECT DISTINCT COALESCE(NULLIF(p.container",
				"SELECT DISTINCT p.pkg_type",
				"SELECT DISTINCT p.source",
			},
		},
		{
			name:  "vulnerability filters",
			start: "func (db *DB) GetVulnFilterOptions",
			end:   "type CveSearchFilter",
			wants: []string{
				"hostIDs []string",
				"v.host_id = ANY($1)",
				"+latestScansSub+",
				"SELECT DISTINCT v.host_id",
				"SELECT DISTINCT COALESCE(NULLIF(v.container",
				"COALESCE(v.finding_source, 'scanner')",
			},
		},
	}
	for _, tt := range tests {
		start := strings.Index(body, tt.start)
		if start < 0 {
			t.Fatalf("%s not found", tt.start)
		}
		end := strings.Index(body[start:], tt.end)
		if end < 0 {
			t.Fatalf("%s end not found", tt.name)
		}
		fn := body[start : start+end]
		for _, want := range tt.wants {
			if !strings.Contains(fn, want) {
				t.Fatalf("%s missing %q: %s", tt.name, want, fn)
			}
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
