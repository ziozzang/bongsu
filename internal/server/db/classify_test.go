package db

import (
	"encoding/json"
	"os"
	"reflect"
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
		{"osv debian release", "osv", `[{"name":"openssl","ecosystem":"Debian:11"}]`, "os-package", "Debian:11"},
		{"osv suse release", "osv", `[{"name":"openssl","ecosystem":"SUSE:Linux Enterprise Server 15"}]`, "os-package", "SUSE:Linux Enterprise Server 15"},
		{"nvd fallback", "nvd", `[]`, "general-cve", ""},
		{"cisa kev fallback", "cisa-kev", `[]`, "general-cve", ""},
		{"epss fallback", "epss", `[]`, "general-cve", ""},
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

func TestDBPoolConfigFromEnv(t *testing.T) {
	t.Setenv("BONGSU_DB_MAX_OPEN_CONNS", "40")
	t.Setenv("BONGSU_DB_MAX_IDLE_CONNS", "12")
	t.Setenv("BONGSU_DB_CONN_MAX_LIFETIME_MINUTES", "9")

	cfg := dbPoolConfigFromEnv()
	if cfg.MaxOpenConns != 40 || cfg.MaxIdleConns != 12 || cfg.ConnMaxLifetimeMin != 9 {
		t.Fatalf("dbPoolConfigFromEnv() = %#v, want max_open=40 max_idle=12 lifetime=9", cfg)
	}
}

func TestDBPoolConfigFallsBackForInvalidValues(t *testing.T) {
	t.Setenv("BONGSU_DB_MAX_OPEN_CONNS", "0")
	t.Setenv("BONGSU_DB_MAX_IDLE_CONNS", "-1")
	t.Setenv("BONGSU_DB_CONN_MAX_LIFETIME_MINUTES", "invalid")

	cfg := dbPoolConfigFromEnv()
	if cfg.MaxOpenConns != 25 || cfg.MaxIdleConns != 5 || cfg.ConnMaxLifetimeMin != 5 {
		t.Fatalf("dbPoolConfigFromEnv() = %#v, want defaults", cfg)
	}
}

func TestAuditLogFilterSupportsTimeRanges(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	modelOut, err := os.ReadFile("../../shared/models/models.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out) + string(modelOut)
	for _, want := range []string{
		`CreatedFrom  *time.Time`,
		`CreatedTo    *time.Time`,
		`created_at >=`,
		`created_at <=`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit log DB time filtering missing %q", want)
		}
	}
}

func TestLatestAuditLogSupportsOperationalSummaries(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetLatestAuditLog")
	if start < 0 {
		t.Fatal("GetLatestAuditLog not found")
	}
	end := strings.Index(body[start:], "type AccessScope")
	if end < 0 {
		t.Fatal("GetLatestAuditLog end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"AuditLogFilter",
		"excludedStatuses []string",
		"NOT (status = ANY($%d))",
		"ORDER BY created_at DESC LIMIT 1",
		"errors.Is(err, sql.ErrNoRows)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("latest audit log helper missing %q: %s", want, fn)
		}
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

func TestCompatibleSecurityCandidateRejectsAmbiguousMultiFixedWithoutRanges(t *testing.T) {
	affected := `[{"name":"foo","ecosystem":"npm","fixed":["1.2.9","2.0.1"]}]`
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "1.3.0", "code-library", "", affected); ok {
		t.Fatal("multi-fixed candidate without affected ranges should not match across ambiguous release branches")
	}
	if _, ok := compatibleSecurityCandidate("foo", "npm", "npm", "2.0.0", "code-library", "", affected); ok {
		t.Fatal("multi-fixed candidate without affected ranges should not match newer branch versions")
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
		{"v40", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U", 8.1},
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

func TestManualCVSSRecalcUsesFullRecalculationPath(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	modelOut, err := os.ReadFile("../../shared/models/models.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out) + string(modelOut)
	start := strings.Index(body, "func (db *DB) RecalcCVSSFromVectors")
	if start < 0 {
		t.Fatal("RecalcCVSSFromVectors not found")
	}
	end := strings.Index(body[start:], "}")
	if end < 0 {
		t.Fatal("RecalcCVSSFromVectors end not found")
	}
	fn := body[start : start+end]
	if !strings.Contains(fn, "return db.CalcCvssScores(ctx)") {
		t.Fatalf("manual CVSS recalculation must reuse full CVSS path: %s", fn)
	}
	if strings.Contains(fn, "cvss_score = 0") {
		t.Fatalf("manual CVSS recalculation must not skip existing CVSS 4.0 scores: %s", fn)
	}

	start = strings.Index(body, "func (db *DB) CalcCvssScores")
	if start < 0 {
		t.Fatal("CalcCvssScores not found")
	}
	end = strings.Index(body[start:], "func (db *DB) GetCveSources")
	if end < 0 {
		t.Fatal("CalcCvssScores end not found")
	}
	fn = body[start : start+end]
	for _, want := range []string{
		"cvss_vector LIKE 'CVSS:4%'",
		"cvss_score = 0",
		"UPDATE cve_database SET cvss_score=$1",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("full CVSS recalculation missing %q: %s", want, fn)
		}
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
	if got := containerSortExpr("critical_count", true); !strings.Contains(got, "v.severity='CRITICAL'") || !strings.Contains(got, "COALESCE(vt.status, 'open')") {
		t.Fatalf("critical count sort expr = %q", got)
	}
	if got := containerSortExpr("max_cvss", true); !strings.Contains(got, "max(v.cvss_score)") || !strings.Contains(got, "COALESCE(vt.status, 'open')") {
		t.Fatalf("max cvss sort expr = %q", got)
	}
	if got := containerSortExpr("c.name; DROP TABLE container_assets", false); got != "c.created_at ASC NULLS LAST" {
		t.Fatalf("unsafe sort expr should fall back, got %q", got)
	}
}

func TestContainerSearchIncludesRiskSummary(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) SearchContainers")
	if start < 0 {
		t.Fatal("SearchContainers not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetPackageHostID")
	if end < 0 {
		t.Fatal("GetPackageHostID not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"package_count",
		"vulnerability_count",
		"critical_count",
		"high_count",
		"max_cvss",
		"currentActionableVulnSQL()",
		"&c.PackageCount",
		"&c.VulnerabilityCount",
		"&c.CriticalCount",
		"&c.HighCount",
		"&c.MaxCVSS",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("container risk summary missing %q: %s", want, fn)
		}
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

func TestAccessScopesSeparateReadAndExportPermissions(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"func (db *DB) GetAccessScope",
		`[]string{"read", "admin"}`,
		"func (db *DB) GetExportScope",
		`[]string{"export", "admin"}`,
		"getAccessScopeForPermissions",
		"p.permission = ANY($2)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("access/export scope split missing %q", want)
		}
	}
}

func TestAccessPolicyExportPermissionMigration(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/018_access_policy_export_permission.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(migration)
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS access_policies_permission_check",
		"ADD CONSTRAINT access_policies_permission_check",
		"'export'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("export permission migration missing %q: %s", want, body)
		}
	}
}

func TestAccessPolicyCveDBResourceMigration(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/023_access_policy_cve_db.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(migration)
	for _, want := range []string{
		"DROP CONSTRAINT IF EXISTS access_policies_resource_type_check",
		"ADD CONSTRAINT access_policies_resource_type_check",
		"'cve_db'",
		"'all'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("cve_db resource migration missing %q: %s", want, body)
		}
	}
}

func TestHasResourcePermissionSupportsGlobalResources(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"func (db *DB) HasResourcePermission",
		"parseAccessSubjectRef(subjectRef)",
		"p.resource_type=$2 OR p.resource_type='all'",
		"p.resource_id='*' OR p.resource_id=''",
		"p.permission = ANY($3)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("global resource permission support missing %q", want)
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
		"staleOnly bool, timeoutSeconds int64",
		"AND scan_type=$%d",
		"AND security_db_revision=$%d",
		"status='pending' AND created_at < now()",
		"status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now()",
		"args = append(args, scanType)",
		"args = append(args, securityDBRevision)",
		"args = append(args, timeoutSeconds)",
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
		"request_age_seconds",
		"claim_age_seconds",
		"&r.RequestAgeS",
		"&r.ClaimAgeS",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request lookup missing %q: %s", want, fn)
		}
	}
}

func TestSecurityDBRescanCountsAreScopedByRevision(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) CountSecurityDBRescanRequestsByStatus")
	if start < 0 {
		t.Fatal("CountSecurityDBRescanRequestsByStatus not found")
	}
	end := strings.Index(body[start:], "func (db *DB) RequeueStaleScanRequests")
	if end < 0 {
		t.Fatal("CountSecurityDBRescanRequestsByStatus end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"scan_type='security-db-update'",
		"security_db_revision=$1",
		"host_id = ANY($2)",
		"GROUP BY status",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("security DB rescan count query missing %q: %s", want, fn)
		}
	}
}

func TestStaleScanRequestCountsAreScopedByTimeoutAndHost(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) CountStaleScanRequestsByState")
	if start < 0 {
		t.Fatal("CountStaleScanRequestsByState not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CountSecurityDBRescanRequestsByStatus")
	if end < 0 {
		t.Fatal("CountStaleScanRequestsByState end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"timeoutSeconds int64",
		"status='pending' AND created_at < now()",
		"status='claimed' AND claimed_at IS NOT NULL AND claimed_at < now()",
		"WHERE status IN ('pending','claimed')",
		"host_id='' OR host_id = ANY($2)",
		"host_id = ANY($2)",
		"GROUP BY stale_state",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("stale scan request count query missing %q: %s", want, fn)
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

func TestScanErrorSummaryIsStoredAndListed(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"CompleteScan(ctx context.Context, id, status, errorSummary string)",
		"UPDATE scans SET status=$2, error_summary=$3",
		"SELECT id, host_id, scan_type, status, error_summary",
		"&s.ErrorSummary",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scan error summary persistence missing %q", want)
		}
	}
	migration, err := os.ReadFile("../../../migrations/021_scan_error_summary.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(migration), "ADD COLUMN IF NOT EXISTS error_summary TEXT NOT NULL DEFAULT ''") {
		t.Fatalf("scan error summary migration missing column: %s", migration)
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
		"type StaleScanRequestRequeueResult struct",
		"CancelledDuplicates int",
		"result.CancelledDuplicates = cancelled",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("stale requeue accounting missing %q", want)
		}
	}
	for _, want := range []string{
		"row_number() OVER (PARTITION BY sr.host_id",
		"has_pending",
		"stale.rn > 1",
		"pending.status='pending'",
		"RowsAffected()",
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
		"jsonb_array_length(ap->'fixed') = 1",
		"jsonb_path_exists(ap, '$.ranges[*].events[*].fixed ? (@ != \"\")')",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("source quality predicate missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, "jsonb_array_length(ap->'fixed') > 0") {
		t.Fatalf("source quality must not treat ambiguous multi-fixed entries as safely matchable: %s", got)
	}
	if strings.Contains(got, "jsonb_array_length(ap->'ranges') > 0") {
		t.Fatalf("source quality must not treat range metadata without fixed events as matchable: %s", got)
	}
}

func TestCveDatabaseSearchSupportsAffectedPackageAndMatchableFilters(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) SearchCveDatabase")
	if start < 0 {
		t.Fatal("SearchCveDatabase not found")
	}
	end := strings.Index(body[start:], "func calcCvssScore")
	if end < 0 {
		t.Fatal("SearchCveDatabase end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"matchableOnly, includePrioritySources bool",
		"referenceKey",
		"cveReferenceKeyFilter(referenceKey)",
		"minEPSS",
		"minEPSSPercentile",
		"includePrioritySources",
		"jsonb_array_elements(CASE WHEN jsonb_typeof(affected_products) = 'array'",
		"ap->>'name' ILIKE",
		"COALESCE(NULLIF(ap->>'ecosystem', ''), ecosystem) ILIKE",
		"ap::text ILIKE",
		"epss_score>=$",
		"epss_percentile>=$",
		"source NOT IN ('cisa-kev', 'epss')",
		"if matchableOnly",
		"cveSourceMatchablePredicateSQL",
		"enrichCveReferenceGroupCounts",
		"ReferenceGroupTotal",
		"ReferenceGroupMatchable",
		"ReferenceGroupSources",
		"ReferenceGroupStatus",
		"context.WithTimeout",
		"BONGSU_CVE_GROUP_SUMMARY_TIMEOUT_MS",
		"markCveReferenceGroupStatus(entries, \"unavailable\")",
		"JOIN cve_reference_keys crk",
		"preferredReferenceGroupKey",
		"pq.Array(keys)",
		"crk.reference_key = k.reference_key",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("CVE search missing %q: %s", want, fn)
		}
	}
	if strings.Contains(fn, "c.title ILIKE ('%%' || k.cve") || strings.Contains(fn, "c.description ILIKE ('%%' || k.cve") {
		t.Fatalf("CVE group count enrichment must avoid broad title/description scans: %s", fn)
	}
	if strings.Contains(fn, "c.refs::text ILIKE ('%%' || k.cve") {
		t.Fatalf("CVE group count enrichment must avoid broad reference text scans until reference keys are indexed: %s", fn)
	}
}

func TestPreferredReferenceGroupKeyUsesCanonicalThenVendorAdvisory(t *testing.T) {
	if got := preferredReferenceGroupKey([]string{"vendor:debian", "debian:DLA-214-1"}); got != "debian:DLA-214-1" {
		t.Fatalf("preferred key = %q, want debian advisory", got)
	}
	if got := preferredReferenceGroupKey([]string{"vendor:debian", "debian:DLA-214-1", "cve:CVE-2026-48840"}); got != "cve:CVE-2026-48840" {
		t.Fatalf("preferred key = %q, want canonical CVE", got)
	}
}

func TestCveReferenceKeyFilterSupportsCanonicalGroups(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		wantFilter string
		wantVals   []string
	}{
		{
			name:       "canonical cve",
			key:        "cve:CVE-2026-48840",
			wantFilter: "cve_reference_keys",
			wantVals:   []string{"cve:CVE-2026-48840"},
		},
		{
			name:       "debian vendor",
			key:        "vendor:debian",
			wantFilter: "cve_reference_keys",
			wantVals:   []string{"vendor:debian"},
		},
		{
			name:       "debian advisory",
			key:        "debian:DLA-214-1",
			wantFilter: "cve_reference_keys",
			wantVals:   []string{"debian:DLA-214-1"},
		},
		{
			name:       "github repo",
			key:        "repo:github.com/mervinpraison/praisonai",
			wantFilter: "cve_reference_keys",
			wantVals:   []string{"repo:github.com/mervinpraison/praisonai"},
		},
		{
			name:       "invalid",
			key:        "cve:not-a-cve",
			wantFilter: "",
			wantVals:   nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter, vals := cveReferenceKeyFilter(tt.key)
			if !strings.Contains(filter, tt.wantFilter) {
				t.Fatalf("filter = %q, want to contain %q", filter, tt.wantFilter)
			}
			if !reflect.DeepEqual(vals, tt.wantVals) {
				t.Fatalf("vals = %#v, want %#v", vals, tt.wantVals)
			}
		})
	}
}

func TestCveReferenceGroupSummaryUsesSameCanonicalFilter(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCveReferenceGroupSummary")
	if start < 0 {
		t.Fatal("GetCveReferenceGroupSummary not found")
	}
	end := strings.Index(body[start:], "func (db *DB) cveReferenceGroupBuckets")
	if end < 0 {
		t.Fatal("cveReferenceGroupBuckets not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"ErrInvalidCveReferenceKey",
		"cveReferenceKeyWhere(key, 1)",
		"cveSourceMatchablePredicateSQL",
		"summary.Sources",
		"summary.Categories",
		"summary.Ecosystems",
		"summary.SourceGroups",
		"summary.ReferenceKeys",
		"summary.Items",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("reference group summary missing %q: %s", want, fn)
		}
	}
	for _, want := range []string{
		"type CveReferenceGroupSummary struct",
		"type CveReferenceGroupBucket struct",
		`json:"reference_keys"`,
		`json:"source_groups"`,
		`json:"matchable"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("reference group summary type missing %q", want)
		}
	}
}

func TestCveReferenceKeysGroupVendorCVEAndAdvisories(t *testing.T) {
	entry := models.CveEntry{
		VulnerabilityID: "DEBIAN-CVE-2026-48840",
		Title:           "Debian tracker item",
		Ecosystem:       "Debian:12",
		References:      `[{"url":"https://security-tracker.debian.org/tracker/CVE-2026-48840","type":"ADVISORY"},{"url":"https://github.com/MervinPraison/PraisonAI","type":"PACKAGE"}]`,
		RawData:         `{"aliases":["GHSA-c2m8-4gcg-v22g","DLA-1234-1"]}`,
	}
	got := cveReferenceKeys(entry)
	for _, want := range []string{
		"cve:CVE-2026-48840",
		"vendor:debian",
		"ghsa:GHSA-c2m8-4gcg-v22g",
		"debian:DLA-1234-1",
		"repo:github.com/mervinpraison/praisonai",
	} {
		found := false
		for _, key := range got {
			if key == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("reference keys missing %q in %#v", want, got)
		}
	}
}

func TestCveReferenceKeysTagDebianAdvisoriesWithoutCVEAlias(t *testing.T) {
	entry := models.CveEntry{
		VulnerabilityID: "DLA-214-1",
		Ecosystem:       "Debian:6.0",
		RawData:         `{"id":"DLA-214-1","aliases":[]}`,
	}
	got := cveReferenceKeys(entry)
	for _, want := range []string{"debian:DLA-214-1", "vendor:debian"} {
		found := false
		for _, key := range got {
			if key == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("reference keys missing %q in %#v", want, got)
		}
	}
}

func TestCvePackageMatchablePredicateRequiresPackageTargetAndFixedData(t *testing.T) {
	got := cvePackageMatchablePredicateSQL("c.affected_products", "c.ecosystem", "p.name", "COALESCE(NULLIF(p.ecosystem, ''), NULLIF(p.pkg_type, ''))")
	for _, want := range []string{
		"jsonb_array_elements(c.affected_products) ap",
		"lower(COALESCE(ap->>'name', '')) = lower(p.name)",
		"NULLIF(ap->>'ecosystem', '')",
		"NULLIF(c.ecosystem, '')",
		"NULLIF(p.ecosystem, '')",
		"NULLIF(p.pkg_type, '')",
		"jsonb_typeof(ap->'fixed') = 'array'",
		"jsonb_array_length(ap->'fixed') = 1",
		"jsonb_path_exists(ap, '$.ranges[*].events[*].fixed ? (@ != \"\")')",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("package matchable predicate missing %q: %s", want, got)
		}
	}
}

func TestCveEntryHasMatchableAffectedProduct(t *testing.T) {
	tests := []struct {
		name             string
		affectedProducts string
		ecosystem        string
		want             bool
		wantCount        int
	}{
		{
			name:             "package ecosystem fixed",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist","fixed":["0.5.2"]}]`,
			want:             true,
			wantCount:        1,
		},
		{
			name:             "cve ecosystem fixed",
			affectedProducts: `[{"name":"phenx/php-svg-lib","fixed":["0.5.2"]}]`,
			ecosystem:        "Packagist",
			want:             true,
			wantCount:        1,
		},
		{
			name:             "range fixed event",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist","ranges":[{"events":[{"introduced":"0"},{"fixed":"0.5.2"}]}]}]`,
			want:             true,
			wantCount:        1,
		},
		{
			name:             "multiple matchable affected packages",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist","fixed":["0.5.2"]},{"name":"phenx/php-font-lib","ecosystem":"Packagist","ranges":[{"events":[{"fixed":"0.5.4"}]}]},{"name":"ignored","ecosystem":"Packagist"}]`,
			want:             true,
			wantCount:        2,
		},
		{
			name:             "ambiguous multi fixed without ranges",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist","fixed":["0.5.2","1.0.0"]}]`,
			want:             false,
			wantCount:        0,
		},
		{
			name:             "multi fixed with range fixed event",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist","fixed":["0.5.2","1.0.0"],"ranges":[{"events":[{"introduced":"0"},{"fixed":"0.5.2"}]}]}]`,
			want:             true,
			wantCount:        1,
		},
		{
			name:             "missing fixed",
			affectedProducts: `[{"name":"phenx/php-svg-lib","ecosystem":"Packagist"}]`,
			want:             false,
		},
		{
			name:             "missing ecosystem",
			affectedProducts: `[{"name":"phenx/php-svg-lib","fixed":["0.5.2"]}]`,
			want:             false,
		},
		{
			name:             "missing package name",
			affectedProducts: `[{"ecosystem":"Packagist","fixed":["0.5.2"]}]`,
			want:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cveEntryHasMatchableAffectedProduct(tt.affectedProducts, tt.ecosystem); got != tt.want {
				t.Fatalf("matchable=%v want %v", got, tt.want)
			}
			if got := cveEntryMatchableAffectedCount(tt.affectedProducts, tt.ecosystem); got != tt.wantCount {
				t.Fatalf("matchable affected count=%v want %v", got, tt.wantCount)
			}
		})
	}
}

func TestCveSourceStatsExposeMatchablePercent(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"MatchablePercent float64",
		`json:"matchable_percent"`,
		"float64(s.Matchable)",
		"float64(s.Count)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("CVE source stats missing matchable percent support %q", want)
		}
	}
}

func TestCveSourceFreshnessStatsAvoidHeavyQualityScan(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCveSourceFreshnessStats")
	if start < 0 {
		t.Fatal("GetCveSourceFreshnessStats not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetSecurityDBRevision")
	if end < 0 {
		t.Fatal("GetSecurityDBRevision not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"SELECT source, count(*) AS count, MAX(updated_at) AS last_update",
		"FROM cve_database",
		"GROUP BY source",
		"type CveSourceFreshnessStats struct",
	} {
		if !strings.Contains(body, want) && !strings.Contains(fn, want) {
			t.Fatalf("source freshness stats missing %q", want)
		}
	}
	for _, disallowed := range []string{
		"jsonb_array_elements",
		"cveSourceMatchablePredicateSQL",
		"affected_products",
	} {
		if strings.Contains(fn, disallowed) {
			t.Fatalf("source freshness stats must avoid heavy quality scan %q: %s", disallowed, fn)
		}
	}
}

func TestCveEnrichmentUsesSafeFixedVersionRules(t *testing.T) {
	for name, got := range map[string]string{
		"contextual": cveContextualFixedVersionSQL("c", "v"),
		"safe":       cveSafeFixedVersionSQL("c"),
		"fixed":      cveFixedVersionSQL("c"),
		"affected":   cveAffectedPackageFixedVersionSQL("ap"),
	} {
		for _, want := range []string{
			"jsonb_array_length",
			"= 1",
			"ranges[*].events[*].fixed",
		} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s CVE fixed enrichment missing %q: %s", name, want, got)
			}
		}
		if strings.Contains(got, "jsonb_array_length(ap->'fixed') > 0") ||
			strings.Contains(got, "affected_products->0->'fixed'->>0") && !strings.Contains(got, "jsonb_array_length") {
			t.Fatalf("%s CVE fixed enrichment can select ambiguous fixed versions: %s", name, got)
		}
	}
}

func TestCveAffectedPackageIndexUsesSharedFixedVersionRules(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, fnName := range []string{
		"insertCveAffectedPackagesTx",
		"RefreshCveAffectedPackagesForCveTx",
		"RebuildCveAffectedPackages",
	} {
		start := strings.Index(body, "func (db *DB) "+fnName)
		if start < 0 {
			t.Fatalf("%s not found", fnName)
		}
		next := strings.Index(body[start+1:], "\nfunc ")
		if next < 0 {
			t.Fatalf("%s body end not found", fnName)
		}
		fn := body[start : start+1+next]
		if !strings.Contains(fn, `fixedExpr := cveAffectedPackageFixedVersionSQL("ap")`) {
			t.Fatalf("%s must use shared affected-package fixed version SQL: %s", fnName, fn)
		}
		if strings.Contains(fn, "jsonb_path_query_first(ap, '$.ranges[*].events[*].fixed") {
			t.Fatalf("%s must not inline affected fixed extraction: %s", fnName, fn)
		}
	}
	got := cveAffectedPackageFixedVersionSQL("ap")
	for _, want := range []string{
		"jsonb_array_length",
		"= 1",
		"$.ranges[*].events[*].fixed",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("affected-package fixed SQL missing %q: %s", want, got)
		}
	}
}

func TestCveAffectedPackageIndexRowsAreListable(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"type CveAffectedPackage struct",
		`json:"package_name"`,
		`json:"fixed_version"`,
		"func (db *DB) ListCveAffectedPackages",
		"SELECT count(*) FROM cve_affected_packages WHERE cve_id=$1",
		"FROM cve_affected_packages",
		"WHERE cve_id=$1",
		"ORDER BY package_name, ecosystem, fixed_version",
		"LIMIT $2 OFFSET $3",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("affected package index listing missing %q", want)
		}
	}
}

func TestCveAffectedPackageIndexStatsUsesSingleMatchableSourcePass(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCveAffectedPackageIndexStats")
	if start < 0 {
		t.Fatal("GetCveAffectedPackageIndexStats not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetCveAffectedPackageIndexHealthStats")
	if end < 0 {
		t.Fatal("GetCveAffectedPackageIndexStats end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"WITH affected_index AS",
		"matchable_sources AS",
		"array_agg(ms.source ORDER BY ms.source)",
		"pq.Array(&stats.MissingMatchableSources)",
		"sum(matchable_cves)",
		"max(latest_matchable_update)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("affected index stats missing %q: %s", want, fn)
		}
	}
	if strings.Count(fn, "cveSourceMatchablePredicateSQL") != 1 {
		t.Fatalf("affected index stats should build the matchable predicate once: %s", fn)
	}
}

func TestRemoveStaleRematchedVulnerabilitiesUsesSourceQualityFixedPredicate(t *testing.T) {
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
	if !strings.Contains(fn, "cveSourceFixedPredicateSQL()") {
		t.Fatalf("stale rematch cleanup must reuse source fixed-quality predicate: %s", fn)
	}
	if strings.Contains(fn, "jsonb_array_length(ap->'fixed') > 0") {
		t.Fatalf("stale rematch cleanup must not keep ambiguous multi-fixed entries: %s", fn)
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
		"ScannedCandidates",
		"compatible > opts.CandidateLimit",
		"JOIN cve_affected_packages cap",
		"cap.package_name = lower(p.name)",
		"cap.ecosystem = %s",
		"JOIN cve_database c ON c.id = cap.cve_id",
		"result.Limited = true",
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
		"ScannedCandidates",
		"scanned_candidates",
		"EligibleSources",
		"eligible_sources,omitempty",
		"ExcludedSources",
		"excluded_sources,omitempty",
		"SourcePolicy",
		"source_policy,omitempty",
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
		`{table: "hosts", column: "agent_token_hash"}`,
		`{table: "packages", column: "asset_type"}`,
		`{table: "packages", column: "purl"}`,
		`{table: "vulnerabilities", column: "pkg_path"}`,
		`{table: "vulnerabilities", column: "finding_source"}`,
		`{table: "cve_database", column: "category"}`,
		`{table: "cve_database", column: "epss_score"}`,
		`{table: "cve_reference_keys"}`,
		`{table: "container_assets"}`,
		`{table: "scan_requests", column: "claimed_by_host_id"}`,
		`{table: "scan_requests", column: "security_db_revision"}`,
		`{table: "audit_logs"}`,
		`{table: "vulnerability_triage"}`,
		`{index: "idx_scan_requests_pending_security_db_host"}`,
		`{index: "idx_vulnerabilities_package_scan_vuln"}`,
		`{index: "idx_vulnerabilities_finding_source"}`,
		`{index: "idx_cve_reference_keys_key"}`,
		"db.columnExists",
		"db.indexExists",
		"db.tableExists",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("legacy schema completeness check missing %q: %s", want, fn)
		}
	}
}

func TestHostAgentTokenBindingPersistence(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"ErrAgentHostTokenMismatch",
		"UpsertHostWithAgentToken",
		"agent_token_hash <> '' AS agent_token_set",
		"&h.AgentTokenSet",
		"agent_token_hash=CASE WHEN hosts.agent_token_hash=''",
		"WHERE $12='' OR hosts.agent_token_hash='' OR hosts.agent_token_hash=$12",
		"VerifyOrBindHostAgentToken",
		"agent_token_hash=CASE WHEN agent_token_hash=''",
		"ResetHostAgentToken",
		"UPDATE hosts SET agent_token_hash=''",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host agent token binding missing %q", want)
		}
	}

	migration, err := os.ReadFile("../../../migrations/019_host_agent_token_hash.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationBody := string(migration)
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS agent_token_hash",
		"idx_hosts_agent_token_hash",
	} {
		if !strings.Contains(migrationBody, want) {
			t.Fatalf("host agent token migration missing %q: %s", want, migrationBody)
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
	errs := []error{ErrInvalidScanRequestStatus, ErrScanRequestNotFound, ErrScanRequestNotActive, ErrScanRequestClaimMismatch, ErrScanRequestNotRetryable}
	for i := range errs {
		for j := i + 1; j < len(errs); j++ {
			if errs[i] == errs[j] {
				t.Fatal("scan request completion errors must be distinct")
			}
		}
	}
}

func TestRequeueScanRequestOnlyRetriesTerminalRequests(t *testing.T) {
	dbFile, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(dbFile)
	start := strings.Index(body, "func (db *DB) RequeueScanRequest")
	if start < 0 {
		t.Fatal("RequeueScanRequest not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CompleteClaimedScanRequest")
	if end < 0 {
		t.Fatal("RequeueScanRequest end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"status IN ('failed','degraded','cancelled')",
		"SET status='pending'",
		"claimed_at=NULL",
		"claimed_by_host_id=''",
		"completed_at=NULL",
		"ErrScanRequestNotRetryable",
		"pending.scan_type='security-db-update'",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan request requeue handling missing %q: %s", want, fn)
		}
	}
}

func TestFilteredRequeueRequiresTerminalRequestsAndFilters(t *testing.T) {
	dbFile, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(dbFile)
	start := strings.Index(body, "func (db *DB) RequeueScanRequestsByFilter")
	if start < 0 {
		t.Fatal("RequeueScanRequestsByFilter not found")
	}
	end := strings.Index(body[start:], "func (db *DB) CompleteClaimedScanRequest")
	if end < 0 {
		t.Fatal("RequeueScanRequestsByFilter end not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"status IN ('failed','degraded','cancelled')",
		"host_id=$%d",
		"status=$%d",
		"scan_type=$%d",
		"security_db_revision=$%d",
		"SET status='pending'",
		"pending.scan_type='security-db-update'",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("filtered scan request requeue handling missing %q: %s", want, fn)
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
	if !strings.Contains(string(agentFile), "scanRequestCompletionFromReport") || !strings.Contains(string(agentFile), `"degraded"`) {
		t.Fatal("agent daemon must propagate degraded report status to scan request completion")
	}
}

func TestUpsertCveEntriesFailsWholeBatchOnAnyInsertError(t *testing.T) {
	fn := "upsertCveEntriesTx"
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

func TestBulkCveAffectedPackageRefreshCanScopeBySource(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"func (db *DB) UpsertCveEntriesWithoutAffectedIndexTx",
		"func (db *DB) RefreshCveAffectedPackagesForSourceTx",
		"LatestMatchableUpdate",
		"stats.Stale",
		"max(c.updated_at)",
		"DELETE FROM cve_affected_packages cap",
		"AND c.source = $1",
		"return db.insertCveAffectedPackagesTx(ctx, tx, source)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("bulk affected package index refresh missing %q", want)
		}
	}
}

func TestCveReferenceKeyIndexIsMaintainedAndIndexed(t *testing.T) {
	migration, err := os.ReadFile("../../../migrations/024_cve_reference_keys.sql")
	if err != nil {
		t.Fatal(err)
	}
	migrationBody := string(migration)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS cve_reference_keys",
		"cve_id TEXT NOT NULL",
		"REFERENCES cve_database(id) ON DELETE CASCADE",
		"PRIMARY KEY (cve_id, reference_key)",
		"idx_cve_reference_keys_key",
	} {
		if !strings.Contains(migrationBody, want) {
			t.Fatalf("CVE reference key migration missing %q: %s", want, migrationBody)
		}
	}

	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"RefreshCveReferenceKeysForCveTx",
		"RebuildCveReferenceKeys",
		"EnsureCveReferenceKeys",
		"GetCveReferenceKeyIndexStats",
		"SELECT id, vulnerability_id, title, description, refs::text FROM cve_database",
		"DELETE FROM cve_reference_keys",
		`pq.CopyIn("cve_reference_keys"`,
		"INSERT INTO cve_reference_keys",
		"cveReferenceKeys(e)",
		"JOIN cve_reference_keys crk",
		"crk.reference_key = k.reference_key",
		"CoveragePercent",
		"LatestCVEUpdate",
		"reference_key LIKE 'cve:%'",
		"reference_key LIKE 'vendor:%'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("CVE reference key index support missing %q", want)
		}
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

func TestRetentionPruneResultCarriesCutoffs(t *testing.T) {
	result := RetentionPruneResult{
		ScanCutoff:    "2026-01-01T00:00:00Z",
		RequestCutoff: "2026-02-01T00:00:00Z",
		AuditCutoff:   "2026-03-01T00:00:00Z",
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"scan_cutoff"`, `"request_cutoff"`, `"audit_cutoff"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("retention prune result missing cutoff field %q: %s", want, data)
		}
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

func TestVulnerabilityRowsExposePackageContext(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	modelOut, err := os.ReadFile("../../shared/models/models.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out) + string(modelOut)
	for _, want := range []string{
		"(SELECT p.asset_type FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.pkg_type FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.ecosystem FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.container_id FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.image_name FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.image_id FROM packages p WHERE p.id = v.package_id)",
		"(SELECT p.target FROM packages p WHERE p.id = v.package_id)",
		"var vulnAdvisorySourcesExpr",
		"var vulnAdvisoryEvidenceExpr",
		"jsonb_agg(jsonb_build_object",
		"'fixed_version'",
		"c.source NOT IN ('cisa-kev', 'epss')",
		"jsonb_array_elements",
		"JOIN packages source_pkg",
		"affectedProductEcosystemSQL(\"c\", \"ap\")",
		"packageEcosystemSQL(\"source_pkg\")",
		"cveSourceFixedPredicateSQL()",
		"&v.AssetType",
		"&v.PkgType",
		"&v.Ecosystem",
		"&v.ContainerID",
		"&v.ImageName",
		"&v.ImageID",
		"&v.Target",
		"pq.Array(&v.AdvisorySources)",
		"json.Unmarshal([]byte(advisoryEvidence.String), &v.AdvisoryEvidence)",
		`json:"asset_type`,
		`json:"pkg_type`,
		`json:"ecosystem`,
		`json:"container_id`,
		`json:"image_name`,
		`json:"image_id`,
		`json:"target`,
		`json:"advisory_sources`,
		`json:"advisory_evidence`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("vulnerability package context missing %q", want)
		}
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
	if !strings.Contains(filterDef, "RiskLevel     string") {
		t.Fatalf("VulnFilter missing risk level: %s", filterDef)
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
	if !strings.Contains(fn, "vulnRiskLevelExpr") {
		t.Fatalf("risk level filter SQL missing: %s", fn)
	}
}

func TestListVulnerabilitiesExposesCisaKevPrioritization(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, want := range []string{
		"Exploited     bool",
		"MinEPSS       float64",
		"MinEPSSPct    float64",
		"&v.Exploited",
		"&v.EPSSScore",
		"&v.EPSSPercentile",
		"&v.RiskScore",
		"&v.RiskLevel",
		`kev.source = 'cisa-kev'`,
		`MAX(cve.epss_score)`,
		`MAX(cve.epss_percentile)`,
		`kev.vulnerability_id = v.vulnerability_id`,
		"if f.Exploited",
		"if f.MinEPSS > 0",
		"if f.MinEPSSPct > 0",
		`"exploited":`,
		`"epss_score":`,
		`"risk_score":`,
		`"risk_level":`,
		"vulnRiskScoreExpr",
		"vulnRiskLevelExpr",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ListVulnerabilities KEV prioritization missing %q", want)
		}
	}
}

func TestCveDatabaseStoresEPSSPriorityColumns(t *testing.T) {
	bodyBytes, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	migration, err := os.ReadFile("../../../migrations/020_cve_epss.sql")
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyBytes)
	migrationBody := string(migration)
	for _, want := range []string{
		"epss_score",
		"epss_percentile",
		"&e.EPSSScore",
		"&e.EPSSPercentile",
		"epss_score=EXCLUDED.epss_score",
		"epss_percentile=EXCLUDED.epss_percentile",
		"func (db *DB) SyncEPSSPriorityColumnsTx",
		"func (db *DB) GetCveEPSSMergeStats",
		"type CveEPSSMergeStats struct",
		"MergeCoveragePercent",
		"source = 'epss'",
		"c.source != 'epss'",
		"latest_epss",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("CVE DB EPSS support missing %q", want)
		}
	}
	for _, want := range []string{
		"ADD COLUMN IF NOT EXISTS epss_score",
		"ADD COLUMN IF NOT EXISTS epss_percentile",
		"idx_cve_db_epss_score",
		"idx_cve_db_epss_percentile",
	} {
		if !strings.Contains(migrationBody, want) {
			t.Fatalf("EPSS migration missing %q: %s", want, migrationBody)
		}
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
		"vulnRiskLevelExpr",
		"riskCritical",
		`"critical": riskCritical`,
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("vuln summary active filter missing %q: %s", want, fn)
		}
	}
}

func TestStatsCanCountCurrentActionableRiskByHost(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCurrentActionableVulnRiskCountsByHost")
	if start < 0 {
		t.Fatal("GetCurrentActionableVulnRiskCountsByHost not found")
	}
	end := strings.Index(body[start:], "func vulnSummaryGroupExpr")
	if end < 0 {
		t.Fatal("vulnSummaryGroupExpr not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"currentActionableVulnSQL()",
		"JOIN ` + latestScansSub",
		"vulnRiskLevelExpr",
		"GROUP BY v.host_id, risk_level",
		"v.host_id = ANY($1)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("active risk count query missing %q: %s", want, fn)
		}
	}
}

func TestStatsCanCountCurrentActionableOverdueRiskByHost(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCurrentActionableOverdueRiskCountsByHost")
	if start < 0 {
		t.Fatal("GetCurrentActionableOverdueRiskCountsByHost not found")
	}
	end := strings.Index(body[start:], "func vulnSummaryGroupExpr")
	if end < 0 {
		t.Fatal("vulnSummaryGroupExpr not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"currentActionableVulnSQL()",
		"overdueSQLCondition()",
		"JOIN ` + latestScansSub",
		"vulnRiskLevelExpr",
		"GROUP BY v.host_id, risk_level",
		"v.host_id = ANY($1)",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("overdue risk count query missing %q: %s", want, fn)
		}
	}
}

func TestScanWebhookCanCountRiskByScan(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetVulnRiskCountsByScan")
	if start < 0 {
		t.Fatal("GetVulnRiskCountsByScan not found")
	}
	end := strings.Index(body[start:], "func (db *DB) GetLatestPackages")
	if end < 0 {
		t.Fatal("GetLatestPackages not found")
	}
	fn := body[start : start+end]
	for _, want := range []string{
		"vulnRiskLevelExpr",
		"JOIN hosts h ON h.id = v.host_id",
		"WHERE v.scan_id=$1",
		"GROUP BY risk_level",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("scan risk count query missing %q: %s", want, fn)
		}
	}
}

func TestTriageLifecycleCountsForMetrics(t *testing.T) {
	out, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	for _, fnName := range []string{"CountVulnerabilityTriageByStatus", "CountVulnerabilityTriageExpiringSoonByStatus"} {
		start := strings.Index(body, "func (db *DB) "+fnName)
		if start < 0 {
			t.Fatalf("%s not found", fnName)
		}
		end := strings.Index(body[start+1:], "\nfunc ")
		if end < 0 {
			t.Fatalf("%s end not found", fnName)
		}
		fn := body[start : start+1+end]
		for _, want := range []string{
			"vulnerability_triage",
			"expires_at",
			"status",
			"count(*)::int",
		} {
			if !strings.Contains(fn, want) {
				t.Fatalf("%s missing %q: %s", fnName, want, fn)
			}
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
