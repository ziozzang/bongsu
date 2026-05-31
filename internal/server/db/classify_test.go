package db

import (
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
