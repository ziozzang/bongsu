package api

import (
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// ---------------------------------------------------------------------------
// truncateValidUTF8
// ---------------------------------------------------------------------------

func TestTruncateValidUTF8ExactLimit(t *testing.T) {
	s := "hello"
	got := truncateValidUTF8(s, 5)
	if got != s {
		t.Fatalf("exact-limit string altered: %q", got)
	}
}

func TestTruncateValidUTF8ShorterThanLimit(t *testing.T) {
	s := "hi"
	got := truncateValidUTF8(s, 10)
	if got != s {
		t.Fatalf("short string altered: %q", got)
	}
}

func TestTruncateValidUTF8ASCIITruncation(t *testing.T) {
	s := "abcdef"
	got := truncateValidUTF8(s, 3)
	if got != "abc" {
		t.Fatalf("ASCII truncation = %q, want %q", got, "abc")
	}
}

func TestTruncateValidUTF8KoreanBoundary(t *testing.T) {
	// Each Korean rune is 3 UTF-8 bytes (U+AC00..U+D7A3).
	// "한글" = 6 bytes. Limit=5 must not split mid-rune → trim to first rune (3 bytes).
	s := "한글"
	got := truncateValidUTF8(s, 5)
	if !utf8.ValidString(got) {
		t.Fatalf("result is not valid UTF-8: %q", got)
	}
	if len(got) > 5 {
		t.Fatalf("result exceeds limit: len=%d", len(got))
	}
	if got != "한" {
		t.Fatalf("Korean truncation = %q, want %q", got, "한")
	}
}

func TestTruncateValidUTF8EmojiMidRuneCut(t *testing.T) {
	// 😀 is 4 UTF-8 bytes. Limit=3 must back off to empty string rather than
	// leaving an invalid sequence.
	s := "😀"
	got := truncateValidUTF8(s, 3)
	if !utf8.ValidString(got) {
		t.Fatalf("emoji mid-rune cut is not valid UTF-8: %q", got)
	}
	if len(got) > 3 {
		t.Fatalf("result exceeds limit: len=%d", len(got))
	}
}

func TestTruncateValidUTF8MixedContent(t *testing.T) {
	// "abc한" = 3 + 3 = 6 bytes. Limit=4 must produce "abc" (3 bytes) not
	// "abc" + first byte of 한 (invalid).
	s := "abc한"
	got := truncateValidUTF8(s, 4)
	if !utf8.ValidString(got) {
		t.Fatalf("mixed truncation not valid UTF-8: %q", got)
	}
	if len(got) > 4 {
		t.Fatalf("result exceeds limit: len=%d", len(got))
	}
	if got != "abc" {
		t.Fatalf("mixed truncation = %q, want %q", got, "abc")
	}
}

// ---------------------------------------------------------------------------
// scanErrorSummary
// ---------------------------------------------------------------------------

func TestScanErrorSummaryEmpty(t *testing.T) {
	if got := scanErrorSummary(nil); got != "" {
		t.Fatalf("empty errors should return empty summary, got %q", got)
	}
	if got := scanErrorSummary([]string{}); got != "" {
		t.Fatalf("nil-like empty slice should return empty summary, got %q", got)
	}
}

func TestScanErrorSummarySingleError(t *testing.T) {
	got := scanErrorSummary([]string{"packages: boom"})
	if !strings.HasPrefix(got, "1 error(s): ") {
		t.Fatalf("single error summary = %q, want prefix '1 error(s): '", got)
	}
	if !strings.Contains(got, "packages: boom") {
		t.Fatalf("single error summary missing error text: %q", got)
	}
}

func TestScanErrorSummaryMultipleErrors(t *testing.T) {
	errs := []string{"packages: oops", "users: nope"}
	got := scanErrorSummary(errs)
	if !strings.HasPrefix(got, "2 error(s): ") {
		t.Fatalf("multi error summary = %q, want prefix '2 error(s): '", got)
	}
	for _, e := range errs {
		if !strings.Contains(got, e) {
			t.Fatalf("summary missing %q: %q", e, got)
		}
	}
}

func TestScanErrorSummaryTruncatesLongSummary(t *testing.T) {
	// Build a summary that will exceed 512 bytes.
	longErr := strings.Repeat("x", 200)
	errs := []string{longErr, longErr, longErr}
	got := scanErrorSummary(errs)
	if len(got) > 512+len("...(truncated)") {
		t.Fatalf("summary too long: len=%d", len(got))
	}
	if !strings.HasSuffix(got, "...(truncated)") {
		t.Fatalf("long summary should end with ...(truncated): %q", got)
	}
	if !utf8.ValidString(got) {
		t.Fatalf("truncated summary is not valid UTF-8")
	}
}

// ---------------------------------------------------------------------------
// normalizePackageAssetContext
// ---------------------------------------------------------------------------

func TestNormalizePackageAssetContextHostPackage(t *testing.T) {
	pkg := models.Package{Name: "openssl", Version: "3.0.13"}
	err := normalizePackageAssetContext(&pkg, "host-1", nil, nil)
	if err != nil {
		t.Fatalf("host package context error: %v", err)
	}
	if pkg.AssetType != "host" {
		t.Fatalf("asset_type = %q, want host", pkg.AssetType)
	}
	if pkg.AssetID != "host-1" {
		t.Fatalf("asset_id = %q, want host-1", pkg.AssetID)
	}
}

func TestNormalizePackageAssetContextHostPackageExplicitType(t *testing.T) {
	pkg := models.Package{Name: "openssl", Version: "3.0.13", AssetType: "host"}
	err := normalizePackageAssetContext(&pkg, "host-42", nil, nil)
	if err != nil {
		t.Fatalf("explicit host type error: %v", err)
	}
	if pkg.AssetType != "host" || pkg.AssetID != "host-42" {
		t.Fatalf("host package = (%q, %q), want host/host-42", pkg.AssetType, pkg.AssetID)
	}
}

func TestNormalizePackageAssetContextContainerByName(t *testing.T) {
	pkg := models.Package{
		Name:      "lodash",
		Container: " api ",
	}
	byName := map[string]models.ContainerAsset{
		"api": {
			Name:        "api",
			ContainerID: "container-1",
			ImageName:   "registry/api:1.0",
			ImageID:     "sha256:abc",
		},
	}
	err := normalizePackageAssetContext(&pkg, "host-1", byName, nil)
	if err != nil {
		t.Fatalf("container-by-name error: %v", err)
	}
	if pkg.AssetType != "container" {
		t.Fatalf("asset_type = %q, want container", pkg.AssetType)
	}
	if pkg.ContainerID != "container-1" {
		t.Fatalf("container_id = %q, want container-1", pkg.ContainerID)
	}
	if pkg.ImageName != "registry/api:1.0" {
		t.Fatalf("image_name = %q, want registry/api:1.0", pkg.ImageName)
	}
	if pkg.AssetID != "container-1" {
		t.Fatalf("asset_id = %q, want container-1", pkg.AssetID)
	}
}

func TestNormalizePackageAssetContextContainerByID(t *testing.T) {
	pkg := models.Package{
		Name:        "debug",
		ContainerID: " cid-99 ",
	}
	byID := map[string]models.ContainerAsset{
		"cid-99": {
			Name:        "svc",
			ContainerID: "cid-99",
			ImageName:   "registry/svc:2.0",
			ImageID:     "sha256:def",
		},
	}
	err := normalizePackageAssetContext(&pkg, "host-1", nil, byID)
	if err != nil {
		t.Fatalf("container-by-id error: %v", err)
	}
	if pkg.AssetType != "container" {
		t.Fatalf("asset_type = %q, want container", pkg.AssetType)
	}
	if pkg.Container != "svc" {
		t.Fatalf("container name = %q, want svc", pkg.Container)
	}
}

func TestNormalizePackageAssetContextInvalidType(t *testing.T) {
	pkg := models.Package{Name: "openssl", AssetType: "service"}
	err := normalizePackageAssetContext(&pkg, "host-1", nil, nil)
	if err == nil {
		t.Fatal("invalid asset_type should return error")
	}
}

func TestNormalizePackageAssetContextContainerByImageName(t *testing.T) {
	// A package that only carries image_name hint should default to container type.
	pkg := models.Package{Name: "openssl", ImageName: "alpine:3.18"}
	err := normalizePackageAssetContext(&pkg, "host-1", nil, nil)
	if err != nil {
		t.Fatalf("image-name-only container package error: %v", err)
	}
	if pkg.AssetType != "container" {
		t.Fatalf("asset_type = %q, want container", pkg.AssetType)
	}
}

func TestNormalizePackageAssetContextContainerFallsBackToNameForAssetID(t *testing.T) {
	// ContainerID is empty; asset_id should fall back to Container name.
	pkg := models.Package{Name: "openssl", AssetType: "container", Container: "mybox"}
	err := normalizePackageAssetContext(&pkg, "host-1", nil, nil)
	if err != nil {
		t.Fatalf("container name fallback error: %v", err)
	}
	if pkg.AssetID != "mybox" {
		t.Fatalf("asset_id fallback = %q, want mybox", pkg.AssetID)
	}
}

// ---------------------------------------------------------------------------
// normalizeVulnerabilityAssetContext
// ---------------------------------------------------------------------------

func TestNormalizeVulnerabilityAssetContextHostDefault(t *testing.T) {
	v := models.Vulnerability{VulnerabilityID: "CVE-2026-0001"}
	err := normalizeVulnerabilityAssetContext(&v, nil, nil)
	if err != nil {
		t.Fatalf("host vuln default error: %v", err)
	}
	// Empty asset_type is valid for host vulnerabilities.
	if v.AssetType != "" {
		t.Fatalf("asset_type = %q, want empty", v.AssetType)
	}
}

func TestNormalizeVulnerabilityAssetContextHostExplicit(t *testing.T) {
	v := models.Vulnerability{VulnerabilityID: "CVE-2026-0001", AssetType: "host"}
	err := normalizeVulnerabilityAssetContext(&v, nil, nil)
	if err != nil {
		t.Fatalf("explicit host vuln error: %v", err)
	}
	if v.AssetType != "host" {
		t.Fatalf("asset_type = %q, want host", v.AssetType)
	}
}

func TestNormalizeVulnerabilityAssetContextContainerFromContainerIDField(t *testing.T) {
	// Having a container_id with no explicit asset_type should infer "container".
	v := models.Vulnerability{VulnerabilityID: "CVE-2026-0002", ContainerID: " cid-1 "}
	byID := map[string]models.ContainerAsset{
		"cid-1": {
			Name:        "web",
			ContainerID: "cid-1",
			ImageName:   "registry/web:3.0",
			ImageID:     "sha256:ghi",
		},
	}
	err := normalizeVulnerabilityAssetContext(&v, nil, byID)
	if err != nil {
		t.Fatalf("container vuln from ContainerID error: %v", err)
	}
	if v.AssetType != "container" {
		t.Fatalf("asset_type = %q, want container", v.AssetType)
	}
	if v.ImageName != "registry/web:3.0" {
		t.Fatalf("image_name = %q, want registry/web:3.0", v.ImageName)
	}
}

func TestNormalizeVulnerabilityAssetContextInvalidType(t *testing.T) {
	v := models.Vulnerability{VulnerabilityID: "CVE-2026-0003", AssetType: "service"}
	err := normalizeVulnerabilityAssetContext(&v, nil, nil)
	if err == nil {
		t.Fatal("invalid asset_type should return error")
	}
}

// ---------------------------------------------------------------------------
// applyContainerContext
// ---------------------------------------------------------------------------

func TestApplyContainerContextByID(t *testing.T) {
	name, cid, imgName, imgID := "", "cid-1", "", ""
	byName := map[string]models.ContainerAsset{}
	byID := map[string]models.ContainerAsset{
		"cid-1": {
			Name:        "api",
			ContainerID: "cid-1",
			ImageName:   "registry/api:1.0",
			ImageID:     "sha256:abc",
		},
	}
	applyContainerContext(&name, &cid, &imgName, &imgID, byName, byID)
	if name != "api" {
		t.Fatalf("name = %q, want api", name)
	}
	if imgName != "registry/api:1.0" {
		t.Fatalf("image_name = %q, want registry/api:1.0", imgName)
	}
	if imgID != "sha256:abc" {
		t.Fatalf("image_id = %q, want sha256:abc", imgID)
	}
}

func TestApplyContainerContextByName(t *testing.T) {
	name, cid, imgName, imgID := "svc", "", "", ""
	byName := map[string]models.ContainerAsset{
		"svc": {
			Name:        "svc",
			ContainerID: "cid-99",
			ImageName:   "registry/svc:2.0",
			ImageID:     "sha256:def",
		},
	}
	applyContainerContext(&name, &cid, &imgName, &imgID, byName, nil)
	if cid != "cid-99" {
		t.Fatalf("container_id = %q, want cid-99", cid)
	}
	if imgName != "registry/svc:2.0" {
		t.Fatalf("image_name = %q, want registry/svc:2.0", imgName)
	}
}

func TestApplyContainerContextNoMatch(t *testing.T) {
	name, cid, imgName, imgID := "unknown", "", "", ""
	applyContainerContext(&name, &cid, &imgName, &imgID, nil, nil)
	// Nothing should be changed when the container is not found.
	if name != "unknown" || cid != "" || imgName != "" || imgID != "" {
		t.Fatalf("unexpected mutation: name=%q cid=%q imgName=%q imgID=%q", name, cid, imgName, imgID)
	}
}

func TestApplyContainerContextDoesNotOverwriteExistingFields(t *testing.T) {
	// When fields are already set, applyContainerContext must not overwrite them.
	name, cid, imgName, imgID := "api", "cid-1", "my-image:pinned", "sha256:local"
	byID := map[string]models.ContainerAsset{
		"cid-1": {
			Name:        "api",
			ContainerID: "cid-1",
			ImageName:   "registry/api:1.0",
			ImageID:     "sha256:remote",
		},
	}
	applyContainerContext(&name, &cid, &imgName, &imgID, nil, byID)
	if imgName != "my-image:pinned" {
		t.Fatalf("image_name was overwritten: %q", imgName)
	}
	if imgID != "sha256:local" {
		t.Fatalf("image_id was overwritten: %q", imgID)
	}
}

// ---------------------------------------------------------------------------
// cleanRequestID
// ---------------------------------------------------------------------------

func TestCleanRequestIDValidInputs(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"abc-123", "abc-123"},
		{"req_456", "req_456"},
		{"scan-req-123", "scan-req-123"},
		{"A.B:C/D", "A.B:C/D"},
		{"  req-1  ", "req-1"}, // trim whitespace
	}
	for _, tc := range cases {
		got := cleanRequestID(tc.in)
		if got != tc.want {
			t.Errorf("cleanRequestID(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCleanRequestIDInvalidInputs(t *testing.T) {
	cases := []string{
		"",
		"bad id with spaces",
		"req!id",
		"req@123",
		strings.Repeat("a", 129), // too long
	}
	for _, raw := range cases {
		got := cleanRequestID(raw)
		if got != "" {
			t.Errorf("cleanRequestID(%q) = %q, want empty", raw, got)
		}
	}
}

func TestCleanRequestIDMaxLengthBoundary(t *testing.T) {
	// Exactly 128 characters should be accepted.
	s := strings.Repeat("a", 128)
	got := cleanRequestID(s)
	if got != s {
		t.Fatalf("128-char request ID should pass, got %q", got)
	}
	// 129 characters should be rejected.
	got = cleanRequestID(s + "a")
	if got != "" {
		t.Fatalf("129-char request ID should be rejected, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// securityContentPolicy
// ---------------------------------------------------------------------------

func TestSecurityContentPolicyContainsRequiredDirectives(t *testing.T) {
	csp := securityContentPolicy()
	required := []string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"base-uri 'self'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	}
	for _, d := range required {
		if !strings.Contains(csp, d) {
			t.Errorf("CSP missing directive %q: %s", d, csp)
		}
	}
}

func TestSecurityContentPolicyIsNonEmpty(t *testing.T) {
	csp := securityContentPolicy()
	if strings.TrimSpace(csp) == "" {
		t.Fatal("CSP must not be empty")
	}
}

// ---------------------------------------------------------------------------
// autoAssignByOwnerEnabled env-default
// ---------------------------------------------------------------------------

func TestAutoAssignByOwnerEnabledUnset(t *testing.T) {
	// Unset the env var to confirm the default is true.
	t.Setenv("BONGSU_AUTO_ASSIGN_BY_OWNER", "")
	if !autoAssignByOwnerEnabled() {
		t.Fatal("auto-assign should default to enabled when env is unset")
	}
}

func TestAutoAssignByOwnerEnabledExplicitTrue(t *testing.T) {
	t.Setenv("BONGSU_AUTO_ASSIGN_BY_OWNER", "true")
	if !autoAssignByOwnerEnabled() {
		t.Fatal("auto-assign should be enabled when env=true")
	}
}

func TestAutoAssignByOwnerEnabledExplicitFalse(t *testing.T) {
	t.Setenv("BONGSU_AUTO_ASSIGN_BY_OWNER", "false")
	if autoAssignByOwnerEnabled() {
		t.Fatal("auto-assign should be disabled when env=false")
	}
}

// ---------------------------------------------------------------------------
// limitParam / offsetParam / floatParam — additional boundary cases
// ---------------------------------------------------------------------------

func TestLimitParamDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := limitParam(req, 25); got != 25 {
		t.Fatalf("missing limit should return default: got %d", got)
	}
}

func TestLimitParamNonNumeric(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=abc", nil)
	if got := limitParam(req, 20); got != 20 {
		t.Fatalf("non-numeric limit should return default: got %d", got)
	}
}

func TestLimitParamNegative(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=-5", nil)
	if got := limitParam(req, 10); got != 10 {
		t.Fatalf("negative limit should return default: got %d", got)
	}
}

func TestLimitParamZero(t *testing.T) {
	req := httptest.NewRequest("GET", "/?limit=0", nil)
	if got := limitParam(req, 15); got != 15 {
		t.Fatalf("zero limit should return default: got %d", got)
	}
}

func TestOffsetParamDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := offsetParam(req); got != 0 {
		t.Fatalf("missing offset should return 0: got %d", got)
	}
}

func TestOffsetParamNonNumeric(t *testing.T) {
	req := httptest.NewRequest("GET", "/?offset=xyz", nil)
	if got := offsetParam(req); got != 0 {
		t.Fatalf("non-numeric offset should return 0: got %d", got)
	}
}

func TestOffsetParamNegative(t *testing.T) {
	req := httptest.NewRequest("GET", "/?offset=-1", nil)
	if got := offsetParam(req); got != 0 {
		t.Fatalf("negative offset should return 0: got %d", got)
	}
}

func TestFloatParamDefault(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	if got := floatParam(req, "min_cvss", 7.5); got != 7.5 {
		t.Fatalf("missing float should return default: got %v", got)
	}
}

func TestFloatParamNonNumeric(t *testing.T) {
	req := httptest.NewRequest("GET", "/?min_cvss=high", nil)
	if got := floatParam(req, "min_cvss", 5.0); got != 5.0 {
		t.Fatalf("non-numeric float should return default: got %v", got)
	}
}

func TestFloatParamNegative(t *testing.T) {
	req := httptest.NewRequest("GET", "/?min_cvss=-1.0", nil)
	if got := floatParam(req, "min_cvss", 3.0); got != 3.0 {
		t.Fatalf("negative float should return default: got %v", got)
	}
}

func TestFloatParamValidValue(t *testing.T) {
	req := httptest.NewRequest("GET", "/?min_cvss=7.8", nil)
	if got := floatParam(req, "min_cvss", 0.0); got != 7.8 {
		t.Fatalf("valid float = %v, want 7.8", got)
	}
}

// ---------------------------------------------------------------------------
// scanFailedPayload — shape verification
// ---------------------------------------------------------------------------

func TestScanFailedPayloadShape(t *testing.T) {
	report := &models.ScanReport{
		ScanID:             "scan-42",
		ScanType:           "daily",
		ScanRequestID:      "req-100",
		SecurityDBRevision: "rev-999",
	}
	report.Host.ID = "host-99"
	report.Host.Hostname = "db01"
	report.Host.IPAddress = "192.168.1.1"

	errs := []string{"packages: boom", "users: nope"}
	summary := "2 error(s): packages: boom; users: nope"
	data := scanFailedPayload(report, "degraded", summary, errs)

	requiredKeys := []string{
		"scan_id", "scan_status", "host_id", "hostname", "ip_address",
		"scan_type", "scan_request_id", "security_db_revision",
		"error_summary", "ingest_errors", "ingest_error_count",
	}
	for _, k := range requiredKeys {
		if _, ok := data[k]; !ok {
			t.Errorf("scanFailedPayload missing key %q", k)
		}
	}

	if data["scan_id"] != "scan-42" {
		t.Errorf("scan_id = %v", data["scan_id"])
	}
	if data["host_id"] != "host-99" {
		t.Errorf("host_id = %v", data["host_id"])
	}
	if data["scan_status"] != "degraded" {
		t.Errorf("scan_status = %v", data["scan_status"])
	}
	if data["ingest_error_count"] != len(errs) {
		t.Errorf("ingest_error_count = %v, want %d", data["ingest_error_count"], len(errs))
	}
	if s, _ := data["error_summary"].(string); !strings.Contains(s, "packages: boom") {
		t.Errorf("error_summary missing error text: %q", s)
	}
}
