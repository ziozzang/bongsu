package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Finding-report persistence: the `report` scenario emits a CVE-grade report with
// a stable dedup_key. We persist it keyed UNIQUE by dedup_key so re-reporting the
// same finding collapses onto one row (bumping seen_count/last_seen) instead of
// leaving ephemeral per-run outputs. Persistence is best-effort — a failure here
// never fails the run (the raw output is already in intel_runs).

// FindingReport is a persisted, deduplicated report row.
type FindingReport struct {
	ID          int64           `json:"id"`
	DedupKey    string          `json:"dedup_key"`
	Finding     string          `json:"finding"`
	Summary     string          `json:"summary"`
	Severity    string          `json:"severity"`
	CVSS        *float64        `json:"cvss,omitempty"`
	Report      json.RawMessage `json:"report"`
	RunID       string          `json:"run_id,omitempty"`
	PrincipalID string          `json:"principal_id,omitempty"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	SeenCount   int             `json:"seen_count"`
}

// FindingReportInput is the normalized upsert payload.
type FindingReportInput struct {
	DedupKey    string
	Finding     string
	Summary     string
	Severity    string
	CVSS        *float64
	Report      json.RawMessage
	RunID       string
	PrincipalID string
}

// FindingReportFilter narrows a list query.
type FindingReportFilter struct {
	Limit    int
	Offset   int
	Severity string
	Finding  string
}

// FindingReportList is the paginated list result.
type FindingReportList struct {
	Reports []FindingReport `json:"reports"`
	Limit   int             `json:"limit"`
	Offset  int             `json:"offset"`
	Total   int             `json:"total"`
}

// maybePersistReport persists a report-scenario output when the run completed with
// a schema-valid response. It is a no-op for every other scenario. Returns the
// persisted row (or nil) — the caller surfaces it on the outcome but never fails
// the run on a persistence error.
func (s *Service) maybePersistReport(ctx context.Context, scenario, runID, principalID, response string, outputValid bool, status string) *FindingReport {
	if scenario != "report" || !outputValid || (status != "" && status != "completed") {
		return nil
	}
	fr, err := s.persistReportOutput(ctx, runID, principalID, response)
	if err != nil {
		// Best-effort: the raw output is already in intel_runs.
		return nil
	}
	return fr
}

// persistReportOutput extracts the report fields from the model's response,
// normalizes the dedup key (with a server-computed fallback), and upserts.
func (s *Service) persistReportOutput(ctx context.Context, runID, principalID, response string) (*FindingReport, error) {
	obj, ok := extractJSONObject(response)
	if !ok {
		return nil, fmt.Errorf("report response is not a JSON object")
	}
	finding := extractString(obj, "finding")
	if finding == "" {
		return nil, fmt.Errorf("report has no finding")
	}
	dedup := normalizeDedupKey(extractString(obj, "dedup_key"))
	if dedup == "" {
		dedup = fallbackDedupKey(obj)
	}
	if dedup == "" {
		return nil, fmt.Errorf("could not derive a dedup key")
	}
	summary := extractString(obj, "summary")
	if summary == "" {
		summary = finding
	}
	// Persist the report object as-is (the model's structured output).
	raw := json.RawMessage(response)
	if canonical, err := json.Marshal(obj); err == nil {
		raw = canonical
	}
	return s.store.UpsertFindingReport(ctx, FindingReportInput{
		DedupKey:    dedup,
		Finding:     truncate(finding, 500),
		Summary:     truncate(summary, 2000),
		Severity:    canonicalizeSeverity(extractString(obj, "severity")),
		CVSS:        extractCVSS(obj, "cvss"),
		Report:      raw,
		RunID:       runID,
		PrincipalID: principalID,
	})
}

// ListFindingReports / GetFindingReport expose the persisted reports to the API.
func (s *Service) ListFindingReports(ctx context.Context, f FindingReportFilter) (FindingReportList, error) {
	if s == nil || s.store == nil {
		return FindingReportList{}, ErrBackboneDisabled
	}
	return s.store.ListFindingReports(ctx, f)
}

func (s *Service) GetFindingReport(ctx context.Context, dedupKey string) (FindingReport, error) {
	if s == nil || s.store == nil {
		return FindingReport{}, ErrBackboneDisabled
	}
	return s.store.GetFindingReportByDedupKey(ctx, normalizeDedupKey(dedupKey))
}

var dedupDisallowed = regexp.MustCompile(`[^a-z0-9._:/@+\- ]`)

// normalizeDedupKey makes an LLM-generated dedup key stable and storable:
// trim, lowercase, collapse whitespace, restrict the charset, and hash-cap very
// long keys so the same finding always maps to the same row.
func normalizeDedupKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if r < 0x20 || unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		b.WriteRune(r)
		prevSpace = false
	}
	s = dedupDisallowed.ReplaceAllString(b.String(), "-")
	s = strings.Trim(s, " -:._/")
	const maxLen = 240
	if len(s) > maxLen {
		h := sha256.Sum256([]byte(s))
		s = s[:200] + ":sha256:" + hex.EncodeToString(h[:])[:24]
	}
	return s
}

// fallbackDedupKey derives a stable key from the finding (+ first affected
// package) when the model omits or empties dedup_key. Prefixed "auto:" so a
// generated key is distinguishable from a model-supplied one.
func fallbackDedupKey(report map[string]any) string {
	finding := extractString(report, "finding")
	if finding == "" {
		return ""
	}
	pkg := ""
	if arr, ok := report["affected_assets"].([]any); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]any); ok {
			pkg = extractString(first, "package")
		}
	}
	h := sha256.Sum256([]byte(strings.ToLower(finding) + "|" + strings.ToLower(pkg)))
	return "auto:" + hex.EncodeToString(h[:])[:16]
}

// canonicalizeSeverity maps free-form model severity to the DB's enum.
func canonicalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "none":
		return "info"
	default:
		return "unknown"
	}
}

func extractString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// extractCVSS reads a 0..10 score from a number or numeric string; anything out
// of range or unparseable yields nil (stored as NULL).
func extractCVSS(m map[string]any, key string) *float64 {
	var f float64
	switch v := m[key].(type) {
	case float64:
		f = v
	case json.Number:
		p, err := v.Float64()
		if err != nil {
			return nil
		}
		f = p
	case string:
		p, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err != nil {
			return nil
		}
		f = p
	default:
		return nil
	}
	if f < 0 || f > 10 {
		return nil
	}
	return &f
}
