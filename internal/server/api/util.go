package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any, allowEmpty bool) error {
	if r.Body == nil {
		if allowEmpty {
			return nil
		}
		return io.EOF
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes())
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(dst)
	if err == io.EOF && allowEmpty {
		return nil
	}
	if err != nil {
		return err
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid trailing json")
	}
	return nil
}

func writeJSONBodyError(w http.ResponseWriter, err error, fallback string) {
	var maxBytesErr *http.MaxBytesError
	if errors.As(err, &maxBytesErr) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	writeError(w, http.StatusBadRequest, fallback)
}

func intParam(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

func boolQuery(r *http.Request, key string) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key))) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func limitParam(r *http.Request, def int) int {
	n := intParam(r, "limit", def)
	if n <= 0 {
		n = def
	}
	maxLimit := envInt("BONGSU_API_MAX_PAGE_LIMIT", 1000)
	if maxLimit <= 0 {
		maxLimit = 1000
	}
	if n > maxLimit {
		return maxLimit
	}
	return n
}

func offsetParam(r *http.Request) int {
	n := intParam(r, "offset", 0)
	maxOffset := envInt("BONGSU_API_MAX_PAGE_OFFSET", 1000000)
	if maxOffset <= 0 {
		maxOffset = 1000000
	}
	if n > maxOffset {
		return maxOffset
	}
	return n
}

func auditTimeParam(r *http.Request, key string, endOfDay bool) (*time.Time, error) {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return &t, nil
	}
	t, err := time.Parse("2006-01-02", raw)
	if err != nil {
		return nil, fmt.Errorf("invalid %s; use RFC3339 or YYYY-MM-DD", key)
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return &t, nil
}

func floatParam(r *http.Request, key string, def float64) float64 {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	if n < 0 {
		return def
	}
	return n
}

func applyAgentStatus(h *models.Host, now time.Time) {
	if h.LastSeen.IsZero() {
		h.AgentStatus = "unknown"
		h.LastSeenAgeS = 0
		return
	}
	age := now.Sub(h.LastSeen)
	if age < 0 {
		age = 0
	}
	h.LastSeenAgeS = int64(age.Seconds())
	online := time.Duration(envInt("BONGSU_AGENT_ONLINE_MINUTES", 26*60)) * time.Minute
	offline := time.Duration(envInt("BONGSU_AGENT_OFFLINE_MINUTES", 72*60)) * time.Minute
	if offline < online {
		offline = online
	}
	switch {
	case age <= online:
		h.AgentStatus = "online"
	case age <= offline:
		h.AgentStatus = "stale"
	default:
		h.AgentStatus = "offline"
	}
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func maxAgentReportBytes() int64 {
	n := envInt("BONGSU_AGENT_REPORT_MAX_BYTES", 512<<20)
	if n <= 0 {
		n = 512 << 20
	}
	return int64(n)
}

func maxTrivyDBUploadBytes() int64 {
	return envBytes("BONGSU_TRIVY_DB_UPLOAD_MAX_BYTES", 2<<30)
}

func maxCveDBImportBytes() int64 {
	return envBytes("BONGSU_CVE_DB_IMPORT_MAX_BYTES", 2<<30)
}

func maxSecurityDBBundleBytes() int64 {
	return envBytes("BONGSU_SECURITY_DB_BUNDLE_MAX_BYTES", 4<<30)
}

func maxMultipartMemoryBytes() int64 {
	return envBytes("BONGSU_MULTIPART_MEMORY_MAX_BYTES", 32<<20)
}

func maxJSONBodyBytes() int64 {
	return envBytes("BONGSU_JSON_BODY_MAX_BYTES", 1<<20)
}

func envBytes(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func envBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envFloat(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return n
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	return cleanCSV(strings.Split(v, ","))
}

func cleanCSV(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-.")
}
