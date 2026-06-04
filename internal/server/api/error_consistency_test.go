package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestWriteErrorReturnsJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "something went wrong")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type = %q, want application/json", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "something went wrong" {
		t.Fatalf("error = %q, want %q", body["error"], "something went wrong")
	}
}

func TestNoHTTPErrorInHandlers(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"middleware.go": true,
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if allowed[name] {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), "http.Error(") {
			t.Errorf("file %s still contains http.Error() — use writeError() instead", name)
		}
	}
}

func TestDecodeJSONBodyRejectsTrailingData(t *testing.T) {
	req := httptest.NewRequest("POST", "/api/test", strings.NewReader(`{"ok":true}{"extra":true}`))
	w := httptest.NewRecorder()
	var body map[string]bool
	if err := decodeJSONBody(w, req, &body, false); err == nil {
		t.Fatal("expected trailing JSON to be rejected")
	}

	req = httptest.NewRequest("POST", "/api/test", strings.NewReader(`{"ok":true} trailing`))
	w = httptest.NewRecorder()
	if err := decodeJSONBody(w, req, &body, false); err == nil {
		t.Fatal("expected trailing garbage to be rejected")
	}
}

func TestAgentReportRejectsTrailingData(t *testing.T) {
	data, err := os.ReadFile("report.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)
	for _, want := range []string{
		"decoder := json.NewDecoder(r.Body)",
		"decoder.Decode(&report)",
		"decoder.Decode(&extra)",
		"err != io.EOF",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("agent report strict JSON decode missing %q", want)
		}
	}
}
