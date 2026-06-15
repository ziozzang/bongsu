package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lib/pq"
)

func TestGetCveSourceWatermarkSQL(t *testing.T) {
	out, err := readAllPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	start := strings.Index(body, "func (db *DB) GetCveSourceWatermark")
	if start < 0 {
		t.Fatal("GetCveSourceWatermark not found")
	}
	fn := body[start : start+600]
	for _, want := range []string{
		"SELECT COUNT(*), MAX(modified_date), MAX(updated_at) FROM cve_database WHERE source=$1",
		"wm.Count",
		"wm.MaxModified",
		"wm.MaxUpdatedAt",
	} {
		if !strings.Contains(fn, want) {
			t.Fatalf("GetCveSourceWatermark missing %q", want)
		}
	}
}

func TestIsRetryableError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"deadlock", &pq.Error{Code: "40P01"}, true},
		{"serialization", &pq.Error{Code: "40001"}, true},
		{"wrapped deadlock", fmt.Errorf("insert CVE-2025-11058: %w", &pq.Error{Code: "40P01"}), true},
		{"unique violation", &pq.Error{Code: "23505"}, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsRetryableError(tc.err); got != tc.want {
				t.Fatalf("IsRetryableError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
