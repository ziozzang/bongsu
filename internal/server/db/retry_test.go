package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lib/pq"
)

func TestIsUniqueViolation(t *testing.T) {
	if !IsUniqueViolation(&pq.Error{Code: "23505"}) {
		t.Fatal("23505 must be a unique violation")
	}
	if IsUniqueViolation(&pq.Error{Code: "23503"}) {
		t.Fatal("foreign-key violation is not a unique violation")
	}
	if IsUniqueViolation(errors.New("boom")) || IsUniqueViolation(nil) {
		t.Fatal("non-pq / nil errors are not unique violations")
	}
}

func TestLastAdminGuardLocksRows(t *testing.T) {
	out, err := readAllPackageGoFiles()
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)
	// The guarded mutations must lock the admin set (and target) FOR UPDATE so the
	// last-admin invariant is race-free, not a check-then-act.
	for _, want := range []string{
		"func lockAdminsAndTarget(",
		"SELECT id FROM local_users WHERE role='admin' FOR UPDATE",
		"SELECT role FROM local_users WHERE id=$1 FOR UPDATE",
		"func (db *DB) DeleteLocalUserGuarded(",
		"func (db *DB) UpdateLocalUserRoleGuarded(",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("last-admin guard missing %q", want)
		}
	}
}

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
