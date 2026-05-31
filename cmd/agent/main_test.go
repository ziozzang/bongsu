package main

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestAppendCollectionErrorBoundsReportErrors(t *testing.T) {
	errs := []string{}
	longErr := strings.Repeat("x", maxCollectionErrorBytes+20)

	errs = appendCollectionError(errs, "users", nil)
	if len(errs) != 0 {
		t.Fatalf("nil error changed slice: %#v", errs)
	}

	errs = appendCollectionError(errs, "users", errors.New("permission denied"))
	if len(errs) != 1 || errs[0] != "users: permission denied" {
		t.Fatalf("plain error = %#v", errs)
	}

	errs = appendCollectionError(errs, "trivy_host", errors.New(longErr))
	if len(errs) != 2 {
		t.Fatalf("error count = %d, want 2", len(errs))
	}
	if !strings.HasPrefix(errs[1], "trivy_host: ") || !strings.HasSuffix(errs[1], "...(truncated)") {
		t.Fatalf("bounded error has unexpected shape: %q", errs[1])
	}

	errs = appendCollectionError(nil, "osquery", errors.New(strings.Repeat("한", maxCollectionErrorBytes)))
	if !utf8.ValidString(errs[0]) {
		t.Fatalf("truncated unicode error is not valid UTF-8: %q", errs[0])
	}

	for i := 0; i < maxCollectionErrors+5; i++ {
		errs = appendCollectionError(errs, "container", errors.New("scan failed"))
	}
	if len(errs) != maxCollectionErrors {
		t.Fatalf("error count = %d, want %d", len(errs), maxCollectionErrors)
	}
	if errs[maxCollectionErrors-1] != "additional collection errors omitted" {
		t.Fatalf("overflow marker missing: %q", errs[maxCollectionErrors-1])
	}
}
