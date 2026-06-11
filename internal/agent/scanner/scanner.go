// Package scanner is a dependency-free package inventory scanner. It reads
// installed-package databases directly off a filesystem root — no trivy, no
// external binary — and produces models.Package values whose pkg_type and
// ecosystem match what the server's CVE matcher expects.
//
// The same ScanRoot entry point works for a host (root "/") and for a
// container (root = the container's merged rootfs), which is how host and
// container inventory share one code path.
package scanner

import (
	"os"
	"path/filepath"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// Result is the outcome of scanning one root: the packages found and the
// distro family that produced them (empty if no OS package DB was present).
type Result struct {
	Packages []models.Package
	OSFamily string // "debian" | "alpine" | "rhel" | ""
	Source   string // which DB was read, e.g. "dpkg", "apk", "rpmdb"
}

// ScanRoot inventories OS packages under root by probing each known package
// database in order. It returns the first database that exists and parses;
// distros ship exactly one, so order only matters for unusual images.
func ScanRoot(root string) (*Result, error) {
	if root == "" {
		root = "/"
	}
	if path := firstExisting(root,
		"var/lib/dpkg/status",
	); path != "" {
		// dpkg is shared by Debian and Ubuntu; the distinction lives in
		// os-release and drives the matcher's pkg_type/ecosystem.
		pkgType := distroIDFromRoot(root)
		if pkgType != "ubuntu" {
			pkgType = "debian"
		}
		pkgs, err := parseDpkgStatus(root, path, pkgType)
		if err != nil {
			return nil, err
		}
		return &Result{Packages: pkgs, OSFamily: pkgType, Source: "dpkg"}, nil
	}
	if path := firstExisting(root,
		"lib/apk/db/installed",
	); path != "" {
		pkgs, err := parseApkInstalled(root, path)
		if err != nil {
			return nil, err
		}
		return &Result{Packages: pkgs, OSFamily: "alpine", Source: "apk"}, nil
	}
	if res, ok, err := scanRPM(root); ok || err != nil {
		return res, err
	}
	return &Result{}, nil
}

func firstExisting(root string, rels ...string) string {
	for _, rel := range rels {
		p := filepath.Join(root, rel)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
