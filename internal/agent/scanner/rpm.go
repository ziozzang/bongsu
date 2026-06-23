package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// scanRPM inventories an RPM-based root. The rpm database has three on-disk
// formats (BerkeleyDB, NDB, sqlite) whose pure-Go parsing is a sizeable effort;
// until that lands, this falls back to the host's own `rpm` binary pointed at
// the target root. On RHEL-family hosts rpm is part of the base OS (unlike a
// bundled scanner), so this keeps RPM hosts/containers working without trivy.
//
// Returns ok=false when no rpm database is present under root.
func scanRPM(root string) (*Result, bool, error) {
	dbDir := filepath.Join(root, "var/lib/rpm")
	if !rpmDBPresent(dbDir) {
		return nil, false, nil
	}
	rpmBin, err := exec.LookPath("rpm")
	if err != nil {
		// DB exists but we can't read it natively yet and rpm isn't available.
		return &Result{OSFamily: "rhel", Source: "rpmdb-unreadable"}, true, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	args := []string{"-qa", "--qf", RPMQueryFormat}
	if abs, aerr := filepath.Abs(root); aerr == nil && abs != "/" {
		args = append([]string{"--root", abs}, args...)
	}
	out, err := exec.CommandContext(ctx, rpmBin, args...).Output()
	if err != nil {
		return nil, true, err
	}
	return &Result{Packages: parseRPMQuery(out), OSFamily: "rhel", Source: "rpm"}, true, nil
}

func rpmDBPresent(dbDir string) bool {
	for _, f := range []string{"rpmdb.sqlite", "Packages", "Packages.db"} {
		if st, err := os.Stat(filepath.Join(dbDir, f)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

// RPMQueryFormat is the --qf template used everywhere rpm is queried (host
// binary or container exec), so all rpm output parses identically.
const RPMQueryFormat = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n"

// ParseRPMQuery parses tab-delimited `rpm -qa --qf RPMQueryFormat` output into
// packages. Exported so the container-exec fallback (which runs rpm inside the
// container) can reuse the same parser.
func ParseRPMQuery(out []byte) []models.Package { return parseRPMQuery(out) }

func parseRPMQuery(out []byte) []models.Package {
	var pkgs []models.Package
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		epoch := strings.TrimSpace(fields[1])
		version := strings.TrimSpace(fields[2])
		arch := strings.TrimSpace(fields[3])
		if name == "" || version == "" {
			continue
		}
		if epoch != "" && epoch != "0" && epoch != "(none)" {
			version = epoch + ":" + version
		}
		var srcName string
		if len(fields) > 4 {
			srcName = rpmSourceName(strings.TrimSpace(fields[4]))
		}
		pkgs = append(pkgs, models.Package{
			ID:        uuid.New().String(),
			Name:      name,
			Version:   version,
			Arch:      arch,
			PkgType:   "rhel",
			Ecosystem: ecosystemForType("rhel"),
			SrcName:   srcName,
			PURL:      purlForPackage("rhel", name, version, arch),
			Source:    "native-rhel",
		})
	}
	return pkgs
}

// rpmSourceName strips the version/arch tail from a SOURCERPM value
// ("openssl-1.1.1k-14.el8_6.src.rpm" → "openssl").
func rpmSourceName(src string) string {
	// rpm reports "(none)" for packages with no source rpm (e.g. gpg-pubkey
	// pseudo-packages); that is not a source name.
	if src == "" || src == "(none)" {
		return ""
	}
	src = strings.TrimSuffix(src, ".src.rpm")
	if i := strings.LastIndex(src, "-"); i > 0 {
		src = src[:i]
		if i := strings.LastIndex(src, "-"); i > 0 {
			src = src[:i]
		}
	}
	return src
}
