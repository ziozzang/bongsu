package scanner

import (
	"bufio"
	"errors"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// parseDpkgStatus reads a dpkg `status` database (RFC822-style stanzas) and
// returns one Package per installed entry. Only packages whose Status is
// "install ok installed" are reported — half-configured/removed entries are
// skipped, matching what dpkg-query -W would show.
func parseDpkgStatus(root, path, pkgType string) ([]models.Package, error) {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []models.Package
	cur := map[string]string{}
	flush := func() {
		defer func() { cur = map[string]string{} }()
		name := cur["Package"]
		version := cur["Version"]
		if name == "" || version == "" {
			return
		}
		// dpkg Status is "<want> <flag> <status-word>"; only the status word
		// "installed" means the package is fully present. Substring matching on
		// "installed" is wrong: "not-installed" (a purged/removed entry that is
		// NOT on disk) and "half-installed" (a broken unpack) both contain it,
		// which would report vulnerabilities for packages that aren't there.
		if st := cur["Status"]; st != "" {
			fields := strings.Fields(st)
			if len(fields) == 0 || fields[len(fields)-1] != "installed" {
				return
			}
		}
		pkgs = append(pkgs, models.Package{
			ID:        uuid.New().String(),
			Name:      name,
			Version:   version,
			Arch:      cur["Architecture"],
			PkgType:   pkgType,
			Ecosystem: ecosystemForType(pkgType),
			SrcName:   dpkgSourceName(cur["Source"], name),
			PURL:      purlForPackage(pkgType, name, version, cur["Architecture"]),
			Source:    "native-" + pkgType,
		})
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var lastKey string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			lastKey = ""
			continue
		}
		// Continuation line (folded multi-line value) starts with a space.
		if line[0] == ' ' || line[0] == '\t' {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		lastKey = strings.TrimSpace(line[:idx])
		cur[lastKey] = strings.TrimSpace(line[idx+1:])
	}
	flush()
	if err := scanner.Err(); err != nil {
		// A single status-file line over bufio.Scanner's 4MiB cap (ErrTooLong)
		// must NOT sink the whole scan: a giant Description or a hostile/corrupt
		// status file shouldn't drop every package. Log-and-degrade — return the
		// packages parsed up to the offending line, with no error. This mirrors
		// ScanRoot's convention of reporting partial inventory rather than total
		// failure. Any other scan error keeps the existing fail-the-scan behavior.
		if errors.Is(err, bufio.ErrTooLong) {
			log.Printf("scanner: dpkg status %s has an oversized line; returning %d packages parsed before it", path, len(pkgs))
			return pkgs, nil
		}
		return pkgs, err
	}
	return pkgs, nil
}

// dpkgSourceName extracts the source package name from a dpkg `Source` field,
// which may carry a parenthesized version: "android-platform-tools (34.0.5-12)".
// Falls back to the binary package name when no source is recorded.
func dpkgSourceName(source, binary string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return binary
	}
	if i := strings.IndexByte(source, '('); i > 0 {
		source = strings.TrimSpace(source[:i])
	}
	if source == "" {
		return binary
	}
	return source
}
