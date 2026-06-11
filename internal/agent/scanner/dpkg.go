package scanner

import (
	"bufio"
	"os"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// parseDpkgStatus reads a dpkg `status` database (RFC822-style stanzas) and
// returns one Package per installed entry. Only packages whose Status is
// "install ok installed" are reported — half-configured/removed entries are
// skipped, matching what dpkg-query -W would show.
func parseDpkgStatus(path, pkgType string) ([]models.Package, error) {
	f, err := os.Open(path)
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
		if st := cur["Status"]; st != "" && !strings.Contains(st, "installed") {
			return
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
	return pkgs, scanner.Err()
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
