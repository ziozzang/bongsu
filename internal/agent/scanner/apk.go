package scanner

import (
	"bufio"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// parseApkInstalled reads an Alpine apk `installed` database. Each package is a
// stanza of single-letter-prefixed fields terminated by a blank line:
//
//	P:alpine-baselayout   (package name)
//	V:3.4.3-r2            (version)
//	A:x86_64             (architecture)
//	o:alpine-baselayout   (origin / source package)
func parseApkInstalled(root, path string) ([]models.Package, error) {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var pkgs []models.Package
	var name, version, arch, origin string
	flush := func() {
		defer func() { name, version, arch, origin = "", "", "", "" }()
		if name == "" || version == "" {
			return
		}
		src := origin
		if src == "" {
			src = name
		}
		pkgs = append(pkgs, models.Package{
			ID:        uuid.New().String(),
			Name:      name,
			Version:   version,
			Arch:      arch,
			PkgType:   "alpine",
			Ecosystem: ecosystemForType("alpine"),
			SrcName:   src,
			PURL:      purlForPackage("alpine", name, version, arch),
			Source:    "native-alpine",
		})
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		val := line[2:]
		switch line[0] {
		case 'P':
			name = val
		case 'V':
			version = val
		case 'A':
			arch = val
		case 'o':
			origin = val
		}
	}
	flush()
	return pkgs, scanner.Err()
}
