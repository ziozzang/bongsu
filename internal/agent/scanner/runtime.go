package scanner

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// ScanRuntimes walks root looking for language RUNTIME interpreters/VMs that
// were installed OUTSIDE the OS package manager: pyenv-compiled Python under
// ~/.pyenv/versions/<X.Y.Z>/, a Node tarball unpacked into /opt/node-v20.../,
// a hand-unpacked JDK in /opt/jdk-21.0.2/, a Go SDK tree, etc.
//
// These interpreters carry their own CVEs (CPython, Node, the JVM) but are
// invisible to both the OS package DB scan (ScanRoot) and the language LIBRARY
// scan (ScanLanguagePackages, which only reads lockfiles/dist-info). This pass
// fills that gap.
//
// Detection is FILESYSTEM-ONLY: we never execute a binary (`python --version`
// would be unsafe and slow on a host scan). Instead we infer the runtime from
// on-disk layout — the well-known directory structure of each distribution —
// and only emit a package when a concrete X.Y or X.Y.Z version can be derived.
// No version → skip, to avoid noise.
//
// It reuses the same bounded WalkDir + skipDir/depth approach as
// ScanLanguagePackages so the two passes prune identical trees.
func ScanRuntimes(root string, maxDepth int) []models.Package {
	if root == "" {
		root = "/"
	}
	if maxDepth <= 0 {
		maxDepth = 12
	}
	rootDepth := strings.Count(filepath.Clean(root), string(os.PathSeparator))
	var pkgs []models.Package

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			depth := strings.Count(filepath.Clean(path), string(os.PathSeparator)) - rootDepth
			if depth == 1 && systemPseudoDir(d.Name()) {
				return fs.SkipDir
			}
			if skipDir(d.Name()) {
				return fs.SkipDir
			}
			if depth > maxDepth {
				return fs.SkipDir
			}
			return nil
		}
		if found := detectRuntime(root, path, d.Name()); len(found) > 0 {
			pkgs = append(pkgs, found...)
		}
		return nil
	}
	_ = filepath.WalkDir(root, walkFn)
	return dedupeRuntimes(pkgs)
}

// detectRuntime inspects a single file. The trigger for every runtime is its
// launcher binary inside a `bin/` directory (bin/python*, bin/node, bin/java,
// bin/ruby, bin/php) or the Go SDK's VERSION file. Anchoring on the binary's
// path keeps FilePath pointing at the actual interpreter, which is what CPE
// matching wants.
func detectRuntime(root, path, name string) []models.Package {
	dir := filepath.Dir(path)            // .../bin
	parent := filepath.Dir(dir)          // the install prefix (.../3.12.1, .../node-v20...)
	inBin := filepath.Base(dir) == "bin" // launcher lives under bin/

	switch {
	case name == "VERSION" && goSDKVersion(root, path) != "":
		// Go SDK tree: <goroot>/VERSION holds e.g. "go1.22.1".
		if v := goSDKVersion(root, path); v != "" {
			return runtimePkg("go", v, "golang", path)
		}
	case inBin && isPythonBinary(name):
		if v := detectPythonVersion(root, path, parent); v != "" {
			return runtimePkg("python", v, "python", path)
		}
	case inBin && name == "node":
		if v := detectNodeVersion(root, path, parent); v != "" {
			return runtimePkg("node.js", v, "nodejs", path)
		}
	case inBin && name == "java":
		if vname, v := detectJavaVersion(root, parent); v != "" {
			return runtimePkg(vname, v, "jdk", path)
		}
	case inBin && name == "ruby":
		if v := detectRubyVersion(parent); v != "" {
			return runtimePkg("ruby", v, "ruby", path)
		}
	case inBin && name == "php":
		if v := detectPHPVersion(root, parent); v != "" {
			return runtimePkg("php", v, "php", path)
		}
	}
	return nil
}

// runtimePkg builds a runtime models.Package. The ecosystem field is set to a
// CPE-style PRODUCT name (python / nodejs / jdk / go / ruby / php) rather than
// an SBOM ecosystem (PyPI / npm / Maven) on purpose: a runtime CVE is matched
// against the NVD CPE product (cpe:2.3:a:python:python, :nodejs:node.js,
// :oracle:jdk / :eclipse:temurin), NOT against a library-registry ecosystem.
// Carrying the CPE product here lets a future CPE matcher consume it directly,
// while the distinct PkgType="runtime" keeps these out of the library matcher.
func runtimePkg(name, version, ecosystem, path string) []models.Package {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	return []models.Package{{
		ID:        uuid.New().String(),
		Name:      name,
		Version:   version,
		PkgType:   "runtime",
		Ecosystem: ecosystem,
		PURL:      "pkg:generic/" + name + "@" + version,
		FilePath:  path,
		Source:    "native-runtime",
	}}
}

var (
	// semverRe matches an X.Y.Z (or X.Y) version embedded in a string.
	semverRe = regexp.MustCompile(`\b(\d+\.\d+(?:\.\d+)?)\b`)
	// pyMinorRe matches a "pythonX.Y" lib dir component.
	pyMinorRe = regexp.MustCompile(`^python(\d+\.\d+)$`)
	// nodeTarballRe matches a "node-vX.Y.Z" path component (tarball layout).
	nodeTarballRe = regexp.MustCompile(`node-v(\d+\.\d+\.\d+)`)
	// pyBinaryRe matches python launcher names: python, python3, python3.12.
	pyBinaryRe = regexp.MustCompile(`^python(\d+(?:\.\d+)?)?$`)
)

func isPythonBinary(name string) bool {
	return pyBinaryRe.MatchString(name)
}

// detectPythonVersion derives a CPython version from the on-disk layout.
//
//   - pyenv / python-build: .../versions/<X.Y.Z>/bin/python* — the install
//     prefix component IS the full version.
//   - generic prefix: a lib/python<X.Y>/ sibling gives the X.Y minor; that's a
//     valid (if coarse) version for CVE matching.
//   - a "python_version" file (pyenv writes these) recording X.Y.Z.
//
// Full X.Y.Z is preferred; we fall back to X.Y only when that's all we have.
func detectPythonVersion(root, binPath, prefix string) string {
	// pyenv layout: parent of bin/ is the version directory, and its parent
	// is literally named "versions".
	base := filepath.Base(prefix)
	if filepath.Base(filepath.Dir(prefix)) == "versions" {
		if m := semverRe.FindString(base); m != "" {
			return m
		}
	}
	// A bare version-looking prefix dir (e.g. /opt/python-3.11.4 or /opt/3.11.4).
	if m := semverRe.FindString(base); m != "" && strings.Count(m, ".") == 2 {
		// Only trust a full X.Y.Z here to avoid grabbing unrelated numbers.
		return m
	}
	// lib/python<X.Y>/ sibling next to bin/.
	if v := pythonLibMinor(filepath.Join(prefix, "lib")); v != "" {
		return v
	}
	// python_version file recording the exact version.
	for _, cand := range []string{
		filepath.Join(prefix, "python_version"),
		filepath.Join(prefix, "version"),
	} {
		if data, err := readFileWithinRoot(root, cand); err == nil {
			if m := semverRe.FindString(string(data)); m != "" {
				return m
			}
		}
	}
	return ""
}

// pythonLibMinor scans a lib/ dir for a python<X.Y> subdirectory and returns
// the X.Y it encodes. site-packages live under lib/pythonX.Y so this is a
// reliable minor-version signal even for hand-built interpreters.
func pythonLibMinor(libDir string) string {
	entries, err := os.ReadDir(libDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if m := pyMinorRe.FindStringSubmatch(e.Name()); m != nil {
			return m[1]
		}
	}
	return ""
}

// detectNodeVersion derives a Node version from:
//   - a "node-vX.Y.Z" component anywhere in the path (official tarball layout);
//   - the bundled npm's package.json "version"? no — that's npm's version, not
//     node's; instead we read lib/node_modules/npm's presence only as a sanity
//     signal and rely on a recorded version file / the tarball name.
//
// Node ships no on-disk file naming its OWN version, so the tarball directory
// name is the primary signal. As a fallback we honor an adjacent version file.
func detectNodeVersion(root, binPath, prefix string) string {
	// Walk the full path for a node-vX.Y.Z component.
	if m := nodeTarballRe.FindStringSubmatch(binPath); m != nil {
		return m[1]
	}
	// Adjacent version file (some packagers drop one).
	for _, cand := range []string{
		filepath.Join(prefix, "node_version"),
		filepath.Join(prefix, "VERSION"),
	} {
		if data, err := readFileWithinRoot(root, cand); err == nil {
			s := strings.TrimSpace(string(data))
			s = strings.TrimPrefix(s, "v")
			if m := semverRe.FindString(s); m != "" {
				return m
			}
		}
	}
	// Bundled npm confirms this is a real Node install, but only emit if the
	// prefix dir itself encodes the version (e.g. /opt/node-v20.11.0).
	if _, err := os.Stat(filepath.Join(prefix, "lib", "node_modules", "npm", "package.json")); err == nil {
		if m := nodeTarballRe.FindStringSubmatch(prefix); m != nil {
			return m[1]
		}
	}
	return ""
}

// detectJavaVersion parses the standard JDK/JRE `release` file that sits next
// to bin/ (i.e. at the install prefix). It is a key="value" file containing
// JAVA_VERSION and IMPLEMENTOR; the implementor distinguishes the CPE vendor
// (Eclipse Adoptium/Temurin vs Oracle vs OpenJDK) and selects the product name.
func detectJavaVersion(root, prefix string) (name, version string) {
	data, err := readFileWithinRoot(root, filepath.Join(prefix, "release"))
	if err != nil {
		return "", ""
	}
	var implementor string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if v, ok := releaseValue(line, "JAVA_VERSION"); ok {
			version = v
		} else if v, ok := releaseValue(line, "IMPLEMENTOR"); ok {
			implementor = v
		}
	}
	if version == "" {
		return "", ""
	}
	// Normalize a leading X.Y.Z out of values like "21.0.2" or "1.8.0_392".
	if m := semverRe.FindString(version); m != "" {
		version = m
	}
	impl := strings.ToLower(implementor)
	switch {
	case strings.Contains(impl, "oracle"):
		name = "jdk" // Oracle JDK → CPE product cpe:2.3:a:oracle:jdk
	case strings.Contains(impl, "adoptium"), strings.Contains(impl, "temurin"),
		strings.Contains(impl, "eclipse"):
		name = "openjdk" // Temurin builds of OpenJDK
	default:
		name = "openjdk"
	}
	return name, version
}

// releaseValue parses a JDK release-file line of the form KEY="value".
func releaseValue(line, key string) (string, bool) {
	prefix := key + "="
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	v := strings.TrimPrefix(line, prefix)
	v = strings.Trim(v, `"`)
	return strings.TrimSpace(v), true
}

// detectRubyVersion reads lib/ruby/<X.Y.Z>/ next to bin/ (the standard Ruby
// install layout — rbenv, ruby-build, source installs all use it).
func detectRubyVersion(prefix string) string {
	entries, err := os.ReadDir(filepath.Join(prefix, "lib", "ruby"))
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() {
			if m := semverRe.FindString(e.Name()); m != "" && strings.Count(m, ".") == 2 {
				return m
			}
		}
	}
	return ""
}

// detectPHPVersion honors an adjacent version file; PHP has no canonical
// on-disk version marker, so this stays conservative.
func detectPHPVersion(root, prefix string) string {
	for _, cand := range []string{
		filepath.Join(prefix, "php_version"),
		filepath.Join(prefix, "VERSION"),
	} {
		if data, err := readFileWithinRoot(root, cand); err == nil {
			if m := semverRe.FindString(string(data)); m != "" {
				return m
			}
		}
	}
	return ""
}

// goSDKVersion reads a Go SDK's VERSION file, whose first line is e.g.
// "go1.22.1". Returns that token verbatim (including the "go" prefix) so it
// matches the Go release naming the Go CVE feeds use.
func goSDKVersion(root, path string) string {
	data, err := readFileWithinRoot(root, path)
	if err != nil {
		return ""
	}
	first := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if strings.HasPrefix(first, "go") && semverRe.MatchString(first) {
		return first
	}
	return ""
}

// dedupeRuntimes collapses identical (name, version, path) detections that can
// arise from symlinked launchers (python → python3 → python3.12 all in one bin).
func dedupeRuntimes(pkgs []models.Package) []models.Package {
	seen := map[string]bool{}
	out := pkgs[:0]
	for _, p := range pkgs {
		key := strings.ToLower(p.Name) + "\x00" + p.Version + "\x00" + p.FilePath
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}
