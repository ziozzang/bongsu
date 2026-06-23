package scanner

import (
	"bufio"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// ScanLanguagePackages walks root looking for language dependency manifests and
// lockfiles anywhere on disk — not just system package locations. This catches
// runtimes installed outside the OS package manager: pyenv (~/.pyenv), nvm
// (~/.nvm), app bundles, vendored dependencies, etc.
//
// It is intentionally bounded: it skips well-known heavy/irrelevant trees and
// caps how deep it descends so a host scan doesn't walk the entire filesystem.
func ScanLanguagePackages(root string, maxDepth int) []models.Package {
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
			// System pseudo-filesystems are pruned only as direct children of
			// the scan root (real /proc, /sys, /dev, /run) — never a user's
			// own "dev" or "run" directory deeper in the tree.
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
		if found := parseManifest(root, path, d.Name()); len(found) > 0 {
			pkgs = append(pkgs, found...)
		}
		return nil
	}
	_ = filepath.WalkDir(root, walkFn)
	return dedupeLangPackages(pkgs)
}

// skipDir prunes trees that are large, irrelevant, or recursive package caches
// that would multiply results. node_modules is deliberately NOT skipped at the
// top level (it holds installed deps) but nested node_modules are pruned to
// avoid exponential walking — handled by depth + dedupe instead.
func skipDir(name string) bool {
	switch name {
	case ".git", ".svn", ".hg",
		".cache", "__pycache__", ".terraform", ".gradle", ".m2":
		return true
	}
	return false
}

// systemPseudoDir lists kernel/virtual filesystems that are meaningless to walk
// for packages. Pruned only at the scan root (see caller).
func systemPseudoDir(name string) bool {
	switch name {
	case "proc", "sys", "dev", "run":
		return true
	}
	return false
}

func parseManifest(root, path, name string) []models.Package {
	switch name {
	case "package-lock.json":
		return parseNpmLock(root, path)
	case "package.json":
		return parsePackageJSON(root, path)
	case "requirements.txt":
		return parseRequirementsTxt(root, path)
	case "go.mod":
		return parseGoMod(root, path)
	case "Cargo.lock":
		return parseCargoLock(root, path)
	case "Gemfile.lock":
		return parseGemfileLock(root, path)
	}
	// PEP 503 installed metadata: .../site-packages/<pkg>-<ver>.dist-info/METADATA
	if name == "METADATA" && strings.Contains(path, ".dist-info") {
		return parsePythonDistInfo(root, path)
	}
	return nil
}

func newLangPkg(name, version, pkgType, path string) models.Package {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return models.Package{}
	}
	return models.Package{
		ID:        uuid.New().String(),
		Name:      name,
		Version:   version,
		PkgType:   pkgType,
		Ecosystem: ecosystemForType(pkgType),
		PURL:      purlForPackage(pkgType, name, version, ""),
		FilePath:  path,
		Source:    "native-lang",
	}
}

func parsePackageJSON(root, path string) []models.Package {
	data, err := readFileWithinRoot(root, path)
	if err != nil {
		return nil
	}
	var pj struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(data, &pj) != nil || pj.Name == "" || pj.Version == "" {
		return nil
	}
	// Only the package's own name/version — dependency ranges in package.json
	// are not resolved versions; lockfiles provide those.
	if p := newLangPkg(pj.Name, pj.Version, "npm", path); p.Name != "" {
		return []models.Package{p}
	}
	return nil
}

func parseNpmLock(root, path string) []models.Package {
	data, err := readFileWithinRoot(root, path)
	if err != nil {
		return nil
	}
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(data, &lock) != nil {
		return nil
	}
	var out []models.Package
	for key, v := range lock.Packages {
		// lockfile v2/v3: keys like "node_modules/lodash"; "" is the root.
		name := key
		if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
			name = key[i+len("node_modules/"):]
		}
		if name == "" || v.Version == "" {
			continue
		}
		if p := newLangPkg(name, v.Version, "npm", path); p.Name != "" {
			out = append(out, p)
		}
	}
	for name, v := range lock.Dependencies { // lockfile v1
		if p := newLangPkg(name, v.Version, "npm", path); p.Name != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseRequirementsTxt(root, path string) []models.Package {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []models.Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Only pinned requirements (name==version) are resolved versions.
		if i := strings.Index(line, "=="); i > 0 {
			name := strings.TrimSpace(line[:i])
			// Strip a PEP 508 extras suffix ("django[bcrypt]" -> "django"); the
			// extras select optional deps and are not part of the project name
			// advisories are keyed on.
			if b := strings.IndexByte(name, '['); b > 0 {
				name = strings.TrimSpace(name[:b])
			}
			rest := strings.TrimSpace(line[i+2:])
			if j := strings.IndexAny(rest, " ;#"); j >= 0 {
				rest = rest[:j]
			}
			if p := newLangPkg(name, rest, "pypi", path); p.Name != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func parsePythonDistInfo(root, path string) []models.Package {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var name, version string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // headers end at first blank line
		}
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
		}
	}
	if p := newLangPkg(name, version, "pypi", path); p.Name != "" {
		return []models.Package{p}
	}
	return nil
}

func parseGoMod(root, path string) []models.Package {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []models.Package
	inRequire := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}
		fields := strings.Fields(line)
		if inRequire && len(fields) >= 2 {
			if p := newLangPkg(fields[0], strings.TrimPrefix(fields[1], "v"), "go", path); p.Name != "" {
				out = append(out, p)
			}
		} else if strings.HasPrefix(line, "require ") && len(fields) >= 3 {
			if p := newLangPkg(fields[1], strings.TrimPrefix(fields[2], "v"), "go", path); p.Name != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func parseCargoLock(root, path string) []models.Package {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []models.Package
	var name string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case line == "[[package]]":
			name = ""
		case strings.HasPrefix(line, "name = "):
			name = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		case strings.HasPrefix(line, "version = ") && name != "":
			version := strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
			if p := newLangPkg(name, version, "cargo", path); p.Name != "" {
				out = append(out, p)
			}
			name = ""
		}
	}
	return out
}

func parseGemfileLock(root, path string) []models.Package {
	f, err := openWithinRoot(root, path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []models.Package
	inSpecs := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs {
			// Gem entries are indented exactly 4 spaces: "    name (version)".
			if !strings.HasPrefix(raw, "    ") || strings.HasPrefix(raw, "      ") {
				if trimmed == "" || !strings.HasPrefix(raw, " ") {
					inSpecs = false
				}
				continue
			}
			open := strings.Index(trimmed, " (")
			closeP := strings.LastIndex(trimmed, ")")
			if open > 0 && closeP > open {
				name := trimmed[:open]
				version := trimmed[open+2 : closeP]
				if p := newLangPkg(name, version, "gem", path); p.Name != "" {
					out = append(out, p)
				}
			}
		}
	}
	return out
}

func dedupeLangPackages(pkgs []models.Package) []models.Package {
	seen := map[string]bool{}
	out := pkgs[:0]
	for _, p := range pkgs {
		key := p.Ecosystem + "\x00" + strings.ToLower(p.Name) + "\x00" + p.Version
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}
