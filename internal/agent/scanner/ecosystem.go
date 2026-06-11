package scanner

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ecosystemForType mirrors trivyparse.ecosystemForType so that native-scanned
// packages carry the exact pkg_type→ecosystem mapping the server matcher
// normalizes against. Keep these two in sync.
func ecosystemForType(pkgType string) string {
	switch strings.ToLower(pkgType) {
	case "ubuntu":
		return "Ubuntu"
	case "debian", "deb":
		return "Debian"
	case "alpine", "apk":
		return "Alpine"
	case "redhat", "centos", "rocky", "alma", "almalinux", "amazon", "oracle", "rpm", "rhel":
		return "RHEL"
	case "python-pkg", "pip", "poetry", "pypi":
		return "PyPI"
	case "node-pkg", "npm", "yarn", "pnpm":
		return "npm"
	case "gomod", "go", "gobinary", "golang":
		return "Go"
	case "jar", "maven":
		return "Maven"
	case "cargo", "rustbinary":
		return "crates.io"
	case "composer":
		return "Packagist"
	case "gem":
		return "RubyGems"
	case "nuget":
		return "NuGet"
	default:
		return ""
	}
}

func purlForPackage(pkgType, name, version, arch string) string {
	if name == "" || version == "" {
		return ""
	}
	purlType := "generic"
	switch ecosystemForType(pkgType) {
	case "Debian", "Ubuntu":
		purlType = "deb"
	case "Alpine":
		purlType = "apk"
	case "RHEL":
		purlType = "rpm"
	case "PyPI":
		purlType = "pypi"
	case "npm":
		purlType = "npm"
	case "Go":
		purlType = "golang"
	case "Maven":
		purlType = "maven"
	case "crates.io":
		purlType = "cargo"
	case "Packagist":
		purlType = "composer"
	case "RubyGems":
		purlType = "gem"
	case "NuGet":
		purlType = "nuget"
	}
	p := fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	if arch != "" && (purlType == "deb" || purlType == "rpm" || purlType == "apk") {
		p += "?arch=" + arch
	}
	return p
}

// distroIDFromRoot reads the lowercased os-release ID under root (e.g. "debian",
// "ubuntu", "alpine", "rhel"). Returns "" when os-release is absent.
func distroIDFromRoot(root string) string {
	data, err := readFileWithinRoot(root, filepath.Join(root, "etc/os-release"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			return strings.ToLower(strings.Trim(strings.TrimPrefix(line, "ID="), `"'`))
		}
	}
	return ""
}
