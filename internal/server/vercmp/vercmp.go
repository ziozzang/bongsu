// Package vercmp implements version comparison as a generic, ecosystem-aware
// ruleset rather than a pile of special cases. Each ecosystem family uses the
// comparison algorithm its package manager actually defines (Debian dpkg, RPM
// rpmvercmp, Alpine apk), with a semver/generic fallback for language packages.
//
// Compare is the single entry point. It returns -1, 0, 1 for a<b, a==b, a>b,
// and ok=false only when the strings cannot be meaningfully compared.
package vercmp

import "strings"

// Compare orders two version strings under the rules of the given ecosystem.
// ecosystem is the normalized family ("debian", "ubuntu", "alpine", "rhel",
// "suse", "azurelinux", or a language ecosystem like "npm"/"pypi"/"go").
func Compare(ecosystem, a, b string) (int, bool) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return 0, false
	}
	if a == b {
		return 0, true
	}
	switch family(ecosystem) {
	case "debian":
		return compareDebian(a, b)
	case "rhel":
		return compareRPM(a, b)
	case "alpine":
		return compareAlpine(a, b)
	default:
		// Language ecosystems (npm/pypi/go/cargo/...) and unknowns use the
		// generic semver-leaning comparator.
		return compareGeneric(a, b)
	}
}

// family maps a normalized ecosystem to the version-algorithm family it uses.
// Debian and Ubuntu share dpkg's algorithm; the RPM distros share rpmvercmp.
func family(ecosystem string) string {
	switch strings.ToLower(strings.TrimSpace(ecosystem)) {
	case "debian", "ubuntu", "deb":
		return "debian"
	case "rhel", "redhat", "centos", "rocky", "almalinux", "alma", "amazon", "oracle", "suse", "opensuse", "azurelinux":
		return "rhel"
	case "alpine", "apk", "wolfi":
		return "alpine"
	default:
		return "generic"
	}
}
