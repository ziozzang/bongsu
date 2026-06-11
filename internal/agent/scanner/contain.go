package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// errOutsideRoot is returned (and skipped by callers) when a path resolves,
// after symlink evaluation, outside the scan root. It is deliberately a
// sentinel: callers treat it like "file absent", not a hard scan failure.
var errOutsideRoot = errors.New("scanner: path resolves outside scan root")

// openWithinRoot opens path for reading but refuses to hand back a file whose
// real (symlink-resolved) location escapes root. This is the containment guard
// for scanning UNTRUSTED container rootfs: a malicious image can plant symlinks
// that point at the HOST filesystem, and naively os.Open-ing them would leak
// host content (e.g. /etc/passwd) into the inventory.
//
// Semantics / accepted tradeoff:
//
//   - A RELATIVE in-root symlink (etc/os-release -> ../usr/lib/os-release)
//     resolves UNDER root via EvalSymlinks and is ALLOWED — legitimate distro
//     layouts (os-release, alternatives) rely on this.
//   - An ABSOLUTE symlink inside the container (etc/os-release -> /usr/lib/...)
//     is interpreted by EvalSymlinks against the HOST root, so it lands OUTSIDE
//     the container root and is REJECTED. We cannot tell the difference between
//     "absolute symlink the image author meant to stay in-container" and "an
//     attack", so we reject all absolute escapes. This asymmetry is the
//     intentional, conservative tradeoff.
//   - A dangling symlink (EvalSymlinks errors) is skipped, same as absent.
//
// HOST-SCAN EXEMPTION: when root == "/" (or resolves to "/"), every path is
// trivially within root, and running EvalSymlinks on every file of a full host
// tree is needless cost — so containment is skipped entirely and this behaves
// exactly like os.Open.
func openWithinRoot(root, path string) (*os.File, error) {
	if err := withinRoot(root, path); err != nil {
		return nil, err
	}
	return os.Open(path)
}

// readFileWithinRoot is the os.ReadFile analogue of openWithinRoot: it returns
// the file contents only when path resolves inside root, otherwise errOutsideRoot
// (or the EvalSymlinks error for a dangling link). See openWithinRoot for the
// containment semantics and the host-scan exemption.
func readFileWithinRoot(root, path string) ([]byte, error) {
	if err := withinRoot(root, path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

// withinRoot performs the containment check shared by openWithinRoot and
// readFileWithinRoot. It returns nil when path is safe to read.
func withinRoot(root, path string) error {
	if isHostRoot(root) {
		return nil
	}
	// Resolve the root itself first: overlayfs merged dirs live under
	// /var/lib/docker/overlay2/<id>/merged and that path can contain its own
	// symlinks; without resolving root we'd reject every legitimately-contained
	// file. A non-resolvable root degrades to the cleaned root.
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		resolvedRoot = filepath.Clean(root)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		// Dangling/broken link or vanished file: treat as absent, skip quietly.
		return err
	}
	resolved = filepath.Clean(resolved)
	// Equal to root, or under root with a path separator boundary so that a
	// sibling like "/rootfoo" is not mistaken for being inside "/root".
	if resolved == resolvedRoot {
		return nil
	}
	prefix := resolvedRoot
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	if strings.HasPrefix(resolved, prefix) {
		return nil
	}
	return errOutsideRoot
}

// isHostRoot reports whether root denotes a full host scan ("/"), in which case
// containment is unnecessary and skipped for cost.
func isHostRoot(root string) bool {
	if root == "" {
		return true
	}
	if filepath.Clean(root) == string(os.PathSeparator) {
		return true
	}
	return false
}
