package db

import (
	"context"
	"fmt"
	"strings"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// DependencyKey is the stable component key for the edge table: the PURL when
// known, else the lowercased package name. Both ingest paths use it so an edge
// from either source joins back to packages consistently.
func DependencyKey(purl, name string) string {
	if p := strings.TrimSpace(purl); p != "" {
		return p
	}
	return strings.ToLower(strings.TrimSpace(name))
}

// StorePackageDependencies replaces the dependency edges for a scan. Edges are
// (parentKey, childKey); self-edges and blanks are dropped. Idempotent: it
// clears the scan's existing edges first so a re-ingest can't accumulate stale
// ones.
func (db *DB) StorePackageDependencies(ctx context.Context, scanID string, edges [][2]string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin dep tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `DELETE FROM package_dependencies WHERE scan_id=$1`, scanID); err != nil {
		return fmt.Errorf("clear deps: %w", err)
	}
	seen := map[string]bool{}
	for _, e := range edges {
		parent, child := strings.TrimSpace(e[0]), strings.TrimSpace(e[1])
		if parent == "" || child == "" || parent == child {
			continue
		}
		k := parent + "\x00" + child
		if seen[k] {
			continue
		}
		seen[k] = true
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO package_dependencies (scan_id, parent_key, child_key) VALUES ($1,$2,$3)
			 ON CONFLICT (scan_id, parent_key, child_key) DO NOTHING`, scanID, parent, child); err != nil {
			return fmt.Errorf("insert dep edge: %w", err)
		}
	}
	return tx.Commit()
}

// BuildScanDependencyEdges derives the edge list for a scan from the packages'
// Dependencies field. A dependency entry is matched to a package in the same
// scan first by exact name, then resolved to that package's DependencyKey, so a
// name-based npm edge points at the child's PURL key when the child has one.
// Unresolvable dependency names are kept as-is (lowercased) so a bare edge still
// records the relationship.
func BuildScanDependencyEdges(pkgs []models.Package) [][2]string {
	nameToKey := make(map[string]string, len(pkgs))
	for _, p := range pkgs {
		if p.Name != "" {
			nameToKey[strings.ToLower(p.Name)] = DependencyKey(p.PURL, p.Name)
		}
	}
	var edges [][2]string
	for _, p := range pkgs {
		if len(p.Dependencies) == 0 {
			continue
		}
		parent := DependencyKey(p.PURL, p.Name)
		for _, dep := range p.Dependencies {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				continue
			}
			child := dep
			if strings.HasPrefix(dep, "pkg:") {
				// already a PURL key
			} else if k, ok := nameToKey[strings.ToLower(dep)]; ok {
				child = k
			} else {
				child = strings.ToLower(dep)
			}
			edges = append(edges, [2]string{parent, child})
		}
	}
	return edges
}

// DependentsOf returns the transitive set of component keys that depend on the
// given key within a scan (reverse reachability) — the dependency blast radius
// of a (typically vulnerable) package. The starting key is excluded.
func (db *DB) DependentsOf(ctx context.Context, scanID, key string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		WITH RECURSIVE dependents(k) AS (
			SELECT parent_key FROM package_dependencies WHERE scan_id=$1 AND child_key=$2
			UNION
			SELECT pd.parent_key FROM package_dependencies pd
			JOIN dependents d ON pd.child_key = d.k
			WHERE pd.scan_id=$1
		)
		SELECT DISTINCT k FROM dependents WHERE k <> $2 ORDER BY k`, scanID, key)
	if err != nil {
		return nil, fmt.Errorf("dependents of %s: %w", key, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
