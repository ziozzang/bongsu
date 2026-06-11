package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// bongsuMigrationLockKey identifies the cluster-wide advisory lock that
// serializes migration runs across server instances.
const bongsuMigrationLockKey = 0x626F6E677375 // "bongsu"

func (db *DB) RunMigrations(ctx context.Context) error {
	files, err := os.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	// Serialize concurrent migration runs (two server instances starting at
	// once) with a session-scoped advisory lock held on a dedicated connection
	// for the whole run.
	lockConn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("migration lock conn: %w", err)
	}
	defer lockConn.Close()
	if _, err := lockConn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, bongsuMigrationLockKey); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		_, _ = lockConn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, bongsuMigrationLockKey)
	}()
	legacyInitialized, err := db.legacySchemaComplete(ctx)
	if err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		filename TEXT PRIMARY KEY,
		checksum TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}
	applied, err := db.appliedMigrations(ctx)
	if err != nil {
		return err
	}
	if len(applied) == 0 && legacyInitialized {
		return db.baselineMigrations(ctx, files)
	}
	for _, f := range files {
		if f.IsDir() || !(len(f.Name()) > 4 && f.Name()[len(f.Name())-4:] == ".sql") {
			continue
		}
		data, err := os.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f.Name(), err)
		}
		checksum := migrationChecksum(data)
		if got, ok := applied[f.Name()]; ok {
			if got != checksum {
				return fmt.Errorf("migration %s checksum mismatch", f.Name())
			}
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", f.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, string(data)); err != nil {
			tx.Rollback()
			return fmt.Errorf("run migration %s: %w", f.Name(), err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (filename, checksum, applied_at) VALUES ($1,$2,now())`, f.Name(), checksum); err != nil {
			tx.Rollback()
			return fmt.Errorf("record migration %s: %w", f.Name(), err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", f.Name(), err)
		}
	}
	return nil
}

func (db *DB) baselineMigrations(ctx context.Context, files []os.DirEntry) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration baseline: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO schema_migrations (filename, checksum, applied_at) VALUES ($1,$2,now()) ON CONFLICT (filename) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("prepare migration baseline: %w", err)
	}
	defer stmt.Close()

	for _, f := range files {
		if f.IsDir() || !(len(f.Name()) > 4 && f.Name()[len(f.Name())-4:] == ".sql") {
			continue
		}
		data, err := os.ReadFile("migrations/" + f.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", f.Name(), err)
		}
		if _, err := stmt.ExecContext(ctx, f.Name(), migrationChecksum(data)); err != nil {
			return fmt.Errorf("baseline migration %s: %w", f.Name(), err)
		}
	}
	return tx.Commit()
}

func (db *DB) legacySchemaComplete(ctx context.Context) (bool, error) {
	checks := []struct {
		table  string
		column string
		index  string
	}{
		{table: "hosts"},
		{table: "hosts", column: "agent_token_hash"},
		{table: "packages", column: "asset_type"},
		{table: "packages", column: "purl"},
		{table: "vulnerabilities", column: "pkg_path"},
		{table: "vulnerabilities", column: "finding_source"},
		{table: "cve_database", column: "category"},
		{table: "cve_database", column: "epss_score"},
		{table: "cve_affected_packages"},
		{table: "cve_reference_keys"},
		{table: "container_assets"},
		{table: "scans", column: "security_db_revision"},
		{table: "scans", column: "scan_request_id"},
		{table: "scan_requests", column: "claimed_by_host_id"},
		{table: "scan_requests", column: "security_db_revision"},
		{table: "audit_logs"},
		{table: "vulnerability_triage"},
		{index: "idx_scan_requests_pending_security_db_host"},
		{index: "idx_vulnerabilities_package_scan_vuln"},
		{index: "idx_vulnerabilities_finding_source"},
		{index: "idx_cve_affected_pkg_name_ecosystem"},
		{index: "idx_cve_affected_vuln_pkg_ecosystem"},
		{index: "idx_cve_reference_keys_key"},
	}
	for _, check := range checks {
		var ok bool
		var err error
		switch {
		case check.index != "":
			ok, err = db.indexExists(ctx, check.index)
		case check.column == "":
			ok, err = db.tableExists(ctx, check.table)
		default:
			ok, err = db.columnExists(ctx, check.table, check.column)
		}
		if err != nil || !ok {
			return ok, err
		}
	}
	return true, nil
}

func (db *DB) tableExists(ctx context.Context, table string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+table).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check table %s: %w", table, err)
	}
	return exists, nil
}

func (db *DB) columnExists(ctx context.Context, table, column string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1
		FROM information_schema.columns
		WHERE table_schema='public' AND table_name=$1 AND column_name=$2
	)`, table, column).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check column %s.%s: %w", table, column, err)
	}
	return exists, nil
}

func (db *DB) indexExists(ctx context.Context, index string) (bool, error) {
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+index).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check index %s: %w", index, err)
	}
	return exists, nil
}

func (db *DB) appliedMigrations(ctx context.Context) (map[string]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT filename, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read schema_migrations: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var filename, checksum string
		if err := rows.Scan(&filename, &checksum); err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
		out[filename] = checksum
	}
	return out, rows.Err()
}

func migrationChecksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

