package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

// --- Local user management ---

// ListLocalUsers returns all dashboard users (without password hashes).
func (db *DB) ListLocalUsers(ctx context.Context) ([]models.LocalUser, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, username, role, created_at, updated_at FROM local_users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("list local users: %w", err)
	}
	defer rows.Close()
	out := []models.LocalUser{}
	for rows.Next() {
		var u models.LocalUser
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountLocalAdmins returns how many admin-role users exist (to guard against
// removing or demoting the last admin).
func (db *DB) CountLocalAdmins(ctx context.Context) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users WHERE role='admin'`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count local admins: %w", err)
	}
	return n, nil
}

// UserGuardResult is the outcome of a last-admin-guarded mutation.
type UserGuardResult int

const (
	UserGuardOK UserGuardResult = iota
	UserGuardNotFound
	UserGuardLastAdmin // refused: would leave zero local admins
)

// lockAdminsAndTarget locks the admin rows (and the target) FOR UPDATE inside tx
// so concurrent demote/delete operations serialize — closing the check-then-act
// race where two callers each see >1 admin and both reduce the count to zero.
func lockAdminsAndTarget(ctx context.Context, tx *sql.Tx, id string) (targetRole string, adminCount int, found bool, err error) {
	// Lock every admin row; this serializes concurrent admin mutations.
	rows, err := tx.QueryContext(ctx, `SELECT id FROM local_users WHERE role='admin' FOR UPDATE`)
	if err != nil {
		return "", 0, false, err
	}
	for rows.Next() {
		var rid string
		if err := rows.Scan(&rid); err != nil {
			rows.Close()
			return "", 0, false, err
		}
		adminCount++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", 0, false, err
	}
	err = tx.QueryRowContext(ctx, `SELECT role FROM local_users WHERE id=$1 FOR UPDATE`, id).Scan(&targetRole)
	if err == sql.ErrNoRows {
		return "", adminCount, false, nil
	}
	if err != nil {
		return "", adminCount, false, err
	}
	return targetRole, adminCount, true, nil
}

// UpdateLocalUserRoleGuarded changes a role, refusing to demote the last admin.
func (db *DB) UpdateLocalUserRoleGuarded(ctx context.Context, id, role string) (UserGuardResult, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return UserGuardOK, err
	}
	defer tx.Rollback()
	targetRole, adminCount, found, err := lockAdminsAndTarget(ctx, tx, id)
	if err != nil {
		return UserGuardOK, err
	}
	if !found {
		return UserGuardNotFound, nil
	}
	if targetRole == "admin" && role != "admin" && adminCount <= 1 {
		return UserGuardLastAdmin, nil
	}
	if _, err := tx.ExecContext(ctx, `UPDATE local_users SET role=$1, updated_at=now() WHERE id=$2`, role, id); err != nil {
		return UserGuardOK, err
	}
	if err := tx.Commit(); err != nil {
		return UserGuardOK, err
	}
	return UserGuardOK, nil
}

// DeleteLocalUserGuarded removes a user, refusing to delete the last admin. Their
// sessions cascade-delete via the FK.
func (db *DB) DeleteLocalUserGuarded(ctx context.Context, id string) (UserGuardResult, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return UserGuardOK, err
	}
	defer tx.Rollback()
	targetRole, adminCount, found, err := lockAdminsAndTarget(ctx, tx, id)
	if err != nil {
		return UserGuardOK, err
	}
	if !found {
		return UserGuardNotFound, nil
	}
	if targetRole == "admin" && adminCount <= 1 {
		return UserGuardLastAdmin, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM local_users WHERE id=$1`, id); err != nil {
		return UserGuardOK, err
	}
	if err := tx.Commit(); err != nil {
		return UserGuardOK, err
	}
	return UserGuardOK, nil
}

// DeleteUserSessions revokes all of a user's sessions (e.g. after a password
// reset or role change).
func (db *DB) DeleteUserSessions(ctx context.Context, userID string) (int, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=$1`, userID)
	if err != nil {
		return 0, fmt.Errorf("delete user sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// --- DB-backed API tokens ---

// CreateAPIToken inserts a new token (the caller supplies the precomputed
// sha256 hash and display prefix; the plaintext secret is never passed here).
func (db *DB) CreateAPIToken(ctx context.Context, name, tokenHash, prefix, role, subject, createdBy string, expiresAt *time.Time) (*models.APIToken, error) {
	var t models.APIToken
	err := db.QueryRowContext(ctx,
		`INSERT INTO api_tokens (name, token_hash, prefix, role, subject, created_by, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7)
		 RETURNING id, name, prefix, role, subject, created_by, created_at, expires_at, last_used_at, revoked_at`,
		name, tokenHash, prefix, role, subject, createdBy, expiresAt,
	).Scan(&t.ID, &t.Name, &t.Prefix, &t.Role, &t.Subject, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt)
	if err != nil {
		return nil, fmt.Errorf("create api token: %w", err)
	}
	return &t, nil
}

// ListAPITokens returns all tokens (metadata only — never the hash).
func (db *DB) ListAPITokens(ctx context.Context) ([]models.APIToken, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, name, prefix, role, subject, created_by, created_at, expires_at, last_used_at, revoked_at
		 FROM api_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()
	out := []models.APIToken{}
	for rows.Next() {
		var t models.APIToken
		if err := rows.Scan(&t.ID, &t.Name, &t.Prefix, &t.Role, &t.Subject, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.LastUsedAt, &t.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken marks a token revoked (idempotent — keeps the row for audit) and
// returns its token_hash so the caller can evict it from the in-memory cache
// without waiting for a full refresh. Returns ErrNoRows-style "token not found".
func (db *DB) RevokeAPIToken(ctx context.Context, id string) (string, error) {
	var hash string
	err := db.QueryRowContext(ctx,
		`UPDATE api_tokens SET revoked_at=COALESCE(revoked_at, now()) WHERE id=$1 RETURNING token_hash`,
		id).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("token not found")
	}
	if err != nil {
		return "", fmt.Errorf("revoke api token: %w", err)
	}
	return hash, nil
}

// ActiveAPIToken is the minimal record loaded into the in-memory auth cache.
type ActiveAPIToken struct {
	ID        string
	TokenHash string
	Role      string
	Subject   string
	ExpiresAt *time.Time
}

// ActiveAPITokens returns all non-revoked, non-expired tokens for the in-memory
// auth lookup cache.
func (db *DB) ActiveAPITokens(ctx context.Context) ([]ActiveAPIToken, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT id, token_hash, role, subject, expires_at FROM api_tokens
		 WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now())`)
	if err != nil {
		return nil, fmt.Errorf("active api tokens: %w", err)
	}
	defer rows.Close()
	out := []ActiveAPIToken{}
	for rows.Next() {
		var t ActiveAPIToken
		if err := rows.Scan(&t.ID, &t.TokenHash, &t.Role, &t.Subject, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TouchAPIToken records a token's last use (best-effort, throttled by caller).
func (db *DB) TouchAPIToken(ctx context.Context, id string) error {
	_, err := db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=now() WHERE id=$1`, id)
	return err
}
