package db

import (
	"context"
	"fmt"
	"time"

	"github.com/ziozzang/bongsu/internal/shared/models"
)

func (db *DB) CreateLocalUser(ctx context.Context, username, passwordHash, role string) (*models.LocalUser, error) {
	var u models.LocalUser
	err := db.QueryRowContext(ctx,
		`INSERT INTO local_users (username, password_hash, role)
		 VALUES ($1, $2, $3)
		 RETURNING id, username, password_hash, role, created_at, updated_at`,
		username, passwordHash, role,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("create local user: %w", err)
	}
	return &u, nil
}

func (db *DB) GetLocalUserByUsername(ctx context.Context, username string) (*models.LocalUser, error) {
	var u models.LocalUser
	err := db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, created_at, updated_at
		 FROM local_users WHERE username = $1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get local user by username: %w", err)
	}
	return &u, nil
}

func (db *DB) GetLocalUserByID(ctx context.Context, id string) (*models.LocalUser, error) {
	var u models.LocalUser
	err := db.QueryRowContext(ctx,
		`SELECT id, username, password_hash, role, created_at, updated_at
		 FROM local_users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("get local user by id: %w", err)
	}
	return &u, nil
}

func (db *DB) UpdateLocalUserPassword(ctx context.Context, id, passwordHash string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE local_users SET password_hash = $1, updated_at = now() WHERE id = $2`,
		passwordHash, id,
	)
	if err != nil {
		return fmt.Errorf("update local user password: %w", err)
	}
	return nil
}

func (db *DB) CreateSession(ctx context.Context, userID, tokenHash string, expiresAt time.Time, ip, userAgent string) (*models.Session, error) {
	var s models.Session
	err := db.QueryRowContext(ctx,
		`INSERT INTO sessions (user_id, token_hash, expires_at, ip_address, user_agent)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, user_id, token_hash, created_at, expires_at, last_used_at, ip_address, user_agent`,
		userID, tokenHash, expiresAt, ip, userAgent,
	).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.LastUsedAt, &s.IPAddress, &s.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}
	return &s, nil
}

func (db *DB) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*models.Session, error) {
	var s models.Session
	err := db.QueryRowContext(ctx,
		`SELECT id, user_id, token_hash, created_at, expires_at, last_used_at, ip_address, user_agent
		 FROM sessions
		 WHERE token_hash = $1 AND expires_at > now()`,
		tokenHash,
	).Scan(&s.ID, &s.UserID, &s.TokenHash, &s.CreatedAt, &s.ExpiresAt, &s.LastUsedAt, &s.IPAddress, &s.UserAgent)
	if err != nil {
		return nil, fmt.Errorf("get session by token hash: %w", err)
	}
	return &s, nil
}

func (db *DB) TouchSession(ctx context.Context, sessionID string) error {
	_, err := db.ExecContext(ctx,
		`UPDATE sessions SET last_used_at = now() WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	return nil
}

func (db *DB) DeleteSession(ctx context.Context, sessionID string) error {
	_, err := db.ExecContext(ctx,
		`DELETE FROM sessions WHERE id = $1`,
		sessionID,
	)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (db *DB) DeleteExpiredSessions(ctx context.Context) (int, error) {
	result, err := db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	n, _ := result.RowsAffected()
	return int(n), nil
}

func (db *DB) CountLocalUsers(ctx context.Context) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_users`).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count local users: %w", err)
	}
	return n, nil
}
