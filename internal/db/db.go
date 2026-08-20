// Package db provides a thin data-access layer over PostgreSQL using pgxpool.
package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"govault/internal/models"
)

// ErrNotFound is returned when a requested row does not exist (or is not owned
// by the requesting user).
var ErrNotFound = errors.New("db: not found")

// ErrDuplicateEmail is returned when registering an email that already exists.
var ErrDuplicateEmail = errors.New("db: email already registered")

// uniqueViolation is the PostgreSQL SQLSTATE for a unique constraint breach.
const uniqueViolation = "23505"

// Store wraps a pgx connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// Connect opens a pgx pool against databaseURL and verifies connectivity.
func Connect(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases all pooled connections.
func (s *Store) Close() { s.pool.Close() }

func isUniqueViolation(err error) bool {
	// pgx surfaces a *pgconn.PgError; check the code without importing pgconn
	// by matching on the message-bearing error string is fragile, so we use
	// errors.As via a small interface satisfied by pgconn.PgError.
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == uniqueViolation
	}
	return false
}

// --- Users ---

// CreateUser inserts a new user and returns the created row.
func (s *Store) CreateUser(ctx context.Context, email, passwordHash string) (*models.User, error) {
	const q = `
		INSERT INTO users (email, password_hash)
		VALUES ($1, $2)
		RETURNING id, email, password_hash, created_at`
	var u models.User
	err := s.pool.QueryRow(ctx, q, email, passwordHash).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDuplicateEmail
		}
		return nil, fmt.Errorf("db: create user: %w", err)
	}
	return &u, nil
}

// GetUserByEmail looks up a user by email. Returns ErrNotFound if absent.
func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	const q = `
		SELECT id, email, password_hash, created_at
		FROM users WHERE email = $1`
	var u models.User
	err := s.pool.QueryRow(ctx, q, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("db: get user by email: %w", err)
	}
	return &u, nil
}

// --- Secrets ---

// CreateSecret stores an encrypted secret for a user and returns the new row's
// metadata (without the ciphertext).
func (s *Store) CreateSecret(ctx context.Context, userID uuid.UUID, name string, encryptedValue []byte) (*models.Secret, error) {
	const q = `
		INSERT INTO secrets (user_id, name, encrypted_value)
		VALUES ($1, $2, $3)
		RETURNING id, user_id, name, created_at, updated_at`
	var sec models.Secret
	err := s.pool.QueryRow(ctx, q, userID, name, encryptedValue).
		Scan(&sec.ID, &sec.UserID, &sec.Name, &sec.CreatedAt, &sec.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("db: create secret: %w", err)
	}
	return &sec, nil
}

// ListSecrets returns metadata for all secrets owned by userID, newest first.
// Encrypted values are intentionally not selected.
func (s *Store) ListSecrets(ctx context.Context, userID uuid.UUID) ([]models.SecretListItem, error) {
	const q = `
		SELECT id, name, created_at, updated_at
		FROM secrets WHERE user_id = $1
		ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list secrets: %w", err)
	}
	defer rows.Close()

	items := make([]models.SecretListItem, 0)
	for rows.Next() {
		var it models.SecretListItem
		if err := rows.Scan(&it.ID, &it.Name, &it.CreatedAt, &it.UpdatedAt); err != nil {
			return nil, fmt.Errorf("db: scan secret: %w", err)
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: iterate secrets: %w", err)
	}
	return items, nil
}

// GetSecret fetches a single secret by id, scoped to userID so a user can only
// read their own. Returns ErrNotFound if it doesn't exist or isn't owned.
func (s *Store) GetSecret(ctx context.Context, id, userID uuid.UUID) (*models.Secret, error) {
	const q = `
		SELECT id, user_id, name, encrypted_value, created_at, updated_at
		FROM secrets WHERE id = $1 AND user_id = $2`
	var sec models.Secret
	err := s.pool.QueryRow(ctx, q, id, userID).
		Scan(&sec.ID, &sec.UserID, &sec.Name, &sec.EncryptedValue, &sec.CreatedAt, &sec.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("db: get secret: %w", err)
	}
	return &sec, nil
}

// DeleteSecret removes a secret by id, scoped to userID. Returns ErrNotFound if
// nothing was deleted.
func (s *Store) DeleteSecret(ctx context.Context, id, userID uuid.UUID) error {
	const q = `DELETE FROM secrets WHERE id = $1 AND user_id = $2`
	tag, err := s.pool.Exec(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("db: delete secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
