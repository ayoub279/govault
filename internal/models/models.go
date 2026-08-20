// Package models defines the core domain types and API request/response shapes.
package models

import (
	"time"

	"github.com/google/uuid"
)

// User represents an account. PasswordHash is never serialized to JSON.
type User struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
}

// Secret represents a stored secret. EncryptedValue holds the AES-256-GCM
// ciphertext and is never exposed via JSON; the decrypted value is surfaced
// through the separate Value field only when a single secret is fetched.
type Secret struct {
	ID             uuid.UUID `json:"id"`
	UserID         uuid.UUID `json:"user_id"`
	Name           string    `json:"name"`
	EncryptedValue []byte    `json:"-"`
	Value          string    `json:"value,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// --- Request payloads ---

// RegisterRequest is the body for POST /auth/register.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest is the body for POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// CreateSecretRequest is the body for POST /secrets.
type CreateSecretRequest struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// --- Response payloads ---

// TokenResponse is returned by login.
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SecretListItem is a single entry in the list view (no decrypted value).
type SecretListItem struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
