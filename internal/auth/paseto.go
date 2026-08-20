package auth

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/o1egl/paseto"
)

// TokenTTL is how long an issued token remains valid.
const TokenTTL = 24 * time.Hour

// TokenMaker issues and verifies PASETO v2 local (symmetric) tokens.
type TokenMaker struct {
	v2  *paseto.V2
	key []byte // 32-byte symmetric key
}

// NewTokenMaker creates a TokenMaker from a 32-byte symmetric key.
func NewTokenMaker(key []byte) (*TokenMaker, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("auth: PASETO key must be 32 bytes, got %d", len(key))
	}
	return &TokenMaker{v2: paseto.NewV2(), key: key}, nil
}

// CreateToken issues a token for the given user, embedding the user id and
// standard time claims. It returns the encrypted token and its expiry.
func (m *TokenMaker) CreateToken(userID uuid.UUID) (string, time.Time, error) {
	now := time.Now()
	expiresAt := now.Add(TokenTTL)

	jsonToken := paseto.JSONToken{
		IssuedAt:   now,
		NotBefore:  now,
		Expiration: expiresAt,
	}
	jsonToken.Set("user_id", userID.String())

	token, err := m.v2.Encrypt(m.key, jsonToken, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: encrypt token: %w", err)
	}
	return token, expiresAt, nil
}

// VerifyToken decrypts and validates a token, returning the embedded user id.
func (m *TokenMaker) VerifyToken(token string) (uuid.UUID, error) {
	var jsonToken paseto.JSONToken
	var footer string

	if err := m.v2.Decrypt(token, m.key, &jsonToken, &footer); err != nil {
		return uuid.Nil, fmt.Errorf("auth: invalid token: %w", err)
	}
	// Validate() checks IssuedAt/NotBefore/Expiration.
	if err := jsonToken.Validate(); err != nil {
		return uuid.Nil, fmt.Errorf("auth: token failed validation: %w", err)
	}

	userID, err := uuid.Parse(jsonToken.Get("user_id"))
	if err != nil {
		return uuid.Nil, fmt.Errorf("auth: token missing valid user_id: %w", err)
	}
	return userID, nil
}
