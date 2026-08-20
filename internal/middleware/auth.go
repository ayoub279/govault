// Package middleware provides HTTP middleware, including PASETO authentication.
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"govault/internal/auth"
)

// contextKey is an unexported type to avoid context key collisions.
type contextKey string

const userIDKey contextKey = "user_id"

// Authenticator validates PASETO tokens and injects the user id into context.
type Authenticator struct {
	maker *auth.TokenMaker
}

// NewAuthenticator builds an Authenticator around a TokenMaker.
func NewAuthenticator(maker *auth.TokenMaker) *Authenticator {
	return &Authenticator{maker: maker}
}

// RequireAuth is middleware that rejects requests lacking a valid bearer token.
// On success it stores the authenticated user id in the request context.
func (a *Authenticator) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			unauthorized(w, "missing authorization header")
			return
		}
		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			unauthorized(w, "authorization header must be 'Bearer <token>'")
			return
		}

		userID, err := a.maker.VerifyToken(parts[1])
		if err != nil {
			unauthorized(w, "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// UserID extracts the authenticated user id from the request context. The bool
// is false if no authenticated user is present.
func UserID(ctx context.Context) (uuid.UUID, bool) {
	id, ok := ctx.Value(userIDKey).(uuid.UUID)
	return id, ok
}

func unauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
