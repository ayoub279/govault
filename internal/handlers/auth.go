package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"govault/internal/auth"
	"govault/internal/db"
	"govault/internal/models"
)

// AuthHandler serves registration and login.
type AuthHandler struct {
	store *db.Store
	maker *auth.TokenMaker
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(store *db.Store, maker *auth.TokenMaker) *AuthHandler {
	return &AuthHandler{store: store, maker: maker}
}

// Register handles POST /auth/register.
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	email, ok := validateEmail(req.Email)
	if !ok {
		writeError(w, http.StatusBadRequest, "a valid email is required")
		return
	}
	if !validatePassword(req.Password) {
		writeError(w, http.StatusBadRequest, "password must be between 8 and 128 characters")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not process password")
		return
	}

	user, err := h.store.CreateUser(r.Context(), email, hash)
	if err != nil {
		if errors.Is(err, db.ErrDuplicateEmail) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// Login handles POST /auth/login and returns a PASETO token on success.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	email, ok := validateEmail(req.Email)
	if !ok || req.Password == "" {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	user, err := h.store.GetUserByEmail(r.Context(), email)
	if err != nil {
		// Same response whether the user is missing or the password is wrong,
		// to avoid leaking which emails are registered.
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if !auth.CheckPassword(user.PasswordHash, req.Password) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}

	token, expiresAt, err := h.maker.CreateToken(user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}

	writeJSON(w, http.StatusOK, models.TokenResponse{Token: token, ExpiresAt: expiresAt})
}
