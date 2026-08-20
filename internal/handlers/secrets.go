package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"govault/internal/crypto"
	"govault/internal/db"
	"govault/internal/middleware"
	"govault/internal/models"
)

// SecretsHandler serves the CRUD endpoints for secrets. All routes assume the
// PASETO middleware has already populated the user id in the request context.
type SecretsHandler struct {
	store *db.Store
	enc   *crypto.Encryptor
}

// NewSecretsHandler constructs a SecretsHandler.
func NewSecretsHandler(store *db.Store, enc *crypto.Encryptor) *SecretsHandler {
	return &SecretsHandler{store: store, enc: enc}
}

// Create handles POST /secrets: validate, encrypt, store.
func (h *SecretsHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req models.CreateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	name, ok := validateSecretName(req.Name)
	if !ok {
		writeError(w, http.StatusBadRequest, "name is required and must be at most 200 characters")
		return
	}
	if !validateSecretValue(req.Value) {
		writeError(w, http.StatusBadRequest, "value is required and must be at most 64 KiB")
		return
	}

	ciphertext, err := h.enc.Encrypt([]byte(req.Value))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not encrypt secret")
		return
	}

	sec, err := h.store.CreateSecret(r.Context(), userID, name, ciphertext)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store secret")
		return
	}

	writeJSON(w, http.StatusCreated, models.SecretListItem{
		ID:        sec.ID,
		Name:      sec.Name,
		CreatedAt: sec.CreatedAt,
		UpdatedAt: sec.UpdatedAt,
	})
}

// List handles GET /secrets: metadata only, no decrypted values.
func (h *SecretsHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	items, err := h.store.ListSecrets(r.Context(), userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not list secrets")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"secrets": items})
}

// Get handles GET /secrets/{id}: returns the decrypted value if owned.
func (h *SecretsHandler) Get(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	sec, err := h.store.GetSecret(r.Context(), id, userID)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not fetch secret")
		return
	}

	plaintext, err := h.enc.Decrypt(sec.EncryptedValue)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not decrypt secret")
		return
	}
	sec.Value = string(plaintext)

	writeJSON(w, http.StatusOK, sec)
}

// Delete handles DELETE /secrets/{id}: removes the secret if owned.
func (h *SecretsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserID(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid secret id")
		return
	}

	if err := h.store.DeleteSecret(r.Context(), id, userID); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not delete secret")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
