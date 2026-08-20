// Package crypto provides authenticated encryption for secret values at rest
// using AES-256-GCM. The 32-byte key is supplied by configuration and never
// stored alongside the ciphertext.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// ErrMalformedCiphertext is returned when a stored value is too short to contain
// a nonce, indicating corruption or tampering.
var ErrMalformedCiphertext = errors.New("crypto: malformed ciphertext")

// Encryptor wraps an AES-256-GCM AEAD.
type Encryptor struct {
	aead cipher.AEAD
}

// New creates an Encryptor from a 32-byte key (AES-256).
func New(key []byte) (*Encryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return &Encryptor{aead: aead}, nil
}

// Encrypt returns nonce||ciphertext for the given plaintext. A fresh random
// nonce is generated for every call.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, e.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	// Seal appends the ciphertext to nonce, so the nonce prefixes the result.
	return e.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt reverses Encrypt, expecting nonce||ciphertext.
func (e *Encryptor) Decrypt(data []byte) ([]byte, error) {
	ns := e.aead.NonceSize()
	if len(data) < ns {
		return nil, ErrMalformedCiphertext
	}
	nonce, ciphertext := data[:ns], data[ns:]
	plaintext, err := e.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
