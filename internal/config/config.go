// Package config loads and validates runtime configuration from the environment.
package config

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all runtime configuration for the API.
type Config struct {
	DatabaseURL   string
	EncryptionKey []byte // 32 bytes, decoded from hex (AES-256)
	PasetoKey     []byte // 32 bytes, decoded from hex (PASETO v2 local symmetric key)
	Port          string
}

// Load reads configuration from environment variables. It will first attempt to
// load a .env file if present (useful for local development); real environment
// variables always take precedence over values in .env.
func Load() (*Config, error) {
	// Best-effort: ignore error if .env is absent.
	_ = godotenv.Load()

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}

	encKey, err := decodeKey("ENCRYPTION_KEY", 32)
	if err != nil {
		return nil, err
	}

	pasetoKey, err := decodeKey("PASETO_KEY", 32)
	if err != nil {
		return nil, err
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &Config{
		DatabaseURL:   dbURL,
		EncryptionKey: encKey,
		PasetoKey:     pasetoKey,
		Port:          port,
	}, nil
}

// decodeKey reads a hex-encoded key from the named env var and verifies its
// decoded length matches wantLen bytes.
func decodeKey(name string, wantLen int) ([]byte, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return nil, fmt.Errorf("%s is required", name)
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex-encoded: %w", name, err)
	}
	if len(key) != wantLen {
		return nil, fmt.Errorf("%s must decode to %d bytes (got %d); generate one with: openssl rand -hex %d", name, wantLen, len(key), wantLen)
	}
	return key, nil
}
