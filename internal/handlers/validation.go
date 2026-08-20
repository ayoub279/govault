package handlers

import (
	"regexp"
	"strings"
)

// Field length limits for basic input validation.
const (
	maxEmailLen       = 254
	minPasswordLen    = 8
	maxPasswordLen    = 128
	maxSecretNameLen  = 200
	maxSecretValueLen = 64 * 1024 // 64 KiB
)

var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// validateEmail trims and checks a basic email shape.
func validateEmail(email string) (string, bool) {
	email = strings.TrimSpace(email)
	if email == "" || len(email) > maxEmailLen || !emailRe.MatchString(email) {
		return "", false
	}
	return strings.ToLower(email), true
}

// validatePassword enforces reasonable length bounds.
func validatePassword(pw string) bool {
	return len(pw) >= minPasswordLen && len(pw) <= maxPasswordLen
}

// validateSecretName trims and bounds a secret name (must be non-empty).
func validateSecretName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxSecretNameLen {
		return "", false
	}
	return name, true
}

// validateSecretValue bounds a secret value (must be non-empty).
func validateSecretValue(value string) bool {
	return value != "" && len(value) <= maxSecretValueLen
}
