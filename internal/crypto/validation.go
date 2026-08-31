package crypto

import (
	"errors"
	"regexp"
)

var (
	ErrInvalidSecretKeyName = errors.New("invalid secret key name: must contain only letters, numbers, and underscores (e.g. API_KEY, DB_URL)")
	validKeyNameRegex       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// ValidateSecretKeyName validates that secret key names are non-empty and formatted cleanly.
func ValidateSecretKeyName(key string) error {
	if len(key) == 0 {
		return errors.New("secret key name cannot be empty")
	}
	if !validKeyNameRegex.MatchString(key) {
		return ErrInvalidSecretKeyName
	}
	return nil
}
