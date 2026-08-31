package crypto

import (
	"errors"
	"regexp"
)

var (
	ErrInvalidSecretKeyName = errors.New("invalid secret key name: must contain only letters, numbers, and underscores (e.g. API_KEY, DB_URL)")
	ErrInvalidProfileName   = errors.New("invalid profile name: must contain only letters, numbers, hyphens, and underscores (e.g. dev, staging, prod-1)")
	validKeyNameRegex       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	validProfileNameRegex   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
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

// ValidateProfileName validates that profile names are non-empty and formatted cleanly.
func ValidateProfileName(name string) error {
	if len(name) == 0 {
		return errors.New("profile name cannot be empty")
	}
	if !validProfileNameRegex.MatchString(name) {
		return ErrInvalidProfileName
	}
	return nil
}
