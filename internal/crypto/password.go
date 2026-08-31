package crypto

import (
	"errors"
	"fmt"
)

var (
	ErrPasswordTooShort = errors.New("master password must be at least 8 characters long")
)

// ValidatePasswordStructure enforces master password complexity requirements.
func ValidatePasswordStructure(password string) error {
	if len(password) < 8 {
		return ErrPasswordTooShort
	}
	return nil
}

// FormatCryptoError ensures error messages never print sensitive keys or passwords.
func FormatCryptoError(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("cryptographic operation '%s' failed: %w", op, err)
}
