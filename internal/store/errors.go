package store

import "errors"

var (
	ErrInvalidMasterPassword = errors.New("invalid master password")
	ErrVaultAlreadyInit      = errors.New("vault is already initialized")
	ErrVaultNotInitialized   = errors.New("vault is not initialized; please run 'devvault init' first")
	ErrProfileNotFound       = errors.New("profile not found")
	ErrSecretNotFound        = errors.New("secret not found")
	ErrCannotDeleteDefault   = errors.New("cannot delete default profile")
)
