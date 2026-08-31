package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// Default KDF Parameters
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024 // 64 MB in KiB
	ArgonThreads = 4
	KeyLen       = 32 // 256 bits
	SaltLen      = 32 // 256 bits
	NonceLen     = 12 // 96 bits for AES-GCM
)

var (
	ErrDecryptionFailed = errors.New("decryption failed: invalid key, tampered ciphertext, or incorrect authentication tag")
	ErrInvalidKeySize   = errors.New("encryption key must be 32 bytes for AES-256")
)

// GenerateSalt returns a cryptographically secure random salt of specified length.
func GenerateSalt(length int) ([]byte, error) {
	if length <= 0 {
		length = SaltLen
	}
	salt := make([]byte, length)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate random salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte key from a master password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonThreads, KeyLen)
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce and optional additional authenticated data (AAD).
func Encrypt(plaintext []byte, key []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	if len(key) != KeyLen {
		return nil, nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// Encrypt & append authentication tag
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM with the provided nonce, key, and AAD.
func Decrypt(nonce []byte, ciphertext []byte, key []byte, aad []byte) ([]byte, error) {
	if len(key) != KeyLen {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// ZeroMemory overwrites the given byte slice with zeros to minimize RAM exposure of secrets.
func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// SecureCompare performs a constant-time comparison of two byte slices to prevent timing attacks.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
