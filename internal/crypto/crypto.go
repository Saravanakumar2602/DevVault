package crypto

import (
	"crypto/subtle"
)

var (
	defaultKDF     = NewArgon2idKDF()
	defaultCipher  = NewAESGCMCipher()
	defaultSaltGen = NewRandomSaltGenerator()
)

// DeriveKey derives a key from password and salt using Argon2id.
func DeriveKey(password string, salt []byte) []byte {
	key, _ := defaultKDF.DeriveKey(password, salt)
	return key
}

// Encrypt encrypts plaintext using AES-256-GCM.
func Encrypt(plaintext []byte, key []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	return defaultCipher.Encrypt(plaintext, key, aad)
}

// Decrypt decrypts ciphertext using AES-256-GCM.
func Decrypt(nonce []byte, ciphertext []byte, key []byte, aad []byte) ([]byte, error) {
	return defaultCipher.Decrypt(nonce, ciphertext, key, aad)
}

// GenerateSalt generates a random salt using crypto/rand.
func GenerateSalt(size int) ([]byte, error) {
	return defaultSaltGen.GenerateSalt(size)
}

// ZeroMemory overwrites sensitive byte slices in memory with zeros.
func ZeroMemory(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroString overwrites a byte slice representation of a string if converted to mutable byte slice.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
