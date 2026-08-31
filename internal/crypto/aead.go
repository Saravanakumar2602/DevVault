package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
)

var (
	ErrDecryptionFailed = errors.New("decryption failed: invalid key, tampered ciphertext, or incorrect authentication tag")
	ErrInvalidKeyLength = errors.New("encryption key length must be 32 bytes for AES-256")
	ErrInvalidNonceLen  = errors.New("invalid nonce length for AES-GCM")
)

// AESGCMCipher implements AEADCipher using AES-256-GCM.
type AESGCMCipher struct{}

func NewAESGCMCipher() *AESGCMCipher {
	return &AESGCMCipher{}
}

func (c *AESGCMCipher) CipherName() string {
	return "AES-256-GCM"
}

// Encrypt encrypts plaintext using AES-256-GCM with a crypto/rand random nonce.
func (c *AESGCMCipher) Encrypt(plaintext []byte, key []byte, aad []byte) (nonce []byte, ciphertext []byte, err error) {
	if len(key) != 32 {
		return nil, nil, ErrInvalidKeyLength
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

// Decrypt decrypts ciphertext using AES-256-GCM and verifies the authentication tag.
func (c *AESGCMCipher) Decrypt(nonce []byte, ciphertext []byte, key []byte, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeyLength
	}
	if len(nonce) == 0 {
		return nil, ErrInvalidNonceLen
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
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
