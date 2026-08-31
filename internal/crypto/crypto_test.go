package crypto_test

import (
	"bytes"
	"testing"

	"devvault/internal/crypto"
)

func TestArgon2idDeriveKey(t *testing.T) {
	salt, err := crypto.GenerateSalt(32)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	key1 := crypto.DeriveKey("my-secret-password", salt)
	key2 := crypto.DeriveKey("my-secret-password", salt)
	key3 := crypto.DeriveKey("different-password", salt)

	if len(key1) != 32 {
		t.Fatalf("expected 32-byte key, got %d bytes", len(key1))
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("expected derived keys for identical inputs to match")
	}

	if bytes.Equal(key1, key3) {
		t.Errorf("expected derived keys for different passwords to differ")
	}
}

func TestAESGCMEncryptDecrypt(t *testing.T) {
	salt, _ := crypto.GenerateSalt(32)
	key := crypto.DeriveKey("password123", salt)

	plaintext := []byte("DB_PASSWORD=SuperSecretPass123!")
	aad := []byte("default:DB_PASSWORD")

	nonce, ciphertext, err := crypto.Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := crypto.Decrypt(nonce, ciphertext, key, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("expected decrypted %s, got %s", string(plaintext), string(decrypted))
	}

	// Test AAD mismatch prevention (Context Binding)
	wrongAAD := []byte("prod:DB_PASSWORD")
	_, err = crypto.Decrypt(nonce, ciphertext, key, wrongAAD)
	if err == nil {
		t.Errorf("expected error when decrypting with mismatched AAD, got nil")
	}

	// Test key mismatch
	wrongKey := crypto.DeriveKey("wrongpassword", salt)
	_, err = crypto.Decrypt(nonce, ciphertext, wrongKey, aad)
	if err == nil {
		t.Errorf("expected error when decrypting with wrong key, got nil")
	}
}

func TestZeroMemory(t *testing.T) {
	secret := []byte("SensitiveTokenData")
	crypto.ZeroMemory(secret)
	for i, b := range secret {
		if b != 0 {
			t.Errorf("expected byte at index %d to be zero, got %d", i, b)
		}
	}
}
