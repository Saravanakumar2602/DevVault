package crypto_test

import (
	"bytes"
	"testing"

	"devvault/internal/crypto"
)

func TestArgon2idKDFDerivation(t *testing.T) {
	kdf := crypto.NewArgon2idKDF()
	saltGen := crypto.NewRandomSaltGenerator()

	salt, err := saltGen.GenerateSalt(32)
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	pass1 := "CorrectMasterPassword123!"
	pass2 := "DifferentMasterPassword456!"

	key1, err := kdf.DeriveKey(pass1, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed for pass1: %v", err)
	}
	defer crypto.ZeroMemory(key1)

	key1Duplicate, err := kdf.DeriveKey(pass1, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed for pass1 duplicate: %v", err)
	}
	defer crypto.ZeroMemory(key1Duplicate)

	key2, err := kdf.DeriveKey(pass2, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed for pass2: %v", err)
	}
	defer crypto.ZeroMemory(key2)

	// 1. Correct password yields identical derived key
	if !bytes.Equal(key1, key1Duplicate) {
		t.Errorf("expected derived keys for identical inputs to match")
	}

	// 2. Different passwords yield different derived keys
	if bytes.Equal(key1, key2) {
		t.Errorf("expected derived keys for different passwords to differ")
	}
}

func TestAESGCMEncryptionDecryption(t *testing.T) {
	kdf := crypto.NewArgon2idKDF()
	cipher := crypto.NewAESGCMCipher()
	saltGen := crypto.NewRandomSaltGenerator()

	salt, _ := saltGen.GenerateSalt(32)
	password := "MasterPassword789!"

	key, err := kdf.DeriveKey(password, salt)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}
	defer crypto.ZeroMemory(key)

	plaintext := []byte("DEVVAULT_SENTINEL_OK")
	aad := []byte("meta:auth_check")

	nonce, ciphertext, err := cipher.Encrypt(plaintext, key, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 1. Correct decryption
	decrypted, err := cipher.Decrypt(nonce, ciphertext, key, aad)
	if err != nil {
		t.Fatalf("Decrypt failed with correct key and data: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("expected decrypted text %s, got %s", string(plaintext), string(decrypted))
	}

	// 2. Incorrect password / key
	wrongKey, _ := kdf.DeriveKey("WrongPassword000!", salt)
	defer crypto.ZeroMemory(wrongKey)

	_, err = cipher.Decrypt(nonce, ciphertext, wrongKey, aad)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for wrong password, got %v", err)
	}

	// 3. Corrupted encrypted data (ciphertext byte flip)
	corruptedCiphertext := make([]byte, len(ciphertext))
	copy(corruptedCiphertext, ciphertext)
	corruptedCiphertext[0] ^= 0xFF

	_, err = cipher.Decrypt(nonce, corruptedCiphertext, key, aad)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for corrupted ciphertext, got %v", err)
	}

	// 4. Corrupted salt
	corruptedSalt := make([]byte, len(salt))
	copy(corruptedSalt, salt)
	corruptedSalt[0] ^= 0xFF

	keyFromCorruptedSalt, _ := kdf.DeriveKey(password, corruptedSalt)
	defer crypto.ZeroMemory(keyFromCorruptedSalt)

	_, err = cipher.Decrypt(nonce, ciphertext, keyFromCorruptedSalt, aad)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for corrupted salt, got %v", err)
	}

	// 5. Corrupted verification nonce
	corruptedNonce := make([]byte, len(nonce))
	copy(corruptedNonce, nonce)
	corruptedNonce[0] ^= 0xFF

	_, err = cipher.Decrypt(corruptedNonce, ciphertext, key, aad)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for corrupted nonce, got %v", err)
	}

	// 6. Corrupted verification AAD
	corruptedAAD := []byte("meta:auth_check_corrupted")
	_, err = cipher.Decrypt(nonce, ciphertext, key, corruptedAAD)
	if err != crypto.ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for corrupted AAD, got %v", err)
	}
}

func TestPasswordStructureValidation(t *testing.T) {
	if err := crypto.ValidatePasswordStructure("short"); err != crypto.ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort for 'short', got %v", err)
	}

	if err := crypto.ValidatePasswordStructure("ValidPass123"); err != nil {
		t.Errorf("expected valid password, got error: %v", err)
	}
}

func TestZeroMemory(t *testing.T) {
	secret := []byte("SensitiveByteData")
	crypto.ZeroMemory(secret)
	for i, b := range secret {
		if b != 0 {
			t.Errorf("expected byte %d to be zero, got %d", i, b)
		}
	}
}
