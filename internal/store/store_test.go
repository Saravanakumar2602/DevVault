package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"devvault/internal/crypto"
	"devvault/internal/store"

	_ "modernc.org/sqlite"
)

func TestEncryptedSecretCRUDLifecycle(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "phase3_crud.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	masterPass := "StrongMasterPassword123!"
	masterKey, err := s.InitSchema(ctx, masterPass)
	if err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}

	// 1. Create secret
	err = s.PutSecret(ctx, "default", "API_KEY", "sk_live_1122334455", "prod,stripe", masterKey)
	if err != nil {
		t.Fatalf("PutSecret create failed: %v", err)
	}

	// 2. Read secret
	sec, err := s.GetSecret(ctx, "default", "API_KEY", masterKey)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if sec.Value != "sk_live_1122334455" {
		t.Errorf("expected secret value 'sk_live_1122334455', got '%s'", sec.Value)
	}

	// 3. Update secret (duplicate name overwrite)
	err = s.PutSecret(ctx, "default", "API_KEY", "sk_live_9988776655", "prod,stripe_updated", masterKey)
	if err != nil {
		t.Fatalf("PutSecret update failed: %v", err)
	}

	updatedSec, err := s.GetSecret(ctx, "default", "API_KEY", masterKey)
	if err != nil {
		t.Fatalf("GetSecret updated failed: %v", err)
	}
	if updatedSec.Value != "sk_live_9988776655" {
		t.Errorf("expected updated value 'sk_live_9988776655', got '%s'", updatedSec.Value)
	}

	// 4. List Metadata (Values must not be present in metadata list)
	metaList, err := s.ListSecretMetadata(ctx, "default")
	if err != nil {
		t.Fatalf("ListSecretMetadata failed: %v", err)
	}
	if len(metaList) != 1 {
		t.Fatalf("expected 1 secret metadata entry, got %d", len(metaList))
	}
	if metaList[0].Key != "API_KEY" {
		t.Errorf("expected key 'API_KEY', got '%s'", metaList[0].Key)
	}

	// 5. Delete secret
	err = s.DeleteSecret(ctx, "default", "API_KEY")
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}

	_, err = s.GetSecret(ctx, "default", "API_KEY", masterKey)
	if err != store.ErrSecretNotFound {
		t.Errorf("expected ErrSecretNotFound after deletion, got %v", err)
	}
}

func TestSecretKeyValidationAndEdgeCases(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "phase3_validation.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	masterPass := "StrongMasterPassword123!"
	masterKey, _ := s.InitSchema(ctx, masterPass)

	// 1. Empty secret name
	err = s.PutSecret(ctx, "default", "", "val", "", masterKey)
	if err == nil {
		t.Errorf("expected error for empty secret name, got nil")
	}

	// 2. Invalid secret name (with spaces and special characters)
	err = s.PutSecret(ctx, "default", "INVALID NAME WITH SPACES!", "val", "", masterKey)
	if err != crypto.ErrInvalidSecretKeyName {
		t.Errorf("expected ErrInvalidSecretKeyName for name with spaces, got %v", err)
	}

	// 3. Wrong master password read
	wrongKey := crypto.DeriveKey("WrongPassword999!", []byte("dummy_salt_data_1234567890123456"))
	s.PutSecret(ctx, "default", "VALID_KEY", "secret_val", "", masterKey)

	_, err = s.GetSecret(ctx, "default", "VALID_KEY", wrongKey)
	if err == nil {
		t.Errorf("expected decryption error when using wrong master password, got nil")
	}

	// 4. Corrupted ciphertext in database
	rawDB, _ := sql.Open("sqlite", dbPath)
	defer rawDB.Close()
	rawDB.Exec("UPDATE secrets SET ciphertext = x'FFFFFFFFFFFFFFFF' WHERE key = 'VALID_KEY'")

	_, err = s.GetSecret(ctx, "default", "VALID_KEY", masterKey)
	if err == nil {
		t.Errorf("expected error when reading corrupted ciphertext, got nil")
	}
}
