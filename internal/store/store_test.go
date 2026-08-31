package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"devvault/internal/store"
)

func TestStoreFullLifecycle(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_devvault.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Check initialized
	init, err := s.IsInitialized(ctx)
	if err != nil {
		t.Fatalf("IsInitialized error: %v", err)
	}
	if init {
		t.Errorf("expected new DB to be uninitialized")
	}

	// Initialize with Master Password
	masterPass := "CorrectHorseBatteryStaple123!"
	masterKey, err := s.InitSchema(ctx, masterPass)
	if err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}
	if len(masterKey) != 32 {
		t.Fatalf("expected 32-byte master key, got %d", len(masterKey))
	}

	// Test Authentication (Correct & Wrong Password)
	authKey, err := s.Authenticate(ctx, masterPass)
	if err != nil {
		t.Fatalf("Authenticate failed with correct password: %v", err)
	}
	if len(authKey) != 32 {
		t.Fatalf("expected 32-byte auth key")
	}

	_, err = s.Authenticate(ctx, "WrongPassword!")
	if err != store.ErrInvalidMasterPassword {
		t.Fatalf("expected ErrInvalidMasterPassword, got %v", err)
	}

	// Test Profile CRUD
	prof, err := s.CreateProfile(ctx, "staging", "Staging environment secrets")
	if err != nil {
		t.Fatalf("CreateProfile failed: %v", err)
	}
	if prof.Name != "staging" {
		t.Errorf("expected profile name 'staging', got %s", prof.Name)
	}

	profiles, err := s.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(profiles) != 2 { // 'default' and 'staging'
		t.Errorf("expected 2 profiles, got %d", len(profiles))
	}

	// Test Secret CRUD
	err = s.PutSecret(ctx, "staging", "DATABASE_URL", "postgres://user:pass@localhost:5432/staging_db", "db,postgres", masterKey)
	if err != nil {
		t.Fatalf("PutSecret failed: %v", err)
	}

	sec, err := s.GetSecret(ctx, "staging", "DATABASE_URL", masterKey)
	if err != nil {
		t.Fatalf("GetSecret failed: %v", err)
	}
	if sec.Value != "postgres://user:pass@localhost:5432/staging_db" {
		t.Errorf("secret value mismatch: got %s", sec.Value)
	}

	secList, err := s.ListSecrets(ctx, "staging", masterKey)
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}
	if len(secList) != 1 {
		t.Errorf("expected 1 secret in staging, got %d", len(secList))
	}

	// Delete Secret
	err = s.DeleteSecret(ctx, "staging", "DATABASE_URL")
	if err != nil {
		t.Fatalf("DeleteSecret failed: %v", err)
	}

	_, err = s.GetSecret(ctx, "staging", "DATABASE_URL", masterKey)
	if err != store.ErrSecretNotFound {
		t.Fatalf("expected ErrSecretNotFound after deletion, got %v", err)
	}
}
