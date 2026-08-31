package store_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"devvault/internal/store"
	_ "modernc.org/sqlite"
)

func TestStoreMasterPasswordAndKeyManagement(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "vault_phase2.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// 1. Initialized check
	init, err := s.IsInitialized(ctx)
	if err != nil {
		t.Fatalf("IsInitialized error: %v", err)
	}
	if init {
		t.Errorf("expected new database to be uninitialized")
	}

	masterPass := "CorrectMasterPassword123!"

	// 2. Initialize schema with Master Password
	masterKey, err := s.InitSchema(ctx, masterPass)
	if err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}
	if len(masterKey) != 32 {
		t.Fatalf("expected 32-byte master key, got %d", len(masterKey))
	}

	// 3. Test correct password authentication
	authKey, err := s.Authenticate(ctx, masterPass)
	if err != nil {
		t.Fatalf("Authenticate failed for correct password: %v", err)
	}
	if len(authKey) != 32 {
		t.Fatalf("expected 32-byte authenticated key")
	}

	// 4. Test incorrect password authentication
	_, err = s.Authenticate(ctx, "IncorrectMasterPassword!")
	if err != store.ErrInvalidMasterPassword {
		t.Fatalf("expected ErrInvalidMasterPassword, got %v", err)
	}
}

func TestStoreCorruptedMetadata(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "corrupted_vault.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	masterPass := "ValidMasterPass123!"
	_, err = s.InitSchema(ctx, masterPass)
	if err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}

	// Corrupt stored auth check payload directly in SQLite
	rawDB, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open raw DB: %v", err)
	}
	defer rawDB.Close()

	_, err = rawDB.Exec("UPDATE meta SET value = 'CORRUPTED_BASE64_DATA==' WHERE key = 'auth_check'")
	if err != nil {
		t.Fatalf("Failed to corrupt metadata: %v", err)
	}

	// Authenticate should fail cleanly with ErrInvalidMasterPassword or decoding error
	_, err = s.Authenticate(ctx, masterPass)
	if err == nil {
		t.Fatalf("expected error when authenticating against corrupted verification data, got nil")
	}
}
