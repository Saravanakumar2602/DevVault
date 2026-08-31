package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"devvault/internal/crypto"
	"devvault/internal/store"

	_ "modernc.org/sqlite"
)

func TestProfileIsolationAndLifecycle(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "phase5_profiles.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	masterPass := "MasterSecretPass123!"
	masterKey, err := s.InitSchema(ctx, masterPass)
	if err != nil {
		t.Fatalf("InitSchema failed: %v", err)
	}

	// 1. Create profiles
	_, err = s.CreateProfile(ctx, "development", "Development environment")
	if err != nil {
		t.Fatalf("CreateProfile development failed: %v", err)
	}

	_, err = s.CreateProfile(ctx, "production", "Production environment")
	if err != nil {
		t.Fatalf("CreateProfile production failed: %v", err)
	}

	profiles, err := s.ListProfiles(ctx)
	if err != nil {
		t.Fatalf("ListProfiles failed: %v", err)
	}
	if len(profiles) != 3 { // 'default', 'development', 'production'
		t.Errorf("expected 3 profiles, got %d", len(profiles))
	}

	// 2. Store identical secret key name (DATABASE_URL) in different profiles
	devDB := "postgres://dev_user:dev_pass@localhost:5432/dev_db"
	prodDB := "postgres://prod_admin:prod_secret@prod-cluster.internal:5432/prod_db"

	err = s.PutSecret(ctx, "development", "DATABASE_URL", devDB, "dev", masterKey)
	if err != nil {
		t.Fatalf("PutSecret development failed: %v", err)
	}

	err = s.PutSecret(ctx, "production", "DATABASE_URL", prodDB, "prod", masterKey)
	if err != nil {
		t.Fatalf("PutSecret production failed: %v", err)
	}

	// 3. Verify Secret Isolation: Retrieve DATABASE_URL from each profile
	devSec, err := s.GetSecret(ctx, "development", "DATABASE_URL", masterKey)
	if err != nil {
		t.Fatalf("GetSecret development failed: %v", err)
	}
	if devSec.Value != devDB {
		t.Errorf("expected dev DB URL '%s', got '%s'", devDB, devSec.Value)
	}

	prodSec, err := s.GetSecret(ctx, "production", "DATABASE_URL", masterKey)
	if err != nil {
		t.Fatalf("GetSecret production failed: %v", err)
	}
	if prodSec.Value != prodDB {
		t.Errorf("expected prod DB URL '%s', got '%s'", prodDB, prodSec.Value)
	}

	// 4. Test Profile Deletion (CASCADE secret deletion)
	err = s.DeleteProfile(ctx, "development")
	if err != nil {
		t.Fatalf("DeleteProfile development failed: %v", err)
	}

	_, err = s.GetSecret(ctx, "development", "DATABASE_URL", masterKey)
	if err != store.ErrProfileNotFound {
		t.Errorf("expected ErrProfileNotFound after deleting profile, got %v", err)
	}

	// Verify production secret remains intact
	prodSecStillExists, err := s.GetSecret(ctx, "production", "DATABASE_URL", masterKey)
	if err != nil || prodSecStillExists.Value != prodDB {
		t.Errorf("expected production secret to remain intact post development profile deletion")
	}

	// 5. Test Prevent deleting default profile
	err = s.DeleteProfile(ctx, "default")
	if err != store.ErrCannotDeleteDefault {
		t.Errorf("expected ErrCannotDeleteDefault, got %v", err)
	}
}

func TestInvalidProfileNameValidation(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "phase5_invalid.db")

	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	s.InitSchema(ctx, "Pass123!")

	_, err = s.CreateProfile(ctx, "INVALID PROFILE NAME!", "desc")
	if err != crypto.ErrInvalidProfileName {
		t.Errorf("expected ErrInvalidProfileName, got %v", err)
	}
}
