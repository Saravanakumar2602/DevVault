package store

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"devvault/internal/crypto"
	"devvault/internal/models"

	_ "modernc.org/sqlite"
)

const (
	MetaSchemaVersion = "schema_version"
	MetaSalt          = "kdf_salt"
	MetaAuthCheck     = "auth_check"
	MetaAuthNonce     = "auth_nonce"
	SentinelValue     = "DEVVAULT_SENTINEL_OK"
	CurrentSchemaVer  = "1"
)

// SecretMetadata holds non-sensitive metadata for secret listing commands.
type SecretMetadata struct {
	Key       string    `json:"key"`
	Tags      string    `json:"tags,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Store struct {
	dbPath string
	db     *sql.DB
}

// Open initializes and returns a SQLite store instance with strict file permissions.
func Open(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create directory for vault database: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database at %s: %w", dbPath, err)
	}

	_ = os.Chmod(dbPath, 0600)

	if _, err := db.Exec("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;"); err != nil {
		// WAL pragma optional
	}

	return &Store{dbPath: dbPath, db: db}, nil
}

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) DBPath() string {
	return s.dbPath
}

func (s *Store) IsInitialized(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table' AND name='meta'").Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to inspect database schema: %w", err)
	}
	return count > 0, nil
}

// InitSchema atomically initializes database schema and metadata within an explicit transaction.
func (s *Store) InitSchema(ctx context.Context, masterPassword string) ([]byte, error) {
	init, err := s.IsInitialized(ctx)
	if err != nil {
		return nil, err
	}
	if init {
		return nil, ErrVaultAlreadyInit
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	schema := `
	CREATE TABLE meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE profiles (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		description TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		profile_id INTEGER NOT NULL,
		key TEXT NOT NULL,
		nonce BLOB NOT NULL,
		ciphertext BLOB NOT NULL,
		tags TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(profile_id) REFERENCES profiles(id) ON DELETE CASCADE,
		UNIQUE(profile_id, key)
	);
	`
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("failed to create database tables: %w", err)
	}

	salt, err := crypto.GenerateSalt(32)
	if err != nil {
		return nil, err
	}
	masterKey := crypto.DeriveKey(masterPassword, salt)

	authNonce, authCiphertext, err := crypto.Encrypt([]byte(SentinelValue), masterKey, []byte("meta:auth_check"))
	if err != nil {
		crypto.ZeroMemory(masterKey)
		return nil, fmt.Errorf("failed to create auth sentinel: %w", err)
	}

	b64Salt := base64.StdEncoding.EncodeToString(salt)
	b64AuthNonce := base64.StdEncoding.EncodeToString(authNonce)
	b64AuthCipher := base64.StdEncoding.EncodeToString(authCiphertext)

	metaEntries := map[string]string{
		MetaSchemaVersion: CurrentSchemaVer,
		MetaSalt:          b64Salt,
		MetaAuthNonce:     b64AuthNonce,
		MetaAuthCheck:     b64AuthCipher,
	}

	for k, v := range metaEntries {
		if _, err := tx.ExecContext(ctx, "INSERT INTO meta (key, value) VALUES (?, ?)", k, v); err != nil {
			crypto.ZeroMemory(masterKey)
			return nil, fmt.Errorf("failed to save metadata %s: %w", k, err)
		}
	}

	if _, err := tx.ExecContext(ctx, "INSERT INTO profiles (name, description) VALUES ('default', 'Default secrets profile')"); err != nil {
		crypto.ZeroMemory(masterKey)
		return nil, fmt.Errorf("failed to create default profile: %w", err)
	}

	if err := tx.Commit(); err != nil {
		crypto.ZeroMemory(masterKey)
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	return masterKey, nil
}

func (s *Store) Authenticate(ctx context.Context, masterPassword string) ([]byte, error) {
	init, err := s.IsInitialized(ctx)
	if err != nil {
		return nil, err
	}
	if !init {
		return nil, ErrVaultNotInitialized
	}

	var b64Salt, b64AuthNonce, b64AuthCipher string
	err = s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", MetaSalt).Scan(&b64Salt)
	if err != nil {
		return nil, fmt.Errorf("missing KDF salt in database: %w", err)
	}
	err = s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", MetaAuthNonce).Scan(&b64AuthNonce)
	if err != nil {
		return nil, fmt.Errorf("missing auth nonce in database: %w", err)
	}
	err = s.db.QueryRowContext(ctx, "SELECT value FROM meta WHERE key = ?", MetaAuthCheck).Scan(&b64AuthCipher)
	if err != nil {
		return nil, fmt.Errorf("missing auth sentinel in database: %w", err)
	}

	salt, err := base64.StdEncoding.DecodeString(b64Salt)
	if err != nil {
		return nil, fmt.Errorf("corrupt KDF salt encoding: %w", err)
	}
	authNonce, err := base64.StdEncoding.DecodeString(b64AuthNonce)
	if err != nil {
		return nil, fmt.Errorf("corrupt auth nonce encoding: %w", err)
	}
	authCiphertext, err := base64.StdEncoding.DecodeString(b64AuthCipher)
	if err != nil {
		return nil, fmt.Errorf("corrupt auth ciphertext encoding: %w", err)
	}

	masterKey := crypto.DeriveKey(masterPassword, salt)
	decryptedSentinel, err := crypto.Decrypt(authNonce, authCiphertext, masterKey, []byte("meta:auth_check"))
	if err != nil || string(decryptedSentinel) != SentinelValue {
		crypto.ZeroMemory(masterKey)
		return nil, ErrInvalidMasterPassword
	}

	return masterKey, nil
}

// Profile CRUD operations

func (s *Store) CreateProfile(ctx context.Context, name, description string) (*models.Profile, error) {
	if err := crypto.ValidateProfileName(name); err != nil {
		return nil, err
	}

	res, err := s.db.ExecContext(ctx, "INSERT INTO profiles (name, description) VALUES (?, ?)", name, description)
	if err != nil {
		return nil, fmt.Errorf("failed to create profile '%s': %w", name, err)
	}
	id, _ := res.LastInsertId()
	return &models.Profile{ID: id, Name: name, Description: description}, nil
}

func (s *Store) GetProfileByName(ctx context.Context, name string) (*models.Profile, error) {
	var p models.Profile
	err := s.db.QueryRowContext(ctx, "SELECT id, name, coalesce(description, ''), created_at, updated_at FROM profiles WHERE name = ?", name).
		Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrProfileNotFound
		}
		return nil, err
	}
	return &p, nil
}

func (s *Store) ListProfiles(ctx context.Context) ([]*models.Profile, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, name, coalesce(description, ''), created_at, updated_at FROM profiles ORDER BY name ASC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var profiles []*models.Profile
	for rows.Next() {
		var p models.Profile
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		profiles = append(profiles, &p)
	}
	return profiles, nil
}

func (s *Store) DeleteProfile(ctx context.Context, name string) error {
	if name == "default" {
		return ErrCannotDeleteDefault
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM profiles WHERE name = ?", name)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrProfileNotFound
	}
	return nil
}

// Secret CRUD operations

func (s *Store) PutSecret(ctx context.Context, profileName, key, value, tags string, masterKey []byte) error {
	if err := crypto.ValidateSecretKeyName(key); err != nil {
		return err
	}

	p, err := s.GetProfileByName(ctx, profileName)
	if err != nil {
		return err
	}

	aad := []byte(fmt.Sprintf("%s:%s", profileName, key))
	nonce, ciphertext, err := crypto.Encrypt([]byte(value), masterKey, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt secret: %w", err)
	}

	query := `
	INSERT INTO secrets (profile_id, key, nonce, ciphertext, tags, updated_at)
	VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
	ON CONFLICT(profile_id, key) DO UPDATE SET
		nonce = excluded.nonce,
		ciphertext = excluded.ciphertext,
		tags = excluded.tags,
		updated_at = CURRENT_TIMESTAMP
	`
	_, err = s.db.ExecContext(ctx, query, p.ID, key, nonce, ciphertext, tags)
	if err != nil {
		return fmt.Errorf("failed to save secret: %w", err)
	}
	return nil
}

func (s *Store) GetSecret(ctx context.Context, profileName, key string, masterKey []byte) (*models.DecryptedSecret, error) {
	if err := crypto.ValidateSecretKeyName(key); err != nil {
		return nil, err
	}

	p, err := s.GetProfileByName(ctx, profileName)
	if err != nil {
		return nil, err
	}

	var nonce, ciphertext []byte
	var tags string
	var updatedAt models.Secret
	err = s.db.QueryRowContext(ctx, "SELECT nonce, ciphertext, coalesce(tags, ''), updated_at FROM secrets WHERE profile_id = ? AND key = ?", p.ID, key).
		Scan(&nonce, &ciphertext, &tags, &updatedAt.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, ErrSecretNotFound
		}
		return nil, err
	}

	aad := []byte(fmt.Sprintf("%s:%s", profileName, key))
	plaintext, err := crypto.Decrypt(nonce, ciphertext, masterKey, aad)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return &models.DecryptedSecret{
		Key:       key,
		Value:     string(plaintext),
		Profile:   profileName,
		Tags:      tags,
		UpdatedAt: updatedAt.UpdatedAt,
	}, nil
}

func (s *Store) ListSecretMetadata(ctx context.Context, profileName string) ([]*SecretMetadata, error) {
	p, err := s.GetProfileByName(ctx, profileName)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key, coalesce(tags, ''), created_at, updated_at FROM secrets WHERE profile_id = ? ORDER BY key ASC", p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*SecretMetadata
	for rows.Next() {
		var m SecretMetadata
		if err := rows.Scan(&m.Key, &m.Tags, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		list = append(list, &m)
	}
	return list, nil
}

func (s *Store) ListSecrets(ctx context.Context, profileName string, masterKey []byte) ([]*models.DecryptedSecret, error) {
	p, err := s.GetProfileByName(ctx, profileName)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.QueryContext(ctx, "SELECT key, nonce, ciphertext, coalesce(tags, ''), updated_at FROM secrets WHERE profile_id = ? ORDER BY key ASC", p.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*models.DecryptedSecret
	for rows.Next() {
		var key, tags string
		var nonce, ciphertext []byte
		var updatedAt models.Secret
		if err := rows.Scan(&key, &nonce, &ciphertext, &tags, &updatedAt.UpdatedAt); err != nil {
			return nil, err
		}

		aad := []byte(fmt.Sprintf("%s:%s", profileName, key))
		plaintext, err := crypto.Decrypt(nonce, ciphertext, masterKey, aad)
		if err != nil {
			continue
		}

		list = append(list, &models.DecryptedSecret{
			Key:       key,
			Value:     string(plaintext),
			Profile:   profileName,
			Tags:      tags,
			UpdatedAt: updatedAt.UpdatedAt,
		})
	}
	return list, nil
}

func (s *Store) DeleteSecret(ctx context.Context, profileName, key string) error {
	if err := crypto.ValidateSecretKeyName(key); err != nil {
		return err
	}

	p, err := s.GetProfileByName(ctx, profileName)
	if err != nil {
		return err
	}

	res, err := s.db.ExecContext(ctx, "DELETE FROM secrets WHERE profile_id = ? AND key = ?", p.ID, key)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		return ErrSecretNotFound
	}
	return nil
}
