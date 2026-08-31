package models

import "time"

// Meta represents key-value metadata stored in the database (e.g. kdf_salt, auth_check).
type Meta struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Profile represents an isolated namespace for secrets.
type Profile struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Secret represents an encrypted secret entry stored in SQLite.
type Secret struct {
	ID         int64     `json:"id"`
	ProfileID  int64     `json:"profile_id"`
	Key        string    `json:"key"`
	Nonce      []byte    `json:"nonce"`      // 12-byte AES-GCM random nonce
	Ciphertext []byte    `json:"ciphertext"` // AES-GCM encrypted payload + tag
	Tags       string    `json:"tags,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// DecryptedSecret holds an unencrypted key-value secret in memory.
type DecryptedSecret struct {
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	Profile   string    `json:"profile"`
	Tags      string    `json:"tags,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}
