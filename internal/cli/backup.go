package cli

import (
	"errors"
	"time"
)

const (
	CurrentBackupVersion = "1.0"
	BackupAAD            = "devvault:backup:v1.0"
)

var (
	ErrIncompatibleBackupVersion = errors.New("incompatible backup format version: expected 1.0")
	ErrCorruptedBackupFile       = errors.New("invalid or corrupted backup file: wrong passphrase or tampered ciphertext")
)

type BackupKDFHeader struct {
	Algorithm string `json:"algorithm"`
	Salt      string `json:"salt"`
	Time      uint32 `json:"time"`
	Memory    uint32 `json:"memory"`
	Threads   uint8  `json:"threads"`
}

type BackupCipherHeader struct {
	Algorithm string `json:"algorithm"`
	Nonce     string `json:"nonce"`
}

type EncryptedBackupFile struct {
	Version string             `json:"version"`
	KDF     BackupKDFHeader    `json:"kdf"`
	Cipher  BackupCipherHeader `json:"cipher"`
	Payload string             `json:"payload"` // Base64 AES-256-GCM payload
}

type ExportedSecret struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Tags  string `json:"tags,omitempty"`
}

type ExportedProfile struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Secrets     []ExportedSecret `json:"secrets"`
}

type BackupPayload struct {
	ExportedAt time.Time         `json:"exported_at"`
	Profiles   []ExportedProfile `json:"profiles"`
}
