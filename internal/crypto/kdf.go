package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultArgonTime    uint32 = 3
	DefaultArgonMemory  uint32 = 64 * 1024 // 64 MB in KiB
	DefaultArgonThreads uint8  = 4
	DefaultKeyLen       uint32 = 32 // 256 bits
	DefaultSaltLen      int    = 32 // 256 bits
)

var (
	ErrInvalidSaltLength    = errors.New("salt length must be at least 16 bytes")
	ErrEmptyMasterPassword  = errors.New("master password cannot be empty")
	ErrFailedToGenerateSalt = errors.New("crypto/rand failed to generate random salt")
)

// Argon2idKDF implements KeyDeriver using the Argon2id key derivation algorithm.
type Argon2idKDF struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

// NewArgon2idKDF returns an Argon2idKDF configured with security defaults.
func NewArgon2idKDF() *Argon2idKDF {
	return &Argon2idKDF{
		Time:    DefaultArgonTime,
		Memory:  DefaultArgonMemory,
		Threads: DefaultArgonThreads,
		KeyLen:  DefaultKeyLen,
	}
}

func (k *Argon2idKDF) AlgorithmName() string {
	return "Argon2id"
}

// DeriveKey derives a key from password and salt using Argon2id.
func (k *Argon2idKDF) DeriveKey(password string, salt []byte) ([]byte, error) {
	if password == "" {
		return nil, ErrEmptyMasterPassword
	}
	if len(salt) < 16 {
		return nil, ErrInvalidSaltLength
	}

	key := argon2.IDKey([]byte(password), salt, k.Time, k.Memory, k.Threads, k.KeyLen)
	return key, nil
}

// RandomSaltGenerator implements SaltGenerator using crypto/rand.
type RandomSaltGenerator struct{}

func NewRandomSaltGenerator() *RandomSaltGenerator {
	return &RandomSaltGenerator{}
}

func (g *RandomSaltGenerator) GenerateSalt(size int) ([]byte, error) {
	if size <= 0 {
		size = DefaultSaltLen
	}
	salt := make([]byte, size)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToGenerateSalt, err)
	}
	return salt, nil
}
