package crypto

// KeyDeriver defines the interface for key derivation functions (e.g. Argon2id).
type KeyDeriver interface {
	DeriveKey(password string, salt []byte) ([]byte, error)
	AlgorithmName() string
}

// AEADCipher defines the interface for authenticated encryption with associated data (e.g. AES-256-GCM).
type AEADCipher interface {
	Encrypt(plaintext []byte, key []byte, aad []byte) (nonce []byte, ciphertext []byte, err error)
	Decrypt(nonce []byte, ciphertext []byte, key []byte, aad []byte) ([]byte, error)
	CipherName() string
}

// SaltGenerator defines the interface for generating secure cryptographic randomness.
type SaltGenerator interface {
	GenerateSalt(size int) ([]byte, error)
}
