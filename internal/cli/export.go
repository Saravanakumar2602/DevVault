package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var exportCmd = &cobra.Command{
	Use:   "export <FILE>",
	Short: "Export all vault profiles and secrets to an encrypted backup file",
	Long: `Encrypts and exports all stored profiles and secret keys to an authenticated backup file.
Plaintext secrets and master passwords are NEVER stored unencrypted.
The backup file is encrypted using an Export Passphrase with Argon2id KDF and AES-256-GCM AEAD.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		outPath := args[0]

		dbPath, err := config.GetDBPath()
		if err != nil {
			return err
		}

		s, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()

		password, err := PromptPassword("🔑 Master Password: ")
		if err != nil {
			return err
		}

		masterKey, err := s.Authenticate(ctx, password)
		if err != nil {
			return err
		}
		defer crypto.ZeroMemory(masterKey)

		// 1. Load profiles & secrets into memory
		profiles, err := s.ListProfiles(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch profiles: %w", err)
		}

		var exportedProfiles []ExportedProfile
		totalSecrets := 0

		for _, p := range profiles {
			secList, err := s.ListSecrets(ctx, p.Name, masterKey)
			if err != nil {
				return fmt.Errorf("failed to read secrets for profile '%s': %w", p.Name, err)
			}

			var exportedSecrets []ExportedSecret
			for _, sec := range secList {
				exportedSecrets = append(exportedSecrets, ExportedSecret{
					Key:   sec.Key,
					Value: sec.Value,
					Tags:  sec.Tags,
				})
				totalSecrets++
			}

			exportedProfiles = append(exportedProfiles, ExportedProfile{
				Name:        p.Name,
				Description: p.Description,
				Secrets:     exportedSecrets,
			})
		}

		payload := BackupPayload{
			ExportedAt: time.Now().UTC(),
			Profiles:   exportedProfiles,
		}

		rawJSON, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal export payload: %w", err)
		}
		defer crypto.ZeroMemory(rawJSON)

		// 2. Prompt for export passphrase
		exportPass, err := PromptBackupPassphrase("🔐 Create passphrase for backup file encryption: ")
		if err != nil {
			return err
		}

		confirmPass, err := PromptBackupPassphrase("🔐 Confirm backup file passphrase: ")
		if err != nil {
			return err
		}

		if exportPass != confirmPass {
			return fmt.Errorf("backup passphrases do not match")
		}

		// 3. Encrypt payload
		salt, err := crypto.GenerateSalt(32)
		if err != nil {
			return err
		}

		kdf := crypto.NewArgon2idKDF()
		exportKey, err := kdf.DeriveKey(exportPass, salt)
		if err != nil {
			return fmt.Errorf("failed to derive backup encryption key: %w", err)
		}
		defer crypto.ZeroMemory(exportKey)

		cipher := crypto.NewAESGCMCipher()
		nonce, ciphertext, err := cipher.Encrypt(rawJSON, exportKey, []byte(BackupAAD))
		if err != nil {
			return fmt.Errorf("failed to encrypt backup file: %w", err)
		}

		backupFile := EncryptedBackupFile{
			Version: CurrentBackupVersion,
			KDF: BackupKDFHeader{
				Algorithm: kdf.AlgorithmName(),
				Salt:      base64.StdEncoding.EncodeToString(salt),
				Time:      kdf.Time,
				Memory:    kdf.Memory,
				Threads:   kdf.Threads,
			},
			Cipher: BackupCipherHeader{
				Algorithm: cipher.CipherName(),
				Nonce:     base64.StdEncoding.EncodeToString(nonce),
			},
			Payload: base64.StdEncoding.EncodeToString(ciphertext),
		}

		fileData, err := json.MarshalIndent(backupFile, "", "  ")
		if err != nil {
			return err
		}

		if err := os.WriteFile(outPath, fileData, 0600); err != nil {
			return fmt.Errorf("failed to write backup file '%s': %w", outPath, err)
		}

		cmd.Printf("📦 Successfully exported %d profile(s) and %d secret(s) to '%s'.\n", len(exportedProfiles), totalSecrets, outPath)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
}
