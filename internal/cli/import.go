package cli

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var (
	flagImportDryRun bool
	flagImportForce  bool
)

var importCmd = &cobra.Command{
	Use:   "import <FILE>",
	Short: "Import vault profiles and secrets from an encrypted backup file",
	Long: `Decrypts and restores vault profiles and secrets from an encrypted backup file.
Supports --dry-run validation mode and prompts before overwriting existing secret entries.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		inPath := args[0]

		fileData, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("failed to read backup file '%s': %w", inPath, err)
		}

		var backupEnc EncryptedBackupFile
		if err := json.Unmarshal(fileData, &backupEnc); err != nil {
			return fmt.Errorf("invalid backup file format: %w", err)
		}

		// 1. Version check
		if backupEnc.Version != CurrentBackupVersion {
			return fmt.Errorf("%w: backup file specifies version '%s'", ErrIncompatibleBackupVersion, backupEnc.Version)
		}

		// 2. Decode headers
		salt, err := base64.StdEncoding.DecodeString(backupEnc.KDF.Salt)
		if err != nil || len(salt) == 0 {
			return fmt.Errorf("%w: invalid salt encoding", ErrCorruptedBackupFile)
		}
		nonce, err := base64.StdEncoding.DecodeString(backupEnc.Cipher.Nonce)
		if err != nil || len(nonce) == 0 {
			return fmt.Errorf("%w: invalid nonce encoding", ErrCorruptedBackupFile)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(backupEnc.Payload)
		if err != nil || len(ciphertext) == 0 {
			return fmt.Errorf("%w: invalid ciphertext payload encoding", ErrCorruptedBackupFile)
		}

		// 3. Prompt passphrase & decrypt
		exportPass, err := PromptBackupPassphrase("🔐 Enter backup file passphrase: ")
		if err != nil {
			return err
		}

		kdf := &crypto.Argon2idKDF{
			Time:    backupEnc.KDF.Time,
			Memory:  backupEnc.KDF.Memory,
			Threads: backupEnc.KDF.Threads,
			KeyLen:  32,
		}
		if kdf.Time == 0 || kdf.Memory == 0 {
			kdf = crypto.NewArgon2idKDF()
		}

		exportKey, err := kdf.DeriveKey(exportPass, salt)
		if err != nil {
			return fmt.Errorf("failed to derive backup key: %w", err)
		}
		defer crypto.ZeroMemory(exportKey)

		cipher := crypto.NewAESGCMCipher()
		plaintext, err := cipher.Decrypt(nonce, ciphertext, exportKey, []byte(BackupAAD))
		if err != nil {
			return ErrCorruptedBackupFile
		}
		defer crypto.ZeroMemory(plaintext)

		var payload BackupPayload
		if err := json.Unmarshal(plaintext, &payload); err != nil {
			return fmt.Errorf("%w: invalid payload structure", ErrCorruptedBackupFile)
		}

		totalSecrets := 0
		for _, p := range payload.Profiles {
			totalSecrets += len(p.Secrets)
		}

		// 4. Dry-Run Mode
		if flagImportDryRun {
			cmd.Printf("🔍 [Dry-Run] Backup file validation successful!\n")
			cmd.Printf("📦 Backup contains %d profile(s) and %d secret(s) exported at %s.\n",
				len(payload.Profiles), totalSecrets, payload.ExportedAt.Format("2006-01-02 15:04:05 UTC"))
			return nil
		}

		// 5. Normal Import Mode: Connect to Store
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

		importedSecrets := 0
		overwrittenSecrets := 0

		for _, p := range payload.Profiles {
			// Ensure profile exists
			_, err := s.GetProfileByName(ctx, p.Name)
			if err != nil {
				_, err = s.CreateProfile(ctx, p.Name, p.Description)
				if err != nil {
					cmd.Printf("⚠️ Warning: Failed to create profile '%s': %v\n", p.Name, err)
					continue
				}
			}

			for _, sec := range p.Secrets {
				// Check duplicate secret
				existing, _ := s.GetSecret(ctx, p.Name, sec.Key, masterKey)
				if existing != nil && !flagImportForce {
					cmd.Printf("⚠️ Secret '%s' in profile '%s' already exists. Overwrite? (y/N): ", sec.Key, p.Name)
					reader := bufio.NewReader(os.Stdin)
					response, err := reader.ReadString('\n')
					if err != nil {
						continue
					}
					response = strings.TrimSpace(strings.ToLower(response))
					if response != "y" && response != "yes" {
						cmd.Printf("⏩ Skipped '%s'.\n", sec.Key)
						continue
					}
					overwrittenSecrets++
				}

				err := s.PutSecret(ctx, p.Name, sec.Key, sec.Value, sec.Tags, masterKey)
				if err != nil {
					cmd.Printf("⚠️ Warning: Failed to import secret '%s': %v\n", sec.Key, err)
					continue
				}
				importedSecrets++
			}
		}

		cmd.Printf("📥 Successfully imported %d secret(s) into vault (%d overwritten).\n", importedSecrets, overwrittenSecrets)
		return nil
	},
}

func init() {
	importCmd.Flags().BoolVar(&flagImportDryRun, "dry-run", false, "Validate backup file structure without modifying database")
	importCmd.Flags().BoolVarP(&flagImportForce, "force", "f", false, "Bypass confirmation prompt when overwriting duplicate secrets")
	RootCmd.AddCommand(importCmd)
}
