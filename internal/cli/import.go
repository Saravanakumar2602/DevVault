package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var importCmd = &cobra.Command{
	Use:   "import <INPUT_FILE>",
	Short: "Import secrets from an encrypted backup file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		inPath := args[0]

		fileData, err := os.ReadFile(inPath)
		if err != nil {
			return fmt.Errorf("failed to read input file '%s': %w", inPath, err)
		}

		var backup EncryptedBackupPayload
		if err := json.Unmarshal(fileData, &backup); err != nil {
			return fmt.Errorf("invalid backup file format: %w", err)
		}

		salt, err := base64.StdEncoding.DecodeString(backup.Salt)
		if err != nil {
			return fmt.Errorf("invalid salt encoding: %w", err)
		}
		nonce, err := base64.StdEncoding.DecodeString(backup.Nonce)
		if err != nil {
			return fmt.Errorf("invalid nonce encoding: %w", err)
		}
		ciphertext, err := base64.StdEncoding.DecodeString(backup.Payload)
		if err != nil {
			return fmt.Errorf("invalid payload encoding: %w", err)
		}

		exportPass, err := PromptPassword("🔐 Enter export file passphrase: ")
		if err != nil {
			return err
		}

		exportKey := crypto.DeriveKey(exportPass, salt)
		defer crypto.ZeroMemory(exportKey)

		plaintext, err := crypto.Decrypt(nonce, ciphertext, exportKey, []byte("export:"+backup.Profile))
		if err != nil {
			return fmt.Errorf("failed to decrypt backup file (wrong passphrase or tampered file)")
		}

		var items []ExportItem
		if err := json.Unmarshal(plaintext, &items); err != nil {
			return fmt.Errorf("failed to parse decrypted secret items: %w", err)
		}

		dbPath, err := config.GetDBPath()
		if err != nil {
			return err
		}

		s, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()

		password, err := PromptPassword("🔑 Vault Master Password: ")
		if err != nil {
			return err
		}

		masterKey, err := s.Authenticate(ctx, password)
		if err != nil {
			return err
		}
		defer crypto.ZeroMemory(masterKey)

		targetProfile := config.ResolveActiveProfile(flagProfile)
		if targetProfile == config.DefaultProfile && backup.Profile != "" {
			targetProfile = backup.Profile
		}

		// Ensure profile exists
		_, err = s.GetProfileByName(ctx, targetProfile)
		if err != nil {
			_, err = s.CreateProfile(ctx, targetProfile, "Imported profile")
			if err != nil {
				return fmt.Errorf("failed to create target profile '%s': %w", targetProfile, err)
			}
		}

		importedCount := 0
		for _, item := range items {
			err := s.PutSecret(ctx, targetProfile, item.Key, item.Value, item.Tags, masterKey)
			if err != nil {
				fmt.Printf("⚠️ Warning: Failed to import secret '%s': %v\n", item.Key, err)
				continue
			}
			importedCount++
		}

		fmt.Printf("📥 Successfully imported %d secret(s) into profile '%s'.\n", importedCount, targetProfile)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(importCmd)
}
