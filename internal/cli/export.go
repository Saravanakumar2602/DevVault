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

type ExportItem struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Tags  string `json:"tags,omitempty"`
}

type EncryptedBackupPayload struct {
	Version string       `json:"version"`
	Profile string       `json:"profile"`
	Salt    string       `json:"salt"`
	Nonce   string       `json:"nonce"`
	Payload string       `json:"payload"` // Base64 AES-GCM encrypted JSON array of ExportItem
}

var exportCmd = &cobra.Command{
	Use:   "export [OUTPUT_FILE]",
	Short: "Export profile secrets to a passphrase-encrypted backup file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		outPath := "devvault_backup.json"
		if len(args) == 1 {
			outPath = args[0]
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

		activeProfile := config.ResolveActiveProfile(flagProfile)
		secrets, err := s.ListSecrets(ctx, activeProfile, masterKey)
		if err != nil {
			return err
		}

		exportItems := make([]ExportItem, 0, len(secrets))
		for _, sec := range secrets {
			exportItems = append(exportItems, ExportItem{
				Key:   sec.Key,
				Value: sec.Value,
				Tags:  sec.Tags,
			})
		}

		rawJSON, err := json.Marshal(exportItems)
		if err != nil {
			return fmt.Errorf("failed to encode secrets JSON: %w", err)
		}

		// Prompt for export encryption passphrase
		exportPass, err := PromptPassword("🔐 Create passphrase for export file encryption: ")
		if err != nil {
			return err
		}

		confirmExportPass, err := PromptPassword("🔐 Confirm export file passphrase: ")
		if err != nil {
			return err
		}

		if exportPass != confirmExportPass {
			return fmt.Errorf("export passphrases do not match")
		}

		salt, err := crypto.GenerateSalt(32)
		if err != nil {
			return err
		}

		exportKey := crypto.DeriveKey(exportPass, salt)
		defer crypto.ZeroMemory(exportKey)

		nonce, ciphertext, err := crypto.Encrypt(rawJSON, exportKey, []byte("export:"+activeProfile))
		if err != nil {
			return fmt.Errorf("failed to encrypt export file: %w", err)
		}

		backup := EncryptedBackupPayload{
			Version: "1",
			Profile: activeProfile,
			Salt:    base64.StdEncoding.EncodeToString(salt),
			Nonce:   base64.StdEncoding.EncodeToString(nonce),
			Payload: base64.StdEncoding.EncodeToString(ciphertext),
		}

		fileData, err := json.MarshalIndent(backup, "", "  ")
		if err != nil {
			return err
		}

		if err := os.WriteFile(outPath, fileData, 0600); err != nil {
			return fmt.Errorf("failed to write export file '%s': %w", outPath, err)
		}

		fmt.Printf("📦 Encrypted backup of profile '%s' (%d secret(s)) saved to '%s'.\n", activeProfile, len(secrets), outPath)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(exportCmd)
}
