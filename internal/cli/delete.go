package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var (
	flagForce bool
)

var deleteCmd = &cobra.Command{
	Use:   "delete <NAME>",
	Short: "Delete a secret from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		key := args[0]

		if err := crypto.ValidateSecretKeyName(key); err != nil {
			return err
		}

		// Prompt confirmation unless force flag is specified
		if !flagForce {
			cmd.Printf("⚠️ Are you sure you want to delete secret '%s'? (y/N): ", key)
			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}

			response = strings.TrimSpace(strings.ToLower(response))
			if response != "y" && response != "yes" {
				cmd.Println("❌ Deletion canceled.")
				return nil
			}
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

		password, err := PromptPassword("🔑 Master Password: ")
		if err != nil {
			return err
		}

		_, err = s.Authenticate(ctx, password)
		if err != nil {
			return err
		}

		activeProfile := config.ResolveActiveProfile(flagProfile)

		err = s.DeleteSecret(ctx, activeProfile, key)
		if err != nil {
			return err
		}

		cmd.Printf("🗑️ Secret '%s' deleted from profile '%s'.\n", key, activeProfile)
		return nil
	},
}

func init() {
	deleteCmd.Flags().BoolVarP(&flagForce, "force", "f", false, "Bypass confirmation prompt before deletion")
	RootCmd.AddCommand(deleteCmd)
}
