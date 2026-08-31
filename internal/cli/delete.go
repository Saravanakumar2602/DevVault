package cli

import (
	"context"
	"fmt"

	"devvault/internal/config"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var deleteCmd = &cobra.Command{
	Use:   "delete <KEY>",
	Short: "Delete a secret from the vault",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		key := args[0]

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

		fmt.Printf("🗑️ Secret '%s' deleted from profile '%s'.\n", key, activeProfile)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(deleteCmd)
}
