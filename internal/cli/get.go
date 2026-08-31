package cli

import (
	"context"
	"fmt"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <KEY>",
	Short: "Retrieve and decrypt a stored secret by key name",
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

		masterKey, err := s.Authenticate(ctx, password)
		if err != nil {
			return err
		}
		defer crypto.ZeroMemory(masterKey)

		activeProfile := config.ResolveActiveProfile(flagProfile)

		sec, err := s.GetSecret(ctx, activeProfile, key, masterKey)
		if err != nil {
			return err
		}

		fmt.Println(sec.Value)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(getCmd)
}
