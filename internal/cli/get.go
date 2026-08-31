package cli

import (
	"context"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var getCmd = &cobra.Command{
	Use:   "get <NAME>",
	Short: "Retrieve and decrypt a stored secret by name",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		key := args[0]

		if err := crypto.ValidateSecretKeyName(key); err != nil {
			return err
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

		// Write decrypted value strictly to output stream and zero memory immediately
		valBytes := []byte(sec.Value)
		cmd.Println(sec.Value)
		crypto.ZeroMemory(valBytes)

		return nil
	},
}

func init() {
	RootCmd.AddCommand(getCmd)
}
