package cli

import (
	"context"
	"fmt"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var flagTags string

var setCmd = &cobra.Command{
	Use:   "set <NAME> [VALUE]",
	Short: "Store an encrypted secret key-value pair",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		key := args[0]

		if err := crypto.ValidateSecretKeyName(key); err != nil {
			return err
		}

		var value string
		if len(args) == 2 {
			value = args[1]
		} else {
			val, err := PromptPassword(fmt.Sprintf("🔒 Enter secret value for '%s': ", key))
			if err != nil {
				return err
			}
			value = val
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

		err = s.PutSecret(ctx, activeProfile, key, value, flagTags, masterKey)

		// Zero plaintext value bytes in RAM
		valBytes := []byte(value)
		crypto.ZeroMemory(valBytes)

		if err != nil {
			return err
		}

		cmd.Printf("✅ Secret '%s' stored successfully in profile '%s'.\n", key, activeProfile)
		return nil
	},
}

func init() {
	setCmd.Flags().StringVarP(&flagTags, "tags", "t", "", "Comma-separated tags or category for the secret")
	RootCmd.AddCommand(setCmd)
}
