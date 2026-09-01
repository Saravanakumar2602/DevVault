package cli

import (
	"context"
	"fmt"

	"devvault/internal/config"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a new DevVault database",
	Long:  "Creates OS-specific config directory, prompts for a master password, and sets up SQLite tables & Argon2id encryption metadata.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		dbPath, err := config.GetDBPath()
		if err != nil {
			return err
		}

		s, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()

		init, err := s.IsInitialized(ctx)
		if err != nil {
			return err
		}
		if init {
			cmd.Println("🔒 DevVault database is already initialized.")
			return nil
		}

		password, err := PromptPassword("🔑 Enter a master password for your vault: ")
		if err != nil {
			return err
		}

		confirmPassword, err := PromptPassword("🔑 Confirm master password: ")
		if err != nil {
			return err
		}

		if password != confirmPassword {
			return fmt.Errorf("passwords do not match")
		}

		_, err = s.InitSchema(ctx, password)
		if err != nil {
			return fmt.Errorf("failed to initialize vault: %w", err)
		}

		// Reset active profile to 'default' in config.json upon initialization
		cfg := &config.AppConfig{
			ActiveProfile: config.DefaultProfile,
		}
		_ = config.SaveConfig(cfg)

		cmd.Println("✅ DevVault successfully initialized!")
		cmd.Printf("📁 Database location: %s\n", dbPath)
		cmd.Println("💡 Tip: Vault database initialized with strict permissions.")
		return nil
	},
}

func init() {
	RootCmd.AddCommand(initCmd)
}
