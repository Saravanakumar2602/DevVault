package cli

import (
	"context"
	"fmt"
	"os"

	"devvault/internal/config"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var flagForceInit bool

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

		if flagForceInit {
			_ = os.Remove(dbPath)
			_ = os.Remove(dbPath + "-wal")
			_ = os.Remove(dbPath + "-shm")
			_ = os.Remove(dbPath + "-journal")
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
		if init && !flagForceInit {
			cmd.Println("🔒 DevVault database is already initialized.")
			cmd.Println("💡 Tip: Use 'devvault init --force' to re-initialize the database with a new password.")
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
	initCmd.Flags().BoolVarP(&flagForceInit, "force", "f", false, "Force re-initialization of vault database (overwrites existing vault)")
	RootCmd.AddCommand(initCmd)
}
