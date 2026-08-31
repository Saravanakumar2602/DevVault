package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var (
	flagProfileForce bool
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage environment secret profiles and active selection",
	Long:  "Subcommands: list, create, use, delete",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles and display the currently active profile",
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

		profiles, err := s.ListProfiles(ctx)
		if err != nil {
			return err
		}

		active := config.ResolveActiveProfile(flagProfile)

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  PROFILE\tSTATUS\tDESCRIPTION\tCREATED AT")
		fmt.Fprintln(w, "  -------\t------\t-----------\t----------")

		for _, p := range profiles {
			marker := " "
			status := ""
			if p.Name == active {
				marker = "*"
				status = "(active)"
			}
			desc := p.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Fprintf(w, "%s %s\t%s\t%s\t%s\n", marker, p.Name, status, desc, p.CreatedAt.Format("2006-01-02"))
		}

		w.Flush()
		cmd.Printf("\n💡 Active Profile: %s\n", active)
		return nil
	},
}

var profileCreateCmd = &cobra.Command{
	Use:   "create <NAME> [DESCRIPTION]",
	Short: "Create a new environment profile scope (e.g. development, staging, production)",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		name := args[0]

		if err := crypto.ValidateProfileName(name); err != nil {
			return err
		}

		desc := ""
		if len(args) == 2 {
			desc = args[1]
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

		_, err = s.CreateProfile(ctx, name, desc)
		if err != nil {
			return err
		}

		cmd.Printf("✅ Profile '%s' created successfully.\n", name)
		return nil
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use <NAME>",
	Short: "Set the active environment profile scope",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		name := args[0]

		if err := crypto.ValidateProfileName(name); err != nil {
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

		// Verify profile exists in database
		_, err = s.GetProfileByName(ctx, name)
		if err != nil {
			return fmt.Errorf("profile '%s' does not exist in vault: %w", name, err)
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			cfg = &config.AppConfig{}
		}

		cfg.ActiveProfile = name
		if err := config.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save active profile configuration: %w", err)
		}

		cmd.Printf("🎯 Switched active profile to '%s'.\n", name)
		return nil
	},
}

var profileDeleteCmd = &cobra.Command{
	Use:   "delete <NAME>",
	Short: "Delete a profile and all its associated secrets",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		name := args[0]

		if err := crypto.ValidateProfileName(name); err != nil {
			return err
		}

		active := config.ResolveActiveProfile(flagProfile)

		// Warning if deleting the active profile
		if name == active && !flagProfileForce {
			cmd.Printf("⚠️ WARNING: Profile '%s' is currently your ACTIVE profile.\nDeleting it will remove all contained secrets and reset the active profile to 'default'. Continue? (y/N): ", name)
			reader := bufio.NewReader(os.Stdin)
			response, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("failed to read confirmation: %w", err)
			}
			response = strings.TrimSpace(strings.ToLower(response))
			if response != "y" && response != "yes" {
				cmd.Println("❌ Profile deletion canceled.")
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

		err = s.DeleteProfile(ctx, name)
		if err != nil {
			return err
		}

		// Reset active profile to default if the deleted profile was active
		if name == active {
			cfg, err := config.LoadConfig()
			if err == nil {
				cfg.ActiveProfile = config.DefaultProfile
				_ = config.SaveConfig(cfg)
			}
		}

		cmd.Printf("🗑️ Profile '%s' and all contained secrets deleted.\n", name)
		return nil
	},
}

func init() {
	profileDeleteCmd.Flags().BoolVarP(&flagProfileForce, "force", "f", false, "Bypass confirmation prompt when deleting active profile")
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	RootCmd.AddCommand(profileCmd)
}
