package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"devvault/internal/config"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var profileCmd = &cobra.Command{
	Use:   "profile",
	Short: "Manage secret namespaces and active profile selection",
	Long:  "Subcommands: list, use, create, delete",
}

var profileListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all profiles and mark the currently active profile",
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

		active := config.ResolveActiveProfile("")

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "  PROFILE\tDESCRIPTION\tCREATED AT")
		fmt.Fprintln(w, "  -------\t-----------\t----------")

		for _, p := range profiles {
			marker := " "
			if p.Name == active {
				marker = "*"
			}
			desc := p.Description
			if desc == "" {
				desc = "-"
			}
			fmt.Fprintf(w, "%s %s\t%s\t%s\n", marker, p.Name, desc, p.CreatedAt.Format("2006-01-02"))
		}

		w.Flush()
		fmt.Printf("\n(* indicates active profile resolved from ~/.devvault/config.json)\n")
		return nil
	},
}

var profileCreateCmd = &cobra.Command{
	Use:   "create <NAME> [DESCRIPTION]",
	Short: "Create a new secret profile scope",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		name := args[0]
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

		fmt.Printf("✅ Profile '%s' created successfully.\n", name)
		return nil
	},
}

var profileUseCmd = &cobra.Command{
	Use:   "use <NAME>",
	Short: "Set global active profile in configuration",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		name := args[0]

		dbPath, err := config.GetDBPath()
		if err != nil {
			return err
		}

		s, err := store.Open(dbPath)
		if err != nil {
			return err
		}
		defer s.Close()

		// Verify profile exists
		_, err = s.GetProfileByName(ctx, name)
		if err != nil {
			return fmt.Errorf("profile '%s' does not exist: %w", name, err)
		}

		cfg, err := config.LoadConfig()
		if err != nil {
			cfg = &config.AppConfig{}
		}

		cfg.ActiveProfile = name
		if err := config.SaveConfig(cfg); err != nil {
			return fmt.Errorf("failed to save active profile configuration: %w", err)
		}

		fmt.Printf("🎯 Active profile set to '%s'.\n", name)
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

		fmt.Printf("🗑️ Profile '%s' and all contained secrets deleted.\n", name)
		return nil
	},
}

func init() {
	profileCmd.AddCommand(profileListCmd)
	profileCmd.AddCommand(profileCreateCmd)
	profileCmd.AddCommand(profileUseCmd)
	profileCmd.AddCommand(profileDeleteCmd)
	RootCmd.AddCommand(profileCmd)
}
