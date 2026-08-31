package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	flagProfile string
)

var RootCmd = &cobra.Command{
	Use:   "devvault",
	Short: "DevVault - Secure local secrets and configuration manager",
	Long: `DevVault is a developer security CLI tool for managing local secrets,
API keys, database URLs, and JWT secrets in an AES-256-GCM encrypted database.
Secrets are injected into application runtimes without leaking to shell histories or disk.`,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&flagProfile, "profile", "p", "", "Target secret profile scope (overrides active profile)")
}
