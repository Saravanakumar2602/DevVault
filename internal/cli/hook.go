package cli

import (
	"devvault/internal/scanner"

	"github.com/spf13/cobra"
)

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install DevVault pre-commit Git hook into .git/hooks/pre-commit",
	Long:  "Installs an idempotent Git pre-commit hook that automatically runs 'devvault scan --staged' before commits.",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := scanner.InstallPreCommitHook()
		if err != nil {
			return err
		}

		cmd.Println("⚓ Successfully installed DevVault pre-commit Git hook into .git/hooks/pre-commit.")
		cmd.Println("🔒 Future Git commits will automatically scan staged files for secret leaks.")
		return nil
	},
}

func init() {
	RootCmd.AddCommand(installHookCmd)
}
