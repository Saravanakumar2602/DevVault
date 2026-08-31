package cli

import (
	"fmt"

	"devvault/internal/scanner"

	"github.com/spf13/cobra"
)

var installHookCmd = &cobra.Command{
	Use:   "install-hook",
	Short: "Install DevVault pre-commit Git hook into .git/hooks/pre-commit",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := scanner.InstallPreCommitHook()
		if err != nil {
			return err
		}

		fmt.Println("⚓ Successfully installed DevVault pre-commit Git hook!")
		fmt.Println("🔒 Future git commits will automatically scan staged files for secret leaks.")
		return nil
	},
}

func init() {
	RootCmd.AddCommand(installHookCmd)
}
