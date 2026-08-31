package cli

import (
	"context"
	"fmt"
	"os"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/runner"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var runCmd = &cobra.Command{
	Use:   "run -- <COMMAND> [ARGS...]",
	Short: "Execute a command with decrypted secrets injected into the process environment",
	Long: `Executes a command with secrets injected as environment variables directly in memory.
Secrets are never written to disk or passed as command line parameters.

Precedence Rule: Vault Secrets > Existing OS Environment Variables.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		subCmd := args[0]
		subArgs := args[1:]

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

		secrets, err := s.ListSecrets(ctx, activeProfile, masterKey)
		if err != nil {
			return fmt.Errorf("failed to fetch profile secrets: %w", err)
		}

		secretMap := make(map[string]string)
		for _, sec := range secrets {
			secretMap[sec.Key] = sec.Value
		}

		r := runner.NewRunner()
		exitCode, err := r.Run(ctx, subCmd, subArgs, secretMap, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())

		// Zero secrets in memory map
		for k, v := range secretMap {
			b := []byte(v)
			crypto.ZeroMemory(b)
			delete(secretMap, k)
		}

		if err != nil {
			return err
		}

		if exitCode != 0 {
			os.Exit(exitCode)
		}

		return nil
	},
}

func init() {
	RootCmd.AddCommand(runCmd)
}
