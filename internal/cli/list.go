package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"devvault/internal/config"
	"devvault/internal/crypto"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var flagShowSecret bool

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List stored secret keys in the target profile",
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
			return err
		}

		fmt.Printf("📋 Profile: %s (%d secret(s))\n\n", activeProfile, len(secrets))
		if len(secrets) == 0 {
			fmt.Println("No secrets found in this profile.")
			return nil
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "KEY\tVALUE\tTAGS\tUPDATED AT")
		fmt.Fprintln(w, "---\t-----\t----\t----------")

		for _, sec := range secrets {
			valDisplay := "********"
			if flagShowSecret {
				valDisplay = sec.Value
			}
			tagsDisplay := sec.Tags
			if tagsDisplay == "" {
				tagsDisplay = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", sec.Key, valDisplay, tagsDisplay, sec.UpdatedAt.Format("2006-01-02 15:04:05"))
		}

		w.Flush()
		return nil
	},
}

func init() {
	listCmd.Flags().BoolVar(&flagShowSecret, "show", false, "Display unmasked secret values in table output")
	RootCmd.AddCommand(listCmd)
}
