package cli

import (
	"context"
	"fmt"
	"text/tabwriter"

	"devvault/internal/config"
	"devvault/internal/store"

	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List secret names and metadata in the target profile (secret values are never displayed)",
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

		_, err = s.Authenticate(ctx, password)
		if err != nil {
			return err
		}

		activeProfile := config.ResolveActiveProfile(flagProfile)

		// List metadata only - secret values are never queried or decrypted
		metaList, err := s.ListSecretMetadata(ctx, activeProfile)
		if err != nil {
			return err
		}

		cmd.Printf("📋 Profile: %s (%d secret(s))\n\n", activeProfile, len(metaList))
		if len(metaList) == 0 {
			cmd.Println("No secrets found in this profile.")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "KEY\tTAGS\tCREATED AT\tUPDATED AT")
		fmt.Fprintln(w, "---\t----\t----------\t----------")

		for _, meta := range metaList {
			tagsDisplay := meta.Tags
			if tagsDisplay == "" {
				tagsDisplay = "-"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", meta.Key, tagsDisplay, meta.CreatedAt.Format("2006-01-02 15:04:05"), meta.UpdatedAt.Format("2006-01-02 15:04:05"))
		}

		w.Flush()
		return nil
	},
}

func init() {
	RootCmd.AddCommand(listCmd)
}
