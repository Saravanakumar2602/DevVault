package cli

import (
	"github.com/spf13/cobra"
)

const Version = "v0.1.0-alpha"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Display the DevVault CLI version",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Printf("DevVault CLI %s\n", Version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
