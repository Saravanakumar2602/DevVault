package cli

import (
	"fmt"
	"os"

	"devvault/internal/scanner"

	"github.com/spf13/cobra"
)

var flagStaged bool

var scanCmd = &cobra.Command{
	Use:   "scan [FILES/DIRECTORIES...]",
	Short: "Scan code files or Git staged changes for secret leaks",
	RunE: func(cmd *cobra.Command, args []string) error {
		var findings []scanner.Finding
		var err error

		if flagStaged {
			fmt.Println("🔍 Scanning Git staged diff...")
			findings, err = scanner.ScanStagedGitDiff()
			if err != nil {
				return err
			}
		} else if len(args) > 0 {
			for _, target := range args {
				info, err := os.Stat(target)
				if err != nil {
					fmt.Printf("⚠️ Cannot read '%s': %v\n", target, err)
					continue
				}

				if !info.IsDir() {
					content, err := os.ReadFile(target)
					if err == nil {
						findings = append(findings, scanner.ScanText(target, string(content))...)
					}
				}
			}
		} else {
			return fmt.Errorf("please specify files/directories to scan, or use --staged flag")
		}

		if len(findings) == 0 {
			fmt.Println("✅ No secret leaks detected!")
			return nil
		}

		fmt.Printf("\n🚨 ALERT: Detected %d potential secret leak(s)!\n\n", len(findings))
		for i, f := range findings {
			fmt.Printf("%d. [%s] File: %s:%d\n   Match: %s\n\n", i+1, f.Rule, f.FilePath, f.LineNumber, f.Match)
		}

		os.Exit(1) // Return non-zero exit code to halt git pre-commit hook
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&flagStaged, "staged", false, "Scan staged Git changes using git diff")
	RootCmd.AddCommand(scanCmd)
}
