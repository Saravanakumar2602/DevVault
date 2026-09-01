package cli

import (
	"os"

	"devvault/internal/scanner"

	"github.com/spf13/cobra"
)

var flagStaged bool

var scanCmd = &cobra.Command{
	Use:   "scan [FILES/DIRECTORIES...]",
	Short: "Scan files or Git staged changes for secret leaks",
	Long: `Heuristic secret scanner for detecting AWS access keys, GitHub tokens, JWTs, private keys, 
passwords in config files, .env files, and high-entropy suspicious tokens.

Output includes severity, file path, line number, secret type, and redacted previews.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var findings []scanner.Finding
		var err error

		if flagStaged {
			cmd.Println("🔍 Scanning Git staged changes...")
			findings, err = scanner.ScanStagedGitDiff()
			if err != nil {
				return err
			}
		} else if len(args) > 0 {
			for _, target := range args {
				info, err := os.Stat(target)
				if err != nil {
					cmd.Printf("⚠️ Cannot access '%s': %v\n", target, err)
					continue
				}

				if info.IsDir() {
					dirFindings, err := scanner.ScanDirectory(target)
					if err == nil {
						findings = append(findings, dirFindings...)
					}
				} else {
					fileFindings, err := scanner.ScanFile(target)
					if err == nil {
						findings = append(findings, fileFindings...)
					}
				}
			}
		} else {
			cmd.Println("🔍 Scanning current working directory...")
			findings, err = scanner.ScanDirectory(".")
			if err != nil {
				return err
			}
		}

		if len(findings) == 0 {
			cmd.Println("✅ No secret leaks detected.")
			return nil
		}

		cmd.Printf("\n❌ Detected %d potential secret leak(s)!\n\n", len(findings))
		for i, f := range findings {
			cmd.Printf("[%d] ❌ %s (Severity: %s)\n", i+1, f.SecretType, f.Severity)
			cmd.Printf("    File: %s\n", f.FilePath)
			cmd.Printf("    Line: %d\n", f.LineNumber)
			cmd.Printf("    Preview: %s\n\n", f.RedactedVal)
		}

		// Return non-zero exit code to halt Git pre-commit hooks when secrets are detected
		os.Exit(1)
		return nil
	},
}

func init() {
	scanCmd.Flags().BoolVar(&flagStaged, "staged", false, "Scan staged Git changes using git diff")
	RootCmd.AddCommand(scanCmd)
}
