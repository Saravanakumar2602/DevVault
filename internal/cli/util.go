package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// PromptPassword prompts the user for their master password without echoing input.
// Falls back to DEVVAULT_MASTER_PASSWORD environment variable if non-interactive.
func PromptPassword(prompt string) (string, error) {
	if envPass := os.Getenv("DEVVAULT_MASTER_PASSWORD"); envPass != "" {
		return envPass, nil
	}

	fmt.Print(prompt)
	passBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println() // Print newline after hidden input
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	pass := string(passBytes)
	if pass == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return pass, nil
}
