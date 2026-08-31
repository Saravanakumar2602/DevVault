package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Runner manages subprocess execution with injected environment variables.
type Runner struct{}

// NewRunner returns a new Runner instance.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes the given command with args, injecting secretEnv into the process environment block.
func (r *Runner) Run(ctx context.Context, command string, args []string, secretEnv map[string]string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("no command specified to execute")
	}

	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Build combined environment: Start with existing OS environment
	envMap := make(map[string]string)
	for _, envStr := range os.Environ() {
		parts := strings.SplitN(envStr, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// Override with decrypted secrets
	for k, v := range secretEnv {
		envMap[k] = v
	}

	// Reconstruct env slice
	finalEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}

	cmd.Env = finalEnv

	// Execute command
	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("command execution failed: %w", err)
	}

	return 0, nil
}
