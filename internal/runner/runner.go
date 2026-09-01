package runner

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"devvault/internal/crypto"
)

// Runner manages subprocess execution with injected environment variables.
type Runner struct{}

// NewRunner returns a new Runner instance.
func NewRunner() *Runner {
	return &Runner{}
}

// Run executes the requested command directly via os/exec without invoking an intermediate shell.
//
// Environment Variable Precedence Rules:
// 1. Inherits all existing OS environment variables (os.Environ()).
// 2. Overrides or appends decrypted profile secrets (Vault Secrets > Existing OS Env).
func (r *Runner) Run(ctx context.Context, command string, args []string, secretEnv map[string]string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if command == "" {
		return 1, fmt.Errorf("no command specified to execute")
	}

	// Create command directly to prevent shell injection vulnerabilities
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	// Build environment map with precedence: Vault Secrets > Existing OS Env
	envMap := make(map[string]string)

	// 1. Load existing OS environment
	for _, envStr := range os.Environ() {
		parts := strings.SplitN(envStr, "=", 2)
		if len(parts) == 2 {
			envMap[parts[0]] = parts[1]
		}
	}

	// 2. Override with decrypted vault secrets
	for k, v := range secretEnv {
		envMap[k] = v
	}

	// Construct final environment array for subprocess
	finalEnv := make([]string, 0, len(envMap))
	for k, v := range envMap {
		finalEnv = append(finalEnv, fmt.Sprintf("%s=%s", k, v))
	}
	cmd.Env = finalEnv

	// Setup signal forwarding (relay SIGINT / SIGTERM to child process)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	doneChan := make(chan struct{})

	// Forward signals to child process in background
	go func() {
		for {
			select {
			case sig := <-sigChan:
				if cmd.Process != nil {
					_ = cmd.Process.Signal(sig)
				}
			case <-doneChan:
				return
			}
		}
	}()

	// Start child process
	if err := cmd.Start(); err != nil {
		close(doneChan)
		signal.Stop(sigChan)
		return 1, fmt.Errorf("failed to start process '%s': %w", command, err)
	}

	// Wait for process completion
	err := cmd.Wait()
	close(doneChan)
	signal.Stop(sigChan)

	// Zero secret environment map in memory immediately post-execution
	for k, v := range secretEnv {
		b := []byte(v)
		crypto.ZeroMemory(b)
		delete(secretEnv, k)
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("process execution failed: %w", err)
	}

	return 0, nil
}
