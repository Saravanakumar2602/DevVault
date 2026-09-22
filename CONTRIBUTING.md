# Contributing to DevVault

Thank you for your interest in contributing to **DevVault**! DevVault is a security-focused local secret manager designed for developers.

## Code of Conduct

Please maintain a respectful, constructive, and inclusive environment when opening issues, submitting pull requests, or participating in discussions.

## How to Contribute

### 1. Reporting Bugs & Feature Requests
- Check existing GitHub Issues before submitting a new one.
- For non-security bugs, open an issue detailing the operating system, Go version, command executed, expected behavior, and actual output.
- For **security vulnerabilities**, follow the private report process outlined in [SECURITY.md](SECURITY.md).

### 2. Development Setup

#### Prerequisites
- **Go**: Version `1.21` or higher.
- **Git**: Installed and configured.

#### Getting Started
1. Fork and clone the repository:
   ```bash
   git clone https://github.com/Saravanakumar2602/DevVault.git
   cd DevVault
   ```
2. Verify local setup:
   ```bash
   go test ./...
   go vet ./...
   go mod verify
   go build ./...
   ```

### 3. Coding Guidelines
- **Go Style**: Follow standard `gofmt` code formatting and official Go Code Review Comments.
- **Security-First**: Never relax cryptographic parameters (Argon2id iterations, memory limits, AES-256-GCM tag validation).
- **Tests**: Write unit tests for all new packages or commands in corresponding `*_test.go` files.
- **No Hardcoded Credentials**: Ensure all test values, documentation examples, and mocks use fake credentials only.

### 4. Submitting Pull Requests (PRs)
1. Create a feature branch: `git checkout -b feature/my-feature`
2. Ensure all tests pass: `go test ./...`
3. Run vet and module verification: `go vet ./... && go mod verify`
4. Commit your changes with clear, descriptive commit messages.
5. Push to your fork and submit a Pull Request to the `main` branch.
