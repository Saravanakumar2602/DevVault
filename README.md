# 🛡️ DevVault

**DevVault** is a local secrets and configuration management CLI application written in Go.

It allows developers to store API keys, database URLs, JWT secrets, and environment variables **encrypted at rest** in a local SQLite database, then inject them into child application process environments without requiring plaintext `.env` or temporary files on disk.

---

## ❓ Design Goals & Operational Security Boundaries

DevVault is designed to prevent plaintext credential files from resting on disk or leaking to version control repositories:

| Security Property | Traditional `.env` Files | 🛡️ DevVault CLI | Technical Implementation & Boundary |
| :--- | :--- | :--- | :--- |
| **At-Rest Storage** | Plaintext files on disk | **Encrypted at rest** | AES-256-GCM AEAD encryption with Argon2id Key Derivation Function (KDF). |
| **Git Leak Prevention** | Requires manual `.gitignore` | **Zero project file footprint + Pre-commit Scanner** | Secrets do not exist as workspace `.env` files. `devvault scan` inspects staged diffs. |
| **Runtime Injection** | Application reads `.env` file from disk | **Child-process environment variables** | `devvault run` passes decrypted secrets directly to the child process environment (`cmd.Env`). *Environment variables are readable by other processes executing under the same OS user account.* |
| **Memory Lifetime** | Plaintext files in memory | **Decrypted only when required + Best-effort zeroing** | `crypto.ZeroMemory` clears mutable byte slices. *Go runtime Garbage Collector heap relocations and immutable string conversions mean guaranteed memory wiping cannot be technically assured in pure Go.* |
| **Multi-Environment** | Juggling `.env.dev` / `.env.prod` | **Isolated profiles** | Contextual Additional Authenticated Data (`AAD="profile_name:secret_key"`) binds payloads to profile scopes. |
| **Backups & Transfers** | Plaintext file sharing | **Passphrase-encrypted backups** | AEAD encrypted backup files (`version: "1.0"`) with `--dry-run` validation. |

---

## ⚡ Quick Start & User Guide

### 1. Installation

#### Option A: Install via Go
```bash
go install github.com/Saravanakumar2602/DevVault/cmd/devvault@latest
```

#### Option B: Build from Source
```bash
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault.exe ./cmd/devvault
```

---

### 2. First-Time Setup (`devvault init`)
Initialize your encrypted vault database:
```bash
devvault init
```
* Prompts for a **Master Password**.
* Initializes SQLite database `devvault.db` in user config directory (`%APPDATA%\devvault` on Windows; `~/.config/devvault` on Linux/macOS).
* Filesystem Permissions: On POSIX systems (Linux/macOS), directory mode is set to `0700` and database file mode to `0600`. On Windows, file access relies on standard Windows user profile directory ACL inheritance.

---

### 3. Storing & Managing Secrets (CRUD)

```bash
# Store an encrypted secret (with optional tags)
devvault set API_KEY "sk_live_9988776655443322" --tags stripe,prod
devvault set DATABASE_URL "postgres://user:pass@localhost:5432/myapp"

# List stored secret metadata (Secret values are NEVER displayed!)
devvault list

# Decrypt and retrieve secret on demand
devvault get API_KEY

# Delete a secret (Prompts for confirmation unless --force / -f is passed)
devvault delete API_KEY --force
```

---

### 4. Environment Profiles (`devvault profile`)

Organize credentials for different deployment scopes (`development`, `staging`, `production`):

```bash
# Create profiles
devvault profile create development "Local dev environment"
devvault profile create production "Production deployment"

# List profiles (Active profile is marked with '* profile (active)')
devvault profile list

# Switch to development profile
devvault profile use development
devvault set DATABASE_URL "postgres://localhost:5432/dev_db"

# Switch to production profile
devvault profile use production
devvault set DATABASE_URL "postgres://prod-cluster.internal:5432/prod_db"

# Retrieve secret from a specific profile scope
devvault get DATABASE_URL                        # Production DB URL
devvault get DATABASE_URL --profile development  # Development DB URL
```

---

### 5. Runtime Secret Injection (`devvault run`)

Inject decrypted secrets into a child process environment without creating plaintext `.env` or temporary files:

```bash
# Node.js / Next.js / Express
devvault run -- npm start

# Python / Django / Flask
devvault run -- python app.py

# Go applications
devvault run -- go run main.go
```

---

### 6. Git Secret Scanner & Pre-Commit Hook (`devvault scan`)

Inspect codebases for accidental secret leaks before committing to version control:

```bash
# Scan current workspace directory
devvault scan

# Scan staged Git diffs (git diff --staged)
devvault scan --staged

# Install automated Git pre-commit hook (.git/hooks/pre-commit)
devvault install-hook
```

---

### 7. Encrypted Backups (`export` & `import`)

Transfer credentials safely or create versioned backups:

```bash
# Export all profiles & secrets to an encrypted backup file
devvault export my_backup.dv

# Dry-run validation (Validates format & AEAD integrity without modifying database)
devvault import my_backup.dv --dry-run

# Import backup file into vault
devvault import my_backup.dv --force
```

---

## 🔒 Cryptographic Implementation Details & Threat Model Limits

- **Key Derivation Function**: Argon2id ($t=3$, $m=64\text{MB}$, $p=4$, 32-byte salt).
- **Authenticated Encryption**: AES-256-GCM AEAD (random 12-byte nonce, Contextual AAD `profile_name:secret_key`).
- **At-Rest Security**: All secret values in SQLite storage are encrypted before SQL insertion. Only encrypted ciphertext reaches SQLite tables and WAL journal files.
- **Memory Clearing Limits**: Best-effort buffer clearing via `crypto.ZeroMemory` is performed on mutable byte slices. However, Go runtime Garbage Collector (GC) heap relocations and immutable string conversions mean memory wiping cannot be technically guaranteed in pure Go.
- **Child-Process Environment Exposure**: `devvault run` passes secrets to child processes using child-process environment variables (`cmd.Env`). Environment variables are readable by other processes running under the same local OS user account.
- **Threat Model Exclusion**: Local root, Administrator, or compromised operating system users with process inspection (`ptrace`/`WinDbg`) capabilities are outside DevVault's threat model.

---

## 🧪 Security & Quality Verification

```bash
# Verify Go module checksums
go mod verify

# Check dependency vulnerabilities
go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Run unit and integration tests
go test -v ./...

# Run static analysis
go vet ./...

# Build binary
go build -o devvault.exe ./cmd/devvault
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
