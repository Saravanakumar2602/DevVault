# 🛡️ DevVault

**DevVault** is a secure, production-grade local secrets and configuration manager for developers, written in Go.

It allows developers to store API keys, database URLs, JWT secrets, and environment variables securely in an **AES-256-GCM encrypted database**, then inject them directly into application runtimes without leaving plaintext `.env` files on disk, shell histories, or git repositories.

---

## ❓ Why DevVault? (The Problem with `.env` Files)

Most developers store credentials in `.env` files and add them to `.gitignore`. However, `.gitignore` alone does not solve major security risks:

| Risk / Limitation | `.gitignore` + `.env` Files | 🛡️ DevVault CLI |
| :--- | :--- | :--- |
| **Disk Storage** | ❌ Plaintext readable on hard drive | ✅ **AES-256-GCM Encrypted (Argon2id KDF)** |
| **Accidental Git Leaks** | ⚠️ High risk (forgotten `.gitignore` entry, `git add -f`) | ✅ **Zero file footprint + Automated Git Scanner** |
| **Malware / Keyloggers** | ❌ Easy target for stolen laptop / NPM malware | ✅ **Secrets encrypted until runtime** |
| **Runtime Injection** | ❌ Must read plain files from disk | ✅ **RAM-only injection (`devvault run -- app`)** |
| **Multi-Environment** | ❌ Messy `.env.dev`, `.env.prod` files | ✅ **Isolated Profiles (`devvault profile use`)** |
| **Backups & Transfers** | ❌ Sending plaintext files over Slack/Email | ✅ **Passphrase-encrypted backups (`export/import`)** |

---

## 🔥 Key Features

- **🔐 AES-256-GCM Authenticated Encryption**: All secrets are encrypted with random 12-byte nonces and Contextual AAD (`profile_name:secret_key`).
- **🛡️ Argon2id Key Derivation**: Master keys derived using Argon2id ($t=3$, $m=64\text{MB}$, $p=4$) with a cryptographically secure 32-byte salt (`crypto/rand`).
- **🚀 RAM-Only Subprocess Injection (`devvault run`)**: Injects decrypted secrets directly into child process memory (`cmd.Env`) and immediately zeroes out RAM buffers post-execution. Zero plaintext files on disk.
- **🌐 Isolated Environment Profiles**: Seamlessly switch between `development`, `testing`, `staging`, and `production` credentials.
- **🔍 Automated Git Secret Scanner (`devvault scan`)**: Detects AWS keys, GitHub tokens, JWTs, private keys, and high-entropy strings before committing.
- **⚓ Idempotent Git Pre-Commit Hook (`devvault install-hook`)**: Automatically blocks secret leaks before commits reach version control.
- **📦 Passphrase-Encrypted Backups (`export` / `import`)**: Versioned backup files (`version: "1.0"`) encrypted with an independent Export Passphrase and AEAD tag verification.
- **💻 Cross-Platform Support**: Strict native OS directory resolution on Windows (`%APPDATA%\devvault`), macOS (`~/Library/Application Support/devvault`), and Linux (`~/.config/devvault`).

---

## ⚡ Quick Start & User Guide

### 1. Installation

#### Option A: Install via Go (Recommended for Go developers)
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
* Initializes SQLite database `devvault.db` with strict POSIX file permissions (`0600` DB / `0700` Dir).

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

### 5. Runtime Secret Injection (`devvault run`) 🎯

Inject decrypted secrets directly into your application's RAM environment without creating `.env` files on disk:

```bash
# Node.js / Next.js / Express
devvault run -- npm start

# Python / Django / Flask
devvault run -- python app.py

# Go applications
devvault run -- go run main.go

# Docker / Shell commands
devvault run -- docker-compose up
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

## 🔒 Security Architecture Specifications

- **KDF**: Argon2id ($t=3$, $m=64\text{MB}$, $p=4$, 32-byte salt).
- **Cipher**: AES-256-GCM AEAD (12-byte random nonce, Contextual AAD `profile_name:secret_key`).
- **RAM Zeroing**: Sensitive byte slices zeroed via `crypto.ZeroMemory` post-execution.
- **Database**: CGO-free pure Go SQLite driver (`modernc.org/sqlite`) with `PRAGMA foreign_keys = ON;` and WAL mode.
- **SQL Safety**: 100% parameterized queries (`?`). Zero dynamic SQL string formatting.
- **Shell Injection Protection**: Commands executed directly via `os/exec.CommandContext` without invoking shell interpreters.

---

## 🧪 Testing & Verification

```bash
# Run unit & integration tests across all packages
go test -v ./...

# Run static security and code analysis
go vet ./...

# Build binary
go build -o devvault.exe ./cmd/devvault
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.
