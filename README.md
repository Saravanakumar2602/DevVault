# DevVault

Secure local secrets management for developers.

DevVault is a cross-platform Go CLI tool for securely storing local development secrets in AES-256-GCM encrypted vaults and injecting them directly into application runtime environments.

## Problem

Developers commonly store sensitive application credentials (API keys, database passwords, OAuth tokens, connection strings) in unencrypted `.env` files within workspace folders. This practice introduces severe security risks:

* **Accidental Git Commits**: Plaintext `.env` files are frequently staged and committed to public or private version control repositories.
* **Malicious Process Access**: Any process or script running under the developer account can freely read unencrypted `.env` files on disk.
* **Local Disk Leakage**: Storing plaintext credentials on disk leaves them vulnerable to host compromises, unencrypted disk backups, and local shoulder surfing.

## Solution

DevVault replaces plaintext `.env` files with an encrypted local SQLite database and in-memory runtime secret injection:

* **Encrypted Storage at Rest**: Secret key-value pairs are stored in a local database encrypted using **AES-256-GCM** authenticated encryption with **Argon2id** key derivation.
* **Runtime Secret Injection**: Secrets are decrypted in memory when executing `devvault run` and injected directly into the child application's environment variables (`os/exec`). No plaintext `.env` files or temporary files are created on disk.
* **Secret Leak Prevention**: Built-in entropy-based and regex scanning (`devvault scan`) and pre-commit hook integration (`devvault install-hook`) prevent credentials from being committed to Git.

## Features

* **AES-256-GCM Encrypted Storage**: Authenticated encryption with unique 96-bit random nonces per payload and tag validation.
* **Argon2id Key Derivation**: High-memory key derivation (64MB RAM, 3 iterations, 4 parallel threads, 16-byte `crypto/rand` salt).
* **Profile Isolation**: Maintain separate secret vaults for `default`, `staging`, and `production` environments with independent master passwords.
* **Runtime Environment Injection**: Subprocess environment injection via `devvault run` eliminates the need for plaintext `.env` files.
* **Interactive Secret Entry**: Prompt for secret values without echoing terminal input, avoiding shell history exposure.
* **Git Secret Scanner**: Entropy-based analysis and heuristic regex engines detect leaked credentials across workspace files.
* **Pre-Commit Hook Integration**: Seamlessly block accidental git commits containing staged credentials.
* **Encrypted Export & Import**: Export vaults into standalone AES-256-GCM encrypted `.dv` files for secure backups.
* **Cross-Platform CLI**: Native binaries for Windows, Linux, and macOS.

## Architecture

```
                                  DEVVAULT ARCHITECTURE
                                  
 [ Developer Master Password ]
               |
               v
      +-----------------+
      |  Argon2id KDF   |  (64 MB, 3 iterations, 4 threads, 16-byte random salt)
      +-----------------+
               |
               v
  [ Derived Key (32 Bytes) ]
               |
               +-----------------------+
               |                       |
               v                       v
      +-----------------+     +-----------------+
      | AES-256-GCM     |     | AAD Binding     |  (AAD = Profile Name)
      | Authenticated   |     | Security Check  |
      | Encryption      |     +-----------------+
      +-----------------+
               |
               v
      +-----------------+
      |  Local Storage  |  (AES-256-GCM Payload: Nonce + Ciphertext + Tag)
      | (devvault.db)   |  (Strict OS file permissions 0600 / ACLs)
      +-----------------+
               |
               | (devvault run -- <cmd>)
               v
      +-----------------+
      | Memory Decrypt  |  (Secrets loaded into RAM only)
      +-----------------+
               |
               v
      +-----------------+
      | Child Process   |  (Injected into Subprocess Env Vars)
      |  (App / Node /  |
      |   Go / Python)  |
      +-----------------+
```

## Installation

### Option 1 — Download Release Binary
Download the pre-compiled binary for your operating system (Windows amd64, Linux amd64/arm64, macOS amd64/arm64) from the [GitHub Releases](https://github.com/Saravanakumar2602/DevVault/releases) page.

### Option 2 — Install via Go (Go 1.21+)
```bash
go install github.com/Saravanakumar2602/DevVault/cmd/devvault@latest
```

### Option 3 — Build from Source

#### Windows (PowerShell)
```powershell
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault.exe ./cmd/devvault
```

#### Linux / macOS (Bash)
```bash
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault ./cmd/devvault
sudo mv devvault /usr/local/bin/
```

## Quick Start

> **Note**: All credentials in this guide are synthetic example values.

### Windows (PowerShell)
```powershell
# 1. Initialize the vault database
.\devvault.exe init

# 2. Store secrets interactively (prevents secret from appearing in shell history)
.\devvault.exe set API_KEY
# Prompt: 🔒 Enter secret value for 'API_KEY': [hidden input]

# Or pass value directly (convenient for scripts):
.\devvault.exe set DB_PASSWORD "ExampleSecurePassword123!" --tags postgres

# 3. List stored secret metadata (values are never exposed)
.\devvault.exe list

# 4. Safely test runtime secret injection without printing secret values
go run ./cmd/devvault-demo
# Or run with devvault:
.\devvault.exe run -- go run ./cmd/devvault-demo
```

### Linux / macOS (Bash)
```bash
# 1. Initialize the vault database
devvault init

# 2. Store secrets interactively
devvault set API_KEY
# Prompt: 🔒 Enter secret value for 'API_KEY': [hidden input]

# 3. List stored secret metadata
devvault list

# 4. Inject secrets into application runtime
devvault run -- node app.js
```

## Command Reference

| Command | Description | Important Flags |
| :--- | :--- | :--- |
| `devvault init` | Initialize vault schema and profile configuration. | `--force` (Re-initialize database) |
| `devvault set <KEY> [VALUE]` | Encrypt and store a secret (prompts interactively if VALUE is omitted). | `-p, --profile` (Override profile), `--tags` (Comma-separated tags) |
| `devvault get <KEY>` | Retrieve and print plaintext value of a secret. | `-p, --profile` (Override profile) |
| `devvault list` | Display secret metadata table (keys, tags, timestamps). | `-p, --profile` (Override profile) |
| `devvault delete <KEY>` | Remove a secret from active profile. | `-p, --profile` (Override profile) |
| `devvault run -- <cmd>` | Inject active profile secrets into child process env. | `-p, --profile` (Override profile) |
| `devvault profile list` | List all profiles and indicate active profile. | None |
| `devvault profile create <NAME>`| Create a new profile with independent password/salt. | `--desc` (Profile description) |
| `devvault profile use <NAME>` | Switch active default profile. | None |
| `devvault profile delete <NAME>`| Delete a profile and all its associated secrets. | None |
| `devvault scan` | Scan workspace files for hardcoded secrets/entropy. | `--dir` (Scan target directory) |
| `devvault install-hook` | Install Git pre-commit secret scanner hook. | None |
| `devvault export <PATH>` | Export profile secrets into encrypted `.dv` archive. | `-p, --profile`, `--export-pass` |
| `devvault import <PATH>` | Import secrets from encrypted `.dv` archive. | `-p, --profile`, `--import-pass` |
| `devvault version` | Show CLI version, build timestamp, and platform. | None |

## Security Model

* **Encryption at Rest**: All secret keys, values, and tags are encrypted prior to database insertion using **AES-256-GCM** authenticated encryption with randomly generated 96-bit nonces.
* **Password-Based Key Derivation**: Master passwords are transformed into 256-bit cryptographic keys using **Argon2id** (`time=3`, `memory=64MB`, `threads=4`). Each profile maintains a unique 16-byte cryptographically secure salt generated via Go's `crypto/rand`.
* **Authenticated Encryption & AAD**: DevVault utilizes Additional Authenticated Data (AAD) during AES-GCM encryption, binding each ciphertext payload to its profile name (`<profile>:<key>`). Tampering with ciphertext or attempting cross-profile payload copying causes GCM authentication tag verification to fail immediately.
* **Secret Runtime Injection**: DevVault decrypts secrets when required and injects them into the child process environment vector via standard OS process spawn APIs without creating plaintext `.env` files.
* **Interactive Secret Entry**: Invoking `devvault set NAME` prompts for secret input without terminal echo (`term.ReadPassword`), preventing secrets from leaking into shell history files (`.bash_history`, PowerShell history).

## Threat Model & Security Limitations

DevVault enforces strong cryptographic defenses for local secrets, but operates under fundamental OS and Go runtime constraints:

* **Go Memory Management & GC**: Go features a garbage-collected runtime. While DevVault zeroes password byte buffers after use, the Go runtime GC may relocate memory blocks before zeroing occurs. DevVault does **not** guarantee complete absence of secret remnants in unallocated process RAM.
* **Child-Process Environment Visibility**: Secrets injected into child processes (`devvault run`) exist in the environment block of the spawned process. On multi-user systems, other processes owned by the same OS user (or root/administrator) can read process environment blocks via OS APIs (`/proc/<pid>/environ` on Linux, `GetEnvironmentVariable` / `NtQueryInformationProcess` on Windows).
* **Windows ACL & File System Permissions**: DevVault sets restrictive permissions on its SQLite database (`0600` on Unix, restricted user-only permissions on Windows NTFS). However, local OS Administrators or root users can bypass file ACLs and inspect database files or process memory.
* **Environment Variable Master Password (`DEVVAULT_MASTER_PASSWORD`)**: Setting `DEVVAULT_MASTER_PASSWORD` allows non-interactive scripting automation. However, environment variables set in parent shells are visible to all child processes executing under the same OS user account.
* **Overall Threat Scope**: DevVault protects against unencrypted file leakage, version control leaks, and non-privileged local process snooping. It is **not** designed to defend against a compromised operating system where malware or a malicious administrator has root access or debugger attachment privileges.

## Verification & Testing

Run the standard verification suite:

```bash
# 1. Module Verification
go mod verify

# 2. Code Static Analysis
go vet ./...

# 3. Unit & Integration Test Suite
go test ./...

# 4. Binary Build Check
go build ./...

# 5. Vulnerability Scan
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

### Race Detector Note
Executing `go test -race ./...` locally requires a compatible CGO C compiler toolchain (e.g., GCC). On 64-bit Windows environments without a 64-bit MinGW toolchain, `go test -race ./...` is executed automatically in the Linux GitHub Actions CI matrix.
