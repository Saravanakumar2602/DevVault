# DevVault

DevVault is a lightweight, zero-dependency, cross-platform CLI tool for securely storing local development secrets in AES-256-GCM encrypted vaults and injecting them directly into application runtime environments.

## Problem

Developers commonly store sensitive application credentials (API keys, database passwords, OAuth tokens, connection strings) in unencrypted `.env` files within workspace folders. This practice introduces severe security risks:

* **Accidental Git Commits**: Plaintext `.env` files are frequently staged and committed to public or private version control repositories.
* **Malicious Process Access**: Any process or script running under the developer account can freely read unencrypted `.env` files on disk.
* **Local Disk Leakage**: Storing plaintext credentials on disk leaves them vulnerable to host compromises, unencrypted disk backups, and local shoulder surfing.

## Solution

DevVault replaces plaintext `.env` files with an encrypted local SQLite database and in-memory runtime secret injection:

* **Encrypted Storage at Rest**: All secret key-value pairs are stored in a local database encrypted using **AES-256-GCM** authenticated encryption with **Argon2id** key derivation.
* **Runtime Secret Injection**: Secrets are decrypted in memory only when executing `devvault run` and injected directly into the child application's environment variables (`os/exec`). No plaintext `.env` files or temporary files are ever created on disk.
* **Secret Leak Prevention**: Built-in entropy-based and regex scanning (`devvault scan`) and pre-commit hook integration (`devvault hook install`) prevent credentials from being committed to Git.

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

## Features

* **AES-256-GCM Encrypted Storage**: Standard authenticated encryption with unique 96-bit random nonces per payload and tag validation.
* **Argon2id Key Derivation**: High-memory, GPU-resistant key derivation (64MB RAM, 3 iterations, 4 parallel threads, 16-byte `crypto/rand` salt).
* **Profile Isolation**: Maintain separate secret vaults for `default`, `staging`, and `production` environments with independent master passwords.
* **Runtime Environment Injection**: Subprocess environment injection via `devvault run` eliminates the need for plaintext `.env` files.
* **Git Secret Scanner**: Entropy-based analysis and heuristic regex engines detect leaked credentials across workspace files.
* **Pre-Commit Hook Integration**: Seamlessly block accidental git commits containing staged credentials.
* **Encrypted Export & Import**: Export vaults into standalone AES-256-GCM encrypted `.dv` files for secure backups and team sharing.
* **Cross-Platform CLI**: Native binaries for Windows, Linux, and macOS without external dependencies.

## Installation

### Windows
```powershell
# Using Go (1.21+)
go install github.com/Saravanakumar2602/DevVault/cmd/devvault@latest

# Or build from source:
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault.exe ./cmd/devvault
```

### Linux
```bash
# Using Go (1.21+)
go install github.com/Saravanakumar2602/DevVault/cmd/devvault@latest

# Or build from source:
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault ./cmd/devvault
sudo mv devvault /usr/local/bin/
```

### macOS
```bash
# Using Go (1.21+)
go install github.com/Saravanakumar2602/DevVault/cmd/devvault@latest

# Or build from source:
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault
go build -o devvault ./cmd/devvault
sudo mv devvault /usr/local/bin/
```

## Quick Start

> **Note**: All credentials in this guide are fake example values.
> **PowerShell Tip**: On Windows PowerShell, if `devvault` is not in your `PATH` via `go install`, run local binaries using `.\devvault.exe` (e.g., `.\devvault.exe init`).

```bash
# Option A: If installed via 'go install' (available in PATH everywhere)
devvault init

# Option B: If running local binary directly on Windows PowerShell
.\devvault.exe init

# 1. Store secrets in the active profile
.\devvault.exe set API_KEY "sk_live_998877665544332211" --tags stripe,prod
.\devvault.exe set DB_PASSWORD "ExampleSecurePassword123!"

# 2. List stored secret metadata (values are never exposed)
.\devvault.exe list

# 3. Inject secrets into an application runtime without creating a .env file
.\devvault.exe run -- node app.js
# Or on Windows PowerShell:
.\devvault.exe run -- cmd /c "echo %API_KEY%"
```

## Command Reference

| Command | Description | Important Flags |
| :--- | :--- | :--- |
| `devvault init` | Initialize vault schema and profile configuration. | `--force` (Re-initialize database) |
| `devvault set <KEY> <VALUE>` | Encrypt and store a secret in active profile. | `-p, --profile` (Override profile), `--tags` (Comma-separated tags) |
| `devvault get <KEY>` | Retrieve and print plaintext value of a secret. | `-p, --profile` (Override profile) |
| `devvault list` | Display secret metadata table (keys, tags, timestamps). | `-p, --profile` (Override profile) |
| `devvault delete <KEY>` | Remove a secret from active profile. | `-p, --profile` (Override profile) |
| `devvault run -- <cmd>` | Inject active profile secrets into child process env. | `-p, --profile` (Override profile) |
| `devvault profile list` | List all profiles and indicate active profile. | None |
| `devvault profile create <NAME>`| Create a new profile with independent password/salt. | `--desc` (Profile description) |
| `devvault profile use <NAME>` | Switch active default profile. | None |
| `devvault profile delete <NAME>`| Delete a profile and all its associated secrets. | None |
| `devvault scan` | Scan workspace files for hardcoded secrets/entropy. | `--dir` (Scan target directory) |
| `devvault hook install` | Install Git pre-commit secret scanner hook. | None |
| `devvault hook uninstall` | Uninstall Git pre-commit hook. | None |
| `devvault export <PATH>` | Export profile secrets into encrypted `.dv` archive. | `-p, --profile`, `--export-pass` |
| `devvault import <PATH>` | Import secrets from encrypted `.dv` archive. | `-p, --profile`, `--import-pass` |
| `devvault backup <PATH>` | Create direct encrypted backup of database file. | None |
| `devvault version` | Show CLI version, build timestamp, and platform. | None |

## Security Model

* **Encryption at Rest**: All secret keys, values, and tags are encrypted prior to database insertion using **AES-256-GCM** authenticated encryption with randomly generated 96-bit nonces.
* **Password-Based Key Derivation**: Master passwords are transformed into 256-bit cryptographic keys using **Argon2id** (`time=3`, `memory=64MB`, `threads=4`). Each profile maintains a unique 16-byte cryptographically secure salt generated via Go's `crypto/rand`.
* **Authenticated Encryption & AAD**: DevVault utilizes Additional Authenticated Data (AAD) during AES-GCM encryption, binding each ciphertext payload to its profile name. Tampering with ciphertext or attempting cross-profile payload copying causes GCM authentication tag verification to fail immediately.
* **Secret Runtime Injection**: Secrets are decrypted strictly in memory upon user invocation of `devvault run` and passed directly into the child process environment vector via standard OS process spawn APIs.
* **Git Secret Scanning**: Entropy analysis and heuristic regex matchers scan staged files prior to git commits to prevent credential disclosure.

## Security Limitations

DevVault enforces strong cryptographic defenses for local secrets, but operates under fundamental OS and Go runtime constraints:

* **Go Memory Management & GC**: Go features a garbage-collected runtime. While DevVault zeroes password byte buffers after use, the Go runtime GC may relocate memory blocks before zeroing occurs. DevVault does **not** guarantee complete absence of secret remnants in unallocated process RAM.
* **Child-Process Environment Visibility**: Secrets injected into child processes (`devvault run`) exist in the environment block of the spawned process. On multi-user systems, other processes owned by the same OS user (or root/administrator) can read process environment blocks via OS APIs (`/proc/<pid>/environ` on Linux, `GetEnvironmentVariable` / `NtQueryInformationProcess` on Windows).
* **Windows ACL & File System Permissions**: DevVault sets restrictive ACL permissions on its SQLite database (`0600` on Unix, restricted user-only permissions on Windows NTFS). However, local OS Administrators or root users can bypass file ACLs and inspect database files or process memory.
* **Threat Model**: DevVault protects against unencrypted file leakage, repo leaks, and non-privileged process snooping. It is **not** designed to defend against a compromised operating system where malware or a malicious administrator has root access or debugger attachment privileges.

## Verification

The repository includes a comprehensive unit test suite, module verification, and vulnerability scanning.

Run the standard verification suite:

```bash
# 1. Module Verification
go mod verify

# 2. Code Static Analysis
go vet ./...

# 3. Unit Test Suite
go test ./...

# 4. Binary Build Check
go build ./...

# 5. Vulnerability Scan
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

### Race Detector Note
Executing `go test -race ./...` could not be completed in the current Windows environment because the required 64-bit MinGW-w64 CGO toolchain was unavailable/incompatible (`cc1.exe: 64-bit mode not compiled in`). On 64-bit Linux/macOS environments with GCC installed, `go test -race ./...` can be run cleanly.
