# DevVault

**DevVault** is a secure local secrets and configuration manager for developers, written in Go.

It allows developers to store API keys, database URLs, JWT secrets, and other sensitive environment variables securely in an AES-256-GCM encrypted database, then inject them into application runtimes without leaking secrets to shell histories, temp files, or version control.

---

## 🔒 Security Architecture

- **Key Derivation Function (KDF)**: Argon2id ($t=3$, $m=64\text{MB}$, $p=4$) with a cryptographically secure 32-byte salt.
- **Authenticated Encryption**: AES-256-GCM AEAD encryption with random 12-byte nonces and Contextual AAD (`profile_name:secret_key`).
- **Zero Plaintext Storage**: Secrets are stored strictly encrypted. Master passwords and keys are zeroed from RAM memory buffers post-execution.
- **OS-Specific Configuration Directory**:
  - **Windows**: `%APPDATA%\devvault` (`C:\Users\<user>\AppData\Roaming\devvault`)
  - **macOS**: `~/Library/Application Support/devvault`
  - **Linux/Unix**: `~/.config/devvault`
- **File Permissions**: Database file initialized with strict Unix file mode `0600` (owner read/write only) and directory mode `0700`.

---

## 🚀 Building & Running

### Prerequisites

- **Go 1.22+** installed.

### Build from Source

```bash
# Clone repository
git clone https://github.com/Saravanakumar2602/DevVault.git
cd DevVault

# Download dependencies
go mod download

# Build binary
go build -o devvault ./cmd/devvault
```

On Windows PowerShell:
```powershell
go build -o devvault.exe ./cmd/devvault
```

---

## 💻 CLI Commands (Phase 1 Foundation)

### 1. View Help
```bash
./devvault --help
```

### 2. View Version
```bash
./devvault version
```

### 3. Initialize Vault Database
```bash
./devvault init
```
Prompts for a master password, creates the OS-specific application directory, initializes the SQLite database tables (`meta`, `profiles`, `secrets`), and generates Argon2id metadata.

---

## 🧪 Running Tests & Code Quality Checks

```bash
# Run unit tests across all packages
go test ./...

# Run static analysis
go vet ./...
```
