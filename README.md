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

## 📦 Encrypted Backup & Restore Format

DevVault supports versioned, passphrase-encrypted backup files (`devvault export` & `devvault import`).

### High-Level Backup Specifications
- **No Plaintext Secrets**: Secrets in the backup payload are encrypted using **AES-256-GCM AEAD** encryption with an Additional Authenticated Data (`AAD`) signature.
- **Key Derivation**: An independent Export Passphrase derives a 256-bit key via Argon2id with a unique 32-byte salt per export file.
- **Versioned Header**: Backup files contain format version metadata (`version: "1.0"`), KDF salt/params, and cipher nonces.
- **Integrity Verification**: Decryption verifies the GCM authentication tag. Any tampering, byte corruption, or invalid passphrases cause immediate validation failure.
- **Dry-Run Validation**: `devvault import backup.dv --dry-run` validates file structure and AEAD integrity without modifying vault databases.

```bash
# Export all profiles and secrets to an encrypted file
devvault export backup.dv

# Validate backup file integrity without modifying database
devvault import backup.dv --dry-run

# Import backup file into vault
devvault import backup.dv
```

---

## 🔍 Git Secret Scanner & Pre-Commit Hook

DevVault includes an integrated heuristic secret scanner for inspecting codebases and Git staged changes before committing.

### Features
- **Patterns Detected**: AWS Access Keys, AWS Secret Keys, GitHub Tokens, Private Key headers, JWTs, `.env` file secret assignments, and high-entropy suspicious tokens.
- **Redacted Previews**: Previews are safely masked (e.g. `AKIA************` or `ghp_...3456`). Secrets are **never** fully printed.
- **Filters**: Automatically ignores `.git/`, `.devvault/`, database files (`devvault.db`), `node_modules/`, binary files (null-byte inspection), and comment lines.
- **Non-Zero Exit Code**: Returns exit status `1` when secrets are detected, making it ideal for CI/CD and pre-commit enforcement.

```bash
# Scan specific files or current directory
devvault scan

# Scan staged Git changes before committing
devvault scan --staged

# Install automated Git pre-commit hook (.git/hooks/pre-commit)
devvault install-hook
```

---

## 🌐 Environment Profiles & Isolation

DevVault supports isolated environment profiles (e.g. `development`, `testing`, `staging`, `production`).

- The same secret name (e.g. `DATABASE_URL`) can exist across multiple profiles with completely different encrypted values.
- AES-256-GCM Additional Authenticated Data (`AAD="profile_name:secret_key"`) binds encrypted secrets to their exact profile namespace.

```bash
# Create profiles
devvault profile create development "Dev credentials"
devvault profile create production "Prod credentials"

# Switch active profile
devvault profile use development
devvault set DATABASE_URL "postgres://localhost:5432/dev_db"

devvault profile use production
devvault set DATABASE_URL "postgres://prod-cluster.internal:5432/prod_db"

# Subprocess runtime injection automatically uses the active profile
devvault run -- npm start
```

---

## 💻 CLI Command Reference

### Encrypted Backups

- **`devvault export <FILE>`**: Export all profiles and secrets to an encrypted backup file.
- **`devvault import <FILE> [--dry-run] [--force]`**: Validate or restore profiles and secrets from an encrypted backup file.

### Secret Scanner & Hooks

- **`devvault scan [FILES/DIRECTORIES...]`**: Scan files or directory trees for secret leaks.
- **`devvault scan --staged`**: Scan Git staged diffs (`git diff --staged`).
- **`devvault install-hook`**: Install automated, idempotent Git pre-commit hook.

### Profile Management

- **`devvault profile list`**: List all profiles with active profile indicator (`* development (active)`).
- **`devvault profile create <NAME> [DESCRIPTION]`**: Create a new secret profile scope.
- **`devvault profile use <NAME>`**: Switch active environment profile scope.
- **`devvault profile delete <NAME> [--force|-f]`**: Delete a profile and all its associated secrets.

### Secrets CRUD & Subprocess Injection

- **`devvault init`**: Initialize vault database and set master password.
- **`devvault set <NAME> [VALUE] [--tags t1,t2]`**: Encrypt and store secret in active profile.
- **`devvault get <NAME>`**: Decrypt and print secret value.
- **`devvault list`**: List stored secret names and metadata (**never displays secret values**).
- **`devvault delete <NAME> [--force|-f]`**: Delete secret key.
- **`devvault run -- <COMMAND> [ARGS...]`**: Inject active profile secrets into child process environment.

---

## 🧪 Running Tests & Code Quality Checks

```bash
# Run unit & integration tests across all packages
go test ./...

# Run static analysis
go vet ./...
```
