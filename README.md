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
