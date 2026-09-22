# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-22

### Added
- **Authenticated Encryption at Rest**: AES-256-GCM cipher with random 96-bit nonces and mandatory Additional Authenticated Data (AAD) binding to profile names.
- **Argon2id Key Derivation**: Hardened password hashing using 64MB memory, 3 iterations, 4 parallelism threads, and 16-byte cryptographically secure salts (`crypto/rand`).
- **Profile Isolation**: Named profiles (`default`, `production`, `staging`, etc.) with independent master passwords, salt, and isolated secret scopes.
- **Runtime Environment Injection**: `devvault run -- <command>` injects decrypted secrets directly into child process environment without creating plaintext temporary files on disk.
- **Git Secret Scanner & Pre-Commit Hook**: `devvault scan` and `devvault hook install` to detect accidental secret leaks in staged files or git repositories using entropy and regex heuristic analysis.
- **Encrypted Portable Export/Import**: `devvault export` and `devvault import` with standalone master passwords for secure backup and cross-machine transfer.
- **Cross-Platform CLI**: Full support for Windows, Linux, and macOS platforms.
- **Automated Verification & CI**: GitHub Actions CI workflow supporting multi-OS verification and vulnerability checks.
