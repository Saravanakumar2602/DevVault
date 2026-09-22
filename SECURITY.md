# Security Policy

## Reporting Security Vulnerabilities

We take the security of **DevVault** very seriously. If you discover or suspect a security vulnerability, please **DO NOT** open a public GitHub issue.

### Preferred Reporting Method

To report a vulnerability privately, please use one of the following methods:

1. **GitHub Security Advisory**: Submit a private vulnerability disclosure directly through the repository under **Security > Advisories > New Advisory**.
2. **Direct Email**: Send a detailed security report to `security@devvault.local` (or contact the maintainers directly via GitHub private messaging/advisories).

### What to Include in Your Report

To help us investigate and remediate the vulnerability quickly, please include:
- A description of the issue and its potential security impact.
- Step-by-step instructions or proof-of-concept (PoC) code to reproduce the issue safely.
- Affected component(s) (e.g., KDF, AEAD, scanner, store, CLI runner).
- Any suggested mitigations or patches if available.

### Disclosure Timeline & Policy

- **Acknowledgement**: We will acknowledge receipt of your vulnerability report within **48 hours**.
- **Assessment & Fix**: We aim to assess the impact and release a patch or mitigation within **14 business days**.
- **Public Disclosure**: Public announcement will be coordinated with the reporter after a patch has been released. We request that you refrain from publicly disclosing sensitive vulnerability details until a fix is made available.

### Security Limitations & Scope

Please review the **Security Limitations** section in [README.md](README.md) before reporting. Known theoretical limitations of local process execution models (e.g., standard OS child process environment variable inheritance, OS swap file memory persistence, local administrator/root memory access) are considered out-of-scope for vulnerability reports unless a specific implementation flaw or bypass is identified in DevVault.
