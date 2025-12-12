# 🔒 DigitalSafe-Crypto-Core (E2EE Transparency Repository)

This repository publishes the cryptographic core used by the DigitalSafe end-to-end encrypted (E2EE) chat client.

**Purpose and Scope**
This project makes the client-side cryptographic primitives available for community review and audit. The goal is to enable independent verification of the cryptographic correctness and to increase transparency of the client-side security functions.

## 📝 Cryptographic Specifications

This project relies on the browser's native Web Crypto API (W3C standard).

| Function | Algorithm | Parameters | Notes |
| :--- | :--- | :--- | :--- |
| Key Derivation | PBKDF2 | SHA-256, 100,000 iterations | Derives a 256-bit key from a user secret (see implementation).
| Symmetric Encryption | AES-GCM | 256-bit key, 12-byte IV | Authenticated encryption (AES-GCM).

**Encryption Flow**
1. Password → (PBKDF2 / 100,000 iterations) → Derived Key (256-bit)
2. Plaintext + Derived Key + Random IV → (AES-GCM) → Ciphertext + IV

## ⚠️ Scope & Disclosure (Redacted)
This repository contains only the client-side cryptographic functions (for example, `deriveKey`, `encrypt`, and `decrypt`) that are intended for public audit.

Server-side operational policies and implementations (such as anti-abuse/rate-limiting, session management, and commercial systems) are maintained privately and are not included in this public repository. For security and anti-abuse reasons, specific thresholds, storage key names, and deployment details are not disclosed here. Qualified security auditors or partners may be granted restricted access to additional materials under appropriate agreements.

If you are performing a formal security review and require access to server-side documentation or operational details, please contact the project maintainers to request restricted access.

## Reviewing & Reporting
We welcome security reports and constructive feedback. To report issues or vulnerabilities, please follow the guidelines in the repository's issue tracker or contact the maintainers directly. Do not include sensitive data or production logs in public issues.

## 📄 License
This project is licensed under the MIT License. See the `LICENSE` file for details.