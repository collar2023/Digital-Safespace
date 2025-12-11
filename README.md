# 🔒 DigitalSafe-Crypto-Core (E2EE Transparency Repository)

This repository contains the cryptographic core implementation for the DigitalSafe end-to-end encrypted (E2EE) chat application.

**Our Commitment to Trust and Transparency:**
The primary goal of this repository is to openly share the most security-critical part of our application with the security community for continuous review and audit.

## 📝 CRYPTOGRAPHIC SPECIFICATIONS

We rely exclusively on the browser's native **Web Crypto API** (W3C Standard) to ensure maximum reliability and security.

| Function | Algorithm | Parameters | Security Strength |
| :--- | :--- | :--- | :--- |
| **Key Derivation** | PBKDF2 (Password-Based Key Derivation Function 2) | Hash: SHA-256 | High |
| **Key Iterations** | 100,000 Iterations | Salt: "SIMPLE_SALT_V2" | High (Meets modern security recommendations) |
| **Symmetric Encryption** | AES-GCM (Advanced Encryption Standard - Galois/Counter Mode) | Key Length: 256-bit, IV: 12 bytes | Excellent (NIST-recommended Authenticated Encryption) |

**Encryption Flow:**
1.  **Password** $\xrightarrow{PBKDF2/100k}$ **Derived Key (256-bit)**
2.  **Plaintext + Derived Key + Random IV** $\xrightarrow{AES-GCM}$ **Ciphertext + IV**

## ⚠️ IMPORTANT NOTE ON SCOPE (IP Protection)

This repository **only** contains the client-side cryptographic functions (`deriveKey`, `encrypt`, `decrypt`).

* **The server-side business logic, including rate limiting, Cloudflare Durable Object session management, and monetization strategies, is proprietary and remains private.**
* All data storage for rate limiting is handled by a private Cloudflare KV namespace and is not exposed in this code.

We invite security researchers to review `DigitalSafe-Crypto-Core.js` for any cryptographic vulnerabilities.

## 📄 LICENSE

This project is licensed under the MIT License. Please see the LICENSE file for details.