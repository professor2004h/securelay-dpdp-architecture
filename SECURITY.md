# Security Policy & Cryptographic Verification

Securelay takes the security of data privacy infrastructure with paramount seriousness. This document outlines our vulnerability disclosure guidelines, cryptographic standards, and enterprise compliance posture for India's DPDP Act 2023 and GDPR.

## 1. Supported Specifications & Standards

| Standard / Framework | Specification | Implementation in Securelay |
| :--- | :--- | :--- |
| **NIST SP 800-88 Rev. 1** | Guidelines for Media Sanitization | Section 5 Cryptographic Erasure via per-principal DEK destruction |
| **NIST SP 800-57** | Key Management Guidelines | Root KEK in HSM; per-principal DEK envelope wrapping |
| **FIPS 140-2 / 140-3** | Cryptographic Module Security Requirements | AES-256-GCM authenticated encryption |
| **India DPDP Act 2023** | Sections 8 (Security Safeguards) & 12 (Erasure) | Runtime ingestion proxy + cryptographic tombstone certificates |
| **CERT-In Directions** | Cyber Security Incident Reporting | Blast radius mitigation: Zero plaintext PII stored in downstream DBs |

---

## 2. Reporting a Vulnerability

If you discover a potential security flaw, vulnerability, or cryptographic anomaly in this reference implementation or Securelay Enterprise Engine, please disclose it responsibly:

* **Direct Security Email**: `securelay.com@gmail.com`
* **Lead Contact**: **Shanmukh Chitturi** ([LinkedIn Profile](https://www.linkedin.com/in/shanmukh-chitturi/))
* **PGP Encryption**: Available upon request for sensitive disclosures.

Please do not open public GitHub issues for security vulnerabilities. We will acknowledge receipt of reports within 24 hours and provide an initial assessment and remediation timeline within 72 hours.

---

## 3. Audits & Verification

Securelay reference architectures undergo ongoing internal and independent code reviews focusing on:
* Memory safety and nonce reuse prevention in AES-GCM routines.
* Cryptographic timing attack resistance during token validation.
* Zeroization proofs for destroyed key material in volatile memory.

For third-party Cert-In empaneled audit documentation or pilot reviews, contact `securelay.com@gmail.com`.
