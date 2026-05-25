# OWASP ASVS 5.0 — V11 Cryptography

> **Source:** OWASP Application Security Verification Standard v5.0.0 (Released May 2025)
> **Chapter:** V11 — Cryptography
> **Reference:** https://github.com/OWASP/ASVS/tree/master/5.0/en
>
> **NOTE:** This is a curated sample of the most critical requirements for the Cryptographic Mitigation Recommender Agent prototype.
> For the complete official ASVS 5.0 content, run: `python scripts/download_kb_sources.py`

---

## Control Objective

Ensure that a verified application uses cryptography effectively to protect data confidentiality, integrity, and authenticity. Cryptographic operations must use approved algorithms, sufficient key lengths, and current best practices.

---

## V11.1 Cryptographic Inventory and Documentation

### V11.1.1 (Level 1)
**Requirement:** Verify that all cryptographic modules, libraries, and assets (algorithms, keys, certificates) are documented and inventoried.

**Rationale:** Maintaining a complete cryptographic bill of materials (CBOM) enables rapid response to algorithm vulnerabilities and supports migration planning (e.g., post-quantum cryptography).

**Implementation Guidance:** Use SAST/DAST tools to discover cryptographic usage. Tools include CryptoMon (eBPF-based), Cryptobom Forge (CodeQL-based).

**Related CWE:** CWE-1240 (Use of a Cryptographic Primitive with a Risky Implementation)

---

## V11.2 Symmetric Cryptography

### V11.2.1 (Level 1)
**Requirement:** Verify that symmetric encryption uses AES-128 or AES-256 with an authenticated encryption mode (AES-GCM or AES-CCM preferred).

**Rationale:** Authenticated encryption modes provide both confidentiality and integrity, preventing tampering attacks.

**Implementation Guidance:**
- **Approved:** AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305
- **Deprecated:** AES-ECB (no semantic security), AES-CBC without HMAC
- **Forbidden:** DES, 3DES (Triple-DES), Blowfish, RC4

**Related CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
**Related NIST:** SP 800-38D (GCM/GMAC), SP 800-175B

### V11.2.2 (Level 1)
**Requirement:** Verify that initialization vectors (IVs) and nonces are generated using a cryptographically secure random number generator and are unique per encryption operation.

**Rationale:** IV/nonce reuse with the same key destroys the security guarantees of authenticated encryption modes.

**Implementation Guidance:** Generate 96-bit random nonces for GCM mode. Use counter mode (incrementing) only when key uniqueness is guaranteed.

**Related CWE:** CWE-329 (Generation of Predictable IV with CBC Mode)

---

## V11.3 Asymmetric Cryptography

### V11.3.1 (Level 1)
**Requirement:** Verify that asymmetric cryptography uses approved algorithms with sufficient key sizes:
- RSA: minimum 2048 bits (3072 bits recommended)
- ECC: minimum P-256 (NIST curves) or Curve25519/Ed25519
- DSA: forbidden (use ECDSA or Ed25519 instead)

**Rationale:** RSA-1024 is broken; smaller ECC curves are vulnerable to discrete log attacks.

**Implementation Guidance:**
- **Approved:** RSA-2048+, RSA-3072+, ECDSA P-256/P-384, Ed25519
- **Deprecated:** RSA-1024
- **Forbidden:** DSA, RSA < 1024

**Related CWE:** CWE-326 (Inadequate Encryption Strength)

### V11.3.2 (Level 2)
**Requirement:** Verify that RSA implementations use OAEP padding for encryption (not PKCS#1 v1.5) and PSS padding for signatures.

**Rationale:** PKCS#1 v1.5 padding is vulnerable to Bleichenbacher's attack.

**Related CWE:** CWE-780 (Use of RSA Algorithm without OAEP)

---

## V11.4 Cryptographic Hashing

### V11.4.1 (Level 1)
**Requirement:** Verify that the application uses approved cryptographic hash functions (SHA-256, SHA-384, SHA-512, SHA-3) and does NOT use MD5 or SHA-1 for security purposes.

**Rationale:** MD5 and SHA-1 are vulnerable to collision attacks and are unsuitable for any security purpose including integrity verification.

**Implementation Guidance:**
- **Approved:** SHA-256, SHA-384, SHA-512, SHA-3 family, BLAKE2/BLAKE3
- **Forbidden:** MD5, SHA-1, MD4, RIPEMD-128

**Related CWE:** CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash)

### V11.4.2 (Level 1)
**Requirement:** Verify that passwords are stored using approved password hashing functions with appropriate work factors:
- Argon2id (preferred): m=64MB (65536 KiB), t=3, p=4
- bcrypt: cost factor >= 12
- scrypt: N=2^17, r=8, p=1
- PBKDF2-HMAC-SHA256: minimum 600,000 iterations (NIST SP 800-63B v4)

**Rationale:** Memory-hard functions like Argon2id resist GPU/ASIC-accelerated cracking.

**Implementation Guidance:**
- **Preferred:** Argon2id
- **Acceptable:** bcrypt cost >=12, scrypt with strong parameters
- **Forbidden:** MD5, SHA-1, SHA-256 (without proper KDF), plaintext storage

**Related CWE:** CWE-916 (Use of Password Hash With Insufficient Computational Effort), CWE-759 (Use of a One-Way Hash without a Salt)
**Related NIST:** SP 800-63B v4 §5.1.1.2

---

## V11.5 Random Values

### V11.5.1 (Level 1)
**Requirement:** Verify that all cryptographic randomness uses a cryptographically secure pseudorandom number generator (CSPRNG), not standard PRNGs.

**Rationale:** Standard PRNGs (java.util.Random, Math.random, rand()) are predictable and unsuitable for keys, IVs, tokens, or session identifiers.

**Implementation Guidance:**
- **Linux:** getrandom(2) syscall, /dev/urandom
- **Windows:** BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
- **macOS/iOS:** SecRandomCopyBytes
- **Java:** java.security.SecureRandom (NOT java.util.Random)
- **Python:** secrets module (NOT random module)
- **Node.js:** crypto.randomBytes() (NOT Math.random())

**Related CWE:** CWE-330 (Use of Insufficiently Random Values), CWE-338 (Use of Cryptographically Weak PRNG)

### V11.5.2 (Level 2)
**Requirement:** Verify that security tokens (session IDs, password reset tokens, CSRF tokens) use at least 128 bits of entropy.

**Rationale:** Tokens with insufficient entropy can be brute-forced or guessed.

**Implementation Guidance:** Generate 16+ bytes (128+ bits) of random data, encoded as base64url or hex.

**Related CWE:** CWE-340 (Generation of Predictable Numbers or Identifiers), CWE-640 (Weak Password Recovery Mechanism)

---

## V11.6 Key Management

### V11.6.1 (Level 1)
**Requirement:** Verify that cryptographic keys are generated by a CSPRNG, never derived from low-entropy sources (passwords, predictable values).

**Rationale:** Keys derived from passwords directly are vulnerable to dictionary attacks.

**Implementation Guidance:** Use HKDF (RFC 5869) or PBKDF2 with high iteration count for password-based key derivation.

**Related CWE:** CWE-321 (Use of Hard-coded Cryptographic Key)

### V11.6.2 (Level 2)
**Requirement:** Verify that cryptographic keys are stored using approved key management solutions (HSM, key vault, KMS) and never embedded in source code, configuration files, or repositories.

**Rationale:** Hard-coded keys are easily exposed through code leaks, decompilation, or repository access.

**Implementation Guidance:**
- **Cloud KMS:** AWS KMS, Google Cloud KMS, Azure Key Vault
- **HSM:** PKCS#11-compatible hardware modules
- **Open Source:** HashiCorp Vault, Mozilla SOPS

**Related CWE:** CWE-321 (Use of Hard-coded Cryptographic Key), CWE-798 (Use of Hard-coded Credentials)

### V11.6.3 (Level 2)
**Requirement:** Verify that cryptographic keys have a documented lifecycle including generation, rotation, archival, and destruction policies.

**Rationale:** Static keys accumulate exposure risk over time; rotation limits the impact of key compromise.

**Implementation Guidance:** Rotate encryption keys annually for L2, quarterly for L3. Implement automated key rotation where possible.

**Related NIST:** SP 800-57 Part 1 Rev 5

---

## V11.7 Transport Layer Security (Cross-reference V12)

### V11.7.1 (Level 1)
**Requirement:** Verify that TLS configuration uses TLS 1.2 minimum (TLS 1.3 preferred) with strong cipher suites only.

**Implementation Guidance:**
- **TLS 1.3 Approved:** TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256
- **TLS 1.2 Approved:** ECDHE-based suites with AES-GCM or ChaCha20-Poly1305
- **Forbidden:** TLS 1.0, TLS 1.1, SSL 3.0, all RC4/DES/3DES/MD5/SHA-1 cipher suites
- Enable HSTS with max-age >= 31536000 (1 year)
- Use certificates with RSA-2048+ or ECDSA P-256+ keys

**Related CWE:** CWE-326 (Inadequate Encryption Strength), CWE-327 (Broken Algorithm), CWE-319 (Cleartext Transmission)

---

## V11.8 JWT and Token Security

### V11.8.1 (Level 1)
**Requirement:** Verify that JSON Web Tokens (JWTs) are signed using approved algorithms (RS256, ES256, EdDSA, HS256 with strong secret) and that the application rejects tokens with `alg: none` or weak algorithms.

**Rationale:** The `alg: none` vulnerability and algorithm confusion attacks have caused widespread JWT compromises.

**Implementation Guidance:**
- **Approved:** RS256 (RSA-PSS preferred), ES256, ES384, EdDSA
- **Conditional:** HS256 with 256-bit+ secret (only for symmetric trust scenarios)
- **Forbidden:** `alg: none`, HS256 with weak secrets, weak algorithm acceptance

**Related CWE:** CWE-347 (Improper Verification of Cryptographic Signature)

### V11.8.2 (Level 1)
**Requirement:** Verify that JWTs include appropriate claims (iss, sub, aud, exp, iat) and have short expiration times (<= 15 minutes for access tokens).

**Rationale:** Long-lived tokens increase blast radius of token theft.

**Related CWE:** CWE-613 (Insufficient Session Expiration)

---

## V11.9 Post-Quantum Cryptography (Future-Ready)

### V11.9.1 (Level 3)
**Requirement:** Verify that the application has a migration plan for post-quantum cryptography (PQC) considering the cryptographic inventory from V11.1.

**Rationale:** Quantum computers will eventually break RSA, ECC, and DH-based cryptography. NIST has standardized PQC algorithms (CRYSTALS-Kyber, CRYSTALS-Dilithium) as of 2024.

**Implementation Guidance:** Identify assets with high "harvest now, decrypt later" risk. Plan migration to NIST PQC standards (FIPS 203, FIPS 204, FIPS 205).

---

## V11.10 Forbidden Cryptography (Negative Requirements)

### V11.10.1 (Level 1)
**Requirement:** Verify that the application does NOT use the following:

| Category | Forbidden Items |
|---|---|
| Hash | MD5, SHA-1, MD4, RIPEMD-128 |
| Symmetric Cipher | DES, 3DES, Blowfish, RC4, RC2 |
| Block Mode | ECB (for confidentiality), CBC without HMAC |
| Asymmetric | RSA < 2048 bits, DSA, DH with weak parameters |
| Padding | PKCS#1 v1.5 (use OAEP/PSS), null padding |
| Random | Math.random(), java.util.Random, rand(), srand(time(0)) |
| TLS | TLS 1.0, TLS 1.1, SSL 3.0 |
| JWT | alg: none, weak HS256 secrets |

**Related CWE:** CWE-327, CWE-328, CWE-916, CWE-330, CWE-347

---

## Cross-References

| ASVS V11 Section | Maps to NIST 800-53 |
|---|---|
| V11.1 Inventory | CM-8, RA-9 |
| V11.2-V11.4 Crypto Algorithms | SC-13 |
| V11.5 Random | SC-13 |
| V11.6 Key Management | SC-12 |
| V11.7 TLS | SC-8, SC-23 |
| V11.8 JWT/Tokens | IA-5, IA-7 |

| ASVS V11 Section | Maps to OWASP Top 10 |
|---|---|
| All | A02:2021 — Cryptographic Failures |

| ASVS V11 Section | Maps to Indonesia Regulations |
|---|---|
| V11.6 Key Management | UU PDP 27/2022 Pasal 35 (kewajiban enkripsi data sensitif) |
| V11.7 TLS | POJK 11/POJK.03/2022 §32 (komunikasi terenkripsi) |

---

**License:** OWASP ASVS is published under Creative Commons CC BY-SA 4.0. This document is a curated excerpt for academic research purposes.
