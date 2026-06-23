---

# PRD: Project PQ-Aura (Post-Quantum Double Ratchet)

**Version:** 1.1 (2026-05-02)  
**Status:** Optimized for External Storage & Cloud-CI  
**Lead Developer:** Shreyas Sengupta  
**Hardware Strategy:** Local Editing (External HDD) + Remote Execution (GitHub Actions)

---

## 1. Executive Summary
PQ-Aura is a high-performance cryptographic library written in Rust. It implements a **Hybrid Post-Quantum Double Ratchet** protocol. To accommodate hardware constraints (External HDD and 2-Core CPU), the project utilizes a **Remote-Heavy Development Model** where local resources are used strictly for source-code management, while all computational tasks are executed via GitHub Actions.

---

## 2. Updated Hardware & Workflow Strategy

### 2.1. The "Thin Client" Workflow
*   **Local Action:** Write code on the external HDD using your preferred editor (VS Code, Cursor, etc.). 
*   **Offshore Action:** Use `git push` to trigger GitHub Actions. 
*   **Feedback Loop:** Monitor the "Actions" tab in GitHub to see compiler errors, warnings, and test results.
*   **HDD Protection:** Avoid running `cargo build` or `cargo check` locally. This prevents the massive `target/` folder (which can grow to several GBs and involve high-frequency writes) from stressing your HDD or slowing down your 2-core system.

### 2.2. `.gitignore` Hardening
To ensure your HDD isn't bogged down by build artifacts, your `.gitignore` must strictly exclude:
```text
/target
**/*.rs.bk
Cargo.lock (optional, but keep it for consistency)
```

---

## 3. Technical Specifications (The "Max-Security" Protocol)

| Component | Technology | Security Rationale |
| :--- | :--- | :--- |
| **PQ KEM** | **ML-KEM-1024** | NIST's strongest post-quantum standard (FIPS 203). |
| **Classical KEM** | **X25519** | Fallback security in case of PQC mathematical discovery. |
| **Symmetric Cipher** | **AES-256-GCM-SIV** | Misuse-resistant; prevents leaks if nonces are reused. |
| **KDF** | **HKDF-BLAKE3** | 2026-standard for high-speed, collision-resistant key derivation. |
| **Hardening** | `Zeroize` + `Subtle` | Wipes memory and prevents timing-attack side channels. |

---

## 4. Feature Requirements

### 4.1. Hybrid Handshake (Phase 1)
*   **Dual-Key Generation:** Functions to generate paired X25519 and ML-KEM-1024 keys.
*   **Shared Secret Derivation:** A BLAKE3-based mixing function that combines entropy from both classical and quantum exchanges.

### 4.2. The Ratchet Engine (Phase 2)
*   **Symmetric Chain:** A chain that advances for every message to ensure forward secrecy.
*   **Asymmetric Update:** A hybrid "re-keying" step that happens periodically to ensure post-compromise security.
*   **Header Encryption:** Standard Signal leaves headers "naked"; PQ-Aura will encrypt message headers so the server cannot see the ratchet count.

---

## 5. Automation & Testing (The "Cloud Compiler")

Since you are not running tests locally, the GitHub Actions file must be exhaustive.

### 5.1. Cloud CI Requirements
*   **Continuous Integration:** Every push triggers a `cargo check` and `cargo test --release`.
*   **Security Audit:** Automatic scan for crate vulnerabilities.
*   **Fuzz Testing:** Use `proptest` in the cloud to hammer the protocol with random data to ensure it never crashes.
*   **Artifact Logging:** If a test fails, the GitHub Action must output a detailed "Trace" so you can debug the code locally without needing to re-run the build.

---

## 6. Implementation Plan for Shreyas

1.  **Repo Setup:** Initialize `pq-aura` on your external HDD.
2.  **Config:** Setup the `Cargo.toml` provided previously.
3.  **The "No-Build" Rule:** Commit to **never** typing `cargo build` on your terminal. Use `git commit -m "feat: implement x" && git push` as your "Compile" button.
4.  **Vibe Coding:** Focus on the logic. Let the GitHub 2-core (or 4-core) cloud runners do the heavy lifting of turning that logic into a binary.

---