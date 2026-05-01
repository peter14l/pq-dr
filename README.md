# PQ-Aura (Post-Quantum Double Ratchet)

PQ-Aura is a high-performance cryptographic library implementing a **Hybrid Post-Quantum Double Ratchet** protocol. It is designed to provide "Defense in Depth" by combining classical elliptic curve cryptography with NIST-standardized quantum-resistant algorithms.

## 🛡️ Security Architecture

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Quantum KEM** | **ML-KEM-1024** | NIST FIPS 203 (Strongest tier). |
| **Classical DH** | **X25519** | Industry standard, provides fallback security. |
| **Symmetric Cipher** | **AES-256-GCM-SIV** | Nonce-misuse resistant encryption. |
| **KDF** | **HKDF-BLAKE3** | High-speed, collision-resistant derivation. |
| **Memory** | **Zeroize** | Automatic wiping of sensitive key material. |

## 🚀 Development Workflow (The "Thin Client" Strategy)

This project is optimized for developers with hardware constraints (e.g., External HDD, Low CPU). 

1.  **Local Editing:** Write code on your local drive.
2.  **Remote Execution:** **Do not run `cargo build` locally.** Push your changes to GitHub.
3.  **Cloud CI:** GitHub Actions handles the heavy lifting (compilation, testing, clippy, and security audits).

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pq-aura = { git = "https://github.com/peter14l/pq-dr.git" }
```

## 🛠️ Usage

Refer to the [INTEGRATION.md](INTEGRATION.md) for a detailed guide on implementing the **Hybrid-X3DH Handshake** and initializing the ratchet.

```rust
use pq_aura::*;

// Initialize state
let mut state = RatchetState::new_alice(root_key, remote_pk, local_pk, local_sk);

// Encrypt
let message = RatchetEngine::encrypt(&mut state, b"Secret message", ad, &mut rng);

// Decrypt
let plaintext = RatchetEngine::decrypt(&mut state, &message, ad).unwrap();
```

## ⚖️ License

Distributed under the **GNU General Public License v3.0**. 

**Important:** Any application built using this protocol or library must be kept open-source under the same or compatible terms. See [LICENSE](LICENSE) for the full text.

---
**Lead Developer:** Shreyas Sengupta  
**Project Date:** 2026-05-02
