# PQ-Aura (Post-Quantum Double Ratchet)

PQ-Aura is a high-performance cryptographic library implementing a **Hybrid Post-Quantum Double Ratchet** protocol. It provides "Defense in Depth" by combining classical elliptic curve cryptography with NIST FIPS 203 quantum-resistant algorithms.

## 🛡️ Security Architecture

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Quantum KEM** | **ML-KEM-1024** | NIST FIPS 203 (Strongest security tier). |
| **Classical DH** | **X25519** | Industry standard; ensures security if PQC is compromised. |
| **Symmetric Cipher** | **AES-256-GCM-SIV** | Nonce-misuse resistant; ideal for high-speed media. |
| **KDF** | **BLAKE3 (XOF)** | 2026-standard for high-speed, parallelizable derivation. |
| **Hardening** | **Zeroize + Subtle** | Prevents memory leaks and timing side-channel attacks. |

## 🧩 How It Works

### 1. Asynchronous Handshake (PQ-X3DH)
PQ-Aura uses a **Post-Quantum Extended Triple Diffie-Hellman** protocol to allow users to establish a secure session even when one party is offline.
*   **Pre-Key Bundles:** Users publish a bundle containing Identity keys and ML-KEM encapsulation keys to a server.
*   **Hybrid Entropy Mixing:** Alice combines entropy from 3-4 classical DH exchanges and 2-3 quantum KEM operations into a single 256-bit **Root Key**.

### 2. The Double Ratchet Engine
Once the session is established, the protocol "ratchets" the keys for every message:
*   **Symmetric Ratchet:** Advances with every message sent or received to provide **Forward Secrecy**.
*   **Asymmetric Ratchet:** Re-keys periodically using a Hybrid (X25519 + ML-KEM) exchange to provide **Post-Compromise Security**.
*   **Header Encryption:** Standard Signal headers are visible; PQ-Aura encrypts message headers using a separate **Header Chain** to hide the ratchet count from servers.

### 3. Cross-Platform Connectivity
PQ-Aura is designed to power modern, secure applications across all environments:
*   **Native FFI:** High-performance bridge for **Android, iOS, Windows, macOS, and Linux**.
*   **WebAssembly (WASM):** Specialized module for **Flutter Web** with browser-safe entropy support.

## 🚀 Development Workflow (The "Thin Client" Strategy)

This project is optimized for developers with hardware constraints (e.g., External HDD, Low CPU). 

1.  **Local Editing:** Write code on your local drive.
2.  **Remote Execution:** Push your changes to GitHub.
3.  **Cloud CI:** GitHub Actions handles the heavy lifting (Compilation, Testing, Clippy, and Security Audits).

## 📦 Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
pq-aura = { git = "https://github.com/peter14l/pq-dr.git" }
```

## 🛠️ Usage Example

### Starting a Handshake
```rust
use pq_aura::handshake::*;

// Alice initiates using Bob's bundle
let (mut alice_state, initial_msg, root_key) = 
    HandshakeEngine::initiate_alice(&bob_bundle, &alice_id_pk, &alice_id_sk, &mut rng);

// Bob responds to the initial message
let (mut bob_state, root_key) = 
    HandshakeEngine::respond_bob(&initial_msg, &bob_id_pk, &bob_id_sk, &bob_signed_sk, Some(&bob_ot_sk)).unwrap();
```

### Encrypting Texts and Media
```rust
use pq_aura::RatchetEngine;

// Works for texts
let msg = RatchetEngine::encrypt(&mut alice_state, b"Hello Bob!", ad, &mut rng);

// Works for large media (Images/Video)
let media_bytes = std::fs::read("video.mp4").unwrap();
let encrypted_media = RatchetEngine::encrypt(&mut alice_state, &media_bytes, ad, &mut rng);
```

## ⚖️ License

Distributed under the **GNU General Public License v3.0**. 

**Important:** Any application built using this protocol or library must be kept open-source under the same or compatible terms. See [LICENSE](LICENSE) for the full text.

---
**Lead Developer:** Shreyas Sengupta  
**Project Date:** 2026-05-02
