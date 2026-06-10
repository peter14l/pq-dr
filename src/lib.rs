//! # PQ-Aura (Post-Quantum Double Ratchet)
//!
//! A high-performance cryptographic library implementing a **Hybrid Post-Quantum Double Ratchet** protocol.
//!
//! ## Security Architecture
//!
//! | Component | Technology | Rationale |
//! | :--- | :--- | :--- |
//! | **Quantum KEM** | **ML-KEM-1024** | NIST FIPS 203 (Strongest security tier) |
//! | **Classical DH** | **X25519** | Industry standard; ensures security if PQC is compromised |
//! | **Symmetric Cipher** | **AES-256-GCM-SIV** | Nonce-misuse resistant; ideal for high-speed media |
//! | **KDF** | **BLAKE3 (XOF)** | 2026-standard for high-speed, parallelizable derivation |
//! | **Hardening** | **Zeroize + Subtle** | Prevents memory leaks and timing side-channel attacks |
//!
//! ## Quick Start
//!
//! ```rust
//! use pq_aura::crypto::*;
//! use rand::thread_rng;
//!
//! let mut rng = thread_rng();
//!
//! // Generate a hybrid keypair
//! let (pk, sk) = generate_hybrid_keypair(&mut rng);
//!
//! // Encapsulate a shared secret
//! let (shared_secret, ciphertext) = hybrid_encapsulate(&pk, &mut rng);
//!
//! // Decapsulate the shared secret
//! let recovered_secret = hybrid_decapsulate(&sk, &ciphertext).unwrap();
//!
//! // Verify the secrets match
//! assert!(constant_time_eq(shared_secret.as_ref(), recovered_secret.as_ref()));
//! ```
//!
//! ## Features
//!
//! - **Hybrid Security**: Combines classical and post-quantum cryptography
//! - **Cross-Platform**: Rust core with FFI, WASM, and JNI bindings
//! - **Forward Secrecy**: Per-message key derivation
//! - **Post-Compromise Security**: Session recovers after key compromise
//! - **Async Handshake**: PQ-X3DH protocol for offline initiation
//!
//! ## Modules
//!
//! - [`crypto`]: Core cryptographic operations
//! - [`ratchet`]: Double Ratchet engine
//! - [`handshake`]: PQ-X3DH handshake protocol
//! - [`state`]: Session state management
//!
//! ## Security Considerations
//!
//! This library has NOT been audited. Use at your own risk in production.
//! See [SECURITY.md](https://github.com/peter14l/pq-dr/blob/main/SECURITY.md) for details.
//!
//! ## License
//!
//! GNU General Public License v3.0

pub mod crypto;
pub mod error;
pub mod handshake;
pub mod ratchet;
pub mod state;

// Re-exports for convenience
pub use crypto::{
    generate_hybrid_keypair, hybrid_decapsulate, hybrid_encapsulate, 
    HybridPublicKey, HybridSecretKey, SecretKeyMaterial,
};
pub use crate::error::AuraError;
pub use handshake::{HandshakeEngine, InitialMessage, PreKeyBundle};
pub use ratchet::{Header, Message, RatchetEngine};
pub use state::{ChainState, HeaderChain, RatchetState};
