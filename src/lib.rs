//! # PQ-Aura: Hybrid Post-Quantum Double Ratchet
//!
//! PQ-Aura is a high-performance cryptographic library implementing a Hybrid Post-Quantum
//! Double Ratchet protocol. It combines classical X25519 Diffie-Hellman with NIST FIPS 203
//! ML-KEM-1024 to provide "Defense in Depth" against both classical and future quantum adversaries.
//!
//! ## Philosophy
//! If one algorithm fails, the other must hold the line. Entropy from both classical
//! and quantum exchanges is merged using BLAKE3 as a Key Derivation Function (KDF).

pub mod crypto;
pub mod ffi;
pub mod handshake;
pub mod jni;
pub mod ratchet;
pub mod state;
pub mod wasm;

pub use crypto::{
    combine_secrets, generate_hybrid_keypair, hybrid_decapsulate, hybrid_encapsulate,
    HybridPublicKey, HybridSecretKey, SecretKeyMaterial,
};
pub use ratchet::{Header, Message, RatchetEngine};
pub use state::RatchetState;
