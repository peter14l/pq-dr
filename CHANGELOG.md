# Changelog

All notable changes to PQ-Aura will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-02

### Added

#### Core Cryptography
- Hybrid Post-Quantum Double Ratchet protocol implementation
- ML-KEM-1024 (NIST FIPS 203) for quantum-resistant key encapsulation
- X25519 for classical Diffie-Hellman key exchange
- AES-256-GCM-SIV for nonce-misuse resistant symmetric encryption
- BLAKE3 for high-speed hashing and key derivation
- Hybrid key generation combining classical and post-quantum primitives

#### Protocol Components
- PQ-X3DH asynchronous handshake protocol
- Double Ratchet engine with per-message key derivation
- Header encryption for metadata protection
- Out-of-order message handling with skip queue
- State export/import for session persistence

#### Platform Support
- Native Rust implementation
- C FFI bindings for cross-language integration
- WebAssembly (WASM) support for browser environments
- JNI bindings for Android/Java integration

#### Security Features
- Zeroize on drop for sensitive key material
- Constant-time comparisons using `subtle` crate
- Memory-safe Rust implementation
- Comprehensive error handling

#### Testing
- Unit tests for all cryptographic operations
- Integration tests for full protocol flow
- Property-based testing with proptest
- Fuzz testing targets for malformed input

#### Documentation
- Comprehensive README with usage examples
- Security policy and vulnerability reporting
- API documentation with rustdoc
- Benchmark suite for performance measurement

### Security
- Initial security architecture implementation
- Threat model documentation
- Supply chain security configuration

[0.1.0]: https://github.com/peter14l/pq-dr/releases/tag/v0.1.0
