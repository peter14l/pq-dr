# PQ-Aura Audit Checklist

This document provides a checklist for security auditors reviewing PQ-Aura.

## Pre-Audit Information

### Codebase Overview

- **Language**: Rust
- **Version**: 0.1.0
- **License**: GPL-3.0
- **Dependencies**: ml-kem, x25519-dalek, aes-gcm-siv, blake3, zeroize, subtle

### Architecture

- **Protocol**: Hybrid Post-Quantum Double Ratchet
- **Components**:
  - PQ-X3DH Handshake
  - Double Ratchet Engine
  - Header Encryption
  - State Management

### Files to Review

```
src/
├── lib.rs          # Module declarations
├── crypto.rs       # Core cryptographic operations
├── handshake.rs    # PQ-X3DH handshake
├── ratchet.rs      # Double Ratchet engine
├── state.rs        # Session state
├── error.rs        # Error types
├── ffi.rs          # C FFI bindings
├── wasm.rs         # WebAssembly bindings
└── jni.rs          # JNI bindings
```

## Audit Checklist

### 1. Cryptographic Primitives

- [ ] **ML-KEM-1024**
  - [ ] Correct implementation of FIPS 203
  - [ ] Proper key generation
  - [ ] Correct encapsulation/decapsulation
  - [ ] No nonce reuse issues

- [ ] **X25519**
  - [ ] Correct implementation of RFC 7748
  - [ ] Proper point validation
  - [ ] No small subgroup attacks

- [ ] **AES-256-GCM-SIV**
  - [ ] Correct implementation of RFC 8452
  - [ ] Proper nonce handling
  - [ ] No nonce reuse issues
  - [ ] Correct authentication tag verification

- [ ] **BLAKE3**
  - [ ] Correct implementation
  - [ ] Proper domain separation
  - [ ] No length extension attacks

### 2. Protocol Implementation

- [ ] **PQ-X3DH Handshake**
  - [ ] Correct key agreement
  - [ ] Proper entropy combination
  - [ ] No replay attacks
  - [ ] Correct state initialization

- [ ] **Double Ratchet**
  - [ ] Correct ratchet advancement
  - [ ] Proper key derivation
  - [ ] No key reuse
  - [ ] Correct skip message handling

- [ ] **Header Encryption**
  - [ ] Correct encryption/decryption
  - [ ] No metadata leakage
  - [ ] Proper key management

### 3. Memory Safety

- [ ] **Zeroize**
  - [ ] All secrets zeroized on drop
  - [ ] No secret material in debug output
  - [ ] Proper use of `ZeroizeOnDrop`

- [ ] **Constant-Time Operations**
  - [ ] All comparisons use `subtle` crate
  - [ ] No data-dependent branching on secrets
  - [ ] No timing side-channels

- [ ] **Memory Safety**
  - [ ] No unsafe code (or minimal and well-documented)
  - [ ] No buffer overflows
  - [ ] No use-after-free
  - [ ] No double-free

### 4. Error Handling

- [ ] **Error Messages**
  - [ ] No secret material in errors
  - [ ] Appropriate error types
  - [ ] No panic on malformed input

- [ ] **Error Recovery**
  - [ ] Graceful degradation
  - [ ] No state corruption on error
  - [ ] Proper cleanup on failure

### 5. Serialization

- [ ] **Input Validation**
  - [ ] Proper length checks
  - [ ] No integer overflows
  - [ ] No panic on malformed input

- [ ] **Output Safety**
  - [ ] No secret material in serialized output
  - [ ] Proper encoding/decoding
  - [ ] Backward compatibility

### 6. FFI/WASM/JNI

- [ ] **FFI Safety**
  - [ ] Proper null pointer checks
  - [ ] No memory leaks
  - [ ] Proper cleanup on error

- [ ] **WASM Safety**
  - [ ] No JavaScript injection
  - [ ] Proper memory management
  - [ ] No panic on invalid input

- [ ] **JNI Safety**
  - [ ] Proper JVM integration
  - [ ] No memory leaks
  - [ ] Proper exception handling

### 7. Side-Channel Resistance

- [ ] **Timing Attacks**
  - [ ] Constant-time comparisons
  - [ ] No data-dependent branching
  - [ ] No cache timing attacks

- [ ] **Power Analysis**
  - [ ] No obvious patterns
  - [ ] Consider masking if needed

- [ ] **Electromagnetic Analysis**
  - [ ] No obvious patterns
  - [ ] Consider shielding if needed

### 8. DoS Resistance

- [ ] **Resource Limits**
  - [ ] Maximum message size limits
  - [ ] Maximum skip message limits
  - [ ] Memory usage limits

- [ ] **Replay Protection**
  - [ ] Message ordering
  - [ ] Duplicate detection
  - [ ] Expiration handling

### 9. Key Management

- [ ] **Key Generation**
  - [ ] Cryptographically secure RNG
  - [ ] Proper entropy sources
  - [ ] No key reuse

- [ ] **Key Storage**
  - [ ] Secure key storage
  - [ ] Key rotation support
  - [ ] Key backup/recovery

- [ ] **Key Exchange**
  - [ ] Authentication
  - [ ] Forward secrecy
  - [ ] Post-compromise security

### 10. Documentation

- [ ] **Security Documentation**
  - [ ] Threat model
  - [ ] Security guarantees
  - [ ] Known limitations

- [ ] **API Documentation**
  - [ ] Usage examples
  - [ ] Safety requirements
  - [ ] Error conditions

## Specific Areas of Concern

### 1. Hybrid KEM Security

The hybrid KEM combines X25519 and ML-KEM-1024. Verify:

- [ ] Both components are properly combined
- [ ] Compromise of one component doesn't affect the other
- [ ] No cross-component attacks

### 2. State Serialization

State is serialized and encrypted. Verify:

- [ ] No sensitive material in plaintext
- [ ] Proper encryption of state
- [ ] No state corruption on serialization/deserialization

### 3. Skip Message Handling

The ratchet supports out-of-order messages. Verify:

- [ ] Proper key storage for skipped messages
- [ ] No memory exhaustion attacks
- [ ] Proper cleanup of old keys

### 4. Header Encryption

Headers are encrypted separately. Verify:

- [ ] No metadata leakage
- [ ] Proper key management
- [ ] No attacks on header encryption

## Recommendations

### Before Production Use

1. **Professional Audit**: Engage a professional security firm
2. **Formal Verification**: Consider formal verification of critical components
3. **Fuzz Testing**: Run extensive fuzz testing
4. **Side-Channel Testing**: Test for timing and power analysis attacks

### Ongoing Security

1. **Regular Updates**: Keep dependencies updated
2. **Security Monitoring**: Monitor for new vulnerabilities
3. **Incident Response**: Have a plan for security incidents
4. **Key Rotation**: Implement regular key rotation

## References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [RFC 7748 (X25519)](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 8452 (AES-256-GCM-SIV)](https://datatracker.ietf.org/doc/html/rfc8452)
- [Signal Protocol Security](https://signal.org/docs/)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)

---

**Last Updated**: 2026-06-10
