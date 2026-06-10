# Security Policy

## Overview

PQ-Aura implements a **Hybrid Post-Quantum Double Ratchet** protocol, providing defense-in-depth against both classical and quantum adversaries. This document describes the security architecture, threat model, and vulnerability reporting process.

## Security Architecture

### Cryptographic Primitives

| Component | Algorithm | Security Level | Standard |
|-----------|-----------|----------------|----------|
| Quantum KEM | ML-KEM-1024 | 256-bit | NIST FIPS 203 |
| Classical DH | X25519 | 128-bit | RFC 7748 |
| Symmetric Cipher | AES-256-GCM-SIV | 256-bit | RFC 8452 |
| KDF | BLAKE3 | 256-bit | BLAKE3 spec |

### Hybrid Security Model

PQ-Aura combines classical and post-quantum cryptography to provide:

1. **Classical Security**: Even if ML-KEM is broken, X25519 provides 128-bit security
2. **Post-Quantum Security**: Even if X25519 is broken by quantum computers, ML-KEM provides 256-bit security
3. **Combined Security**: An attacker must break BOTH to compromise the protocol

### Protocol Components

#### PQ-X3DH Handshake
- **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
- **Post-Compromise Security**: Session recovers after key compromise
- **Offline Asynchronous**: Alice can initiate a session while Bob is offline

#### Double Ratchet Engine
- **Per-Message Key Derivation**: Every message uses a unique key
- **Header Encryption**: Message metadata is encrypted
- **Out-of-Order Support**: Handles delayed/reordered messages
- **Skip Limit**: Prevents DoS attacks via excessive message skipping

## Threat Model

### What We Protect Against

1. **Passive Eavesdropping**: All communication is encrypted
2. **Active Man-in-the-Middle**: Authentication via identity keys
3. **Quantum Computing Attacks**: Post-quantum KEM provides security
4. **Key Compromise**: Forward secrecy and post-compromise security
5. **Message Reordering**: Out-of-order message handling
6. **Metadata Leakage**: Header encryption hides ratchet state

### What We Don't Protect Against

1. **Endpoint Compromise**: If the device is fully compromised, all keys are exposed
2. **Side-Channel Attacks**: Timing, power, electromagnetic analysis
3. **Malicious Server**: The server can deny service but cannot decrypt
4. **Rubber Hose Cryptography**: Physical coercion

### Assumptions

1. Random number generation is truly random
2. The initial key exchange happens over an authenticated channel
3. The server correctly relays messages (can be untrusted for confidentiality)
4. Users verify each other's identity keys

## Known Limitations

1. **No Formal Verification**: The protocol has not been formally verified
2. **Limited Audit**: No professional security audit has been conducted
3. **Implementation Risks**: Rust memory safety is not absolute (unsafe code exists)
4. **Side-Channel Resistance**: Not explicitly tested for timing attacks

## Recommendations for Production Use

1. **Get a Professional Audit**: Before production use, engage a security firm
2. **Formal Verification**: Consider formal verification of critical components
3. **Side-Channel Testing**: Test for timing and power analysis attacks
4. **Key Management**: Implement proper key rotation and backup
5. **Monitoring**: Log and monitor for anomalous behavior

## Vulnerability Reporting

### How to Report

If you discover a security vulnerability:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** disclose the vulnerability publicly
3. **DO** email security@[oasis-project].com (or contact via Signal)
4. **DO** provide detailed reproduction steps
5. **DO** suggest a fix if possible

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)
- Your contact information for follow-up

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 1 week
- **Fix Timeline**: Depends on severity
- **Disclosure**: Coordinated with reporter

### Bug Bounty

We currently do not have a bug bounty program, but we will acknowledge researchers who responsibly disclose vulnerabilities.

## Security Audit Status

| Date | Auditor | Scope | Status |
|------|---------|-------|--------|
| - | - | - | Not yet audited |

We are seeking funding for a professional security audit. If you can help, please contact us.

## References

- [Signal Protocol Security](https://signal.org/docs/)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [PQ X3DH](https://signal.org/docs/specifications/x3dh/)

---

**Last Updated**: 2026-06-10  
**Contact**: security@[oasis-project].com
