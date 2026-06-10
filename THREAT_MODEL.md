# Threat Model for PQ-Aura

## Overview

This document describes the threat model for PQ-Aura, a Hybrid Post-Quantum Double Ratchet protocol.

## Security Goals

1. **Confidentiality**: Messages cannot be read by unauthorized parties
2. **Integrity**: Messages cannot be modified without detection
3. **Forward Secrecy**: Compromise of long-term keys doesn't affect past sessions
4. **Post-Compromise Security**: Session recovers after key compromise
5. **Post-Quantum Security**: Security against quantum computer attacks

## Actors

### 1. Passive Eavesdropper

**Capabilities**:
- Observe all network traffic
- Record encrypted messages
- Perform offline analysis

**Protections**:
- All messages are encrypted with AES-256-GCM-SIV
- Headers are encrypted separately
- No metadata leakage

### 2. Active Man-in-the-Middle

**Capabilities**:
- Intercept and modify network traffic
- Inject new messages
- Replay old messages

**Protections**:
- Authentication via identity keys
- Message ordering and sequencing
- Replay protection

### 3. Quantum Computer Attacker

**Capabilities**:
- Break classical public key cryptography (RSA, ECC)
- Perform Shor's algorithm for factoring

**Protections**:
- ML-KEM-1024 provides post-quantum security
- Hybrid design ensures security even if one component is broken

### 4. Compromised Device

**Capabilities**:
- Full access to device memory
- Ability to extract keys
- Ability to impersonate user

**Limitations**:
- Cannot protect against fully compromised endpoints
- Must rely on device security measures

### 5. Malicious Server

**Capabilities**:
- Deny service
- Attempt to decrypt messages
- Corrupt message delivery

**Protections**:
- Server cannot decrypt messages (end-to-end encryption)
- Server cannot forge messages (authentication)
- Message ordering prevents corruption

## Attack Scenarios

### 1. Passive Eavesdropping

**Attack**: Attacker records all encrypted traffic and attempts to decrypt.

**Defense**:
- AES-256-GCM-SIV encryption
- Per-message key derivation
- Header encryption

**Result**: Attack fails.

### 2. Active Man-in-the-Middle

**Attack**: Attacker intercepts and modifies messages in transit.

**Defense**:
- Identity key authentication
- Message authentication codes
- Sequence numbers

**Result**: Attack fails.

### 3. Quantum Computer Attack

**Attack**: Attacker uses quantum computer to break key exchange.

**Defense**:
- ML-KEM-1024 provides post-quantum security
- Hybrid design ensures security even if X25519 is broken

**Result**: Attack fails.

### 4. Long-Term Key Compromise

**Attack**: Attacker compromises a user's long-term identity key.

**Defense**:
- Forward secrecy: past sessions remain secure
- Post-compromise security: future sessions recover

**Result**: Past sessions secure, future sessions recover.

### 5. Session State Compromise

**Attack**: Attacker compromises ratchet state.

**Defense**:
- State is encrypted at rest
- State export requires encryption key
- Proper cleanup on compromise

**Result**: Attacker cannot decrypt without encryption key.

### 6. Side-Channel Attack

**Attack**: Attacker uses timing, power, or electromagnetic analysis.

**Defense**:
- Constant-time comparisons using `subtle` crate
- No data-dependent branching on secrets
- Memory-safe Rust implementation

**Result**: Limited attack surface, but not fully protected.

## Assumptions

1. **Random Number Generation**: The system has access to a cryptographically secure random number generator.

2. **Initial Key Exchange**: The initial key exchange happens over an authenticated channel (e.g., in-person meeting, trusted third party).

3. **Server Honesty**: The server correctly relays messages (but can be untrusted for confidentiality).

4. **User Verification**: Users verify each other's identity keys through an out-of-band channel.

5. **Device Security**: Devices are reasonably secure (not fully compromised).

## Out of Scope

1. **Endpoint Compromise**: If a device is fully compromised, all keys are exposed.

2. **Rubber Hose Cryptography**: Physical coercion cannot be protected against.

3. **Malware**: Advanced malware that can bypass security measures.

4. **Social Engineering**: Attacks that trick users into revealing information.

5. **Physical Attacks**: Side-channel attacks requiring physical access.

## Security Properties

### Forward Secrecy

**Definition**: Compromise of long-term keys doesn't affect past sessions.

**Implementation**:
- Per-message key derivation
- Ephemeral keys for each ratchet step
- Key erasure after use

### Post-Compromise Security

**Definition**: Session recovers after key compromise.

**Implementation**:
- Regular ratchet advancement
- New key pairs for each ratchet step
- Key erasure after use

### Post-Quantum Security

**Definition**: Security against quantum computer attacks.

**Implementation**:
- ML-KEM-1024 (NIST FIPS 203)
- Hybrid design with X25519
- Conservative security parameters

## Recommendations

### For Users

1. **Verify Identity Keys**: Always verify identity keys out-of-band.
2. **Keep Software Updated**: Use the latest version of PQ-Aura.
3. **Secure Devices**: Keep devices secure and encrypted.
4. **Report Vulnerabilities**: Report any suspected vulnerabilities responsibly.

### For Developers

1. **Get a Professional Audit**: Before production use, engage a security firm.
2. **Formal Verification**: Consider formal verification of critical components.
3. **Fuzz Testing**: Run extensive fuzz testing.
4. **Side-Channel Testing**: Test for timing and power analysis attacks.

### For Deployments

1. **Key Management**: Implement proper key rotation and backup.
2. **Monitoring**: Monitor for anomalous behavior.
3. **Incident Response**: Have a plan for security incidents.
4. **Regular Reviews**: Conduct regular security reviews.

## References

- [Signal Protocol Security](https://signal.org/docs/)
- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/)
- [PQ X3DH](https://signal.org/docs/specifications/x3dh/)

---

**Last Updated**: 2026-06-10
