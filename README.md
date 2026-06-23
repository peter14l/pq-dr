---
title: PQ-Aura Cloud Key Server
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: docker
pinned: false
---

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
*   **Flutter FFI Plugin (`/pq_aura_flutter`):** Drop-in Dart library that connects your Flutter mobile and desktop apps to the native Rust engine.
*   **WebAssembly (WASM):** Specialized module for **Flutter Web** and JS environments with browser-safe entropy support.
*   **Native C/C++ Header (`/include`):** Direct library integration for low-level systems and custom game engines.

## 📂 Project Structure

*   **`src/`**: Core Rust implementation of the Hybrid Post-Quantum Double Ratchet (ML-KEM + X25519).
*   **`pq_aura_flutter/`**: The developer-friendly Flutter FFI plugin wrapper.
*   **`server/`**: A high-performance Axum-based cloud key exchange and mailbox server.
*   **`include/`**: C/C++ API header declarations.

## 🚀 Running the Cloud Key Server

The server manages user registration, pre-key bundle uploads, and queues offline messages.

```bash
cd server
cargo run --release
```

It runs on `http://0.0.0.0:8080` with the following API endpoints:

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/prekey/upload` | Upload a user's `PreKeyBundle` |
| `GET` | `/prekey/fetch/:username` | Retrieve a user's `PreKeyBundle` |
| `POST` | `/message/send` | Enqueue an encrypted message for an offline user |
| `GET` | `/message/fetch/:username` | Retrieve and flush pending messages |
| `GET` | `/config` | Returns Razorpay public key to the frontend |
| `POST` | `/webhook/razorpay` | Razorpay payment webhook (HMAC-SHA256 verified) |

## 📱 Flutter Integration Example

Add the local plugin package to your Flutter `pubspec.yaml`:

```yaml
dependencies:
  pq_aura_flutter:
    path: ./path/to/pq_aura_flutter
```

Then drop the client into your Dart code:

```dart
import 'package:pq_aura_flutter/pq_aura_flutter.dart';

// 1. Generate keys
PqKeyPair identityKeyPair = PqAuraClient.generateKeyPair();

// 2. Create PreKeyBundle to upload to the server
PqPreKeyBundle bundle = PqAuraClient.createBundle(identityKeyPair.publicKey);

// 3. Initiate session as Alice
var handshake = PqAuraClient.initAlice(
  remoteBundle: bobBundle,
  localIdentityKeyPair: identityKeyPair,
);

PqSession session = handshake.session;
PqInitialMessage initialMsg = handshake.initialMessage;

// 4. Encrypt message
PqMessage encrypted = session.encrypt(Uint8List.fromList("Hello!".codeUnits), associatedData);
```

## 🛠️ Rust Usage Example

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

## 💳 Payment & Licensing

PQ-Aura uses a **dual-licensing model**. The library is free under GPL-3.0 for open-source projects. Proprietary / closed-source applications require a **Commercial SDK License**.

| Tier | Price | Details |
|------|-------|---------|
| **Open Source** | Free | GPL-3.0 — source must stay open |
| **Commercial SDK** | ₹16,500 / month | Removes copyleft for proprietary apps |
| **Enterprise** | Custom | Multi-seat, self-hosted, SLA — email peter_parker_2008@outlook.com |

The payment system (Razorpay + Resend email) is fully implemented in the server. For complete setup instructions — including Razorpay webhook registration, Resend domain verification, environment variables, Hugging Face Spaces secrets, and end-to-end testing — see **[PAYMENTS.md](PAYMENTS.md)**.

## ☕ Support my Work

I built this library to make hybrid post-quantum end-to-end encryption accessible to every developer. I am starting college soon, and I am maintaining this open-source work in my free time. 

If you find this project useful, or if you'd like to support my education and ongoing development of PQ-Aura, please consider supporting me!

[![support](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/peter20)

## ⚖️ License

Distributed under the **GNU General Public License v3.0**. 

**Important:** Any application built using this protocol or library must be kept open-source under the same or compatible terms. See [LICENSE](LICENSE) for the full text.

---
**Lead Developer:** Shreyas Sengupta  
**Project Date:** 2026-06-22
