# PQ-Aura Integration Guide: Hybrid-X3DH Handshake

To use **PQ-Aura** in a real-world chat application, you must first establish an initial shared secret and exchange public keys. This is typically done using an **Extended Triple Diffie-Hellman (X3DH)** handshake, which we upgrade here to a **Hybrid-X3DH** to maintain post-quantum resistance from message zero.

## 1. The Hybrid Pre-key Bundle
Each user (e.g., Bob) should publish a "Pre-key Bundle" to a central server. This bundle contains:
- **Identity Key ($IK_B$):** Long-term Hybrid Public Key.
- **Signed Pre-key ($SPK_B$):** Medium-term Hybrid Public Key, signed by $IK_B$.
- **One-Time Pre-keys ($OPK_B$):** A set of ephemeral Hybrid Public Keys (recommended for maximum security).

## 2. The Hybrid-X3DH Handshake (Alice to Bob)
When Alice wants to message Bob, she:
1.  Fetches Bob's Pre-key Bundle.
2.  Generates her own ephemeral Hybrid Keypair ($EK_A$).
3.  Performs four DH/KEM exchanges:
    - $DH_1 = HybridKEM(EK_A, SPK_B)$
    - $DH_2 = HybridKEM(IK_A, SPK_B)$
    - $DH_3 = HybridKEM(EK_A, IK_B)$
    - $DH_4 = HybridKEM(EK_A, OPK_B)$ (if $OPK$ exists)
4.  Calculates the **Initial Root Key**:
    $SK = BLAKE3(DH_1 || DH_2 || DH_3 || DH_4)$

## 3. Initializing PQ-Aura
Once the $SK$ is derived, Alice can initialize her `RatchetState`:

```rust
use pq_aura::*;

// 1. Derive the initial root key via Hybrid-X3DH logic
let initial_root_key = SecretKeyMaterial(derived_sk_bytes);

// 2. Alice initializes as the initiator
let mut alice_state = RatchetState::new_alice(
    initial_root_key,
    bob_spk.clone(),   // Initial remote DH key
    alice_ek_pk.clone(), // Local ephemeral PK
    alice_ek_sk,       // Local ephemeral SK
);

// 3. Send the first message
let ad = b"Alice-to-Bob-Handshake";
let message = RatchetEngine::encrypt(&mut alice_state, b"Hi Bob!", ad, &mut rng);
```

## 4. Handling the First Message (Bob)
Bob receives the message along with Alice's $IK_A$ and $EK_A$. He:
1.  Repeats the Hybrid-X3DH calculations to derive the same $SK$.
2.  Initializes his `RatchetState`:

```rust
let mut bob_state = RatchetState::new_bob(
    initial_root_key,
    bob_spk_pk.clone(),
    bob_spk_sk,
);

// Bob decrypts the first message
let plaintext = RatchetEngine::decrypt(&mut bob_state, &message, ad).unwrap();
```

## 5. Implementation Recommendations
- **Identity Binding:** Ensure that the Hybrid Identity Keys are bound to the user's account.
- **Key Rotation:** Rotate Signed Pre-keys every 1–4 weeks.
- **Persistence:** Use the `serde` implementation in `RatchetState` to save sessions to your local database (e.g., SQLite or sled) on the external HDD.
- **Memory Safety:** Always ensure that `RatchetState` is dropped properly to trigger `Zeroize`.
