use crate::crypto::{self, HybridPublicKey, HybridSecretKey, SecretKeyMaterial};
use crate::state::RatchetState;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A Post-Quantum Pre-Key Bundle.
/// This is what a user publishes to the server so others can start a chat with them.
#[derive(Serialize, Deserialize, Clone)]
pub struct PreKeyBundle {
    pub identity_pk: HybridPublicKey,
    pub signed_pre_key: HybridPublicKey,
    // For simplicity in this implementation, we use a single one-time pre-key.
    // In production, Bob would upload a batch of these.
    pub one_time_pre_key: Option<HybridPublicKey>,
}

impl PreKeyBundle {
    /// Serializes the bundle to bytes using JSON (for FFI transfer).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize PreKeyBundle")
    }

    /// Deserializes a bundle from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        serde_json::from_slice(bytes).map_err(|_| "Failed to deserialize PreKeyBundle")
    }
}

/// The first message sent to initiate a session.
/// Contains the ephemeral keys Alice generated to perform the handshake.
#[derive(Serialize, Deserialize, Clone)]
pub struct InitialMessage {
    pub alice_identity_pk: HybridPublicKey,
    pub ephemeral_pk: HybridPublicKey,
    pub kem_ciphertext_identity: Vec<u8>,
    pub kem_ciphertext_signed: Vec<u8>,
    pub kem_ciphertext_one_time: Option<Vec<u8>>,
    // The actual Double Ratchet message (e.g., "Hello Bob!")
    pub ratchet_message: crate::ratchet::Message,
}

impl InitialMessage {
    /// Serializes the message to bytes using JSON (for FFI transfer).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Failed to serialize InitialMessage")
    }

    /// Deserializes a message from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        serde_json::from_slice(bytes).map_err(|_| "Failed to deserialize InitialMessage")
    }
}

pub struct HandshakeEngine;

impl HandshakeEngine {
    /// Alice initiates a session using Bob's PreKeyBundle.
    pub fn initiate_alice<R: RngCore + CryptoRng>(
        bundle: &PreKeyBundle,
        alice_identity_pk: &HybridPublicKey,
        alice_identity_sk: &HybridSecretKey,
        rng: &mut R,
    ) -> (RatchetState, InitialMessage, SecretKeyMaterial) {
        // 1. Generate ephemeral keypair
        let (ephemeral_pk, ephemeral_sk) = crypto::generate_hybrid_keypair(rng);

        // 2. Perform Hybrid DH exchanges (X25519 + ML-KEM)
        // DH1 = Alice Identity <-> Bob Signed Pre-Key
        let x_dh1 = alice_identity_sk
            .classic
            .diffie_hellman(&bundle.signed_pre_key.classic);
        let (ss_kem1, ct_kem1) = crypto::hybrid_encapsulate(&bundle.identity_pk, rng);

        // DH2 = Alice Ephemeral <-> Bob Identity
        let x_dh2 = ephemeral_sk
            .classic
            .diffie_hellman(&bundle.identity_pk.classic);
        let (ss_kem2, ct_kem2) = crypto::hybrid_encapsulate(&bundle.signed_pre_key, rng);

        // DH3 = Alice Ephemeral <-> Bob Signed Pre-Key
        let x_dh3 = ephemeral_sk
            .classic
            .diffie_hellman(&bundle.signed_pre_key.classic);

        // DH4 (Optional) = Alice Ephemeral <-> Bob One-Time Pre-Key
        let mut x_dh4_bytes = [0u8; 32];
        let mut ss_kem3_opt = None;
        let mut ct_kem3_opt = None;

        if let Some(otpk) = &bundle.one_time_pre_key {
            let x_dh4 = ephemeral_sk.classic.diffie_hellman(&otpk.classic);
            x_dh4_bytes = *x_dh4.as_bytes();
            let (ss, ct) = crypto::hybrid_encapsulate(otpk, rng);
            ss_kem3_opt = Some(ss);
            ct_kem3_opt = Some(ct);
        }

        // 3. Combine all entropy using BLAKE3
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PQ-X3DH Handshake Context");
        hasher.update(x_dh1.as_bytes());
        hasher.update(x_dh2.as_bytes());
        hasher.update(x_dh3.as_bytes());
        hasher.update(&x_dh4_bytes);
        hasher.update(ss_kem1.as_ref());
        hasher.update(ss_kem2.as_ref());
        if let Some(ss) = ss_kem3_opt {
            hasher.update(ss.as_ref());
        }

        let root_key = SecretKeyMaterial(hasher.finalize().into());

        // 4. Initialize Ratchet State
        // Alice generates a NEW ephemeral for the Double Ratchet DH.
        let (dr_pk, dr_sk) = crypto::generate_hybrid_keypair(rng);

        let state = RatchetState::new_alice(
            root_key.clone(),
            bundle.identity_pk.clone(), // Initial remote PK (Bob's identity)
            dr_pk,
            dr_sk,
        );

        let initial_msg = InitialMessage {
            alice_identity_pk: alice_identity_pk.clone(),
            ephemeral_pk,
            kem_ciphertext_identity: ct_kem1,
            kem_ciphertext_signed: ct_kem2,
            kem_ciphertext_one_time: ct_kem3_opt,
            ratchet_message: crate::ratchet::Message {
                header_ciphertext: Vec::new(),
                payload_ciphertext: Vec::new(),
            },
        };

        (state, initial_msg, root_key)
    }

    /// Bob responds to Alice's InitialMessage using his local secret keys.
    pub fn respond_bob(
        message: &InitialMessage,
        _bob_identity_pk: &HybridPublicKey,
        bob_identity_sk: &HybridSecretKey,
        bob_signed_sk: &HybridSecretKey,
        bob_otpk_sk: Option<&HybridSecretKey>,
    ) -> Result<(RatchetState, SecretKeyMaterial), &'static str> {
        // 1. Perform Hybrid DH exchanges (X25519 + ML-KEM)

        // DH1 = Alice Identity <-> Bob Signed Pre-Key
        let x_dh1 = bob_signed_sk
            .classic
            .diffie_hellman(&message.alice_identity_pk.classic);

        // DH2 = Alice Ephemeral <-> Bob Identity
        let x_dh2 = bob_identity_sk
            .classic
            .diffie_hellman(&message.ephemeral_pk.classic);

        // DH3 = Alice Ephemeral <-> Bob Signed Pre-Key
        let x_dh3 = bob_signed_sk
            .classic
            .diffie_hellman(&message.ephemeral_pk.classic);

        let ss_kem1 =
            crypto::hybrid_decapsulate(bob_identity_sk, &message.kem_ciphertext_identity)?;
        let ss_kem2 = crypto::hybrid_decapsulate(bob_signed_sk, &message.kem_ciphertext_signed)?;

        let mut x_dh4_bytes = [0u8; 32];
        let mut ss_kem3_opt = None;

        if let Some(ct3) = &message.kem_ciphertext_one_time {
            let otpk_sk = bob_otpk_sk.ok_or("One-time pre-key secret missing")?;
            let x_dh4 = otpk_sk
                .classic
                .diffie_hellman(&message.ephemeral_pk.classic);
            x_dh4_bytes = *x_dh4.as_bytes();
            let ss = crypto::hybrid_decapsulate(otpk_sk, ct3)?;
            ss_kem3_opt = Some(ss);
        }

        // 2. Combine all entropy
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PQ-X3DH Handshake Context");
        hasher.update(x_dh1.as_bytes());
        hasher.update(x_dh2.as_bytes());
        hasher.update(x_dh3.as_bytes());
        hasher.update(&x_dh4_bytes);
        hasher.update(ss_kem1.as_ref());
        hasher.update(ss_kem2.as_ref());
        if let Some(ss) = ss_kem3_opt {
            hasher.update(ss.as_ref());
        }

        let root_key = SecretKeyMaterial(hasher.finalize().into());

        // 3. Initialize Bob's Ratchet State
        // Bob uses Alice's Identity PK as the remote PK initially.
        // He generates a NEW DH keypair for the ratchet.
        let mut rng = rand::thread_rng();
        let (dr_pk, dr_sk) = crypto::generate_hybrid_keypair(&mut rng);

        let mut state = RatchetState::new_bob(root_key.clone(), dr_pk, dr_sk);
        state.remote_dh_pk = Some(message.alice_identity_pk.clone());

        Ok((state, root_key))
    }
}

// Helper trait to allow cloning or conversion of ML-KEM keys for state initialization.
impl From<ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>> for HybridPublicKey {
    fn from(_sk: ml_kem::kem::DecapsulationKey<ml_kem::MlKem1024Params>) -> Self {
        // In a real implementation, we'd store the PK alongside the SK or derive it.
        // For now, we'll assume the caller provides the correct PK.
        unimplemented!("Conversion from SK to PK is not directly supported by the crate without the original bytes.")
    }
}
