use aes_gcm_siv::{
    aead::{Aead, KeyInit, Payload},
    Aes256GcmSiv, Nonce,
};
use blake3::Hasher;
use ml_kem::{
    kem::Decapsulate, kem::DecapsulationKey, kem::Encapsulate, kem::EncapsulationKey,
    EncodedSizeUser, KemCore, MlKem1024, MlKem1024Params,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::hash::Hash;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The length of a symmetric key in bytes (32 bytes for AES-256).
pub const KEY_LEN: usize = 32;

/// A wrapper for sensitive symmetric keys that ensures they are zeroed on drop.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyMaterial(#[serde(with = "serde_bytes_fixed")] pub [u8; KEY_LEN]);

impl Default for SecretKeyMaterial {
    fn default() -> Self {
        Self([0u8; KEY_LEN])
    }
}

impl AsRef<[u8]> for SecretKeyMaterial {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hybrid Public Key containing both X25519 and ML-KEM-1024 components.
#[derive(Clone, Serialize, Deserialize)]
pub struct HybridPublicKey {
    pub classic: XPublicKey,
    #[serde(with = "serde_quantum_pubkey")]
    pub quantum: EncapsulationKey<MlKem1024Params>,
}

impl PartialEq for HybridPublicKey {
    fn eq(&self, other: &Self) -> bool {
        let x_eq = self.classic.as_bytes().ct_eq(other.classic.as_bytes());
        let ml_eq = (&self.quantum.as_bytes()[..]).ct_eq(&other.quantum.as_bytes()[..]);
        (x_eq & ml_eq).into()
    }
}

impl Eq for HybridPublicKey {}

impl ConstantTimeEq for SecretKeyMaterial {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for SecretKeyMaterial {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for SecretKeyMaterial {}

impl Hash for HybridPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.classic.as_bytes().hash(state);
        self.quantum.as_bytes().hash(state);
    }
}

/// Hybrid Secret Key containing both X25519 and ML-KEM-1024 components.
pub struct HybridSecretKey {
    pub classic: XStaticSecret,
    pub quantum: DecapsulationKey<MlKem1024Params>,
}

impl Zeroize for HybridSecretKey {
    fn zeroize(&mut self) {
        self.classic.zeroize();
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Generates a new Hybrid Keypair.
pub fn generate_hybrid_keypair<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> (HybridPublicKey, HybridSecretKey) {
    let x_secret = XStaticSecret::random_from_rng(&mut *rng);
    let x_public = XPublicKey::from(&x_secret);

    let (ml_sk, ml_pk) = MlKem1024::generate(rng);

    (
        HybridPublicKey {
            classic: x_public,
            quantum: ml_pk,
        },
        HybridSecretKey {
            classic: x_secret,
            quantum: ml_sk,
        },
    )
}

impl HybridPublicKey {
    /// Serializes the hybrid public key to bytes for FFI transfer.
    /// Format: [32 bytes X25519 public key] + [1568 bytes ML-KEM-1024 public key]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 1568);
        bytes.extend_from_slice(self.classic.as_bytes());
        bytes.extend_from_slice(&self.quantum.as_bytes());
        bytes
    }

    /// Deserializes a hybrid public key from bytes.
    /// Format: [32 bytes X25519] + [1568 bytes ML-KEM-1024]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 + 1568 {
            return Err("Invalid hybrid public key length");
        }
        let (x_bytes, ml_bytes) = bytes.split_at(32);
        let x_pk = XPublicKey::from(<[u8; 32]>::try_from(x_bytes).unwrap());
        let ml_pk = EncapsulationKey::<MlKem1024Params>::from_bytes(
            ml_bytes
                .try_into()
                .map_err(|_| "Invalid ML-KEM public key")?,
        );
        Ok(HybridPublicKey {
            classic: x_pk,
            quantum: ml_pk,
        })
    }
}

impl HybridSecretKey {
    /// Serializes the hybrid secret key to bytes for FFI transfer.
    /// Format: [32 bytes X25519 secret] + [3168 bytes ML-KEM-1024 secret key]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 3168);
        bytes.extend_from_slice(&self.classic.to_bytes());
        bytes.extend_from_slice(&self.quantum.as_bytes());
        bytes
    }

    /// Deserializes a hybrid secret key from bytes.
    /// Format: [32 bytes X25519] + [3168 bytes ML-KEM-1024]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != 32 + 3168 {
            return Err("Invalid hybrid secret key length");
        }
        let (x_bytes, ml_bytes) = bytes.split_at(32);
        let x_sk = XStaticSecret::from(<[u8; 32]>::try_from(x_bytes).unwrap());
        let ml_sk = DecapsulationKey::<MlKem1024Params>::from_bytes(
            ml_bytes
                .try_into()
                .map_err(|_| "Invalid ML-KEM secret key")?,
        );
        Ok(HybridSecretKey {
            classic: x_sk,
            quantum: ml_sk,
        })
    }
}

/// Combines classical and quantum entropy using BLAKE3 as a KDF.
pub fn combine_secrets(classic: &[u8], quantum: &[u8]) -> SecretKeyMaterial {
    let mut hasher = Hasher::new();
    hasher.update(b"PQ-Aura Hybrid KDF");
    hasher.update(classic);
    hasher.update(quantum);
    let output = hasher.finalize();
    SecretKeyMaterial(output.into())
}

/// Encapsulates a shared secret for a given hybrid public key.
pub fn hybrid_encapsulate<R: RngCore + CryptoRng>(
    pk: &HybridPublicKey,
    rng: &mut R,
) -> (SecretKeyMaterial, Vec<u8>) {
    let ephemeral_x_secret = XStaticSecret::random_from_rng(&mut *rng);
    let ephemeral_x_public = XPublicKey::from(&ephemeral_x_secret);
    let x_shared = ephemeral_x_secret.diffie_hellman(&pk.classic);

    let (ml_ciphertext, ml_shared) = pk.quantum.encapsulate(rng).expect("Encapsulation failed");

    let shared_secret = combine_secrets(x_shared.as_bytes(), ml_shared.as_ref());

    let mut ciphertext = Vec::new();
    ciphertext.extend_from_slice(ephemeral_x_public.as_bytes());
    ciphertext.extend_from_slice(ml_ciphertext.as_ref());

    (shared_secret, ciphertext)
}

/// Decapsulates a shared secret using a hybrid secret key.
pub fn hybrid_decapsulate(
    sk: &HybridSecretKey,
    ciphertext: &[u8],
) -> Result<SecretKeyMaterial, &'static str> {
    if ciphertext.len() < 32 {
        return Err("Invalid ciphertext length");
    }

    let (x_public_bytes, ml_ciphertext_bytes) = ciphertext.split_at(32);
    let ephemeral_x_public = XPublicKey::from(<[u8; 32]>::try_from(x_public_bytes).unwrap());

    let x_shared = sk.classic.diffie_hellman(&ephemeral_x_public);

    let ml_ciphertext = ml_kem::Ciphertext::<MlKem1024>::try_from(ml_ciphertext_bytes)
        .map_err(|_| "Invalid ML-KEM ciphertext")?;
    let ml_shared = sk
        .quantum
        .decapsulate(&ml_ciphertext)
        .map_err(|_| "Decapsulation failed")?;

    Ok(combine_secrets(x_shared.as_bytes(), ml_shared.as_ref()))
}

/// Encrypts a message using AES-256-GCM-SIV.
pub fn encrypt(key: &SecretKeyMaterial, nonce: &[u8; 12], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new((&key.0).into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("Encryption failed")
}

/// Decrypts a message using AES-256-GCM-SIV.
pub fn decrypt(
    key: &SecretKeyMaterial,
    nonce: &[u8; 12],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256GcmSiv::new((&key.0).into());
    let nonce = Nonce::from_slice(nonce);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .map_err(|_| "Decryption failed")
}

/// Constant-time comparison for secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Domain labels for different KDF operations.
pub const KDF_LABEL_ROOT: &str = "PQ-Aura v1: Root Ratchet";
pub const KDF_LABEL_CHAIN: &str = "PQ-Aura v1: Message Chain";
pub const KDF_LABEL_HEADER: &str = "PQ-Aura v1: Header Key";
pub const KDF_LABEL_STATE: &str = "PQ-Aura v1: State Export";

/// KDF for the Root Ratchet. Mixes the current root key with a new shared secret.
pub fn kdf_root_step(
    root_key: &SecretKeyMaterial,
    shared_secret: &SecretKeyMaterial,
) -> (SecretKeyMaterial, SecretKeyMaterial) {
    let mut hasher = Hasher::new_derive_key(KDF_LABEL_ROOT);
    hasher.update(root_key.as_ref());
    hasher.update(shared_secret.as_ref());

    let mut reader = hasher.finalize_xof();
    let mut okm = [0u8; 64];
    reader.fill(&mut okm);

    let (new_root, new_chain) = okm.split_at(32);
    (
        SecretKeyMaterial(<[u8; 32]>::try_from(new_root).unwrap()),
        SecretKeyMaterial(<[u8; 32]>::try_from(new_chain).unwrap()),
    )
}

/// KDF for the Message Chain. Advances the chain key and produces a message key.
pub fn kdf_chain_step(chain_key: &SecretKeyMaterial) -> (SecretKeyMaterial, SecretKeyMaterial) {
    let mut hasher = Hasher::new_derive_key(KDF_LABEL_CHAIN);
    hasher.update(chain_key.as_ref());

    let mut reader = hasher.finalize_xof();
    let mut okm = [0u8; 64];
    reader.fill(&mut okm);

    let (new_chain, msg_key) = okm.split_at(32);
    (
        SecretKeyMaterial(<[u8; 32]>::try_from(new_chain).unwrap()),
        SecretKeyMaterial(<[u8; 32]>::try_from(msg_key).unwrap()),
    )
}

/// KDF for Header Key derivation.
pub fn kdf_header_step(root_key: &SecretKeyMaterial) -> (SecretKeyMaterial, SecretKeyMaterial) {
    let mut hasher = Hasher::new_derive_key(KDF_LABEL_HEADER);
    hasher.update(root_key.as_ref());

    let mut reader = hasher.finalize_xof();
    let mut okm = [0u8; 64];
    reader.fill(&mut okm);

    let (header_key, next_header_key) = okm.split_at(32);
    (
        SecretKeyMaterial(<[u8; 32]>::try_from(header_key).unwrap()),
        SecretKeyMaterial(<[u8; 32]>::try_from(next_header_key).unwrap()),
    )
}

/// Generates a unique nonce for a given index and label.
pub fn generate_nonce(index: u32, label: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = label;
    nonce[1..5].copy_from_slice(&index.to_le_bytes());
    nonce
}

mod serde_bytes_fixed {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        bytes.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        let array = vec
            .try_into()
            .map_err(|_| serde::de::Error::custom("Expected 32 bytes"))?;
        Ok(array)
    }
}

mod serde_quantum_pubkey {
    use super::*;
    use ml_kem::kem::EncapsulationKey;

    pub fn serialize<S>(
        key: &EncapsulationKey<MlKem1024Params>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<EncapsulationKey<MlKem1024Params>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let array = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length"))?;
        Ok(EncapsulationKey::from_bytes(array))
    }
}

pub mod serde_quantum_secretkey {
    use super::*;
    use ml_kem::kem::DecapsulationKey;

    pub fn serialize<S>(
        key: &DecapsulationKey<MlKem1024Params>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        key.as_bytes().serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<DecapsulationKey<MlKem1024Params>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let array = bytes
            .as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("Invalid length"))?;
        Ok(DecapsulationKey::from_bytes(array))
    }
}
