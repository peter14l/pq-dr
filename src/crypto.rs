use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use blake3::Hasher;
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    Encoded, MlKem1024,
};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
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
    pub quantum: Encoded<MlKem1024>,
}

/// Hybrid Secret Key containing both X25519 and ML-KEM-1024 components.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSecretKey {
    pub classic: XStaticSecret,
    pub quantum: ml_kem::SecretKey<MlKem1024>,
}

/// Generates a new Hybrid Keypair.
pub fn generate_hybrid_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (HybridPublicKey, HybridSecretKey) {
    let x_secret = XStaticSecret::random_from_rng(rng);
    let x_public = XPublicKey::from(&x_secret);

    let (ml_pk, ml_sk) = MlKem1024::generate(rng);

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

/// Combines classical and quantum entropy using BLAKE3 as a KDF.
///
/// This implements the "Defense in Depth" philosophy: if one algorithm is broken,
/// the resulting secret remains secure as long as the other holds.
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
    // X25519 ephemeral exchange
    let ephemeral_x_secret = XStaticSecret::random_from_rng(rng);
    let ephemeral_x_public = XPublicKey::from(&ephemeral_x_secret);
    let x_shared = ephemeral_x_secret.diffie_hellman(&pk.classic);

    // ML-KEM-1024 encapsulation
    let (ml_shared, ml_ciphertext) = pk.quantum.encapsulate(rng).expect("Encapsulation failed");

    // Combine secrets
    let shared_secret = combine_secrets(x_shared.as_bytes(), ml_shared.as_ref());

    // Ciphertext contains both the X25519 ephemeral public key and the ML-KEM ciphertext
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

    // Split ciphertext into X25519 public key and ML-KEM ciphertext
    let (x_public_bytes, ml_ciphertext_bytes) = ciphertext.split_at(32);
    let ephemeral_x_public = XPublicKey::from(<[u8; 32]>::try_from(x_public_bytes).unwrap());
    
    // X25519 exchange
    let x_shared = sk.classic.diffie_hellman(&ephemeral_x_public);

    // ML-KEM-1024 decapsulation
    let ml_ciphertext = ml_kem::Ciphertext::<MlKem1024>::try_from(ml_ciphertext_bytes)
        .map_err(|_| "Invalid ML-KEM ciphertext")?;
    let ml_shared = sk.quantum.decapsulate(&ml_ciphertext).map_err(|_| "Decapsulation failed")?;

    // Combine secrets
    Ok(combine_secrets(x_shared.as_bytes(), ml_shared.as_ref()))
}

/// Encrypts a message using AES-256-GCM-SIV.
pub fn encrypt(key: &SecretKeyMaterial, nonce: &[u8; 12], ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256GcmSiv::new(key.0.as_ref().into());
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, aes_gcm_siv::aead::Payload { msg: plaintext, aad: ad })
        .expect("Encryption failed")
}

/// Decrypts a message using AES-256-GCM-SIV.
pub fn decrypt(key: &SecretKeyMaterial, nonce: &[u8; 12], ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = Aes256GcmSiv::new(key.0.as_ref().into());
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, aes_gcm_siv::aead::Payload { msg: ciphertext, aad: ad })
        .map_err(|_| "Decryption failed")
}

/// Constant-time comparison for secrets.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// KDF for generating new keys from a root key.
pub fn kdf_step(root_key: &SecretKeyMaterial, info: &[u8]) -> (SecretKeyMaterial, SecretKeyMaterial) {
    let hk = Hkdf::<blake3::Hasher>::new(None, root_key.as_ref());
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm).expect("HKDF expansion failed");
    
    let (new_root, new_chain) = okm.split_at(32);
    (
        SecretKeyMaterial(<[u8; 32]>::try_from(new_root).unwrap()),
        SecretKeyMaterial(<[u8; 32]>::try_from(new_chain).unwrap())
    )
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
        let array = vec.try_into().map_err(|_| serde::de::Error::custom("Expected 32 bytes"))?;
        Ok(array)
    }
}
