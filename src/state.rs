use crate::crypto::{HybridPublicKey, HybridSecretKey, SecretKeyMaterial};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// State of a single symmetric chain (either sending or receiving).
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ChainState {
    pub key: SecretKeyMaterial,
    pub index: u32,
}

/// State for Header Encryption chains.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HeaderChain {
    pub key: SecretKeyMaterial,
    pub index: u32,
}

/// The main state for a Double Ratchet session.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct RatchetState {
    /// Root key used to derive chain keys.
    pub root_key: SecretKeyMaterial,

    /// The current hybrid keypair for the DH ratchet.
    #[serde(skip)]
    pub dh_sk: Option<HybridSecretKey>,
    pub dh_pk: HybridPublicKey,

    /// The remote party's current hybrid public key.
    pub remote_dh_pk: HybridPublicKey,

    /// Sending chain state.
    pub send_chain: Option<ChainState>,

    /// Receiving chain state.
    pub recv_chain: Option<ChainState>,

    /// Header encryption chains.
    pub send_header_chain: Option<HeaderChain>,
    pub recv_header_chain: Option<HeaderChain>,
    pub next_recv_header_chain: Option<HeaderChain>,

    /// Previous sending chain length.
    pub prev_send_len: u32,

    /// Skipped message keys for handling out-of-order messages.
    #[zeroize(skip)]
    pub skipped_msg_keys: HashMap<(HybridPublicKey, u32), SecretKeyMaterial>,

    /// Pending KEM ciphertext to be sent in the next header
    pub pending_kem_ciphertext: Vec<u8>,
}

impl RatchetState {
    /// Creates a new RatchetState for the initiator (Alice).
    pub fn new_alice(
        root_key: SecretKeyMaterial,
        remote_pk: HybridPublicKey,
        local_pk: HybridPublicKey,
        local_sk: HybridSecretKey,
    ) -> Self {
        Self {
            root_key,
            dh_sk: Some(local_sk),
            dh_pk: local_pk,
            remote_dh_pk: remote_pk,
            send_chain: None,
            recv_chain: None,
            send_header_chain: None,
            recv_header_chain: None,
            next_recv_header_chain: None,
            prev_send_len: 0,
            skipped_msg_keys: HashMap::new(),
            pending_kem_ciphertext: Vec::new(),
        }
    }

    /// Creates a new RatchetState for the responder (Bob).
    pub fn new_bob(
        root_key: SecretKeyMaterial,
        local_pk: HybridPublicKey,
        local_sk: HybridSecretKey,
    ) -> Self {
        Self {
            root_key,
            dh_sk: Some(local_sk),
            dh_pk: local_pk,
            // Remote PK will be set on the first message
            remote_dh_pk: unsafe { std::mem::zeroed() },
            send_chain: None,
            recv_chain: None,
            send_header_chain: None,
            recv_header_chain: None,
            next_recv_header_chain: None,
            prev_send_len: 0,
            skipped_msg_keys: HashMap::new(),
            pending_kem_ciphertext: Vec::new(),
        }
    }
}

// Custom implementation for HybridPublicKey because Encoded<MlKem1024> might not be easily zeroable
// but we wrap secrets in Zeroize. Public keys are usually okay but let's be safe.
impl Zeroize for HybridPublicKey {
    fn zeroize(&mut self) {
        // Public keys don't strictly need zeroizing but we can zero the bytes if accessible
    }
}
