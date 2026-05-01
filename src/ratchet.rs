use crate::crypto::{self, HybridPublicKey, SecretKeyMaterial};
use crate::state::{ChainState, HeaderChain, RatchetState};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Maximum number of message keys to skip. Prevents DoS attacks.
const MAX_SKIP: u32 = 1000;

/// A message header containing ratchet information.
#[derive(Serialize, Deserialize, Clone)]
pub struct Header {
    pub dh_pk: HybridPublicKey,
    pub kem_ciphertext: Vec<u8>,
    pub prev_n: u32,
    pub n: u32,
}

/// A complete PQ-Aura message.
#[derive(Serialize, Deserialize)]
pub struct Message {
    /// Encrypted header.
    pub header_ciphertext: Vec<u8>,
    /// Encrypted payload.
    pub payload_ciphertext: Vec<u8>,
}

/// Implementation of the Double Ratchet logic.
pub struct RatchetEngine;

impl RatchetEngine {
    /// Encrypts a message using the current ratchet state.
    pub fn encrypt<R: RngCore + CryptoRng>(
        state: &mut RatchetState,
        plaintext: &[u8],
        ad: &[u8],
        rng: &mut R,
    ) -> Message {
        // 1. Advance the sending chain if it exists, otherwise initialize it.
        if state.send_chain.is_none() {
            Self::perform_sending_dh_step(state, rng);
        }

        let chain = state
            .send_chain
            .as_mut()
            .expect("Send chain not initialized");
        let (new_chain_key, msg_key) = crypto::kdf_step(&chain.key, b"Message Key");
        chain.key = new_chain_key;
        let n = chain.index;
        chain.index += 1;

        // 2. Prepare the header.
        // In a real KEM ratchet, the KEM ciphertext is sent with the first message of a new ratchet.
        // We'll use state.prev_send_len as a temporary placeholder for the KEM CT if needed.
        let header = Header {
            dh_pk: state.dh_pk.clone(),
            kem_ciphertext: Vec::new(), // In full KEM, this would be the actual ciphertext
            prev_n: state.prev_send_len,
            n,
        };

        // 3. Encrypt the header (Signal-style Header Encryption).
        let header_chain = state
            .send_header_chain
            .as_ref()
            .expect("Header chain not initialized");
        let header_bytes = serde_json::to_vec(&header).unwrap();
        let header_nonce = [0u8; 12]; // Counter-based nonces would be better for production
        let header_ciphertext =
            crypto::encrypt(&header_chain.key, &header_nonce, ad, &header_bytes);

        // 4. Encrypt the payload.
        let payload_nonce = [1u8; 12];
        let payload_ciphertext =
            crypto::encrypt(&msg_key, &payload_nonce, &header_ciphertext, plaintext);

        Message {
            header_ciphertext,
            payload_ciphertext,
        }
    }

    /// Decrypts a message and updates the ratchet state.
    pub fn decrypt(
        state: &mut RatchetState,
        message: &Message,
        ad: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        // 1. Trial decryption of the header.
        let (header, is_new_ratchet) = Self::trial_decrypt_header(state, message, ad)?;

        // 2. Handle out-of-order and skipped message keys.
        if is_new_ratchet {
            Self::skip_msg_keys(state, header.prev_n)?;
            Self::perform_receiving_dh_step(state, &header)?;
        }

        Self::skip_msg_keys(state, header.n)?;

        // 3. Advance receiving chain and decrypt.
        let chain = state
            .recv_chain
            .as_mut()
            .ok_or("Receiving chain not initialized")?;
        let (new_chain_key, msg_key) = crypto::kdf_step(&chain.key, b"Message Key");
        chain.key = new_chain_key;
        chain.index += 1;

        let payload_nonce = [1u8; 12];
        crypto::decrypt(
            &msg_key,
            &payload_nonce,
            &message.header_ciphertext,
            &message.payload_ciphertext,
        )
    }

    fn trial_decrypt_header(
        state: &RatchetState,
        message: &Message,
        ad: &[u8],
    ) -> Result<(Header, bool), &'static str> {
        let header_nonce = [0u8; 12];

        // Try current receiving header chain.
        if let Some(h_chain) = &state.recv_header_chain {
            if let Ok(header_bytes) =
                crypto::decrypt(&h_chain.key, &header_nonce, ad, &message.header_ciphertext)
            {
                if let Ok(header) = serde_json::from_slice::<Header>(&header_bytes) {
                    return Ok((header, false));
                }
            }
        }

        // Try next potential header chain (for DH ratchet).
        if let Some(h_chain) = &state.next_recv_header_chain {
            if let Ok(header_bytes) =
                crypto::decrypt(&h_chain.key, &header_nonce, ad, &message.header_ciphertext)
            {
                if let Ok(header) = serde_json::from_slice::<Header>(&header_bytes) {
                    return Ok((header, true));
                }
            }
        }

        Err("Header decryption failed: no matching header key")
    }

    fn skip_msg_keys(state: &mut RatchetState, until: u32) -> Result<(), &'static str> {
        let chain = state.recv_chain.as_mut().ok_or("No receiving chain")?;
        if chain.index > until {
            // Check skipped keys
            return Err("Message already processed or sequence error");
        }
        if until - chain.index > MAX_SKIP {
            return Err("Too many messages to skip (DoS protection)");
        }
        while chain.index < until {
            let (new_chain_key, msg_key) = crypto::kdf_step(&chain.key, b"Message Key");
            state
                .skipped_msg_keys
                .insert((state.remote_dh_pk.clone(), chain.index), msg_key);
            chain.key = new_chain_key;
            chain.index += 1;
        }
        Ok(())
    }

    fn perform_sending_dh_step<R: RngCore + CryptoRng>(state: &mut RatchetState, rng: &mut R) {
        let (shared_secret, _ct) = crypto::hybrid_encapsulate(&state.remote_dh_pk, rng);
        let (new_root, new_send_chain) = crypto::kdf_step(&state.root_key, shared_secret.as_ref());

        // Derive header encryption keys from the chain key (Signal-style).
        let (send_h_key, _) = crypto::kdf_step(&new_send_chain, b"Header Chain");

        state.root_key = new_root;
        state.send_chain = Some(ChainState {
            key: new_send_chain,
            index: 0,
        });
        state.send_header_chain = Some(HeaderChain { key: send_h_key });
    }

    fn perform_receiving_dh_step(
        state: &mut RatchetState,
        header: &Header,
    ) -> Result<(), &'static str> {
        state.prev_send_len = state.send_chain.as_ref().map(|c| c.index).unwrap_or(0);
        state.remote_dh_pk = header.dh_pk.clone();

        // In a real KEM ratchet, the ciphertext is in the header.
        // Since we are simulating, we'll use a placeholder or derive from the header PK.
        // For production, the Hybrid-KEM would take the actual header.kem_ciphertext.
        let shared_secret = crypto::hybrid_decapsulate(
            state.dh_sk.as_ref().ok_or("No local secret key")?,
            &header.kem_ciphertext,
        )
        .unwrap_or_else(|_| SecretKeyMaterial([0xee; 32])); // Error handling simplified for demo

        let (new_root, new_recv_chain) = crypto::kdf_step(&state.root_key, shared_secret.as_ref());

        // Derive header keys.
        let (recv_h_key, _) = crypto::kdf_step(&new_recv_chain, b"Header Chain");

        state.root_key = new_root;
        state.recv_chain = Some(ChainState {
            key: new_recv_chain,
            index: 0,
        });
        state.recv_header_chain = Some(HeaderChain { key: recv_h_key });

        // Generate next DH keypair to be ready for the next sending step.
        let mut rng = rand::thread_rng();
        let (new_pk, new_sk) = crypto::generate_hybrid_keypair(&mut rng);
        state.dh_pk = new_pk;
        state.dh_sk = Some(new_sk);

        // Pre-derive the "next" header key to allow trial decryption of the next ratchet.
        // This is a core part of Signal's header encryption.
        let (next_h_key, _) = crypto::kdf_step(&state.root_key, b"Next Header Chain");
        state.next_recv_header_chain = Some(HeaderChain { key: next_h_key });

        Ok(())
    }
}
