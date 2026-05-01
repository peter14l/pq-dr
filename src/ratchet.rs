use crate::crypto::{self, HybridPublicKey};
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

        // 2. Prepare the header, including the post-quantum ciphertext.
        let header = Header {
            dh_pk: state.dh_pk.clone(),
            kem_ciphertext: state.pending_kem_ciphertext.clone(),
            prev_n: state.prev_send_len,
            n,
        };

        // 3. Encrypt the header (Signal-style Header Encryption).
        let header_chain = state
            .send_header_chain
            .as_mut()
            .expect("Header chain not initialized");
        let header_bytes = serde_json::to_vec(&header).unwrap();

        let mut header_nonce = [0u8; 12];
        header_nonce[0..4].copy_from_slice(&header_chain.index.to_le_bytes());
        header_chain.index += 1;

        let header_ciphertext =
            crypto::encrypt(&header_chain.key, &header_nonce, ad, &header_bytes);

        // 4. Encrypt the payload.
        let payload_nonce = [1u8; 12]; // Safe because msg_key is unique per message.
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
        let (header, is_new_ratchet, try_idx, mut worked_h_chain) =
            Self::trial_decrypt_header(state, message, ad)?;

        // 2. Check if this is a skipped/delayed message.
        if let Some(msg_key) = state
            .skipped_msg_keys
            .remove(&(header.dh_pk.clone(), header.n))
        {
            // Update the index of the header chain that worked
            if is_new_ratchet {
                // This is unusual for a skipped key, but let's be robust.
            } else if let Some(h_chain) = state.recv_header_chain.as_mut() {
                h_chain.index = std::cmp::max(h_chain.index, try_idx + 1);
            }

            let payload_nonce = [1u8; 12];
            return crypto::decrypt(
                &msg_key,
                &payload_nonce,
                &message.header_ciphertext,
                &message.payload_ciphertext,
            );
        }

        // 3. Handle out-of-order and skipped message keys for new messages.
        if is_new_ratchet {
            Self::skip_msg_keys(state, header.prev_n)?;
            worked_h_chain.index = try_idx + 1;
            Self::perform_receiving_dh_step(state, &header, worked_h_chain)?;
        } else {
            if let Some(h_chain) = state.recv_header_chain.as_mut() {
                h_chain.index = std::cmp::max(h_chain.index, try_idx + 1);
            }
        }

        Self::skip_msg_keys(state, header.n)?;

        // 4. Advance receiving chain and decrypt.
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
    ) -> Result<(Header, bool, u32, HeaderChain), &'static str> {
        // Try current receiving header chain.
        if let Some(h_chain) = &state.recv_header_chain {
            let start = h_chain.index.saturating_sub(10);
            let end = h_chain.index + 10;
            for try_idx in start..end {
                let mut header_nonce = [0u8; 12];
                header_nonce[0..4].copy_from_slice(&try_idx.to_le_bytes());
                if let Ok(header_bytes) =
                    crypto::decrypt(&h_chain.key, &header_nonce, ad, &message.header_ciphertext)
                {
                    if let Ok(header) = serde_json::from_slice::<Header>(&header_bytes) {
                        return Ok((header, false, try_idx, h_chain.clone()));
                    }
                }
            }
        }

        // Try next potential header chain (for DH ratchet).
        if let Some(h_chain) = &state.next_recv_header_chain {
            let start = h_chain.index.saturating_sub(10);
            let end = h_chain.index + 10;
            for try_idx in start..end {
                let mut header_nonce = [0u8; 12];
                header_nonce[0..4].copy_from_slice(&try_idx.to_le_bytes());
                if let Ok(header_bytes) =
                    crypto::decrypt(&h_chain.key, &header_nonce, ad, &message.header_ciphertext)
                {
                    if let Ok(header) = serde_json::from_slice::<Header>(&header_bytes) {
                        return Ok((header, true, try_idx, h_chain.clone()));
                    }
                }
            }
        }

        Err("Header decryption failed: no matching header key")
    }

    fn skip_msg_keys(state: &mut RatchetState, until: u32) -> Result<(), &'static str> {
        if state.recv_chain.is_none() {
            if until == 0 {
                return Ok(());
            } else {
                return Err("No receiving chain");
            }
        }
        let remote_pk = state.remote_dh_pk.as_ref().ok_or("No remote public key")?;
        let chain = state.recv_chain.as_mut().unwrap();
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
                .insert((remote_pk.clone(), chain.index), msg_key);
            chain.key = new_chain_key;
            chain.index += 1;
        }
        Ok(())
    }

    fn perform_sending_dh_step<R: RngCore + CryptoRng>(state: &mut RatchetState, rng: &mut R) {
        let remote_pk = state.remote_dh_pk.as_ref().expect("No remote public key");
        let (shared_secret, ct) = crypto::hybrid_encapsulate(remote_pk, rng);
        state.pending_kem_ciphertext = ct;
        let (new_root, new_send_chain) = crypto::kdf_step(&state.root_key, shared_secret.as_ref());

        // Derive header keys: one for the current chain, and one for the next potential chain.
        let (send_h_key, next_h_key) = crypto::kdf_step(&new_root, b"Header Keys");

        // Use current next_recv_header_chain for this outgoing step.
        if let Some(initial_h_chain) = state.next_recv_header_chain.take() {
            state.send_header_chain = Some(initial_h_chain);
        } else {
            state.send_header_chain = Some(HeaderChain {
                key: send_h_key,
                index: 0,
            });
        }

        state.root_key = new_root;
        state.send_chain = Some(ChainState {
            key: new_send_chain,
            index: 0,
        });
        state.next_recv_header_chain = Some(HeaderChain {
            key: next_h_key,
            index: 0,
        });
    }

    fn perform_receiving_dh_step(
        state: &mut RatchetState,
        header: &Header,
        worked_h_chain: HeaderChain,
    ) -> Result<(), &'static str> {
        state.prev_send_len = state.send_chain.as_ref().map(|c| c.index).unwrap_or(0);
        state.remote_dh_pk = Some(header.dh_pk.clone());

        let shared_secret = crypto::hybrid_decapsulate(
            state.dh_sk.as_ref().ok_or("No local secret key")?,
            &header.kem_ciphertext,
        )
        .map_err(|_| "Decapsulation failed")?;

        let (new_root, new_recv_chain) = crypto::kdf_step(&state.root_key, shared_secret.as_ref());

        // Derive the header key for the NEXT ratchet.
        let (_, next_h_key) = crypto::kdf_step(&new_root, b"Header Keys");

        state.root_key = new_root;
        state.recv_chain = Some(ChainState {
            key: new_recv_chain,
            index: 0,
        });
        state.send_chain = None; // Trigger new sending ratchet on next encrypt

        // The header chain that worked for this message is now our current receiving header chain.
        state.recv_header_chain = Some(worked_h_chain);

        // Generate next DH keypair to be ready for the next sending step.
        let mut rng = rand::thread_rng();
        let (new_pk, new_sk) = crypto::generate_hybrid_keypair(&mut rng);
        state.dh_pk = new_pk;
        state.dh_sk = Some(new_sk);

        // Derive next potential header key from root key.
        state.next_recv_header_chain = Some(HeaderChain {
            key: next_h_key,
            index: 0,
        });

        Ok(())
    }
}
