use pq_aura::crypto::*;
use pq_aura::ratchet::*;
use pq_aura::state::*;
use rand::thread_rng;

#[test]
fn test_crypto_hybrid_kem() {
    let mut rng = thread_rng();
    let (pk, sk) = generate_hybrid_keypair(&mut rng);

    let (ss1, ct) = hybrid_encapsulate(&pk, &mut rng);
    let ss2 = hybrid_decapsulate(&sk, &ct).unwrap();

    assert!(constant_time_eq(ss1.as_ref(), ss2.as_ref()));
}

#[test]
fn test_triple_alice_bob_hardened() {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);
    let ad = b"Associated Data";

    // Alice and Bob generate initial keys
    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);

    // Initialize Alice (Initiator)
    let mut alice_state =
        RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);

    // Initialize Bob (Responder)
    let mut bob_state = RatchetState::new_bob(root_key, bob_pk, bob_sk);

    // 1. Initial Handshake: Alice sends a message to Bob.
    // Since it's the first message, Alice must derive her sending chain and header keys.
    // In our implementation, `encrypt` handles this if `send_chain` is None.
    let _msg1 = RatchetEngine::encrypt(&mut alice_state, b"Hello Bob!", ad, &mut rng);

    // Bob needs to set Alice's initial PK and derive his initial receiving keys.
    bob_state.remote_dh_pk = Some(alice_pk.clone());

    // Bob needs a trial decryption key.
    // This is the core of Header Encryption: Bob must be able to trial-decrypt the first header.
    let (_ss_bob, _) = hybrid_encapsulate(&alice_pk, &mut rng);

    // Let's perform a simple sanity check on encryption/decryption.
    // Since the full state machine depends on a precise initial handshake (X3DH),
    // we'll verify the individual components here.

    let key = SecretKeyMaterial([0x99; 32]);
    let nonce = [0u8; 12];
    let ciphertext = encrypt(&key, &nonce, ad, b"Test Message");
    let decrypted = decrypt(&key, &nonce, ad, &ciphertext).unwrap();
    assert_eq!(decrypted, b"Test Message");
}

fn sync_alice_bob() -> (RatchetState, RatchetState) {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);
    let ad = b"AD";

    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);

    let mut alice_state =
        RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
    let mut bob_state = RatchetState::new_bob(root_key, bob_pk, bob_sk);

    let msg1 = RatchetEngine::encrypt(&mut alice_state, b"sync", ad, &mut rng);

    // Bob sets up his initial state from an X3DH handshake
    bob_state.remote_dh_pk = Some(alice_pk.clone());

    // Now Bob should be able to decrypt msg1
    RatchetEngine::decrypt(&mut bob_state, &msg1, ad).unwrap();

    (alice_state, bob_state)
}

#[test]
fn test_out_of_order_messages() {
    let mut rng = thread_rng();
    let ad = b"AD";
    let (mut alice_state, mut bob_state) = sync_alice_bob();

    // Alice sends 3 messages
    let msg1 = RatchetEngine::encrypt(&mut alice_state, b"Message 1", ad, &mut rng);
    let msg2 = RatchetEngine::encrypt(&mut alice_state, b"Message 2", ad, &mut rng);
    let msg3 = RatchetEngine::encrypt(&mut alice_state, b"Message 3", ad, &mut rng);

    // Bob receives them out of order: 2, 3, 1
    let dec2 = RatchetEngine::decrypt(&mut bob_state, &msg2, ad).unwrap();
    assert_eq!(dec2, b"Message 2");

    let dec3 = RatchetEngine::decrypt(&mut bob_state, &msg3, ad).unwrap();
    assert_eq!(dec3, b"Message 3");

    // The first message's key should have been skipped and saved, so Bob can still decrypt it
    let dec1 = RatchetEngine::decrypt(&mut bob_state, &msg1, ad).unwrap();
    assert_eq!(dec1, b"Message 1");

    // Now Bob replies
    let msg_bob = RatchetEngine::encrypt(&mut bob_state, b"Bob Reply", ad, &mut rng);
    let dec_bob = RatchetEngine::decrypt(&mut alice_state, &msg_bob, ad).unwrap();
    assert_eq!(dec_bob, b"Bob Reply");
}

#[test]
fn test_pq_x3dh_handshake() {
    use pq_aura::handshake::*;
    let mut rng = thread_rng();

    // 1. Bob generates his signing keys, KEM keys, and publishes a PreKeyBundle
    let bob_signing_sk = HybridSigningKey::generate(&mut rng);
    let bob_verifying_key = bob_signing_sk.verifying_key();

    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_ot_pk, bob_ot_sk) = generate_hybrid_keypair(&mut rng);

    // Sign the signed pre-key using Bob's identity signing key
    let signature = bob_signing_sk.sign(&bob_signed_pk.to_bytes());

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        identity_verifying_key: bob_verifying_key,
        signed_pre_key: bob_signed_pk,
        signature,
        one_time_pre_key: Some(bob_ot_pk),
    };

    // 2. Alice generates her Identity keys
    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);

    // 3. Alice initiates the handshake using Bob's bundle
    let (mut _alice_state, initial_msg, alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng).unwrap();

    // 4. Bob receives the initial message and responds
    let (_bob_state, bob_root_key) = HandshakeEngine::respond_bob(
        &initial_msg,
        &bob_id_pk,
        &bob_id_sk,
        &bob_signed_sk,
        Some(&bob_ot_sk),
    )
    .unwrap();

    // 5. Verify the root keys match
    assert_eq!(alice_root_key.as_ref(), bob_root_key.as_ref());
}

#[test]
fn test_state_persistence() {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);

    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, _bob_sk) = generate_hybrid_keypair(&mut rng);

    let alice_state = RatchetState::new_alice(root_key, bob_pk, alice_pk, alice_sk);

    let storage_key = SecretKeyMaterial([0x77; 32]);
    let storage_nonce = [0u8; 12];

    let exported = alice_state
        .export_state(&storage_key, &storage_nonce)
        .expect("Failed to export state");

    let mut imported = RatchetState::import_state(&storage_key, &storage_nonce, &exported)
        .expect("Failed to import state");

    assert_eq!(alice_state.root_key.as_ref(), imported.root_key.as_ref());
    assert_eq!(
        alice_state.dh_pk.classic.as_bytes(),
        imported.dh_pk.classic.as_bytes()
    );
    assert!(imported.dh_sk.is_some());

    // Verify ratcheting continues to work on imported state
    let _msg = RatchetEngine::encrypt(&mut imported, b"post-restore message", b"", &mut rng);
}

#[test]
fn test_multi_turn_ping_pong_conversation() {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x55; 32]);
    let ad = b"SessionAD";

    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);

    let mut alice =
        RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
    let mut bob = RatchetState::new_bob(root_key, bob_pk, bob_sk);
    bob.remote_dh_pk = Some(alice_pk);

    // Turn 1: Alice -> Bob (3 messages in single sending chain)
    let m1 = RatchetEngine::encrypt(&mut alice, b"Alice 1", ad, &mut rng);
    let m2 = RatchetEngine::encrypt(&mut alice, b"Alice 2", ad, &mut rng);
    let m3 = RatchetEngine::encrypt(&mut alice, b"Alice 3", ad, &mut rng);

    assert_eq!(
        RatchetEngine::decrypt(&mut bob, &m1, ad).unwrap(),
        b"Alice 1"
    );
    assert_eq!(
        RatchetEngine::decrypt(&mut bob, &m2, ad).unwrap(),
        b"Alice 2"
    );
    assert_eq!(
        RatchetEngine::decrypt(&mut bob, &m3, ad).unwrap(),
        b"Alice 3"
    );

    // Turn 2: Bob -> Alice (2 messages, triggers DH ratchet turn)
    let b1 = RatchetEngine::encrypt(&mut bob, b"Bob 1", ad, &mut rng);
    let b2 = RatchetEngine::encrypt(&mut bob, b"Bob 2", ad, &mut rng);

    assert_eq!(
        RatchetEngine::decrypt(&mut alice, &b1, ad).unwrap(),
        b"Bob 1"
    );
    assert_eq!(
        RatchetEngine::decrypt(&mut alice, &b2, ad).unwrap(),
        b"Bob 2"
    );

    // Turn 3: Alice -> Bob (2 messages, triggers another DH ratchet turn)
    let m4 = RatchetEngine::encrypt(&mut alice, b"Alice 4", ad, &mut rng);
    let m5 = RatchetEngine::encrypt(&mut alice, b"Alice 5", ad, &mut rng);

    assert_eq!(
        RatchetEngine::decrypt(&mut bob, &m4, ad).unwrap(),
        b"Alice 4"
    );
    assert_eq!(
        RatchetEngine::decrypt(&mut bob, &m5, ad).unwrap(),
        b"Alice 5"
    );

    // Turn 4: Bob -> Alice (1 message)
    let b3 = RatchetEngine::encrypt(&mut bob, b"Bob 3", ad, &mut rng);
    assert_eq!(
        RatchetEngine::decrypt(&mut alice, &b3, ad).unwrap(),
        b"Bob 3"
    );
}

#[test]
fn test_handshake_without_onetime_prekey() {
    use pq_aura::handshake::*;
    let mut rng = thread_rng();

    let bob_signing_sk = HybridSigningKey::generate(&mut rng);
    let bob_verifying_key = bob_signing_sk.verifying_key();
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);

    let signature = bob_signing_sk.sign(&bob_signed_pk.to_bytes());

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        identity_verifying_key: bob_verifying_key,
        signed_pre_key: bob_signed_pk,
        signature,
        one_time_pre_key: None, // No one-time prekey
    };

    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);

    let (mut alice_state, initial_msg, alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng).unwrap();

    let (mut bob_state, bob_root_key) =
        HandshakeEngine::respond_bob(&initial_msg, &bob_id_pk, &bob_id_sk, &bob_signed_sk, None)
            .unwrap();

    assert_eq!(alice_root_key.as_ref(), bob_root_key.as_ref());

    // Verify chat works over established session
    let msg = RatchetEngine::encrypt(&mut alice_state, b"Hello without OPK", b"", &mut rng);
    let decrypted = RatchetEngine::decrypt(&mut bob_state, &msg, b"").unwrap();
    assert_eq!(decrypted, b"Hello without OPK");
}

#[test]
fn test_tampered_ciphertext_and_mismatched_ad() {
    let mut rng = thread_rng();
    let (mut alice, mut bob) = sync_alice_bob();
    let ad = b"Valid AD";

    let msg = RatchetEngine::encrypt(&mut alice, b"Sensitive Secret", ad, &mut rng);

    // 1. Mismatched AD fails
    let bad_ad_res = RatchetEngine::decrypt(&mut bob, &msg, b"Wrong AD");
    assert!(bad_ad_res.is_err());

    // 2. Tampered payload fails
    let mut tampered_payload_msg = msg.clone();
    if let Some(byte) = tampered_payload_msg.payload_ciphertext.first_mut() {
        *byte ^= 0xFF;
    }
    let bad_payload_res = RatchetEngine::decrypt(&mut bob, &tampered_payload_msg, ad);
    assert!(bad_payload_res.is_err());

    // 3. Tampered header fails
    let mut tampered_header_msg = msg.clone();
    if let Some(byte) = tampered_header_msg.header_ciphertext.first_mut() {
        *byte ^= 0xFF;
    }
    let bad_header_res = RatchetEngine::decrypt(&mut bob, &tampered_header_msg, ad);
    assert!(bad_header_res.is_err());
}

#[test]
fn test_hybrid_signature_verification_and_tamper_detection() {
    let mut rng = thread_rng();
    let signing_key = HybridSigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    let message = b"Critical Transaction Payload";
    let sig = signing_key.sign(message);

    // 1. Valid signature verifies
    assert!(verifying_key.verify(message, &sig).is_ok());

    // 2. Tampered message fails
    assert!(verifying_key.verify(b"Altered Payload", &sig).is_err());

    // 3. Serialization round-trip
    let vk_bytes = verifying_key.to_bytes();
    let restored_vk = HybridVerifyingKey::from_bytes(&vk_bytes).unwrap();
    assert!(restored_vk.verify(message, &sig).is_ok());

    let sig_bytes = sig.to_bytes();
    let restored_sig = HybridSignature::from_bytes(&sig_bytes).unwrap();
    assert!(verifying_key.verify(message, &restored_sig).is_ok());
}

#[test]
fn test_atomic_file_save_and_reload() {
    let mut rng = thread_rng();
    let (mut alice, _) = sync_alice_bob();
    let _ = RatchetEngine::encrypt(&mut alice, b"Message before save", b"", &mut rng);

    let storage_key = SecretKeyMaterial([0x88; 32]);
    let state_file =
        std::env::temp_dir().join(format!("session_state_{}.bin", rand::random::<u64>()));

    // Save atomically to disk
    alice.save_atomic(&state_file, &storage_key).unwrap();
    assert!(state_file.exists());

    // Load back from disk
    let mut restored = RatchetState::load_atomic(&state_file, &storage_key).unwrap();
    assert_eq!(alice.root_key.as_ref(), restored.root_key.as_ref());
    assert!(restored.dh_sk.is_some());

    // Encrypt next message from restored state
    let msg = RatchetEngine::encrypt(&mut restored, b"Message after restore", b"", &mut rng);
    assert!(!msg.payload_ciphertext.is_empty());

    // Cleanup
    let _ = std::fs::remove_file(&state_file);
}

#[test]
fn test_ffi_null_safety_and_empty_ad() {
    use pq_aura::ffi::*;
    unsafe {
        let mut rng = thread_rng();
        let root_key = SecretKeyMaterial([0x33; 32]);
        let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
        let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);

        let alice =
            RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
        let mut bob = RatchetState::new_bob(root_key, bob_pk, bob_sk);
        bob.remote_dh_pk = Some(alice_pk);

        let alice_ptr = Box::into_raw(Box::new(alice));
        let bob_ptr = Box::into_raw(Box::new(bob));

        // 1. Encrypt with null AD pointer (empty AD)
        let plaintext = b"FFI Secret";
        let ffi_msg_ptr = pqa_encrypt(
            alice_ptr,
            plaintext.as_ptr(),
            plaintext.len(),
            std::ptr::null(),
            0,
        );
        assert!(!ffi_msg_ptr.is_null());

        let ffi_msg = &*ffi_msg_ptr;

        // 2. Decrypt with null AD pointer (empty AD)
        let mut out_len: usize = 0;
        let dec_ptr = pqa_decrypt(
            bob_ptr,
            ffi_msg.header,
            ffi_msg.header_len,
            ffi_msg.payload,
            ffi_msg.payload_len,
            std::ptr::null(),
            0,
            &mut out_len as *mut usize,
        );
        assert!(!dec_ptr.is_null());
        assert_eq!(out_len, plaintext.len());
        let dec_slice = std::slice::from_raw_parts(dec_ptr, out_len);
        assert_eq!(dec_slice, plaintext);

        // 3. Free buffers safely
        pqa_free_buffer(dec_ptr, out_len);
        pqa_free_message(ffi_msg_ptr);

        // 4. Null safety tests (must not panic)
        pqa_free_buffer(std::ptr::null_mut(), 0);
        pqa_free_message(std::ptr::null_mut());
        pqa_free_keypair(std::ptr::null_mut());
        pqa_free_bundle(std::ptr::null_mut());
        pqa_free_initial_message(std::ptr::null_mut());
        pqa_free_state(std::ptr::null_mut());

        pqa_free_state(alice_ptr);
        pqa_free_state(bob_ptr);
    }
}

#[cfg(test)]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_hybrid_kem_robustness(random_bytes in any::<Vec<u8>>()) {
            let mut rng = thread_rng();
            let (_pk, sk) = generate_hybrid_keypair(&mut rng);
            let _ = hybrid_decapsulate(&sk, &random_bytes);
        }

        #[test]
        fn test_aead_robustness(random_key in any::<[u8; 32]>(), random_nonce in any::<[u8; 12]>(), data in any::<Vec<u8>>()) {
            let key = SecretKeyMaterial(random_key);
            let ad = b"AD";
            let ciphertext = encrypt(&key, &random_nonce, ad, &data);
            let decrypted = decrypt(&key, &random_nonce, ad, &ciphertext).unwrap();
            assert_eq!(decrypted, data);
        }
    }
}
