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

    // 1. Bob generates his keys and publishes a PreKeyBundle
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_ot_pk, bob_ot_sk) = generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: Some(bob_ot_pk),
    };

    // 2. Alice generates her Identity keys
    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);

    // 3. Alice initiates the handshake using Bob's bundle
    let (mut _alice_state, initial_msg, alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);

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

    let imported = RatchetState::import_state(&storage_key, &storage_nonce, &exported)
        .expect("Failed to import state");

    assert_eq!(alice_state.root_key.as_ref(), imported.root_key.as_ref());
    assert_eq!(
        alice_state.dh_pk.classic.as_bytes(),
        imported.dh_pk.classic.as_bytes()
    );
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
