use pq_aura::crypto::*;
use pq_aura::handshake::*;
use rand::thread_rng;

#[test]
fn test_prekey_bundle_serialization_roundtrip() {
    let mut rng = thread_rng();

    let (bob_id_pk, _bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, _bob_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_ot_pk, _bob_ot_sk) = generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk,
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: Some(bob_ot_pk),
    };

    let bytes = bundle.to_bytes();
    let bundle2 = PreKeyBundle::from_bytes(&bytes).unwrap();

    assert_eq!(bundle.identity_pk, bundle2.identity_pk);
    assert_eq!(bundle.signed_pre_key, bundle2.signed_pre_key);
    assert!(bundle2.one_time_pre_key.is_some());
}

#[test]
fn test_prekey_bundle_without_one_time_pre_key() {
    let mut rng = thread_rng();

    let (bob_id_pk, _bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, _bob_signed_sk) = generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk,
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: None,
    };

    let bytes = bundle.to_bytes();
    let bundle2 = PreKeyBundle::from_bytes(&bytes).unwrap();

    assert!(bundle2.one_time_pre_key.is_none());
}

#[test]
fn test_initial_message_serialization_roundtrip() {
    let mut rng = thread_rng();

    let (alice_id_pk, _alice_id_sk) = generate_hybrid_keypair(&mut rng);
    let (ephemeral_pk, _ephemeral_sk) = generate_hybrid_keypair(&mut rng);

    let initial_msg = InitialMessage {
        alice_identity_pk: alice_id_pk,
        ephemeral_pk,
        kem_ciphertext_identity: vec![0u8; 100],
        kem_ciphertext_signed: vec![0u8; 100],
        kem_ciphertext_one_time: Some(vec![0u8; 100]),
        ratchet_message: pq_aura::ratchet::Message {
            header_ciphertext: vec![0u8; 50],
            payload_ciphertext: vec![0u8; 50],
        },
    };

    let bytes = initial_msg.to_bytes();
    let initial_msg2 = InitialMessage::from_bytes(&bytes).unwrap();

    assert_eq!(
        initial_msg.alice_identity_pk,
        initial_msg2.alice_identity_pk
    );
    assert_eq!(initial_msg.ephemeral_pk, initial_msg2.ephemeral_pk);
    assert_eq!(
        initial_msg.kem_ciphertext_identity,
        initial_msg2.kem_ciphertext_identity
    );
}

#[test]
fn test_handshake_without_one_time_pre_key() {
    let mut rng = thread_rng();

    // Bob generates keys without one-time pre-key
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: None,
    };

    // Alice initiates
    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);
    let (mut alice_state, initial_msg, alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);

    // Bob responds
    let (mut bob_state, bob_root_key) =
        HandshakeEngine::respond_bob(&initial_msg, &bob_id_pk, &bob_id_sk, &bob_signed_sk, None)
            .unwrap();

    // Verify root keys match
    assert_eq!(alice_root_key.as_ref(), bob_root_key.as_ref());

    // Exchange messages
    let ad = b"test";
    let msg = RatchetEngine::encrypt(&mut alice_state, b"Hello!", ad, &mut rng);
    let dec = RatchetEngine::decrypt(&mut bob_state, &msg, ad).unwrap();
    assert_eq!(dec, b"Hello!");
}

#[test]
fn test_handshake_fails_with_wrong_keys() {
    let mut rng = thread_rng();

    // Bob generates keys
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_ot_pk, bob_ot_sk) = generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: Some(bob_ot_pk),
    };

    // Alice initiates
    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);
    let (mut _alice_state, initial_msg, _alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);

    // Eve tries to respond with wrong keys
    let (eve_id_pk, eve_id_sk) = generate_hybrid_keypair(&mut rng);
    let (eve_signed_pk, eve_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (eve_ot_pk, eve_ot_sk) = generate_hybrid_keypair(&mut rng);

    let result = HandshakeEngine::respond_bob(
        &initial_msg,
        &eve_id_pk,
        &eve_id_sk,
        &eve_signed_sk,
        Some(&eve_ot_sk),
    );

    // Should fail because Eve doesn't have Bob's keys
    assert!(result.is_err());
}

#[test]
fn test_multiple_handshakes_same_identity_keys() {
    let mut rng = thread_rng();

    // Bob uses same identity keys for multiple sessions
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);

    for i in 0..3 {
        let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);
        let (bob_ot_pk, bob_ot_sk) = generate_hybrid_keypair(&mut rng);

        let bundle = PreKeyBundle {
            identity_pk: bob_id_pk.clone(),
            signed_pre_key: bob_signed_pk,
            one_time_pre_key: Some(bob_ot_pk),
        };

        let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);
        let (mut alice_state, initial_msg, alice_root_key) =
            HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);

        let (mut bob_state, bob_root_key) = HandshakeEngine::respond_bob(
            &initial_msg,
            &bob_id_pk,
            &bob_id_sk,
            &bob_signed_sk,
            Some(&bob_ot_sk),
        )
        .unwrap();

        assert_eq!(alice_root_key.as_ref(), bob_root_key.as_ref());

        // Each session should work independently
        let msg = RatchetEngine::encrypt(
            &mut alice_state,
            format!("Session {}", i).as_bytes(),
            b"AD",
            &mut rng,
        );
        let dec = RatchetEngine::decrypt(&mut bob_state, &msg, b"AD").unwrap();
        assert_eq!(dec, format!("Session {}", i).as_bytes());
    }
}

#[test]
fn test_prekey_bundle_invalid_bytes() {
    let result = PreKeyBundle::from_bytes(b"invalid json");
    assert!(result.is_err());
}

#[test]
fn test_initial_message_invalid_bytes() {
    let result = InitialMessage::from_bytes(b"invalid json");
    assert!(result.is_err());
}
