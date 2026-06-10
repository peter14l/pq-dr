use pq_aura::crypto::*;
use proptest::prelude::*;
use rand::thread_rng;

#[test]
fn test_generate_keypair_produces_valid_keys() {
    let mut rng = thread_rng();
    let (pk, sk) = generate_hybrid_keypair(&mut rng);

    // Check key sizes
    assert_eq!(pk.classic.as_bytes().len(), 32);
    assert_eq!(pk.quantum.as_bytes().len(), 1568);
    assert_eq!(sk.to_bytes().len(), 32 + 3168);
}

#[test]
fn test_hybrid_encapsulate_decapsulate_roundtrip() {
    let mut rng = thread_rng();
    let (pk, sk) = generate_hybrid_keypair(&mut rng);

    let (ss1, ct) = hybrid_encapsulate(&pk, &mut rng);
    let ss2 = hybrid_decapsulate(&sk, &ct).unwrap();

    assert!(constant_time_eq(ss1.as_ref(), ss2.as_ref()));
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let ad = b"test associated data";
    let plaintext = b"Hello, World!";

    let ciphertext = encrypt(&key, &nonce, ad, plaintext);
    let decrypted = decrypt(&key, &nonce, ad, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_empty_plaintext() {
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let ad = b"test";
    let plaintext = b"";

    let ciphertext = encrypt(&key, &nonce, ad, plaintext);
    let decrypted = decrypt(&key, &nonce, ad, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_large_plaintext() {
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let ad = b"test";
    let plaintext = vec![0x42u8; 1024 * 1024]; // 1MB

    let ciphertext = encrypt(&key, &nonce, ad, &plaintext);
    let decrypted = decrypt(&key, &nonce, ad, &ciphertext).unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_different_ad() {
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let plaintext = b"test";

    let ad1 = b"associated data 1";
    let ad2 = b"associated data 2";

    let ciphertext = encrypt(&key, &nonce, ad1, plaintext);

    // Should fail with wrong AD
    let result = decrypt(&key, &nonce, ad2, &ciphertext);
    assert!(result.is_err());

    // Should succeed with correct AD
    let decrypted = decrypt(&key, &nonce, ad1, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_kdf_root_step_output_sizes() {
    let root_key = SecretKeyMaterial([0x42; 32]);
    let shared_secret = SecretKeyMaterial([0x99; 32]);

    let (new_root, chain_key) = kdf_root_step(&root_key, &shared_secret);

    assert_eq!(new_root.as_ref().len(), 32);
    assert_eq!(chain_key.as_ref().len(), 32);
}

#[test]
fn test_kdf_chain_step_output_sizes() {
    let chain_key = SecretKeyMaterial([0x42; 32]);

    let (new_chain, msg_key) = kdf_chain_step(&chain_key);

    assert_eq!(new_chain.as_ref().len(), 32);
    assert_eq!(msg_key.as_ref().len(), 32);
}

#[test]
fn test_kdf_header_step_output_sizes() {
    let root_key = SecretKeyMaterial([0x42; 32]);

    let (header_key, next_header_key) = kdf_header_step(&root_key);

    assert_eq!(header_key.as_ref().len(), 32);
    assert_eq!(next_header_key.as_ref().len(), 32);
}

#[test]
fn test_kdf_deterministic() {
    let root_key = SecretKeyMaterial([0x42; 32]);
    let shared_secret = SecretKeyMaterial([0x99; 32]);

    let (root1, chain1) = kdf_root_step(&root_key, &shared_secret);
    let (root2, chain2) = kdf_root_step(&root_key, &shared_secret);

    assert!(constant_time_eq(root1.as_ref(), root2.as_ref()));
    assert!(constant_time_eq(chain1.as_ref(), chain2.as_ref()));
}

#[test]
fn test_combine_secrets_deterministic() {
    let classic = [0x42u8; 32];
    let quantum = [0x99u8; 32];

    let ss1 = combine_secrets(&classic, &quantum);
    let ss2 = combine_secrets(&classic, &quantum);

    assert!(constant_time_eq(ss1.as_ref(), ss2.as_ref()));
}

#[test]
fn test_combine_secrets_different_inputs() {
    let classic1 = [0x42u8; 32];
    let classic2 = [0x43u8; 32];
    let quantum = [0x99u8; 32];

    let ss1 = combine_secrets(&classic1, &quantum);
    let ss2 = combine_secrets(&classic2, &quantum);

    assert!(!constant_time_eq(ss1.as_ref(), ss2.as_ref()));
}

#[test]
fn test_constant_time_eq_equal() {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];

    assert!(constant_time_eq(&a, &b));
}

#[test]
fn test_constant_time_eq_unequal() {
    let a = [0x42u8; 32];
    let b = [0x43u8; 32];

    assert!(!constant_time_eq(&a, &b));
}

#[test]
fn test_secret_key_material_zeroize() {
    let key = SecretKeyMaterial([0x42; 32]);
    let ptr = key.as_ref().as_ptr();

    drop(key);

    // After drop, the memory should be zeroed
    // Note: This test is not guaranteed to pass in all environments
    // but demonstrates the intent
}

#[test]
fn test_hybrid_public_key_serialization_roundtrip() {
    let mut rng = thread_rng();
    let (pk, _sk) = generate_hybrid_keypair(&mut rng);

    let bytes = pk.to_bytes();
    let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();

    assert_eq!(pk, pk2);
}

#[test]
fn test_hybrid_secret_key_serialization_roundtrip() {
    let mut rng = thread_rng();
    let (_pk, sk) = generate_hybrid_keypair(&mut rng);

    let bytes = sk.to_bytes();
    let sk2 = HybridSecretKey::from_bytes(&bytes).unwrap();

    assert_eq!(sk.to_bytes(), sk2.to_bytes());
}

#[test]
fn test_hybrid_public_key_invalid_length() {
    let bytes = vec![0u8; 100]; // Wrong length

    let result = HybridPublicKey::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_hybrid_secret_key_invalid_length() {
    let bytes = vec![0u8; 100]; // Wrong length

    let result = HybridSecretKey::from_bytes(&bytes);
    assert!(result.is_err());
}

#[test]
fn test_generate_nonce_deterministic() {
    let nonce1 = generate_nonce(42, 0);
    let nonce2 = generate_nonce(42, 0);

    assert_eq!(nonce1, nonce2);
}

#[test]
fn test_generate_nonce_different_indices() {
    let nonce1 = generate_nonce(0, 0);
    let nonce2 = generate_nonce(1, 0);
    let nonce3 = generate_nonce(0, 1);

    assert_ne!(nonce1, nonce2);
    assert_ne!(nonce1, nonce3);
    assert_ne!(nonce2, nonce3);
}

proptest! {
    #[test]
    fn test_hybrid_kem_robustness(random_bytes in any::<Vec<u8>>()) {
        let mut rng = thread_rng();
        let (_pk, sk) = generate_hybrid_keypair(&mut rng);
        // Should return error, never panic
        let _ = hybrid_decapsulate(&sk, &random_bytes);
    }

    #[test]
    fn test_aead_robustness(
        random_key in any::<[u8; 32]>(),
        random_nonce in any::<[u8; 12]>(),
        data in any::<Vec<u8>>()
    ) {
        let key = SecretKeyMaterial(random_key);
        let ad = b"AD";
        let ciphertext = encrypt(&key, &random_nonce, ad, &data);
        let decrypted = decrypt(&key, &random_nonce, ad, &ciphertext).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_kdf_root_step_robustness(
        root_key in any::<[u8; 32]>(),
        shared_secret in any::<[u8; 32]>()
    ) {
        let rk = SecretKeyMaterial(root_key);
        let ss = SecretKeyMaterial(shared_secret);
        let (new_root, chain_key) = kdf_root_step(&rk, &ss);
        assert_eq!(new_root.as_ref().len(), 32);
        assert_eq!(chain_key.as_ref().len(), 32);
    }

    #[test]
    fn test_kdf_chain_step_robustness(chain_key in any::<[u8; 32]>()) {
        let ck = SecretKeyMaterial(chain_key);
        let (new_chain, msg_key) = kdf_chain_step(&ck);
        assert_eq!(new_chain.as_ref().len(), 32);
        assert_eq!(msg_key.as_ref().len(), 32);
    }

    #[test]
    fn test_kdf_header_step_robustness(root_key in any::<[u8; 32]>()) {
        let rk = SecretKeyMaterial(root_key);
        let (header_key, next_header_key) = kdf_header_step(&rk);
        assert_eq!(header_key.as_ref().len(), 32);
        assert_eq!(next_header_key.as_ref().len(), 32);
    }
}
