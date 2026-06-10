#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_aura::crypto::*;
use pq_aura::state::RatchetState;
use rand::thread_rng;

fuzz_target!(|data: &[u8]| {
    // Fuzz serialization roundtrip - should never panic
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);
    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, _bob_sk) = generate_hybrid_keypair(&mut rng);
    
    let state = RatchetState::new_alice(root_key, bob_pk, alice_pk, alice_sk);
    
    // Test export/import roundtrip
    let storage_key = SecretKeyMaterial([0x77; 32]);
    let storage_nonce = [0u8; 12];
    
    if let Ok(exported) = state.export_state(&storage_key, &storage_nonce) {
        let _ = RatchetState::import_state(&storage_key, &storage_nonce, &exported);
    }
    
    // Also fuzz with random data
    let _ = RatchetState::import_state(&storage_key, &storage_nonce, data);
});
