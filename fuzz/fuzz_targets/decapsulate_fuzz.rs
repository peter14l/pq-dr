#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_aura::crypto::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz hybrid_decapsulate with random bytes - should never panic
    let mut rng = rand::thread_rng();
    let (_pk, sk) = generate_hybrid_keypair(&mut rng);
    
    // Test that decapsulate returns an error, never panics
    let _ = hybrid_decapsulate(&sk, data);
});
