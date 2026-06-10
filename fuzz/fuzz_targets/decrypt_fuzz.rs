#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_aura::crypto::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz decrypt with random ciphertext - should never panic
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let ad = b"fuzz associated data";
    
    // Test that decrypt returns an error, never panics
    let _ = decrypt(&key, &nonce, ad, data);
    
    // Test with random key
    if data.len() >= 32 {
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&data[..32]);
        let random_key = SecretKeyMaterial(key_bytes);
        let _ = decrypt(&random_key, &nonce, ad, &data[32..]);
    }
});
