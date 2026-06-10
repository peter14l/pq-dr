//! Basic usage example for PQ-Aura
//! 
//! This example demonstrates:
//! - Generating hybrid keypairs
//! - Encrypting and decrypting messages
//! - Constant-time comparison

use pq_aura::crypto::*;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    
    println!("=== PQ-Aura Basic Usage ===\n");
    
    // 1. Generate a hybrid keypair
    println!("1. Generating hybrid keypair...");
    let (public_key, secret_key) = generate_hybrid_keypair(&mut rng);
    println!("   Public key: {} bytes", public_key.to_bytes().len());
    println!("   Secret key: {} bytes (zeroized on drop)", secret_key.to_bytes().len());
    
    // 2. Encapsulate a shared secret
    println!("\n2. Encapsulating shared secret...");
    let (shared_secret_1, ciphertext) = hybrid_encapsulate(&public_key, &mut rng);
    println!("   Ciphertext: {} bytes", ciphertext.len());
    println!("   Shared secret: {} bytes", shared_secret_1.as_ref().len());
    
    // 3. Decapsulate the shared secret
    println!("\n3. Decapsulating shared secret...");
    let shared_secret_2 = hybrid_decapsulate(&secret_key, &ciphertext).unwrap();
    println!("   Shared secret: {} bytes", shared_secret_2.as_ref().len());
    
    // 4. Verify the shared secrets match
    println!("\n4. Verifying shared secrets match...");
    assert!(constant_time_eq(shared_secret_1.as_ref(), shared_secret_2.as_ref()));
    println!("   ✓ Shared secrets match (constant-time comparison)");
    
    // 5. Encrypt a message
    println!("\n5. Encrypting message...");
    let key = SecretKeyMaterial([0x42; 32]); // In practice, derive from shared_secret
    let nonce = [0u8; 12];
    let associated_data = b"Additional authenticated data";
    let plaintext = b"Hello, World! This is a secret message.";
    
    let ciphertext = encrypt(&key, &nonce, associated_data, plaintext);
    println!("   Plaintext: {} bytes", plaintext.len());
    println!("   Ciphertext: {} bytes", ciphertext.len());
    
    // 6. Decrypt the message
    println!("\n6. Decrypting message...");
    let decrypted = decrypt(&key, &nonce, associated_data, &ciphertext).unwrap();
    assert_eq!(decrypted, plaintext);
    println!("   ✓ Decrypted successfully");
    println!("   Message: {}", String::from_utf8_lossy(&decrypted));
    
    // 7. Demonstrate KDF operations
    println!("\n7. Key Derivation Functions...");
    let root_key = SecretKeyMaterial([0x42; 32]);
    let shared_secret = SecretKeyMaterial([0x99; 32]);
    
    let (new_root, chain_key) = kdf_root_step(&root_key, &shared_secret);
    println!("   Root key: {} bytes", new_root.as_ref().len());
    println!("   Chain key: {} bytes", chain_key.as_ref().len());
    
    let (chain_key_2, msg_key) = kdf_chain_step(&chain_key);
    println!("   Next chain key: {} bytes", chain_key_2.as_ref().len());
    println!("   Message key: {} bytes", msg_key.as_ref().len());
    
    println!("\n=== All tests passed! ===");
}
