//! Multi-message ratchet conversation example
//! 
//! This example demonstrates:
//! - Full conversation between Alice and Bob
//! - Multiple messages each way
//! - Out-of-order message handling
//! - State persistence

use pq_aura::crypto::*;
use pq_aura::ratchet::*;
use pq_aura::state::*;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    let ad = b"Conversation associated data";
    
    println!("=== Ratchet Conversation Example ===\n");
    
    // Initialize both parties with shared root key
    let root_key = SecretKeyMaterial([0x42; 32]);
    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);
    
    let mut alice_state = RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
    let mut bob_state = RatchetState::new_bob(root_key, bob_pk, bob_sk);
    
    // Sync states with first message
    println!("1. Initial sync...");
    let sync_msg = RatchetEngine::encrypt(&mut alice_state, b"sync", ad, &mut rng);
    bob_state.remote_dh_pk = Some(alice_pk);
    let _ = RatchetEngine::decrypt(&mut bob_state, &sync_msg, ad);
    println!("   ✓ States synchronized");
    
    // 2. Alice sends multiple messages
    println!("\n2. Alice sending 5 messages...");
    let mut alice_msgs = Vec::new();
    for i in 0..5 {
        let msg = RatchetEngine::encrypt(
            &mut alice_state,
            format!("Alice message {}", i).as_bytes(),
            ad,
            &mut rng,
        );
        alice_msgs.push(msg);
        println!("   Sent message {}", i);
    }
    
    // 3. Bob receives messages in order
    println!("\n3. Bob receiving messages in order...");
    for (i, msg) in alice_msgs.iter().enumerate() {
        let dec = RatchetEngine::decrypt(&mut bob_state, msg, ad).unwrap();
        println!("   Received: {}", String::from_utf8_lossy(&dec));
    }
    
    // 4. Bob sends reply
    println!("\n4. Bob sending reply...");
    let reply = RatchetEngine::encrypt(&mut bob_state, b"Got all your messages!", ad, &mut rng);
    let dec = RatchetEngine::decrypt(&mut alice_state, &reply, ad).unwrap();
    println!("   Alice received: {}", String::from_utf8_lossy(&dec));
    
    // 5. Out-of-order messages
    println!("\n5. Testing out-of-order messages...");
    let mut alice_out_of_order = Vec::new();
    for i in 0..3 {
        let msg = RatchetEngine::encrypt(
            &mut alice_state,
            format!("Out of order {}", i).as_bytes(),
            ad,
            &mut rng,
        );
        alice_out_of_order.push(msg);
    }
    
    // Bob receives in reverse order: 2, 0, 1
    let dec2 = RatchetEngine::decrypt(&mut bob_state, &alice_out_of_order[2], ad).unwrap();
    println!("   Received message 2: {}", String::from_utf8_lossy(&dec2));
    
    let dec0 = RatchetEngine::decrypt(&mut bob_state, &alice_out_of_order[0], ad).unwrap();
    println!("   Received message 0: {}", String::from_utf8_lossy(&dec0));
    
    let dec1 = RatchetEngine::decrypt(&mut bob_state, &alice_out_of_order[1], ad).unwrap();
    println!("   Received message 1: {}", String::from_utf8_lossy(&dec1));
    
    // 6. State persistence
    println!("\n6. State persistence test...");
    let storage_key = SecretKeyMaterial([0x77; 32]);
    let storage_nonce = [0u8; 12];
    
    // Save Alice's state
    let alice_exported = alice_state.export_state(&storage_key, &storage_nonce).unwrap();
    println!("   Alice exported state: {} bytes", alice_exported.len());
    
    // Save Bob's state
    let bob_exported = bob_state.export_state(&storage_key, &storage_nonce).unwrap();
    println!("   Bob exported state: {} bytes", bob_exported.len());
    
    // Import and continue
    let alice_imported = RatchetState::import_state(&storage_key, &storage_nonce, &alice_exported).unwrap();
    let bob_imported = RatchetState::import_state(&storage_key, &storage_nonce, &bob_exported).unwrap();
    
    // Continue conversation after import
    let msg = RatchetEngine::encrypt(&mut alice_imported, b"After import", ad, &mut rng);
    let dec = RatchetEngine::decrypt(&mut bob_imported, &msg, ad).unwrap();
    println!("   Message after import: {}", String::from_utf8_lossy(&dec));
    
    // 7. Large message test
    println!("\n7. Large message test...");
    let large_message = vec![0x42u8; 1024 * 1024]; // 1MB
    let msg = RatchetEngine::encrypt(&mut alice_imported, &large_message, ad, &mut rng);
    println!("   Encrypted {} bytes", large_message.len());
    
    let dec = RatchetEngine::decrypt(&mut bob_imported, &msg, ad).unwrap();
    assert_eq!(dec.len(), large_message.len());
    println!("   Decrypted {} bytes", dec.len());
    
    println!("\n=== Conversation complete! ===");
}
