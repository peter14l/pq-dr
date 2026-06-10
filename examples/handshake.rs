//! Full PQ-X3DH handshake example
//! 
//! This example demonstrates:
//! - Bob generating keys and creating a PreKeyBundle
//! - Alice initiating a handshake
//! - Bob responding to the handshake
//! - Both parties verifying root keys match
//! - Exchanging first messages

use pq_aura::crypto::*;
use pq_aura::handshake::*;
use pq_aura::ratchet::*;
use pq_aura::state::*;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    let ad = b"Session associated data";
    
    println!("=== PQ-X3DH Handshake Example ===\n");
    
    // 1. Bob generates his keys
    println!("1. Bob generating keys...");
    let (bob_id_pk, bob_id_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_signed_pk, bob_signed_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_ot_pk, bob_ot_sk) = generate_hybrid_keypair(&mut rng);
    
    println!("   Identity key: {} bytes", bob_id_pk.to_bytes().len());
    println!("   Signed pre-key: {} bytes", bob_signed_pk.to_bytes().len());
    println!("   One-time pre-key: {} bytes", bob_ot_pk.to_bytes().len());
    
    // 2. Bob creates his PreKeyBundle
    println!("\n2. Bob creating PreKeyBundle...");
    let bundle = PreKeyBundle {
        identity_pk: bob_id_pk.clone(),
        signed_pre_key: bob_signed_pk,
        one_time_pre_key: Some(bob_ot_pk),
    };
    println!("   Bundle created: {} bytes", bundle.to_bytes().len());
    
    // 3. Alice generates her identity keys
    println!("\n3. Alice generating identity keys...");
    let (alice_id_pk, alice_id_sk) = generate_hybrid_keypair(&mut rng);
    println!("   Identity key: {} bytes", alice_id_pk.to_bytes().len());
    
    // 4. Alice initiates the handshake
    println!("\n4. Alice initiating handshake...");
    let (mut alice_state, initial_msg, alice_root_key) =
        HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);
    
    println!("   Initial message: {} bytes", initial_msg.to_bytes().len());
    println!("   Alice root key: {} bytes", alice_root_key.as_ref().len());
    
    // 5. Bob responds to the handshake
    println!("\n5. Bob responding to handshake...");
    let (mut bob_state, bob_root_key) = HandshakeEngine::respond_bob(
        &initial_msg,
        &bob_id_pk,
        &bob_id_sk,
        &bob_signed_sk,
        Some(&bob_ot_sk),
    )
    .unwrap();
    
    println!("   Bob root key: {} bytes", bob_root_key.as_ref().len());
    
    // 6. Verify root keys match
    println!("\n6. Verifying root keys match...");
    assert_eq!(alice_root_key.as_ref(), bob_root_key.as_ref());
    println!("   ✓ Root keys match!");
    
    // 7. Exchange first messages
    println!("\n7. Exchanging first messages...");
    
    // Alice sends to Bob
    let msg1 = RatchetEngine::encrypt(&mut alice_state, b"Hello Bob!", ad, &mut rng);
    println!("   Alice -> Bob: {} bytes", msg1.payload_ciphertext.len());
    
    // Bob decrypts
    let dec1 = RatchetEngine::decrypt(&mut bob_state, &msg1, ad).unwrap();
    println!("   Bob decrypted: {}", String::from_utf8_lossy(&dec1));
    
    // Bob replies
    let msg2 = RatchetEngine::encrypt(&mut bob_state, b"Hello Alice!", ad, &mut rng);
    println!("   Bob -> Alice: {} bytes", msg2.payload_ciphertext.len());
    
    // Alice decrypts
    let dec2 = RatchetEngine::decrypt(&mut alice_state, &msg2, ad).unwrap();
    println!("   Alice decrypted: {}", String::from_utf8_lossy(&dec2));
    
    // 8. Multiple messages
    println!("\n8. Exchanging multiple messages...");
    for i in 0..5 {
        let msg = RatchetEngine::encrypt(
            &mut alice_state,
            format!("Message {}", i).as_bytes(),
            ad,
            &mut rng,
        );
        let dec = RatchetEngine::decrypt(&mut bob_state, &msg, ad).unwrap();
        println!("   Message {}: {}", i, String::from_utf8_lossy(&dec));
    }
    
    // 9. State persistence
    println!("\n9. State persistence...");
    let storage_key = SecretKeyMaterial([0x77; 32]);
    let storage_nonce = [0u8; 12];
    
    let exported = alice_state.export_state(&storage_key, &storage_nonce).unwrap();
    println!("   Exported state: {} bytes", exported.len());
    
    let imported = RatchetState::import_state(&storage_key, &storage_nonce, &exported).unwrap();
    println!("   Imported state successfully");
    
    // Continue with imported state
    let msg = RatchetEngine::encrypt(&mut imported, b"After import", ad, &mut rng);
    let dec = RatchetEngine::decrypt(&mut bob_state, &msg, ad).unwrap();
    println!("   Message after import: {}", String::from_utf8_lossy(&dec));
    
    println!("\n=== Handshake complete! ===");
}
