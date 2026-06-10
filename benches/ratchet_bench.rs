use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pq_aura::crypto::*;
use pq_aura::handshake::*;
use pq_aura::ratchet::*;
use pq_aura::state::*;
use rand::thread_rng;

fn bench_ratchet_encrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);
    let ad = b"benchmark associated data";
    
    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);
    
    let mut alice_state = RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
    let mut bob_state = RatchetState::new_bob(root_key, bob_pk, bob_sk);
    
    // Sync states
    let msg1 = RatchetEngine::encrypt(&mut alice_state, b"sync", ad, &mut rng);
    bob_state.remote_dh_pk = Some(alice_pk);
    let _ = RatchetEngine::decrypt(&mut bob_state, &msg1, ad);
    
    let plaintext = b"Hello, World! This is a test message for benchmarking.";
    
    c.bench_function("ratchet_encrypt", |b| {
        b.iter(|| RatchetEngine::encrypt(black_box(&mut alice_state), black_box(plaintext), black_box(ad), black_box(&mut rng)))
    });
}

fn bench_ratchet_decrypt(c: &mut Criterion) {
    let mut rng = thread_rng();
    let root_key = SecretKeyMaterial([0x42; 32]);
    let ad = b"benchmark associated data";
    
    let (alice_pk, alice_sk) = generate_hybrid_keypair(&mut rng);
    let (bob_pk, bob_sk) = generate_hybrid_keypair(&mut rng);
    
    let mut alice_state = RatchetState::new_alice(root_key.clone(), bob_pk.clone(), alice_pk.clone(), alice_sk);
    let mut bob_state = RatchetState::new_bob(root_key, bob_pk, bob_sk);
    
    // Sync states
    let msg1 = RatchetEngine::encrypt(&mut alice_state, b"sync", ad, &mut rng);
    bob_state.remote_dh_pk = Some(alice_pk);
    let _ = RatchetEngine::decrypt(&mut bob_state, &msg1, ad);
    
    let plaintext = b"Hello, World! This is a test message for benchmarking.";
    let message = RatchetEngine::encrypt(&mut alice_state, plaintext, ad, &mut rng);
    
    c.bench_function("ratchet_decrypt", |b| {
        b.iter(|| RatchetEngine::decrypt(black_box(&mut bob_state), black_box(&message), black_box(ad)))
    });
}

fn bench_full_handshake(c: &mut Criterion) {
    c.bench_function("full_pq_x3dh_handshake", |b| {
        b.iter(|| {
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
            let (mut alice_state, initial_msg, alice_root_key) =
                HandshakeEngine::initiate_alice(&bundle, &alice_id_pk, &alice_id_sk, &mut rng);
            
            // Bob responds
            let (mut bob_state, bob_root_key) = HandshakeEngine::respond_bob(
                &initial_msg,
                &bob_id_pk,
                &bob_id_sk,
                &bob_signed_sk,
                Some(&bob_ot_sk),
            )
            .unwrap();
            
            // First message
            let msg = RatchetEngine::encrypt(&mut alice_state, b"Hello!", b"AD", &mut rng);
            let dec = RatchetEngine::decrypt(&mut bob_state, &msg, b"AD").unwrap();
            
            (alice_root_key, bob_root_key, dec)
        })
    });
}

criterion_group!(
    benches,
    bench_ratchet_encrypt,
    bench_ratchet_decrypt,
    bench_full_handshake,
);
criterion_main!(benches);
