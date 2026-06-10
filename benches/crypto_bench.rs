use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pq_aura::crypto::*;

fn bench_generate_keypair(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    c.bench_function("generate_hybrid_keypair", |b| {
        b.iter(|| generate_hybrid_keypair(black_box(&mut rng)))
    });
}

fn bench_encapsulate_decapsulate(c: &mut Criterion) {
    let mut rng = rand::thread_rng();
    let (pk, sk) = generate_hybrid_keypair(&mut rng);
    
    c.bench_function("hybrid_encapsulate", |b| {
        b.iter(|| hybrid_encapsulate(black_box(&pk), &mut rng))
    });
    
    let (ss, ct) = hybrid_encapsulate(&pk, &mut rng);
    c.bench_function("hybrid_decapsulate", |b| {
        b.iter(|| hybrid_decapsulate(black_box(&sk), black_box(&ct)))
    });
    
    let _ = ss;
}

fn bench_encrypt_decrypt(c: &mut Criterion) {
    let key = SecretKeyMaterial([0x42; 32]);
    let nonce = [0u8; 12];
    let ad = b"benchmark associated data";
    let plaintext = b"Hello, World! This is a test message for benchmarking.";
    
    c.bench_function("aes256gcm_siv_encrypt", |b| {
        b.iter(|| encrypt(black_box(&key), black_box(&nonce), black_box(ad), black_box(plaintext)))
    });
    
    let ciphertext = encrypt(&key, &nonce, ad, plaintext);
    c.bench_function("aes256gcm_siv_decrypt", |b| {
        b.iter(|| decrypt(black_box(&key), black_box(&nonce), black_box(ad), black_box(&ciphertext)))
    });
}

fn bench_kdf_operations(c: &mut Criterion) {
    let root_key = SecretKeyMaterial([0x42; 32]);
    let shared_secret = SecretKeyMaterial([0x99; 32]);
    let chain_key = SecretKeyMaterial([0xAA; 32]);
    
    c.bench_function("kdf_root_step", |b| {
        b.iter(|| kdf_root_step(black_box(&root_key), black_box(&shared_secret)))
    });
    
    c.bench_function("kdf_chain_step", |b| {
        b.iter(|| kdf_chain_step(black_box(&chain_key)))
    });
    
    c.bench_function("kdf_header_step", |b| {
        b.iter(|| kdf_header_step(black_box(&root_key)))
    });
}

fn bench_combine_secrets(c: &mut Criterion) {
    let classic = [0x42u8; 32];
    let quantum = [0x99u8; 32];
    
    c.bench_function("combine_secrets", |b| {
        b.iter(|| combine_secrets(black_box(&classic), black_box(&quantum)))
    });
}

fn bench_constant_time_eq(c: &mut Criterion) {
    let a = [0x42u8; 32];
    let b = [0x42u8; 32];
    let c_val = [0x99u8; 32];
    
    c.bench_function("constant_time_eq_equal", |b| {
        b.iter(|| constant_time_eq(black_box(&a), black_box(&b)))
    });
    
    c.bench_function("constant_time_eq_unequal", |b| {
        b.iter(|| constant_time_eq(black_box(&a), black_box(&c_val)))
    });
}

criterion_group!(
    benches,
    bench_generate_keypair,
    bench_encapsulate_decapsulate,
    bench_encrypt_decrypt,
    bench_kdf_operations,
    bench_combine_secrets,
    bench_constant_time_eq,
);
criterion_main!(benches);
