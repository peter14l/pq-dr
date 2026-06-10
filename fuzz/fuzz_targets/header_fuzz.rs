#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_aura::ratchet::Header;

fuzz_target!(|data: &[u8]| {
    // Fuzz Header::from_bytes with random data - should never panic
    let _ = Header::from_bytes(data);
});
