#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_aura::handshake::*;

fuzz_target!(|data: &[u8]| {
    // Fuzz PreKeyBundle::from_bytes with random data - should never panic
    let _ = PreKeyBundle::from_bytes(data);
    
    // Fuzz InitialMessage::from_bytes with random data - should never panic
    let _ = InitialMessage::from_bytes(data);
});
