use crate::ratchet::{Message, RatchetEngine};
use crate::state::RatchetState;
use rand::thread_rng;

/// A simple FFI-friendly wrapper for a Message.
#[repr(C)]
pub struct FfiMessage {
    pub header: *mut u8,
    pub header_len: usize,
    pub payload: *mut u8,
    pub payload_len: usize,
}

/// Encrypts a message from Flutter.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_encrypt(
    state_ptr: *mut RatchetState,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    ad_ptr: *const u8,
    ad_len: usize,
) -> *mut FfiMessage {
    let state = &mut *state_ptr;
    let plaintext = std::slice::from_raw_parts(plaintext_ptr, plaintext_len);
    let ad = std::slice::from_raw_parts(ad_ptr, ad_len);
    let mut rng = thread_rng();

    let msg = RatchetEngine::encrypt(state, plaintext, ad, &mut rng);

    let header_vec = serde_json::to_vec(&msg.header_ciphertext).unwrap();
    let payload_vec = msg.payload_ciphertext;

    let ffi_msg = Box::new(FfiMessage {
        header_len: header_vec.len(),
        header: Box::into_raw(header_vec.into_boxed_slice()) as *mut u8,
        payload_len: payload_vec.len(),
        payload: Box::into_raw(payload_vec.into_boxed_slice()) as *mut u8,
    });

    Box::into_raw(ffi_msg)
}

/// Decrypts a message from Flutter.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_decrypt(
    state_ptr: *mut RatchetState,
    header_ptr: *const u8,
    header_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    ad_ptr: *const u8,
    ad_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let state = &mut *state_ptr;
    let header_ciphertext = std::slice::from_raw_parts(header_ptr, header_len);
    let payload_ciphertext = std::slice::from_raw_parts(payload_ptr, payload_len);
    let ad = std::slice::from_raw_parts(ad_ptr, ad_len);

    // Reconstruct the Message object
    let message = Message {
        header_ciphertext: header_ciphertext.to_vec(),
        payload_ciphertext: payload_ciphertext.to_vec(),
    };

    match RatchetEngine::decrypt(state, &message, ad) {
        Ok(plaintext) => {
            *out_len = plaintext.len();
            Box::into_raw(plaintext.into_boxed_slice()) as *mut u8
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Frees a message allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_message(msg_ptr: *mut FfiMessage) {
    if msg_ptr.is_null() {
        return;
    }
    let msg = Box::from_raw(msg_ptr);
    let _ = Box::from_raw(std::slice::from_raw_parts_mut(msg.header, msg.header_len));
    let _ = Box::from_raw(std::slice::from_raw_parts_mut(msg.payload, msg.payload_len));
}

/// Frees a buffer allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_buffer(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let _ = Box::from_raw(std::slice::from_raw_parts_mut(ptr, len));
}
