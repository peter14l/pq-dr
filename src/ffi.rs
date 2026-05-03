use crate::crypto::{self, HybridPublicKey, HybridSecretKey, SecretKeyMaterial};
use crate::handshake::{HandshakeEngine, InitialMessage, PreKeyBundle};
use crate::ratchet::{Message, RatchetEngine};
use crate::state::RatchetState;
use rand::thread_rng;
use std::ffi::CStr;
use std::path::Path;
use std::ptr::null_mut;

/// A simple FFI-friendly wrapper for a Message.
#[repr(C)]
pub struct FfiMessage {
    pub header: *mut u8,
    pub header_len: usize,
    pub payload: *mut u8,
    pub payload_len: usize,
}

/// FFI-friendly wrapper for a HybridPublicKey (opaque pointer for now, serialized via bytes).
/// Use pqa_serialize_public_key() and pqa_deserialize_public_key() for transfer.
#[repr(C)]
pub struct FfiKeyPair {
    pub public_key: *mut u8,
    pub public_key_len: usize,
    pub secret_key: *mut u8, // Opaque handle - in Rust we keep the secret internally
    pub secret_key_len: usize,
}

/// FFI-friendly wrapper for a PreKeyBundle.
#[repr(C)]
pub struct FfiPreKeyBundle {
    pub identity_pk: *mut u8,
    pub identity_pk_len: usize,
    pub signed_pre_key: *mut u8,
    pub signed_pre_key_len: usize,
    pub one_time_pre_key: *mut u8,
    pub one_time_pre_key_len: usize,
    pub has_one_time: bool,
}

/// FFI-friendly wrapper for an InitialMessage.
#[repr(C)]
pub struct FfiInitialMessage {
    pub state_ptr: *mut RatchetState, // Alice's new state
    pub alice_identity_pk: *mut u8,
    pub alice_identity_pk_len: usize,
    pub ephemeral_pk: *mut u8,
    pub ephemeral_pk_len: usize,
    pub kem_ciphertext_identity: *mut u8,
    pub kem_ciphertext_identity_len: usize,
    pub kem_ciphertext_signed: *mut u8,
    pub kem_ciphertext_signed_len: usize,
    pub kem_ciphertext_one_time: *mut u8,
    pub kem_ciphertext_one_time_len: usize,
    pub has_one_time: bool,
    pub ratchet_message_header: *mut u8,
    pub ratchet_message_header_len: usize,
    pub ratchet_message_payload: *mut u8,
    pub ratchet_message_payload_len: usize,
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

    let header_vec = msg.header_ciphertext;
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
    let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
        msg.header,
        msg.header_len,
    ));
    let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
        msg.payload,
        msg.payload_len,
    ));
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
    let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
}

// ============================================================================
// Key Management FFI Functions
// ============================================================================

/// Generates a new hybrid keypair (X25519 + ML-KEM-1024).
///
/// # Safety
/// Returns a pointer to an FfiKeyPair. Caller must free with pqa_free_keypair.
#[no_mangle]
pub unsafe extern "C" fn pqa_generate_keypair() -> *mut FfiKeyPair {
    let mut rng = thread_rng();
    let (public_key, secret_key) = crypto::generate_hybrid_keypair(&mut rng);

    // Serialize keys to bytes using to_bytes() for FFI-friendly format
    let pk_bytes = public_key.to_bytes();
    let sk_bytes = secret_key.to_bytes();

    // Save lengths before moving the vectors
    let pk_len = pk_bytes.len();
    let sk_len = sk_bytes.len();

    let ffi_kp = Box::new(FfiKeyPair {
        public_key: Box::into_raw(pk_bytes.into_boxed_slice()) as *mut u8,
        public_key_len: pk_len,
        secret_key: Box::into_raw(sk_bytes.into_boxed_slice()) as *mut u8,
        secret_key_len: sk_len,
    });

    Box::into_raw(ffi_kp)
}

/// Frees a keypair allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_keypair(kp_ptr: *mut FfiKeyPair) {
    if kp_ptr.is_null() {
        return;
    }
    let kp = Box::from_raw(kp_ptr);
    if !kp.public_key.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            kp.public_key,
            kp.public_key_len,
        ));
    }
    if !kp.secret_key.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            kp.secret_key,
            kp.secret_key_len,
        ));
    }
}

/// Creates a PreKeyBundle from an identity public key.
/// Generates a signed pre-key and one-time pre-key internally.
///
/// # Safety
/// `identity_pk_ptr` must point to valid hybrid public key bytes (32 + 1568 bytes).
/// Returns a pointer to an FfiPreKeyBundle. Caller must free with pqa_free_bundle.
#[no_mangle]
pub unsafe extern "C" fn pqa_create_bundle(
    identity_pk_ptr: *const u8,
    identity_pk_len: usize,
) -> *mut FfiPreKeyBundle {
    let identity_pk_bytes = std::slice::from_raw_parts(identity_pk_ptr, identity_pk_len);
    let identity_pk: HybridPublicKey =
        HybridPublicKey::from_bytes(identity_pk_bytes).expect("Invalid identity public key");

    let mut rng = thread_rng();

    // Generate signed pre-key
    let (signed_pk, _signed_sk) = crypto::generate_hybrid_keypair(&mut rng);

    // Generate one-time pre-key
    let (ot_pk, _ot_sk) = crypto::generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk,
        signed_pre_key: signed_pk,
        one_time_pre_key: Some(ot_pk),
    };

    // Serialize bundle components using to_bytes()
    let identity_pk_bytes = bundle.identity_pk.to_bytes();
    let signed_pk_bytes = bundle.signed_pre_key.to_bytes();
    let ot_pk_bytes = bundle.one_time_pre_key.as_ref().map(|pk| pk.to_bytes());

    let ffi_bundle = Box::new(FfiPreKeyBundle {
        identity_pk: Box::into_raw(identity_pk_bytes.clone().into_boxed_slice()) as *mut u8,
        identity_pk_len: identity_pk_bytes.len(),
        signed_pre_key: Box::into_raw(signed_pk_bytes.clone().into_boxed_slice()) as *mut u8,
        signed_pre_key_len: signed_pk_bytes.len(),
        one_time_pre_key: ot_pk_bytes
            .as_ref()
            .map(|v| Box::into_raw(v.clone().into_boxed_slice()) as *mut u8)
            .unwrap_or(null_mut()),
        one_time_pre_key_len: ot_pk_bytes.as_ref().map(|v| v.len()).unwrap_or(0),
        has_one_time: ot_pk_bytes.is_some(),
    });

    Box::into_raw(ffi_bundle)
}

/// Frees a bundle allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_bundle(bundle_ptr: *mut FfiPreKeyBundle) {
    if bundle_ptr.is_null() {
        return;
    }
    let bundle = Box::from_raw(bundle_ptr);
    if !bundle.identity_pk.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bundle.identity_pk,
            bundle.identity_pk_len,
        ));
    }
    if !bundle.signed_pre_key.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bundle.signed_pre_key,
            bundle.signed_pre_key_len,
        ));
    }
    if !bundle.one_time_pre_key.is_null() && bundle.has_one_time {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            bundle.one_time_pre_key,
            bundle.one_time_pre_key_len,
        ));
    }
}

// ============================================================================
// Handshake FFI Functions
// ============================================================================

/// Initiates a session as Alice (initiator).
///
/// # Safety
/// `remote_bundle_ptr` must point to a valid serialized PreKeyBundle (JSON bytes).
/// `local_identity_pk_ptr` must point to valid HybridPublicKey bytes (32 + 1568 bytes).
/// `local_identity_sk_ptr` must point to valid HybridSecretKey bytes (32 + 3168 bytes).
/// Returns a pointer to an FfiInitialMessage. Caller must free with pqa_free_initial_message.
/// The caller can retrieve the state pointer from the returned FfiInitialMessage.state_ptr field.
#[no_mangle]
pub unsafe extern "C" fn pqa_init_alice(
    remote_bundle_ptr: *const u8,
    remote_bundle_len: usize,
    local_identity_pk_ptr: *const u8,
    local_identity_pk_len: usize,
    local_identity_sk_ptr: *const u8,
    local_identity_sk_len: usize,
) -> *mut FfiInitialMessage {
    let remote_bundle_bytes = std::slice::from_raw_parts(remote_bundle_ptr, remote_bundle_len);
    let remote_bundle: PreKeyBundle =
        serde_json::from_slice(remote_bundle_bytes).expect("Invalid remote bundle");

    let local_pk_bytes = std::slice::from_raw_parts(local_identity_pk_ptr, local_identity_pk_len);
    let local_identity_pk =
        HybridPublicKey::from_bytes(local_pk_bytes).expect("Invalid local identity public key");

    let local_sk_bytes = std::slice::from_raw_parts(local_identity_sk_ptr, local_identity_sk_len);
    let local_identity_sk =
        HybridSecretKey::from_bytes(local_sk_bytes).expect("Invalid local identity secret key");

    let mut rng = thread_rng();
    let (state, initial_msg, _root_key) = HandshakeEngine::initiate_alice(
        &remote_bundle,
        &local_identity_pk,
        &local_identity_sk,
        &mut rng,
    );

    // Box the state and get pointer
    let state_box = Box::new(state);
    let state_ptr = Box::into_raw(state_box) as *mut RatchetState;

    // Build FFI InitialMessage
    // Serialize keys using to_bytes() - save lengths BEFORE moving
    let alice_pk_bytes = initial_msg.alice_identity_pk.to_bytes();
    let alice_pk_len = alice_pk_bytes.len();
    let ephemeral_pk_bytes = initial_msg.ephemeral_pk.to_bytes();
    let ephemeral_pk_len = ephemeral_pk_bytes.len();

    let kem_identity = initial_msg.kem_ciphertext_identity.clone();
    let kem_identity_len = kem_identity.len();
    let kem_signed = initial_msg.kem_ciphertext_signed.clone();
    let kem_signed_len = kem_signed.len();
    let kem_one_time = initial_msg.kem_ciphertext_one_time.clone();
    let kem_one_time_len = kem_one_time.as_ref().map(|v| v.len()).unwrap_or(0);
    let has_one_time = kem_one_time.is_some();

    // Serialize the ratchet message
    let header_bytes = initial_msg.ratchet_message.header_ciphertext.clone();
    let header_len = header_bytes.len();
    let payload_bytes = initial_msg.ratchet_message.payload_ciphertext.clone();
    let payload_len = payload_bytes.len();

    let ffi_msg = Box::new(FfiInitialMessage {
        state_ptr, // Store state pointer in the struct
        alice_identity_pk: Box::into_raw(alice_pk_bytes.into_boxed_slice()) as *mut u8,
        alice_identity_pk_len: alice_pk_len,
        ephemeral_pk: Box::into_raw(ephemeral_pk_bytes.into_boxed_slice()) as *mut u8,
        ephemeral_pk_len: ephemeral_pk_len,
        kem_ciphertext_identity: Box::into_raw(kem_identity.into_boxed_slice()) as *mut u8,
        kem_ciphertext_identity_len: kem_identity_len,
        kem_ciphertext_signed: Box::into_raw(kem_signed.into_boxed_slice()) as *mut u8,
        kem_ciphertext_signed_len: kem_signed_len,
        kem_ciphertext_one_time: kem_one_time
            .as_ref()
            .map(|v| Box::into_raw(v.clone().into_boxed_slice()) as *mut u8)
            .unwrap_or(null_mut()),
        kem_ciphertext_one_time_len: kem_one_time_len,
        has_one_time,
        ratchet_message_header: Box::into_raw(header_bytes.into_boxed_slice()) as *mut u8,
        ratchet_message_header_len: header_len,
        ratchet_message_payload: Box::into_raw(payload_bytes.into_boxed_slice()) as *mut u8,
        ratchet_message_payload_len: payload_len,
    });

    Box::into_raw(ffi_msg)
}

/// Responds to an initial message as Bob (receiver).
///
/// # Safety
/// `initial_msg_ptr` must point to valid InitialMessage bytes (JSON serialized).
/// `local_identity_pk_ptr` must point to valid HybridPublicKey bytes (from to_bytes()).
/// `local_identity_sk_ptr` must point to valid HybridSecretKey bytes (from to_bytes()).
/// `local_signed_sk_ptr` must point to valid HybridSecretKey bytes (from to_bytes()).
/// `local_ot_sk_ptr` may be null if no one-time pre-key.
/// Returns a pointer to a RatchetState. Caller must free with pqa_free_state.
#[no_mangle]
pub unsafe extern "C" fn pqa_init_bob(
    initial_msg_ptr: *const u8,
    initial_msg_len: usize,
    local_identity_pk_ptr: *const u8,
    local_identity_pk_len: usize,
    local_identity_sk_ptr: *const u8,
    local_identity_sk_len: usize,
    local_signed_sk_ptr: *const u8,
    local_signed_sk_len: usize,
    local_ot_sk_ptr: *const u8,
    local_ot_sk_len: usize,
    has_ot_sk: bool,
) -> *mut RatchetState {
    let initial_msg_bytes = std::slice::from_raw_parts(initial_msg_ptr, initial_msg_len);
    let initial_msg: InitialMessage =
        serde_json::from_slice(initial_msg_bytes).expect("Invalid initial message");

    let local_pk_bytes = std::slice::from_raw_parts(local_identity_pk_ptr, local_identity_pk_len);
    let local_identity_pk =
        HybridPublicKey::from_bytes(local_pk_bytes).expect("Invalid local identity public key");

    let local_sk_bytes = std::slice::from_raw_parts(local_identity_sk_ptr, local_identity_sk_len);
    let local_identity_sk =
        HybridSecretKey::from_bytes(local_sk_bytes).expect("Invalid local identity secret key");

    let signed_sk_bytes = std::slice::from_raw_parts(local_signed_sk_ptr, local_signed_sk_len);
    let local_signed_sk =
        HybridSecretKey::from_bytes(signed_sk_bytes).expect("Invalid signed secret key");

    let local_ot_sk = if has_ot_sk && !local_ot_sk_ptr.is_null() {
        let ot_sk_bytes = std::slice::from_raw_parts(local_ot_sk_ptr, local_ot_sk_len);
        Some(HybridSecretKey::from_bytes(ot_sk_bytes).expect("Invalid one-time secret key"))
    } else {
        None
    };

    let (state, _root_key) = HandshakeEngine::respond_bob(
        &initial_msg,
        &local_identity_pk,
        &local_identity_sk,
        &local_signed_sk,
        local_ot_sk.as_ref(),
    )
    .expect("Failed to respond to initial message");

    Box::into_raw(Box::new(state))
}

// ============================================================================
// State Serialization FFI Functions
// ============================================================================

/// Serializes a RatchetState to bytes for persistent storage.
///
/// # Safety
/// `state_ptr` must be a valid pointer to a RatchetState.
/// Returns a pointer to the serialized bytes. Caller must free with pqa_free_buffer.
#[no_mangle]
pub unsafe extern "C" fn pqa_serialize_state(state_ptr: *const RatchetState) -> *mut u8 {
    let state = &*state_ptr;
    let serialized = serde_json::to_vec(state).expect("Failed to serialize state");
    Box::into_raw(serialized.into_boxed_slice()) as *mut u8
}

/// Returns the length of the serialized state (call this first to allocate buffer).
///
/// # Safety
/// `state_ptr` must be a valid pointer to a RatchetState.
#[no_mangle]
pub unsafe extern "C" fn pqa_serialize_state_len(state_ptr: *const RatchetState) -> usize {
    let state = &*state_ptr;
    serde_json::to_vec(state)
        .expect("Failed to serialize state")
        .len()
}

/// Deserializes bytes back into a RatchetState.
///
/// # Safety
/// `bytes_ptr` must point to valid serialized RatchetState bytes.
/// Returns a pointer to the deserialized RatchetState. Caller must free with pqa_free_state.
#[no_mangle]
pub unsafe extern "C" fn pqa_deserialize_state(
    bytes_ptr: *const u8,
    bytes_len: usize,
) -> *mut RatchetState {
    let bytes = std::slice::from_raw_parts(bytes_ptr, bytes_len);
    let state: RatchetState = serde_json::from_slice(bytes).expect("Failed to deserialize state");
    Box::into_raw(Box::new(state))
}

/// Frees a RatchetState allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_state(state_ptr: *mut RatchetState) {
    if !state_ptr.is_null() {
        let _ = Box::from_raw(state_ptr);
    }
}

/// Frees an initial message allocated by the FFI.
///
/// # Safety
/// This function is unsafe because it handles raw pointers.
#[no_mangle]
pub unsafe extern "C" fn pqa_free_initial_message(msg_ptr: *mut FfiInitialMessage) {
    if msg_ptr.is_null() {
        return;
    }
    let msg = Box::from_raw(msg_ptr);
    if !msg.alice_identity_pk.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.alice_identity_pk,
            msg.alice_identity_pk_len,
        ));
    }
    if !msg.ephemeral_pk.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.ephemeral_pk,
            msg.ephemeral_pk_len,
        ));
    }
    if !msg.kem_ciphertext_identity.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.kem_ciphertext_identity,
            msg.kem_ciphertext_identity_len,
        ));
    }
    if !msg.kem_ciphertext_signed.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.kem_ciphertext_signed,
            msg.kem_ciphertext_signed_len,
        ));
    }
    if !msg.kem_ciphertext_one_time.is_null() && msg.has_one_time {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.kem_ciphertext_one_time,
            msg.kem_ciphertext_one_time_len,
        ));
    }
    if !msg.ratchet_message_header.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.ratchet_message_header,
            msg.ratchet_message_header_len,
        ));
    }
    if !msg.ratchet_message_payload.is_null() {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            msg.ratchet_message_payload,
            msg.ratchet_message_payload_len,
        ));
    }
}

/// Atomically saves the state to a file.
///
/// # Safety
/// `path_ptr` must be a null-terminated UTF-8 string.
/// `key_ptr` must point to 32 bytes of key material.
#[no_mangle]
pub unsafe extern "C" fn pqa_save_atomic(
    state_ptr: *const RatchetState,
    path_ptr: *const i8,
    key_ptr: *const u8,
) -> bool {
    let state = &*state_ptr;
    let path_str = CStr::from_ptr(path_ptr).to_str().unwrap();
    let path = Path::new(path_str);

    let key_bytes = std::slice::from_raw_parts(key_ptr, 32);
    let key = SecretKeyMaterial::from_bytes(key_bytes);

    state.save_atomic(path, &key).is_ok()
}

/// Loads the state from an atomically saved file.
///
/// # Safety
/// `path_ptr` must be a null-terminated UTF-8 string.
/// `key_ptr` must point to 32 bytes of key material.
#[no_mangle]
pub unsafe extern "C" fn pqa_load_atomic(
    path_ptr: *const i8,
    key_ptr: *const u8,
) -> *mut RatchetState {
    let path_str = CStr::from_ptr(path_ptr).to_str().unwrap();
    let path = Path::new(path_str);

    let key_bytes = std::slice::from_raw_parts(key_ptr, 32);
    let key = SecretKeyMaterial::from_bytes(key_bytes);

    match RatchetState::load_atomic(path, &key) {
        Ok(state) => Box::into_raw(Box::new(state)),
        Err(_) => std::ptr::null_mut(),
    }
}
