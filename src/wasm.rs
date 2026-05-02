use crate::ratchet::{Message, RatchetEngine};
use crate::state::RatchetState;
use rand::thread_rng;
use wasm_bindgen::prelude::*;

/// Wrapper for the RatchetState to be used in JS/Wasm.
#[wasm_bindgen]
pub struct WasmRatchetState {
    inner: RatchetState,
}

#[wasm_bindgen]
impl WasmRatchetState {
    /// Note: Initializing state usually requires keys.
    /// In a real app, you'd pass serialized keys or perform a handshake.
    pub fn dummy_init() -> Self {
        panic!("Initialization requires proper keys. Use a handshake to create a RatchetState.");
    }
}

#[wasm_bindgen]
pub struct WasmMessage {
    header: Vec<u8>,
    payload: Vec<u8>,
}

#[wasm_bindgen]
impl WasmMessage {
    #[wasm_bindgen(getter)]
    pub fn header(&self) -> Vec<u8> {
        self.header.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Vec<u8> {
        self.payload.clone()
    }
}

#[wasm_bindgen]
pub fn pqa_encrypt_wasm(state: &mut WasmRatchetState, plaintext: &[u8], ad: &[u8]) -> WasmMessage {
    let mut rng = thread_rng();
    let msg = RatchetEngine::encrypt(&mut state.inner, plaintext, ad, &mut rng);

    WasmMessage {
        header: serde_json::to_vec(&msg.header_ciphertext).unwrap(),
        payload: msg.payload_ciphertext,
    }
}

#[wasm_bindgen]
pub fn pqa_decrypt_wasm(
    state: &mut WasmRatchetState,
    header: &[u8],
    payload: &[u8],
    ad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let message = Message {
        header_ciphertext: header.to_vec(),
        payload_ciphertext: payload.to_vec(),
    };

    RatchetEngine::decrypt(&mut state.inner, &message, ad).map_err(|e| JsValue::from_str(e))
}
