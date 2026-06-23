#![allow(clippy::missing_safety_doc)]

use crate::crypto::{self, HybridPublicKey, HybridSecretKey, HybridSigningKey};
use crate::handshake::{HandshakeEngine, InitialMessage, PreKeyBundle};
use crate::ratchet::{Message, RatchetEngine};
use crate::state::RatchetState;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jbyteArray, jlong, jstring, jboolean, JNI_TRUE};
use jni::JNIEnv;
use rand::thread_rng;
use serde::Serialize;
use zeroize::Zeroize;

#[derive(Serialize)]
struct JniKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

#[derive(Serialize)]
struct JniSigningKeyPair {
    verifying_key: Vec<u8>,
    signing_key: Vec<u8>,
}

#[derive(Serialize)]
struct JniAliceResult {
    state_ptr: jlong,
    initial_message: InitialMessage,
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_generate_1keypair(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let mut rng = thread_rng();
    let (pk, sk) = crypto::generate_hybrid_keypair(&mut rng);
    let keypair = JniKeyPair {
        public_key: pk.to_bytes(),
        secret_key: sk.to_bytes(),
    };
    match serde_json::to_string(&keypair) {
        Ok(json) => match env.new_string(json) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_generate_1signing_1keypair(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    let mut rng = thread_rng();
    let sk = HybridSigningKey::generate(&mut rng);
    let vk = sk.verifying_key();
    let keypair = JniSigningKeyPair {
        verifying_key: vk.to_bytes(),
        signing_key: sk.to_bytes(),
    };
    match serde_json::to_string(&keypair) {
        Ok(json) => match env.new_string(json) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_create_1bundle(
    env: JNIEnv,
    _class: JClass,
    identity_pk: jbyteArray,
    signing_key: jbyteArray,
) -> jstring {
    let identity_pk_obj = JByteArray::from_raw(identity_pk);
    let identity_pk_bytes = match env.convert_byte_array(&identity_pk_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let identity_pk = match HybridPublicKey::from_bytes(&identity_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return std::ptr::null_mut(),
    };

    let signing_key_obj = JByteArray::from_raw(signing_key);
    let signing_key_bytes = match env.convert_byte_array(&signing_key_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let signing_key = match HybridSigningKey::from_bytes(&signing_key_bytes) {
        Ok(sk) => sk,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut rng = thread_rng();
    let (signed_pk, _signed_sk) = crypto::generate_hybrid_keypair(&mut rng);
    let signature = signing_key.sign(&signed_pk.to_bytes());
    let verifying_key = signing_key.verifying_key();
    let (ot_pk, _ot_sk) = crypto::generate_hybrid_keypair(&mut rng);

    let bundle = PreKeyBundle {
        identity_pk,
        identity_verifying_key: verifying_key,
        signed_pre_key: signed_pk,
        signature,
        one_time_pre_key: Some(ot_pk),
    };

    match serde_json::to_string(&bundle) {
        Ok(json) => match env.new_string(json) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_init_1alice(
    mut env: JNIEnv,
    _class: JClass,
    remote_bundle_json: jstring,
    local_identity_pk: jbyteArray,
    local_identity_sk: jbyteArray,
) -> jstring {
    let bundle_jstr = JString::from_raw(remote_bundle_json);
    let bundle_str: String = match env.get_string(&bundle_jstr) {
        Ok(s) => s.into(),
        Err(_) => return std::ptr::null_mut(),
    };
    let remote_bundle: PreKeyBundle = match serde_json::from_str(&bundle_str) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let local_pk_obj = JByteArray::from_raw(local_identity_pk);
    let local_pk_bytes = match env.convert_byte_array(&local_pk_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let local_identity_pk = match HybridPublicKey::from_bytes(&local_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return std::ptr::null_mut(),
    };

    let local_sk_obj = JByteArray::from_raw(local_identity_sk);
    let local_sk_bytes = match env.convert_byte_array(&local_sk_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };
    let local_identity_sk = match HybridSecretKey::from_bytes(&local_sk_bytes) {
        Ok(sk) => sk,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut rng = thread_rng();
    match HandshakeEngine::initiate_alice(&remote_bundle, &local_identity_pk, &local_identity_sk, &mut rng) {
        Ok((state, initial_message, _root_key)) => {
            let state_ptr = Box::into_raw(Box::new(state)) as jlong;
            let result = JniAliceResult { state_ptr, initial_message };
            match serde_json::to_string(&result) {
                Ok(json) => match env.new_string(json) {
                    Ok(js) => js.into_raw(),
                    Err(_) => std::ptr::null_mut(),
                },
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_respond_1bob(
    mut env: JNIEnv,
    _class: JClass,
    initial_msg_json: jstring,
    local_identity_pk: jbyteArray,
    local_identity_sk: jbyteArray,
    local_signed_sk: jbyteArray,
    local_ot_sk: jbyteArray,
    has_ot_sk: jboolean,
) -> jlong {
    let msg_jstr = JString::from_raw(initial_msg_json);
    let msg_str: String = match env.get_string(&msg_jstr) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let initial_msg: InitialMessage = match serde_json::from_str(&msg_str) {
        Ok(m) => m,
        Err(_) => return 0,
    };

    let local_pk_obj = JByteArray::from_raw(local_identity_pk);
    let local_pk_bytes = match env.convert_byte_array(&local_pk_obj) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let local_identity_pk = match HybridPublicKey::from_bytes(&local_pk_bytes) {
        Ok(pk) => pk,
        Err(_) => return 0,
    };

    let local_sk_obj = JByteArray::from_raw(local_identity_sk);
    let local_sk_bytes = match env.convert_byte_array(&local_sk_obj) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let local_identity_sk = match HybridSecretKey::from_bytes(&local_sk_bytes) {
        Ok(sk) => sk,
        Err(_) => return 0,
    };

    let signed_sk_obj = JByteArray::from_raw(local_signed_sk);
    let signed_sk_bytes = match env.convert_byte_array(&signed_sk_obj) {
        Ok(b) => b,
        Err(_) => return 0,
    };
    let local_signed_sk = match HybridSecretKey::from_bytes(&signed_sk_bytes) {
        Ok(sk) => sk,
        Err(_) => return 0,
    };

    let ot_sk = if has_ot_sk == JNI_TRUE {
        let ot_sk_obj = JByteArray::from_raw(local_ot_sk);
        let ot_sk_bytes = match env.convert_byte_array(&ot_sk_obj) {
            Ok(b) => b,
            Err(_) => return 0,
        };
        match HybridSecretKey::from_bytes(&ot_sk_bytes) {
            Ok(sk) => Some(sk),
            Err(_) => return 0,
        }
    } else {
        None
    };

    match HandshakeEngine::respond_bob(&initial_msg, &local_identity_pk, &local_identity_sk, &local_signed_sk, ot_sk.as_ref()) {
        Ok((state, _root_key)) => Box::into_raw(Box::new(state)) as jlong,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_encrypt(
    env: JNIEnv,
    _class: JClass,
    state_ptr: jlong,
    plaintext: jbyteArray,
    ad: jbyteArray,
) -> jstring {
    let state = &mut *(state_ptr as *mut RatchetState);

    let plaintext_obj = JByteArray::from_raw(plaintext);
    let plaintext_bytes = match env.convert_byte_array(&plaintext_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let ad_obj = JByteArray::from_raw(ad);
    let ad_bytes = match env.convert_byte_array(&ad_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let mut rng = thread_rng();
    let msg = RatchetEngine::encrypt(state, &plaintext_bytes, &ad_bytes, &mut rng);

    match serde_json::to_string(&msg) {
        Ok(json) => match env.new_string(json) {
            Ok(js) => js.into_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_decrypt(
    env: JNIEnv,
    _class: JClass,
    state_ptr: jlong,
    header: jbyteArray,
    payload: jbyteArray,
    ad: jbyteArray,
) -> jbyteArray {
    let state = unsafe { &mut *(state_ptr as *mut RatchetState) };

    let header_obj = unsafe { JByteArray::from_raw(header) };
    let header_bytes = match env.convert_byte_array(&header_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let payload_obj = unsafe { JByteArray::from_raw(payload) };
    let payload_bytes = match env.convert_byte_array(&payload_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let ad_obj = unsafe { JByteArray::from_raw(ad) };
    let ad_bytes = match env.convert_byte_array(&ad_obj) {
        Ok(b) => b,
        Err(_) => return std::ptr::null_mut(),
    };

    let message = Message {
        header_ciphertext: header_bytes,
        payload_ciphertext: payload_bytes,
    };

    match RatchetEngine::decrypt(state, &message, &ad_bytes) {
        Ok(plaintext) => match env.byte_array_from_slice(&plaintext) {
            Ok(arr) => arr.as_raw(),
            Err(_) => std::ptr::null_mut(),
        },
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_init_1state(
    env: JNIEnv,
    _class: JClass,
    serialized_state: jbyteArray,
) -> jlong {
    let obj = unsafe { JByteArray::from_raw(serialized_state) };
    let bytes = match env.convert_byte_array(&obj) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    match serde_json::from_slice::<RatchetState>(&bytes) {
        Ok(state) => Box::into_raw(Box::new(state)) as jlong,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_load_1atomic(
    mut env: JNIEnv,
    _class: JClass,
    path: jni::sys::jstring,
    key: jbyteArray,
) -> jlong {
    let path_obj = unsafe { JString::from_raw(path) };
    let path_str: String = match env.get_string(&path_obj) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let key_obj = unsafe { JByteArray::from_raw(key) };
    let key_bytes = match env.convert_byte_array(&key_obj) {
        Ok(b) => b,
        Err(_) => return 0,
    };

    if key_bytes.len() != 32 {
        return 0;
    }

    let path = std::path::Path::new(&path_str);
    let key_material = crate::crypto::SecretKeyMaterial::from_bytes(&key_bytes);

    match RatchetState::load_atomic(path, &key_material) {
        Ok(state) => Box::into_raw(Box::new(state)) as jlong,
        Err(_) => 0,
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_save_1atomic(
    mut env: JNIEnv,
    _class: JClass,
    state_ptr: jlong,
    path: jni::sys::jstring,
    key: jbyteArray,
) -> jni::sys::jboolean {
    let state = unsafe { &*(state_ptr as *const RatchetState) };

    let path_obj = unsafe { JString::from_raw(path) };
    let path_str: String = match env.get_string(&path_obj) {
        Ok(s) => s.into(),
        Err(_) => return jni::sys::JNI_FALSE,
    };

    let key_obj = unsafe { JByteArray::from_raw(key) };
    let key_bytes = match env.convert_byte_array(&key_obj) {
        Ok(b) => b,
        Err(_) => return jni::sys::JNI_FALSE,
    };

    if key_bytes.len() != 32 {
        return jni::sys::JNI_FALSE;
    }

    let path = std::path::Path::new(&path_str);
    let key_material = crate::crypto::SecretKeyMaterial::from_bytes(&key_bytes);

    if state.save_atomic(path, &key_material).is_ok() {
        jni::sys::JNI_TRUE
    } else {
        jni::sys::JNI_FALSE
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_com_pqaura_PqAuraNative_free_1state(
    _env: JNIEnv,
    _class: JClass,
    state_ptr: jlong,
) {
    if state_ptr != 0 {
        unsafe {
            let mut state = Box::from_raw(state_ptr as *mut RatchetState);
            state.zeroize();
        }
    }
}
