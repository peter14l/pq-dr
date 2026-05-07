use crate::ratchet::{Message, RatchetEngine};
use crate::state::RatchetState;
use jni::objects::{JClass, JByteArray, JString};
use jni::sys::{jbyteArray, jlong};
use jni::JNIEnv;

#[no_mangle]
pub extern "system" fn Java_com_oasis_app_PqAuraNative_decrypt(
    mut env: JNIEnv,
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
        Ok(plaintext) => {
            match env.byte_array_from_slice(&plaintext) {
                Ok(arr) => arr.as_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_oasis_app_PqAuraNative_init_1state(
    mut env: JNIEnv,
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
pub extern "system" fn Java_com_oasis_app_PqAuraNative_load_1atomic(
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
pub extern "system" fn Java_com_oasis_app_PqAuraNative_save_1atomic(
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
pub extern "system" fn Java_com_oasis_app_PqAuraNative_free_1state(
    _env: JNIEnv,
    _class: JClass,
    state_ptr: jlong,
) {
    if state_ptr != 0 {
        unsafe {
            let _ = Box::from_raw(state_ptr as *mut RatchetState);
        }
    }
}
