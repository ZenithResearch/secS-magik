#![cfg(target_arch = "wasm32")]
#![cfg(feature = "uniffi")]

extern crate alloc;
use alloc::vec::Vec;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_encrypt(key_bytes: &[u8], nonce_bytes: &[u8], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let key_array: &[u8; 32] = key_bytes
        .try_into()
        .expect("key_bytes must be exactly 32 bytes");
    let nonce_array: &[u8; 12] = nonce_bytes
        .try_into()
        .expect("nonce_bytes must be exactly 12 bytes");
    crate::tunnel::encrypt_payload(key_array, nonce_array, plaintext, aad)
}

#[wasm_bindgen]
pub fn wasm_decrypt(
    key_bytes: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let key_array: &[u8; 32] = key_bytes
        .try_into()
        .expect("key_bytes must be exactly 32 bytes");
    let nonce_array: &[u8; 12] = nonce_bytes
        .try_into()
        .expect("nonce_bytes must be exactly 12 bytes");
    crate::tunnel::decrypt_payload(key_array, nonce_array, ciphertext, aad)
        .map_err(|_| JsValue::from_str("decryption failed"))
}
