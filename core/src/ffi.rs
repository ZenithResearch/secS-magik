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

#[wasm_bindgen]
pub fn wasm_seal_intake_envelope_v1(
    recipient_public: &[u8],
    ephemeral_secret: &[u8],
    nonce: &[u8],
    intake: &[u8],
    requester_evidence: &[u8],
    expires_at_ms: u64,
) -> Result<Vec<u8>, JsValue> {
    let recipient_public: &[u8; 32] = recipient_public
        .try_into()
        .map_err(|_| JsValue::from_str("recipient_public must be exactly 32 bytes"))?;
    let ephemeral_secret: &[u8; 32] = ephemeral_secret
        .try_into()
        .map_err(|_| JsValue::from_str("ephemeral_secret must be exactly 32 bytes"))?;
    let nonce: &[u8; 12] = nonce
        .try_into()
        .map_err(|_| JsValue::from_str("nonce must be exactly 12 bytes"))?;
    crate::intake_envelope::seal_intake_envelope_v1(
        recipient_public,
        ephemeral_secret,
        nonce,
        intake,
        requester_evidence,
        expires_at_ms,
    )
    .map_err(|_| JsValue::from_str("intake envelope rejected"))
}
