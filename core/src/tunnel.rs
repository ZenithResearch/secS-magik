extern crate alloc;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(public_key).to_bytes()
}

/// Canonical AEAD associated data binding a tunnel ciphertext to its packet
/// envelope. Fixed byte order: `session_id` (16) || `opcode` (1) ||
/// `claim_ttl` (8, big-endian) — 25 bytes total. Both peers must derive the
/// AAD from the same envelope fields or decryption fails with an AEAD error.
pub fn packet_aad(session_id: &[u8; 16], opcode: u8, claim_ttl: u64) -> [u8; 25] {
    let mut aad = [0u8; 25];
    aad[..16].copy_from_slice(session_id);
    aad[16] = opcode;
    aad[17..].copy_from_slice(&claim_ttl.to_be_bytes());
    aad
}

pub fn encrypt_payload(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    plaintext: &[u8],
    aad: &[u8],
) -> Vec<u8> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encryption failure")
}

pub fn decrypt_payload(
    key_bytes: &[u8; 32],
    nonce_bytes: &[u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::aead::Error> {
    let key = Key::from(*key_bytes);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(
        nonce,
        Payload {
            msg: ciphertext,
            aad,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn test_tunnel_cycle() {
        let alice_secret = EphemeralSecret::random_from_rng(OsRng);
        let bob_secret = EphemeralSecret::random_from_rng(OsRng);

        // Dalek 2.0 requires explicitly converting the reference to a PublicKey
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);

        let alice_shared = derive_shared_secret(alice_secret, &bob_public);
        let bob_shared = derive_shared_secret(bob_secret, &alice_public);

        assert_eq!(alice_shared, bob_shared);

        let key_bytes = alice_shared;
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);

        let plaintext = b"Hello, secure tunnel!";
        let ciphertext = encrypt_payload(&key_bytes, &nonce_bytes, plaintext, b"");
        let decrypted = decrypt_payload(&key_bytes, &nonce_bytes, &ciphertext, b"")
            .expect("decryption failure");

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn encrypt_payload_adds_poly1305_authentication_tag() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let plaintext = b"authenticated bytes";

        let ciphertext = encrypt_payload(&key, &nonce, plaintext, b"");

        assert_eq!(ciphertext.len(), plaintext.len() + 16);
        assert_ne!(ciphertext, plaintext);
    }

    #[test]
    fn decrypt_payload_rejects_wrong_key() {
        let key = [1u8; 32];
        let wrong_key = [9u8; 32];
        let nonce = [2u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"secret", b"");

        assert!(decrypt_payload(&wrong_key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn decrypt_payload_rejects_wrong_nonce() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let wrong_nonce = [3u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"secret", b"");

        assert!(decrypt_payload(&key, &wrong_nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn decrypt_payload_rejects_tampered_ciphertext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut ciphertext = encrypt_payload(&key, &nonce, b"secret", b"");
        ciphertext[0] ^= 0x01;

        assert!(decrypt_payload(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn decrypt_payload_rejects_tampered_authentication_tag() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let mut ciphertext = encrypt_payload(&key, &nonce, b"secret", b"");
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0x80;

        assert!(decrypt_payload(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn encrypt_decrypt_round_trips_empty_payload() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let ciphertext = encrypt_payload(&key, &nonce, b"", b"");
        let plaintext = decrypt_payload(&key, &nonce, &ciphertext, b"").unwrap();

        assert!(plaintext.is_empty());
        assert_eq!(ciphertext.len(), 16);
    }

    #[test]
    fn decrypt_payload_rejects_empty_ciphertext() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];

        assert!(decrypt_payload(&key, &nonce, b"", b"").is_err());
    }

    #[test]
    fn same_plaintext_with_different_nonce_produces_different_ciphertext() {
        let key = [1u8; 32];
        let plaintext = b"nonce domain separation";
        let ciphertext_a = encrypt_payload(&key, &[2u8; 12], plaintext, b"");
        let ciphertext_b = encrypt_payload(&key, &[3u8; 12], plaintext, b"");

        assert_ne!(ciphertext_a, ciphertext_b);
    }

    #[test]
    fn packet_aad_uses_fixed_field_order() {
        let aad = packet_aad(&[0xAA; 16], 0x10, 300);

        assert_eq!(aad.len(), 25);
        assert_eq!(&aad[..16], &[0xAA; 16]);
        assert_eq!(aad[16], 0x10);
        assert_eq!(&aad[17..], &300u64.to_be_bytes());
    }

    #[test]
    fn aad_round_trips_with_matching_associated_data() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = packet_aad(&[0xAA; 16], 0x10, 300);

        let ciphertext = encrypt_payload(&key, &nonce, b"bound payload", &aad);
        let plaintext = decrypt_payload(&key, &nonce, &ciphertext, &aad).unwrap();

        assert_eq!(plaintext, b"bound payload");
    }

    #[test]
    fn decrypt_rejects_different_session_in_aad() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let encrypt_aad = packet_aad(&[0xAA; 16], 0x10, 300);
        let splice_aad = packet_aad(&[0xBB; 16], 0x10, 300);
        let ciphertext = encrypt_payload(&key, &nonce, b"bound payload", &encrypt_aad);

        assert!(decrypt_payload(&key, &nonce, &ciphertext, &splice_aad).is_err());
    }

    #[test]
    fn decrypt_rejects_different_opcode_in_aad() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let encrypt_aad = packet_aad(&[0xAA; 16], 0x10, 300);
        let splice_aad = packet_aad(&[0xAA; 16], 0x20, 300);
        let ciphertext = encrypt_payload(&key, &nonce, b"bound payload", &encrypt_aad);

        assert!(decrypt_payload(&key, &nonce, &ciphertext, &splice_aad).is_err());
    }

    #[test]
    fn decrypt_rejects_different_claim_ttl_in_aad() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let encrypt_aad = packet_aad(&[0xAA; 16], 0x10, 300);
        let splice_aad = packet_aad(&[0xAA; 16], 0x10, 301);
        let ciphertext = encrypt_payload(&key, &nonce, b"bound payload", &encrypt_aad);

        assert!(decrypt_payload(&key, &nonce, &ciphertext, &splice_aad).is_err());
    }

    #[test]
    fn aad_field_order_is_not_commutative() {
        // Swapping which bytes land in the session vs opcode/ttl positions must
        // not produce a colliding AAD.
        let a = packet_aad(&[0x10; 16], 0xAA, 300);
        let b = packet_aad(&[0xAA; 16], 0x10, 300);

        assert_ne!(a, b);
    }

    #[test]
    fn empty_plaintext_round_trips_with_aad() {
        let key = [1u8; 32];
        let nonce = [2u8; 12];
        let aad = packet_aad(&[0xAA; 16], 0x10, 300);

        let ciphertext = encrypt_payload(&key, &nonce, b"", &aad);
        assert_eq!(ciphertext.len(), 16);
        assert!(decrypt_payload(&key, &nonce, &ciphertext, &aad)
            .unwrap()
            .is_empty());
        assert!(decrypt_payload(&key, &nonce, &ciphertext, b"").is_err());
    }

    #[test]
    fn same_plaintext_with_different_key_produces_different_ciphertext() {
        let nonce = [2u8; 12];
        let plaintext = b"key domain separation";
        let ciphertext_a = encrypt_payload(&[1u8; 32], &nonce, plaintext, b"");
        let ciphertext_b = encrypt_payload(&[9u8; 32], &nonce, plaintext, b"");

        assert_ne!(ciphertext_a, ciphertext_b);
    }
}
