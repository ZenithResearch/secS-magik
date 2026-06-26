extern crate alloc;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, Key, KeyInit, Nonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPublicKeySummary {
    pub key_id: String,
    pub public_key_hex: String,
}

pub fn tunnel_public_key_id(public_key: &[u8; 32]) -> String {
    let digest = Sha256::digest(public_key);
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("tunnel:x25519:{hex}")
}

pub fn tunnel_public_key_summary(public_key: &[u8; 32]) -> TunnelPublicKeySummary {
    TunnelPublicKeySummary {
        key_id: tunnel_public_key_id(public_key),
        public_key_hex: public_key
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

pub fn derive_shared_secret(secret: EphemeralSecret, public_key: &PublicKey) -> [u8; 32] {
    secret.diffie_hellman(public_key).to_bytes()
}

const SECS_TUNNEL_HKDF_INFO_V1: &[u8] = b"secs-magik tunnel key v1";

pub fn parse_tunnel_key_hex(input: &str) -> Option<[u8; 32]> {
    let clean = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
        .unwrap_or(input)
        .trim();

    if clean.len() != 64 {
        return None;
    }

    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        let end = start + 2;
        *byte = u8::from_str_radix(&clean[start..end], 16).ok()?;
    }
    Some(out)
}

pub fn derive_tunnel_key_hkdf(
    shared_secret: &[u8; 32],
    session_id: &[u8; 16],
    client_public: &[u8; 32],
    server_public: &[u8; 32],
) -> [u8; 32] {
    let mut salt = [0u8; 80];
    salt[..16].copy_from_slice(session_id);
    salt[16..48].copy_from_slice(client_public);
    salt[48..].copy_from_slice(server_public);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut out = [0u8; 32];
    hk.expand(SECS_TUNNEL_HKDF_INFO_V1, &mut out)
        .expect("HKDF output length is fixed and valid");
    out
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
    #[test]
    fn hkdf_derived_tunnel_key_matches_on_both_peers_and_binds_session() {
        let alice_secret = EphemeralSecret::random_from_rng(OsRng);
        let bob_secret = EphemeralSecret::random_from_rng(OsRng);
        let alice_public = PublicKey::from(&alice_secret);
        let bob_public = PublicKey::from(&bob_secret);
        let alice_shared = derive_shared_secret(alice_secret, &bob_public);
        let bob_shared = derive_shared_secret(bob_secret, &alice_public);
        let session_a = [0xA1; 16];
        let session_b = [0xB2; 16];
        let alice_public_bytes = alice_public.to_bytes();
        let bob_public_bytes = bob_public.to_bytes();

        let alice_key = derive_tunnel_key_hkdf(
            &alice_shared,
            &session_a,
            &alice_public_bytes,
            &bob_public_bytes,
        );
        let bob_key = derive_tunnel_key_hkdf(
            &bob_shared,
            &session_a,
            &alice_public_bytes,
            &bob_public_bytes,
        );
        let other_session_key = derive_tunnel_key_hkdf(
            &alice_shared,
            &session_b,
            &alice_public_bytes,
            &bob_public_bytes,
        );

        assert_eq!(alice_key, bob_key);
        assert_ne!(
            alice_key, alice_shared,
            "raw X25519 output must not be used directly as the AEAD key"
        );
        assert_ne!(
            alice_key, other_session_key,
            "session_id must domain-separate tunnel keys"
        );
    }

    #[test]
    fn parse_tunnel_key_hex_matches_server_contract() {
        assert_eq!(
            parse_tunnel_key_hex(
                "0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
            ),
            Some([0xAB; 32])
        );
        assert_eq!(
            parse_tunnel_key_hex(
                "  0202020202020202020202020202020202020202020202020202020202020202  "
            ),
            Some([2u8; 32])
        );
        assert!(parse_tunnel_key_hex("00").is_none());
        assert!(parse_tunnel_key_hex(
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
        )
        .is_none());
    }
    #[test]
    fn tunnel_public_key_id_is_stable_redacted_and_public_key_bound() {
        let public_a = [0xA5; 32];
        let public_b = [0x5A; 32];

        let id_a = tunnel_public_key_id(&public_a);
        let id_a_again = tunnel_public_key_id(&public_a);
        let id_b = tunnel_public_key_id(&public_b);

        assert_eq!(id_a, id_a_again);
        assert_ne!(id_a, id_b);
        assert!(id_a.starts_with("tunnel:x25519:"));
        assert_eq!(id_a.len(), "tunnel:x25519:".len() + 32);
        assert!(!id_a.contains("a5a5a5a5a5a5a5a5"));
    }

    #[test]
    fn tunnel_public_key_summary_exposes_only_key_id_and_public_key() {
        let public = [0x23; 32];
        let summary = tunnel_public_key_summary(&public);

        assert_eq!(summary.key_id, tunnel_public_key_id(&public));
        assert_eq!(summary.public_key_hex.len(), 64);
        assert!(summary
            .public_key_hex
            .chars()
            .all(|ch| ch.is_ascii_hexdigit()));
        assert!(!format!("{summary:?}").contains("secret"));
    }
}
