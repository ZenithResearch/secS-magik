use crate::runtime_mode::RuntimeMode;
use libsec_core::{tunnel::decrypt_payload, ZenithPacket};

pub fn decrypt_machine_payload(
    packet: &ZenithPacket,
    mode: RuntimeMode,
) -> Result<Vec<u8>, String> {
    match load_tunnel_key() {
        Some(key) => decrypt_payload(&key, &packet.nonce, &packet.encrypted_payload, b"")
            .map_err(|_| "ChaCha20Poly1305 authentication failed".to_string()),
        None if mode.allows_plaintext() => Ok(packet.encrypted_payload.clone()),
        None => Err("missing tunnel key".to_string()),
    }
}

pub fn load_tunnel_key() -> Option<[u8; 32]> {
    std::env::var("SECS_TUNNEL_KEY_HEX")
        .or_else(|_| std::env::var("SECZ_TUNNEL_KEY_HEX"))
        .ok()
        .and_then(|hex| parse_hex_32(&hex))
}

pub fn parse_hex_32(input: &str) -> Option<[u8; 32]> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use libsec_core::tunnel::encrypt_payload;
    use serial_test::serial;

    fn packet_with(payload: Vec<u8>) -> ZenithPacket {
        ZenithPacket {
            session_id: [0xFF; 16],
            nonce: [2u8; 12],
            opcode: 0x10,
            proof: vec![1],
            claim_ttl: 1,
            encrypted_payload: payload,
            mac: [0u8; 16],
        }
    }

    #[test]
    fn parse_hex_32_accepts_plain_lowercase_hex() {
        let parsed =
            parse_hex_32("0101010101010101010101010101010101010101010101010101010101010101")
                .unwrap();

        assert_eq!(parsed, [1u8; 32]);
    }

    #[test]
    fn parse_hex_32_accepts_0x_prefixed_uppercase_hex() {
        let parsed =
            parse_hex_32("0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB")
                .unwrap();

        assert_eq!(parsed, [0xAB; 32]);
    }

    #[test]
    fn parse_hex_32_trims_outer_whitespace() {
        let parsed =
            parse_hex_32("  0202020202020202020202020202020202020202020202020202020202020202  ")
                .unwrap();

        assert_eq!(parsed, [2u8; 32]);
    }

    #[test]
    fn parse_hex_32_rejects_short_long_and_non_hex_keys() {
        assert!(parse_hex_32("00").is_none());
        assert!(
            parse_hex_32("010101010101010101010101010101010101010101010101010101010101010100")
                .is_none()
        );
        assert!(
            parse_hex_32("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
                .is_none()
        );
    }

    #[test]
    #[serial]
    fn load_tunnel_key_prefers_canonical_secs_key_over_legacy_secz_key() {
        std::env::set_var(
            "SECZ_TUNNEL_KEY_HEX",
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        std::env::set_var(
            "SECS_TUNNEL_KEY_HEX",
            "0202020202020202020202020202020202020202020202020202020202020202",
        );

        assert_eq!(load_tunnel_key().unwrap(), [2u8; 32]);

        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    }

    #[test]
    #[serial]
    fn load_tunnel_key_uses_secs_fallback_when_secz_key_absent() {
        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
        std::env::set_var(
            "SECS_TUNNEL_KEY_HEX",
            "0202020202020202020202020202020202020202020202020202020202020202",
        );

        assert_eq!(load_tunnel_key().unwrap(), [2u8; 32]);

        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    }

    #[test]
    #[serial]
    fn decrypt_machine_payload_decrypts_when_tunnel_key_is_configured() {
        std::env::set_var(
            "SECZ_TUNNEL_KEY_HEX",
            "0101010101010101010101010101010101010101010101010101010101010101",
        );
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        let ciphertext = encrypt_payload(&[1u8; 32], &[2u8; 12], b"ciphertext payload", b"");
        let packet = packet_with(ciphertext);

        assert_eq!(
            decrypt_machine_payload(&packet, RuntimeMode::LocalDevTunnel).unwrap(),
            b"ciphertext payload"
        );

        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
    }

    #[test]
    #[serial]
    fn decrypt_machine_payload_rejects_wrong_tunnel_key() {
        std::env::set_var(
            "SECZ_TUNNEL_KEY_HEX",
            "0909090909090909090909090909090909090909090909090909090909090909",
        );
        std::env::remove_var("SECS_TUNNEL_KEY_HEX");
        let ciphertext = encrypt_payload(&[1u8; 32], &[2u8; 12], b"ciphertext payload", b"");
        let packet = packet_with(ciphertext);

        assert!(decrypt_machine_payload(&packet, RuntimeMode::LocalDevTunnel).is_err());

        std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
    }
}
