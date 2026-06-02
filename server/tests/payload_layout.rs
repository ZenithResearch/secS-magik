use libsec_core::{tunnel::encrypt_payload, ZenithPacket};
use serial_test::serial;
use server::payload::{decrypt_machine_payload, load_tunnel_key, parse_hex_32};
use server::runtime_mode::RuntimeMode;

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
fn payload_hex_key_parser_lives_in_library() {
    let parsed =
        parse_hex_32("0xABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB").unwrap();

    assert_eq!(parsed, [0xAB; 32]);
    assert!(parse_hex_32("00").is_none());
}

#[test]
#[serial]
fn payload_library_plaintext_requires_explicit_local_dev_mode() {
    std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
    std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    let packet = packet_with(b"plain".to_vec());

    assert_eq!(
        decrypt_machine_payload(&packet, RuntimeMode::LocalDevPlaintext).unwrap(),
        b"plain"
    );
    assert_eq!(
        decrypt_machine_payload(&packet, RuntimeMode::ProductionVerified).unwrap_err(),
        "missing tunnel key"
    );
}

#[test]
#[serial]
fn payload_library_decrypts_with_configured_tunnel_key() {
    std::env::set_var(
        "SECZ_TUNNEL_KEY_HEX",
        "0101010101010101010101010101010101010101010101010101010101010101",
    );
    std::env::remove_var("SECS_TUNNEL_KEY_HEX");
    let ciphertext = encrypt_payload(&[1u8; 32], &[2u8; 12], b"ciphertext payload");
    let packet = packet_with(ciphertext);

    assert_eq!(
        decrypt_machine_payload(&packet, RuntimeMode::LocalDevTunnel).unwrap(),
        b"ciphertext payload"
    );
    assert_eq!(load_tunnel_key().unwrap(), [1u8; 32]);

    std::env::remove_var("SECZ_TUNNEL_KEY_HEX");
}
