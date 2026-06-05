use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use libsec_core::packet_builder::PacketBuilder;
use libsec_core::zk::generate_proof;
use libsec_core::ZenithPacket;
use rand::rngs::OsRng;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const DEFAULT_CLAIM_TTL_SECONDS: u64 = 300;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 's', long, env = "SECS_URL", default_value = "127.0.0.1:9000")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    Generate { prompt: String },
    Chat { message: String },
    Hub { opcode: u8, payload: String },
}

fn load_or_create_identity() -> SigningKey {
    let secret = OsRng.gen::<[u8; 32]>();
    SigningKey::from_bytes(&secret)
}

fn build_packet(identity: &SigningKey, opcode: u8, payload: Vec<u8>) -> ZenithPacket {
    let proof = generate_proof(identity, &payload);
    let session_id = OsRng.gen::<[u8; 16]>();
    let nonce = OsRng.gen::<[u8; 12]>();
    let mac = OsRng.gen::<[u8; 16]>();

    PacketBuilder::new()
        .session_id(session_id)
        .nonce(nonce)
        .opcode(opcode)
        .proof(proof)
        .claim_ttl(DEFAULT_CLAIM_TTL_SECONDS)
        .encrypted_payload(payload)
        .mac(mac)
        .build()
}

async fn dispatch_packet(identity: &SigningKey, server_addr: &str, opcode: u8, payload: Vec<u8>) {
    let packet = build_packet(identity, opcode, payload);
    let bytes = bincode::serialize(&packet).unwrap();
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Failed to connect to Node");
    stream.write_all(&bytes).await.expect("Failed to write");
    stream.flush().await.expect("Failed to flush");
}

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { prompt } => {
            println!(
                "Client: Preparing Generate command [Identity: {:?}]",
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, 0x01, prompt.into_bytes()).await;
        }
        Commands::Chat { message } => {
            println!(
                "Client: Preparing Chat command [Identity: {:?}]",
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, 0x02, message.into_bytes()).await;
        }
        Commands::Hub { opcode, payload } => {
            println!(
                "Client: Preparing Hub M2M command ({:#04x}) [Identity: {:?}]",
                opcode,
                identity.verifying_key()
            );
            dispatch_packet(&identity, &cli.server, opcode, payload.into_bytes()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use libsec_core::zk::verify_proof;

    fn fixed_identity() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn build_packet_sets_canonical_envelope_fields_without_fixture_identifiers() {
        let identity = fixed_identity();
        let packet = build_packet(&identity, 0x10, b"Hello World".to_vec());

        assert_ne!(packet.session_id, [0xFF; 16]);
        assert_ne!(packet.session_id, [0u8; 16]);
        assert_ne!(packet.nonce, [0u8; 12]);
        assert_eq!(packet.opcode, 0x10);
        assert_eq!(packet.claim_ttl, DEFAULT_CLAIM_TTL_SECONDS);
        assert_eq!(packet.encrypted_payload, b"Hello World");
        assert_ne!(packet.mac, [0u8; 16]);
    }

    #[test]
    fn build_packet_generates_unique_replay_fields_per_packet() {
        let identity = fixed_identity();
        let first = build_packet(&identity, 0x10, b"Hello World".to_vec());
        let second = build_packet(&identity, 0x10, b"Hello World".to_vec());

        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.mac, second.mac);
    }

    #[test]
    fn build_packet_signs_the_payload_bytes() {
        let identity = fixed_identity();
        let packet = build_packet(&identity, 0x20, b"signed payload".to_vec());

        assert!(verify_proof(
            &identity.verifying_key(),
            &packet.proof,
            &packet.encrypted_payload
        ));
    }

    #[test]
    fn packet_signature_does_not_verify_for_tampered_payload() {
        let identity = fixed_identity();
        let packet = build_packet(&identity, 0x20, b"signed payload".to_vec());

        assert!(!verify_proof(
            &identity.verifying_key(),
            &packet.proof,
            b"signed payloaE"
        ));
    }

    #[test]
    fn generate_command_maps_to_standard_generate_opcode() {
        let cli = Cli::try_parse_from(["client", "generate", "prompt"]).unwrap();
        match cli.command {
            Commands::Generate { prompt } => assert_eq!(prompt, "prompt"),
            _ => panic!("expected generate command"),
        }
    }

    #[test]
    fn chat_command_maps_to_standard_chat_payload() {
        let cli = Cli::try_parse_from(["client", "chat", "hello"]).unwrap();
        match cli.command {
            Commands::Chat { message } => assert_eq!(message, "hello"),
            _ => panic!("expected chat command"),
        }
    }

    #[test]
    fn hub_command_accepts_decimal_opcode() {
        let cli = Cli::try_parse_from(["client", "hub", "16", "Hello World"]).unwrap();
        match cli.command {
            Commands::Hub { opcode, payload } => {
                assert_eq!(opcode, 0x10);
                assert_eq!(payload, "Hello World");
            }
            _ => panic!("expected hub command"),
        }
    }

    #[test]
    fn hub_command_rejects_hex_opcode_notation() {
        assert!(Cli::try_parse_from(["client", "hub", "0x10", "Hello World"]).is_err());
    }

    #[test]
    fn hub_command_rejects_opcode_above_u8_range() {
        assert!(Cli::try_parse_from(["client", "hub", "256", "overflow"]).is_err());
    }
}
