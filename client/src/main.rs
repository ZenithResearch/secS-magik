use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use libsec_core::caller_proof::{caller_canonical_bytes, encode_caller_proof};
use libsec_core::ingress_request::{encode_ingress_request_v2, IngressRequestV2};
use libsec_core::packet_builder::PacketBuilder;
use libsec_core::response::{DecisionResponse, MAX_DECISION_RESPONSE_BYTES};
use libsec_core::tunnel::{
    derive_shared_secret, derive_tunnel_key_hkdf, encrypt_payload, packet_aad,
    parse_tunnel_key_hex, tunnel_public_key_id,
};
use libsec_core::zk::generate_proof;
use libsec_core::ZenithPacket;
use rand::rngs::OsRng;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

const DEFAULT_CLAIM_TTL_SECONDS: u64 = 300;

/// Demo/test affordance: claim TTL override in seconds (SECS_CLAIM_TTL).
/// Lets a demo show the gateway's typed expiry reject live (TTL 0). Invalid
/// values fall back to the default.
fn claim_ttl_seconds() -> u64 {
    std::env::var("SECS_CLAIM_TTL")
        .ok()
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(DEFAULT_CLAIM_TTL_SECONDS)
}

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short = 's', long, env = "SECS_URL", default_value = "127.0.0.1:9000")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    Generate {
        prompt: String,
    },
    Chat {
        message: String,
    },
    Hub {
        opcode: u8,
        payload: String,
    },
    /// Print this caller's key id and public key as a receiver-registry entry.
    Identity,
}

/// The caller's signing identity: a stable key plus the registry lookup id
/// carried (as a reference only) in the caller proof envelope.
struct CallerIdentity {
    signing_key: SigningKey,
    key_id: String,
}

#[derive(Debug, PartialEq, Eq)]
enum CallerKeyFileError {
    Inaccessible,
    UnsafePermissions,
    Malformed,
}

impl std::fmt::Display for CallerKeyFileError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inaccessible => write!(formatter, "caller key file is inaccessible"),
            Self::UnsafePermissions => write!(
                formatter,
                "caller key file must be a regular, non-symlink file with owner-only permissions"
            ),
            Self::Malformed => write!(formatter, "caller key file must hold 64 hex characters"),
        }
    }
}

// Mirrors the server's identity.rs key-file safety checks. core is no_std,
// so the filesystem checks cannot live there, and depending on the server
// crate would drag sqlx/ledger code into the client.
fn validate_caller_key_file_safety(path: &Path) -> Result<(), CallerKeyFileError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| CallerKeyFileError::Inaccessible)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CallerKeyFileError::UnsafePermissions);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CallerKeyFileError::UnsafePermissions);
        }
    }

    Ok(())
}

fn parse_hex_secret_key(raw: &str) -> Result<[u8; 32], CallerKeyFileError> {
    let value: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    if value.len() != 64 {
        return Err(CallerKeyFileError::Malformed);
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk).map_err(|_| CallerKeyFileError::Malformed)?;
        bytes[index] = u8::from_str_radix(hex, 16).map_err(|_| CallerKeyFileError::Malformed)?;
    }
    Ok(bytes)
}

fn derive_caller_key_id(signing_key: &SigningKey) -> String {
    // Same derivation shape as the server's derive_ed25519_key_id.
    let digest = Sha256::digest(signing_key.verifying_key().as_bytes());
    let hex: String = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("caller:ed25519:{hex}")
}

fn load_caller_key_from_file(path: &Path) -> Result<SigningKey, CallerKeyFileError> {
    validate_caller_key_file_safety(path)?;
    let raw = std::fs::read_to_string(path).map_err(|_| CallerKeyFileError::Inaccessible)?;
    Ok(SigningKey::from_bytes(&parse_hex_secret_key(&raw)?))
}

fn create_caller_key_file(path: &Path) -> Result<SigningKey, CallerKeyFileError> {
    let secret = OsRng.gen::<[u8; 32]>();
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|_| CallerKeyFileError::Inaccessible)?;
        file.write_all(hex.as_bytes())
            .map_err(|_| CallerKeyFileError::Inaccessible)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, hex.as_bytes()).map_err(|_| CallerKeyFileError::Inaccessible)?;
    }

    Ok(SigningKey::from_bytes(&secret))
}

fn load_or_create_persistent_identity(path: &Path) -> Result<SigningKey, CallerKeyFileError> {
    if path.exists() {
        load_caller_key_from_file(path)
    } else {
        create_caller_key_file(path)
    }
}

/// Caller identity resolution: SECS_CALLER_KEY_PATH selects a stable,
/// file-backed key (created owner-private on first use); without it the key
/// is ephemeral per process — fine for local dev, useless for production
/// registries by design. SECS_CALLER_KEY_ID overrides the derived id.
fn load_or_create_identity() -> CallerIdentity {
    let signing_key = match std::env::var_os("SECS_CALLER_KEY_PATH") {
        Some(path) => {
            let path = std::path::PathBuf::from(path);
            load_or_create_persistent_identity(&path).unwrap_or_else(|error| {
                panic!("client: cannot use caller key file {path:?} - {error}")
            })
        }
        None => {
            let secret = OsRng.gen::<[u8; 32]>();
            SigningKey::from_bytes(&secret)
        }
    };
    let key_id = std::env::var("SECS_CALLER_KEY_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| derive_caller_key_id(&signing_key));
    CallerIdentity {
        signing_key,
        key_id,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelMode {
    Plaintext,
    StaticKey([u8; 32]),
    SessionKey { server_public_key: [u8; 32] },
}

#[derive(Debug, PartialEq, Eq)]
enum TunnelKeyConfigError {
    Malformed,
    PinnedKeyIdMismatch,
}

impl std::fmt::Display for TunnelKeyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(formatter, "tunnel key env var must hold 64 hex characters"),
            Self::PinnedKeyIdMismatch => write!(formatter, "gateway tunnel public key id does not match pinned SECS_TUNNEL_SERVER_X25519_PUBLIC_ID"),
        }
    }
}

fn load_tunnel_mode_from_env() -> Result<TunnelMode, TunnelKeyConfigError> {
    if let Ok(value) = std::env::var("SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX")
        .or_else(|_| std::env::var("SECZ_TUNNEL_SERVER_X25519_PUBLIC_HEX"))
    {
        let server_public_key =
            parse_tunnel_key_hex(&value).ok_or(TunnelKeyConfigError::Malformed)?;
        if let Ok(expected_key_id) = std::env::var("SECS_TUNNEL_SERVER_X25519_PUBLIC_ID")
            .or_else(|_| std::env::var("SECZ_TUNNEL_SERVER_X25519_PUBLIC_ID"))
        {
            if !expected_key_id.trim().is_empty()
                && expected_key_id.trim() != tunnel_public_key_id(&server_public_key)
            {
                return Err(TunnelKeyConfigError::PinnedKeyIdMismatch);
            }
        }
        return Ok(TunnelMode::SessionKey { server_public_key });
    }
    if let Ok(value) =
        std::env::var("SECS_TUNNEL_KEY_HEX").or_else(|_| std::env::var("SECZ_TUNNEL_KEY_HEX"))
    {
        let key = parse_tunnel_key_hex(&value).ok_or(TunnelKeyConfigError::Malformed)?;
        return Ok(TunnelMode::StaticKey(key));
    }
    Ok(TunnelMode::Plaintext)
}

struct BuiltPacket {
    packet: ZenithPacket,
    client_ephemeral_public_key: Option<[u8; 32]>,
}

#[cfg(test)]
fn build_packet(identity: &CallerIdentity, opcode: u8, payload: Vec<u8>) -> ZenithPacket {
    build_packet_with_tunnel_mode(identity, opcode, payload, TunnelMode::Plaintext).packet
}

fn build_packet_with_tunnel_mode(
    identity: &CallerIdentity,
    opcode: u8,
    payload: Vec<u8>,
    tunnel_mode: TunnelMode,
) -> BuiltPacket {
    let session_id = OsRng.gen::<[u8; 16]>();
    let nonce = OsRng.gen::<[u8; 12]>();
    // The mac field is reserved (M12.6 option b): zeroed, never verified.
    // Random bytes here were security theater; authentication lives in the
    // caller proof (M12.1) and tunnel AEAD binding (M12.4).
    let mac = [0u8; 16];
    let claim_ttl = claim_ttl_seconds();

    let aad = packet_aad(&session_id, opcode, claim_ttl);
    let (wire_payload, client_ephemeral_public_key): (Vec<u8>, Option<[u8; 32]>) = match tunnel_mode
    {
        TunnelMode::Plaintext => (payload, None),
        TunnelMode::StaticKey(key) => (encrypt_payload(&key, &nonce, &payload, &aad), None),
        TunnelMode::SessionKey { server_public_key } => {
            let client_secret = EphemeralSecret::random_from_rng(OsRng);
            let client_public = PublicKey::from(&client_secret).to_bytes();
            let server_public = PublicKey::from(server_public_key);
            let shared = derive_shared_secret(client_secret, &server_public);
            let key =
                derive_tunnel_key_hkdf(&shared, &session_id, &client_public, &server_public_key);
            (
                encrypt_payload(&key, &nonce, &payload, &aad),
                Some(client_public),
            )
        }
    };

    // Sign the canonical envelope bytes — session, nonce, opcode, TTL, and
    // encrypted payload — so the proof cannot be re-bound to a different packet.
    let canonical = caller_canonical_bytes(&session_id, &nonce, opcode, claim_ttl, &wire_payload);
    let signature_bytes = generate_proof(&identity.signing_key, &canonical);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);
    let proof = encode_caller_proof(&identity.key_id, &signature);

    BuiltPacket {
        packet: PacketBuilder::new()
            .session_id(session_id)
            .nonce(nonce)
            .opcode(opcode)
            .proof(proof)
            .claim_ttl(claim_ttl)
            .encrypted_payload(wire_payload)
            .mac(mac)
            .build(),
        client_ephemeral_public_key,
    }
}

const DECISION_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Send one packet and read the gateway's decision frame. Returns the decoded
/// decision, or `None` when the server closed without answering (older
/// gateways) — the send itself still succeeded in that case.
async fn dispatch_packet(
    identity: &CallerIdentity,
    server_addr: &str,
    opcode: u8,
    payload: Vec<u8>,
) -> Option<DecisionResponse> {
    let tunnel_mode = load_tunnel_mode_from_env()
        .unwrap_or_else(|error| panic!("client: invalid tunnel configuration - {error}"));
    let built = build_packet_with_tunnel_mode(identity, opcode, payload, tunnel_mode);
    let bytes = match built.client_ephemeral_public_key {
        Some(client_ephemeral_public_key) => encode_ingress_request_v2(&IngressRequestV2::new(
            built.packet,
            Vec::new(),
            Vec::new(),
            client_ephemeral_public_key,
        ))
        .expect("client-built ingress v2 request is bounded"),
        None => bincode::serialize(&built.packet).unwrap(),
    };
    // Demo/test affordance: persist the exact wire bytes so a demo can replay
    // them verbatim and show the gateway's replay rejection.
    if let Some(path) = std::env::var_os("SECS_SAVE_PACKET_PATH") {
        if let Err(error) = std::fs::write(&path, &bytes) {
            eprintln!("Client: failed to save packet bytes to {path:?} - {error}");
        }
    }
    let mut stream = TcpStream::connect(server_addr)
        .await
        .expect("Failed to connect to Node");
    stream.write_all(&bytes).await.expect("Failed to write");
    stream.flush().await.expect("Failed to flush");
    // Close our write half so the gateway's read-to-EOF completes, then read
    // the single bounded decision frame.
    stream.shutdown().await.expect("Failed to close write half");

    let mut frame = Vec::new();
    let read = tokio::time::timeout(
        DECISION_READ_TIMEOUT,
        stream
            .take((MAX_DECISION_RESPONSE_BYTES + 1) as u64)
            .read_to_end(&mut frame),
    )
    .await;
    match read {
        Ok(Ok(_)) if frame.is_empty() => None,
        Ok(Ok(_)) => DecisionResponse::decode(&frame),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Print the decision for humans/scripts and convert it to an exit code:
/// accept (or no frame from an older gateway) exits 0, reject exits 1.
fn report_decision(response: Option<DecisionResponse>) -> i32 {
    match response {
        Some(response) if response.is_accepted() => {
            println!(
                "Client: decision=accepted context={} receipt={}",
                response.context_id.as_deref().unwrap_or("-"),
                response.receipt_id.as_deref().unwrap_or("-")
            );
            0
        }
        Some(response) => {
            println!(
                "Client: decision=rejected reason={} context={} receipt={}",
                response.reason_code.as_deref().unwrap_or("-"),
                response.context_id.as_deref().unwrap_or("-"),
                response.receipt_id.as_deref().unwrap_or("-")
            );
            1
        }
        None => {
            println!("Client: decision=none (gateway closed without a decision frame)");
            0
        }
    }
}

#[tokio::main]
async fn main() {
    let identity = load_or_create_identity();
    let cli = Cli::parse();

    let exit_code = match cli.command {
        Commands::Generate { prompt } => {
            println!(
                "Client: Preparing Generate command [Caller: {}]",
                identity.key_id
            );
            report_decision(
                dispatch_packet(&identity, &cli.server, 0x01, prompt.into_bytes()).await,
            )
        }
        Commands::Chat { message } => {
            println!(
                "Client: Preparing Chat command [Caller: {}]",
                identity.key_id
            );
            report_decision(
                dispatch_packet(&identity, &cli.server, 0x02, message.into_bytes()).await,
            )
        }
        Commands::Hub { opcode, payload } => {
            println!(
                "Client: Preparing Hub M2M command ({:#04x}) [Caller: {}]",
                opcode, identity.key_id
            );
            report_decision(
                dispatch_packet(&identity, &cli.server, opcode, payload.into_bytes()).await,
            )
        }
        Commands::Identity => {
            let public_key_hex: String = identity
                .signing_key
                .verifying_key()
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            println!(
                "{{\"key_id\": \"{}\", \"subject_id\": \"caller:{}\", \"algorithm\": \"ed25519\", \"public_key_hex\": \"{}\"}}",
                identity.key_id, identity.key_id, public_key_hex
            );
            0
        }
    };
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use libsec_core::zk::verify_proof;
    use serial_test::serial;

    fn fixed_identity() -> CallerIdentity {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let key_id = derive_caller_key_id(&signing_key);
        CallerIdentity {
            signing_key,
            key_id,
        }
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
        assert_eq!(
            packet.mac, [0u8; 16],
            "reserved mac field must be zeroed, not filled with decorative bytes"
        );
    }

    #[test]
    fn build_packet_generates_unique_replay_fields_per_packet() {
        let identity = fixed_identity();
        let first = build_packet(&identity, 0x10, b"Hello World".to_vec());
        let second = build_packet(&identity, 0x10, b"Hello World".to_vec());

        assert_ne!(first.session_id, second.session_id);
        assert_ne!(first.nonce, second.nonce);
        assert_eq!(first.mac, second.mac, "reserved mac field is always zero");
    }

    #[test]
    fn build_packet_carries_versioned_caller_proof_over_canonical_envelope_bytes() {
        let identity = fixed_identity();
        let packet = build_packet(&identity, 0x20, b"signed payload".to_vec());

        let parts = libsec_core::caller_proof::decode_caller_proof(&packet.proof)
            .expect("proof must be a versioned caller proof envelope");
        assert_eq!(parts.key_id, identity.key_id);

        let canonical = caller_canonical_bytes(
            &packet.session_id,
            &packet.nonce,
            packet.opcode,
            packet.claim_ttl,
            &packet.encrypted_payload,
        );
        assert!(verify_proof(
            &identity.signing_key.verifying_key(),
            &parts.signature,
            &canonical
        ));
    }

    #[test]
    fn caller_proof_does_not_verify_when_rebound_to_a_different_envelope() {
        let identity = fixed_identity();
        let packet = build_packet(&identity, 0x20, b"signed payload".to_vec());
        let parts = libsec_core::caller_proof::decode_caller_proof(&packet.proof).unwrap();

        // Same proof, different session: canonical bytes change, so the
        // signature must not verify.
        let rebound = caller_canonical_bytes(
            &[0xEE; 16],
            &packet.nonce,
            packet.opcode,
            packet.claim_ttl,
            &packet.encrypted_payload,
        );
        assert!(!verify_proof(
            &identity.signing_key.verifying_key(),
            &parts.signature,
            &rebound
        ));
    }

    #[test]
    fn persistent_caller_key_is_stable_across_loads_and_owner_private() {
        let path = std::env::temp_dir().join(format!(
            "secs-caller-key-{}-{}.hex",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_file(&path);

        let first = load_or_create_persistent_identity(&path).unwrap();
        let second = load_or_create_persistent_identity(&path).unwrap();
        assert_eq!(first.to_bytes(), second.to_bytes());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "caller key file must be owner-private");
        }

        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn group_readable_caller_key_file_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!(
            "secs-caller-key-loose-{}-{}.hex",
            std::process::id(),
            line!()
        ));
        std::fs::write(&path, "11".repeat(32)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert_eq!(
            load_caller_key_from_file(&path).unwrap_err(),
            CallerKeyFileError::UnsafePermissions
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn malformed_caller_key_file_is_rejected() {
        let path = std::env::temp_dir().join(format!(
            "secs-caller-key-malformed-{}-{}.hex",
            std::process::id(),
            line!()
        ));
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            file.write_all(b"not hex at all").unwrap();
        }
        #[cfg(not(unix))]
        std::fs::write(&path, b"not hex at all").unwrap();

        assert_eq!(
            load_caller_key_from_file(&path).unwrap_err(),
            CallerKeyFileError::Malformed
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn decision_reporting_maps_to_exit_codes() {
        assert_eq!(
            report_decision(Some(DecisionResponse::accepted(
                Some("ctx".to_string()),
                Some("receipt".to_string())
            ))),
            0
        );
        assert_eq!(
            report_decision(Some(DecisionResponse::rejected(
                "bad_caller_proof",
                None,
                Some("receipt".to_string())
            ))),
            1
        );
        // Older gateways close without a frame: the send still succeeded.
        assert_eq!(report_decision(None), 0);
    }

    #[test]
    fn derived_caller_key_id_is_stable_and_reference_shaped() {
        let identity = fixed_identity();
        let again = derive_caller_key_id(&identity.signing_key);

        assert_eq!(identity.key_id, again);
        assert!(identity.key_id.starts_with("caller:ed25519:"));
        assert_eq!(identity.key_id.len(), "caller:ed25519:".len() + 32);
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

    #[test]
    fn build_packet_with_static_tunnel_key_encrypts_and_signs_ciphertext() {
        let identity = fixed_identity();
        let built = build_packet_with_tunnel_mode(
            &identity,
            0x10,
            b"secret payload".to_vec(),
            TunnelMode::StaticKey([7u8; 32]),
        );
        let aad = packet_aad(
            &built.packet.session_id,
            built.packet.opcode,
            built.packet.claim_ttl,
        );
        let decrypted = libsec_core::tunnel::decrypt_payload(
            &[7u8; 32],
            &built.packet.nonce,
            &built.packet.encrypted_payload,
            &aad,
        )
        .unwrap();
        assert_eq!(decrypted, b"secret payload");
        assert_ne!(built.packet.encrypted_payload, b"secret payload");
        assert!(libsec_core::caller_proof::decode_caller_proof(&built.packet.proof).is_some());
    }

    #[test]
    fn build_packet_with_session_tunnel_key_emits_v2_client_public_key() {
        let identity = fixed_identity();
        let server_secret = x25519_dalek::StaticSecret::from([8u8; 32]);
        let server_public_key = PublicKey::from(&server_secret).to_bytes();
        let built = build_packet_with_tunnel_mode(
            &identity,
            0x10,
            b"session secret".to_vec(),
            TunnelMode::SessionKey { server_public_key },
        );
        let client_public = built.client_ephemeral_public_key.unwrap();
        let shared = server_secret
            .diffie_hellman(&PublicKey::from(client_public))
            .to_bytes();
        let key = derive_tunnel_key_hkdf(
            &shared,
            &built.packet.session_id,
            &client_public,
            &server_public_key,
        );
        let aad = packet_aad(
            &built.packet.session_id,
            built.packet.opcode,
            built.packet.claim_ttl,
        );
        let decrypted = libsec_core::tunnel::decrypt_payload(
            &key,
            &built.packet.nonce,
            &built.packet.encrypted_payload,
            &aad,
        )
        .unwrap();
        assert_eq!(decrypted, b"session secret");
    }
    #[test]
    #[serial]
    fn load_tunnel_mode_rejects_mismatched_pinned_gateway_key_id() {
        let server_secret = x25519_dalek::StaticSecret::from([8u8; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let public_hex = server_public
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        std::env::set_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX", public_hex);
        std::env::set_var(
            "SECS_TUNNEL_SERVER_X25519_PUBLIC_ID",
            "tunnel:x25519:00000000000000000000000000000000",
        );

        assert_eq!(
            load_tunnel_mode_from_env(),
            Err(TunnelKeyConfigError::PinnedKeyIdMismatch)
        );

        std::env::remove_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX");
        std::env::remove_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_ID");
    }

    #[test]
    #[serial]
    fn load_tunnel_mode_accepts_matching_pinned_gateway_key_id() {
        let server_secret = x25519_dalek::StaticSecret::from([9u8; 32]);
        let server_public = PublicKey::from(&server_secret).to_bytes();
        let public_hex = server_public
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let key_id = libsec_core::tunnel::tunnel_public_key_id(&server_public);
        std::env::set_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX", public_hex);
        std::env::set_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_ID", key_id);

        assert!(matches!(
            load_tunnel_mode_from_env(),
            Ok(TunnelMode::SessionKey { .. })
        ));

        std::env::remove_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_HEX");
        std::env::remove_var("SECS_TUNNEL_SERVER_X25519_PUBLIC_ID");
    }
}
