use crate::config::{validate_production_startup_readiness, GatewayRuntimeConfig};
use crate::gateway::{init_telemetry_schema, register_runtime_bindings, ConfigurableRouter};
use crate::identity::{
    explicit_test_fixture_identity, load_node_verifier_identity, VerifierIdentityConfig,
};
use crate::manifest::ReceiverManifest;
use crate::payload::decrypt_machine_payload;
use crate::runtime_mode::RuntimeMode;
use crate::verifier::{VerificationError, Verifier};
use bincode::Options;
use libsec_core::ZenithPacket;
use rand::rngs::OsRng;
use rand::Rng;
use sqlx::sqlite::SqlitePoolOptions;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

static PRE_DECODE_REJECT_SEQUENCE: AtomicU64 = AtomicU64::new(1);
pub const DEFAULT_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_INGRESS_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum IngressReadError {
    Transport(std::io::Error),
    ReadTimeout,
    WireFrameTooLarge {
        limit: usize,
    },
    LogicalFrameTooLarge {
        field: &'static str,
        declared_len: u64,
        limit: usize,
    },
    MalformedPacket(Box<bincode::ErrorKind>),
}

impl fmt::Display for IngressReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport read failed: {error}"),
            Self::ReadTimeout => write!(formatter, "wire read timed out before EOF"),
            Self::WireFrameTooLarge { limit } => {
                write!(
                    formatter,
                    "wire frame exceeded configured limit of {limit} bytes"
                )
            }
            Self::LogicalFrameTooLarge {
                field,
                declared_len,
                limit,
            } => write!(
                formatter,
                "packet field {field} declared {declared_len} bytes, exceeding configured logical limit of {limit} bytes"
            ),
            Self::MalformedPacket(error) => write!(formatter, "malformed packet: {error}"),
        }
    }
}

impl std::error::Error for IngressReadError {}

pub async fn read_bounded_wire_packet<R>(
    reader: R,
    max_wire_bytes: usize,
    read_timeout: Duration,
) -> Result<Option<ZenithPacket>, IngressReadError>
where
    R: AsyncRead + Unpin,
{
    let mut bounded_reader = reader.take((max_wire_bytes as u64).saturating_add(1));
    let mut wire_bytes = Vec::with_capacity(max_wire_bytes.min(64 * 1024));
    match timeout(read_timeout, bounded_reader.read_to_end(&mut wire_bytes)).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(IngressReadError::Transport(error)),
        Err(_) => return Err(IngressReadError::ReadTimeout),
    }

    if wire_bytes.is_empty() {
        return Ok(None);
    }

    if wire_bytes.len() > max_wire_bytes {
        return Err(IngressReadError::WireFrameTooLarge {
            limit: max_wire_bytes,
        });
    }

    reject_huge_declared_vec_lengths(&wire_bytes, max_wire_bytes)?;

    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(max_wire_bytes as u64)
        .deserialize::<ZenithPacket>(&wire_bytes)
        .map(Some)
        .map_err(IngressReadError::MalformedPacket)
}

fn reject_huge_declared_vec_lengths(
    wire_bytes: &[u8],
    max_wire_bytes: usize,
) -> Result<(), IngressReadError> {
    const SESSION_ID_BYTES: usize = 16;
    const NONCE_BYTES: usize = 12;
    const OPCODE_BYTES: usize = 1;
    const U64_BYTES: usize = 8;
    const PROOF_LEN_OFFSET: usize = SESSION_ID_BYTES + NONCE_BYTES + OPCODE_BYTES;

    let Some(proof_len) = read_le_u64(wire_bytes, PROOF_LEN_OFFSET) else {
        return Ok(());
    };
    reject_declared_len("proof", proof_len, max_wire_bytes)?;

    let proof_len_usize =
        usize::try_from(proof_len).map_err(|_| IngressReadError::LogicalFrameTooLarge {
            field: "proof",
            declared_len: proof_len,
            limit: max_wire_bytes,
        })?;
    let payload_len_offset = PROOF_LEN_OFFSET
        .checked_add(U64_BYTES)
        .and_then(|offset| offset.checked_add(proof_len_usize))
        .and_then(|offset| offset.checked_add(U64_BYTES));
    let Some(payload_len_offset) = payload_len_offset else {
        return Err(IngressReadError::LogicalFrameTooLarge {
            field: "proof",
            declared_len: proof_len,
            limit: max_wire_bytes,
        });
    };

    if let Some(payload_len) = read_le_u64(wire_bytes, payload_len_offset) {
        reject_declared_len("encrypted_payload", payload_len, max_wire_bytes)?;
    }

    Ok(())
}

fn read_le_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let len_bytes: [u8; 8] = bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(len_bytes))
}

fn reject_declared_len(
    field: &'static str,
    declared_len: u64,
    max_wire_bytes: usize,
) -> Result<(), IngressReadError> {
    if declared_len > max_wire_bytes as u64 {
        return Err(IngressReadError::LogicalFrameTooLarge {
            field,
            declared_len,
            limit: max_wire_bytes,
        });
    }
    Ok(())
}

pub async fn handle_gateway_connection(router: Arc<ConfigurableRouter>, socket: TcpStream) {
    handle_gateway_connection_with_limits(
        router,
        socket,
        DEFAULT_MAX_WIRE_BYTES,
        DEFAULT_INGRESS_READ_TIMEOUT,
        RuntimeMode::ProductionVerified,
    )
    .await;
}

pub async fn handle_gateway_connection_with_limits(
    router: Arc<ConfigurableRouter>,
    socket: TcpStream,
    max_wire_bytes: usize,
    read_timeout: Duration,
    runtime_mode: RuntimeMode,
) {
    let packet = match read_bounded_wire_packet(socket, max_wire_bytes, read_timeout).await {
        Ok(Some(packet)) => packet,
        Ok(None) => return,
        Err(IngressReadError::MalformedPacket(error)) => {
            eprintln!("secS [Transport]: rejected malformed packet - {}", error);
            record_pre_decode_reject(&router).await;
            return;
        }
        Err(IngressReadError::WireFrameTooLarge { limit }) => {
            eprintln!(
                "secS [Transport]: rejected oversized wire frame above {} bytes before packet decode",
                limit
            );
            record_pre_decode_reject(&router).await;
            return;
        }
        Err(error) => {
            eprintln!(
                "secS [Transport]: failed to read bounded connection - {}",
                error
            );
            record_pre_decode_reject(&router).await;
            return;
        }
    };

    if let Err(error) = Verifier::verify_prototype_envelope(&packet) {
        eprintln!(
            "secS [Auth]: rejected packet with invalid prototype proof envelope - {}",
            error.reason_code()
        );
        router.record_reject(&packet, error).await;
        return;
    }

    let payload = match decrypt_machine_payload(&packet, runtime_mode) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("secS [Crypto]: rejected undecryptable payload - {}", e);
            router
                .record_reject(&packet, crate::verifier::VerificationError::BadMac)
                .await;
            return;
        }
    };

    let manifest = ReceiverManifest::default_v0();
    let signed_context =
        match Verifier::verify_manifest_operation_and_sign_for_runtime_with_identity_and_caller(
            &packet,
            &manifest,
            router.expected_audience(),
            current_unix_seconds(),
            router.identity(),
            runtime_mode,
            router.caller_keys(),
        ) {
            Ok(context) => context,
            Err(error) => {
                eprintln!(
                    "secS [Manifest]: rejected packet before handler lookup - {}",
                    error.reason_code()
                );
                router.record_reject(&packet, error).await;
                return;
            }
        };

    router.route_verified(&signed_context, payload).await;
}

async fn record_pre_decode_reject(router: &ConfigurableRouter) {
    let sequence = PRE_DECODE_REJECT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    let packet = ZenithPacket {
        session_id: [0u8; 16],
        nonce,
        opcode: 0,
        proof: Vec::new(),
        claim_ttl: 0,
        encrypted_payload: Vec::new(),
        mac: [0u8; 16],
    };
    router
        .record_reject(&packet, VerificationError::MalformedPacket)
        .await;
}

fn current_unix_seconds() -> u64 {
    // Fail-closed: a clock-read failure yields the sentinel, which the
    // verifier and signed-context checks reject as expired (M12.5).
    crate::clock::failclosed_unix_seconds()
}

pub async fn run_prototype_gateway(addr: &str, db_url: &str, label: &str) {
    let mut config = GatewayRuntimeConfig::from_env()
        .unwrap_or_else(|error| panic!("secS gateway: invalid runtime config - {error}"));
    config.bind_addr = addr.to_string();
    config.db_url = db_url.to_string();
    run_gateway_with_config(config, label).await;
}

pub async fn run_gateway_with_config(config: GatewayRuntimeConfig, label: &str) {
    validate_production_startup_readiness(&config)
        .unwrap_or_else(|error| panic!("secS gateway: startup readiness check failed - {error}"));

    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&config.db_url)
        .await
        .expect("secS gateway: failed to connect to node_telemetry SQLite DB");

    init_telemetry_schema(&pool)
        .await
        .expect("secS gateway: failed to initialize node_telemetry table");

    let identity = match config.runtime_mode {
        RuntimeMode::ProductionVerified => load_node_verifier_identity(&VerifierIdentityConfig {
            runtime_mode: config.runtime_mode,
            verifier_key_path: config.verifier_key_path.clone(),
            verifier_key_id: config.verifier_key_id.clone(),
        })
        .unwrap_or_else(|error| {
            panic!("secS gateway: failed to load production verifier identity - {error}")
        }),
        RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => {
            explicit_test_fixture_identity("verifier:local-prototype", OsRng.gen::<[u8; 32]>())
        }
    };
    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool,
        config.execution_limits(),
        identity,
        config.receiver_audience.clone(),
    );
    register_runtime_bindings(&mut router, config.runtime_mode);

    let router = Arc::new(router);
    let listener = TcpListener::bind(&config.bind_addr)
        .await
        .expect("secS gateway: failed to bind TCP listener");

    let local_addr = listener
        .local_addr()
        .expect("secS gateway: failed to read bound TCP listener address");
    println!(
        "{} listening on {} with runtime_mode={} receiver_audience={} max_wire_bytes={} read_timeout_ms={} max_in_flight_connections={} allowed_evidence_adapters={}",
        label,
        local_addr,
        config.runtime_mode.label(),
        config.receiver_audience,
        config.max_wire_bytes,
        config.ingress_read_timeout.as_millis(),
        config.max_in_flight_connections,
        config.allowed_evidence_adapters.join(",")
    );

    let in_flight = Arc::new(Semaphore::new(config.max_in_flight_connections));
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
                    eprintln!(
                        "secS [Transport]: refused connection from {} because in-flight cap {} is saturated",
                        peer, config.max_in_flight_connections
                    );
                    drop(socket);
                    continue;
                };
                println!("secS [Transport]: accepted connection from {}", peer);
                let router = Arc::clone(&router);
                let max_wire_bytes = config.max_wire_bytes;
                let ingress_read_timeout = config.ingress_read_timeout;
                let runtime_mode = config.runtime_mode;
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_gateway_connection_with_limits(
                        router,
                        socket,
                        max_wire_bytes,
                        ingress_read_timeout,
                        runtime_mode,
                    )
                    .await;
                });
            }
            Err(e) => eprintln!("secS [Transport]: failed to accept connection - {}", e),
        }
    }
}
