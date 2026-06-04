use crate::config::GatewayRuntimeConfig;
use crate::gateway::{init_telemetry_schema, register_runtime_bindings, ConfigurableRouter};
use crate::identity::{
    explicit_test_fixture_identity, load_node_verifier_identity, VerifierIdentityConfig,
};
use crate::manifest::ReceiverManifest;
use crate::payload::decrypt_machine_payload;
use crate::runtime_mode::RuntimeMode;
use crate::verifier::Verifier;
use libsec_core::ZenithPacket;
use sqlx::sqlite::SqlitePoolOptions;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const LOCAL_VERIFIER_SECRET_KEY: [u8; 32] = [7u8; 32];
pub const DEFAULT_MAX_WIRE_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_INGRESS_READ_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum IngressReadError {
    Transport(std::io::Error),
    ReadTimeout,
    WireFrameTooLarge { limit: usize },
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

    bincode::deserialize::<ZenithPacket>(&wire_bytes)
        .map(Some)
        .map_err(IngressReadError::MalformedPacket)
}

pub async fn handle_gateway_connection(router: Arc<ConfigurableRouter>, socket: TcpStream) {
    handle_gateway_connection_with_limits(
        router,
        socket,
        DEFAULT_MAX_WIRE_BYTES,
        DEFAULT_INGRESS_READ_TIMEOUT,
    )
    .await;
}

pub async fn handle_gateway_connection_with_limits(
    router: Arc<ConfigurableRouter>,
    socket: TcpStream,
    max_wire_bytes: usize,
    read_timeout: Duration,
) {
    let packet = match read_bounded_wire_packet(socket, max_wire_bytes, read_timeout).await {
        Ok(Some(packet)) => packet,
        Ok(None) => return,
        Err(IngressReadError::MalformedPacket(error)) => {
            eprintln!("secS [Transport]: rejected malformed packet - {}", error);
            return;
        }
        Err(IngressReadError::WireFrameTooLarge { limit }) => {
            eprintln!(
                "secS [Transport]: rejected oversized wire frame above {} bytes before packet decode",
                limit
            );
            return;
        }
        Err(error) => {
            eprintln!(
                "secS [Transport]: failed to read bounded connection - {}",
                error
            );
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

    let payload = match decrypt_machine_payload(&packet, RuntimeMode::from_env()) {
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
    let signed_context = match Verifier::verify_manifest_operation_and_sign_with_identity(
        &packet,
        &manifest,
        router.expected_audience(),
        current_unix_seconds(),
        router.identity(),
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

fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub async fn run_prototype_gateway(addr: &str, db_url: &str, label: &str) {
    let mut config = GatewayRuntimeConfig::from_env()
        .unwrap_or_else(|error| panic!("secS gateway: invalid runtime config - {error}"));
    config.bind_addr = addr.to_string();
    config.db_url = db_url.to_string();
    run_gateway_with_config(config, label).await;
}

pub async fn run_gateway_with_config(config: GatewayRuntimeConfig, label: &str) {
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
            explicit_test_fixture_identity("verifier:local-prototype", LOCAL_VERIFIER_SECRET_KEY)
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

    println!(
        "{} listening on {} with runtime_mode={} receiver_audience={} max_wire_bytes={} read_timeout_ms={} allowed_evidence_adapters={}",
        label,
        config.bind_addr,
        config.runtime_mode.label(),
        config.receiver_audience,
        config.max_wire_bytes,
        config.ingress_read_timeout.as_millis(),
        config.allowed_evidence_adapters.join(",")
    );

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                println!("secS [Transport]: accepted connection from {}", peer);
                let router = Arc::clone(&router);
                let max_wire_bytes = config.max_wire_bytes;
                let ingress_read_timeout = config.ingress_read_timeout;
                tokio::spawn(async move {
                    handle_gateway_connection_with_limits(
                        router,
                        socket,
                        max_wire_bytes,
                        ingress_read_timeout,
                    )
                    .await;
                });
            }
            Err(e) => eprintln!("secS [Transport]: failed to accept connection - {}", e),
        }
    }
}
