use crate::gateway::{init_telemetry_schema, register_prototype_bindings, ConfigurableRouter};
use crate::manifest::ReceiverManifest;
use crate::payload::decrypt_machine_payload;
use crate::runtime_mode::RuntimeMode;
use crate::verifier::Verifier;
use libsec_core::ZenithPacket;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

const LOCAL_VERIFIER_KEY_ID: &str = "verifier:local-prototype";
const LOCAL_VERIFIER_SECRET_KEY: [u8; 32] = [7u8; 32];
const LOCAL_AUDIENCE: &str = "secS://prototype-gateway";

pub async fn handle_gateway_connection(router: Arc<ConfigurableRouter>, mut socket: TcpStream) {
    let mut wire_bytes = Vec::new();
    if let Err(e) = socket.read_to_end(&mut wire_bytes).await {
        eprintln!("secS [Transport]: failed to read connection - {}", e);
        return;
    }

    if wire_bytes.is_empty() {
        return;
    }

    let packet = match bincode::deserialize::<ZenithPacket>(&wire_bytes) {
        Ok(packet) => packet,
        Err(e) => {
            eprintln!("secS [Transport]: rejected malformed packet - {}", e);
            return;
        }
    };

    if let Err(error) = Verifier::verify_prototype_envelope(&packet) {
        eprintln!(
            "secS [Auth]: rejected packet with invalid prototype proof envelope - {}",
            error.reason_code()
        );
        return;
    }

    let payload = match decrypt_machine_payload(&packet, RuntimeMode::from_env()) {
        Ok(payload) => payload,
        Err(e) => {
            eprintln!("secS [Crypto]: rejected undecryptable payload - {}", e);
            return;
        }
    };

    let manifest = ReceiverManifest::default_v0();
    let signed_context = match Verifier::verify_manifest_operation_and_sign(
        &packet,
        &manifest,
        LOCAL_AUDIENCE,
        current_unix_seconds(),
        LOCAL_VERIFIER_KEY_ID,
        &LOCAL_VERIFIER_SECRET_KEY,
    ) {
        Ok(context) => context,
        Err(error) => {
            eprintln!(
                "secS [Manifest]: rejected packet before handler lookup - {}",
                error.reason_code()
            );
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
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("secS gateway: failed to connect to node_telemetry SQLite DB");

    init_telemetry_schema(&pool)
        .await
        .expect("secS gateway: failed to initialize node_telemetry table");

    let mut router = ConfigurableRouter::new(pool);
    register_prototype_bindings(&mut router);

    let router = Arc::new(router);
    let listener = TcpListener::bind(addr)
        .await
        .expect("secS gateway: failed to bind TCP listener");

    println!("{} listening on {}", label, addr);

    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                println!("secS [Transport]: accepted connection from {}", peer);
                let router = Arc::clone(&router);
                tokio::spawn(async move {
                    handle_gateway_connection(router, socket).await;
                });
            }
            Err(e) => eprintln!("secS [Transport]: failed to accept connection - {}", e),
        }
    }
}
