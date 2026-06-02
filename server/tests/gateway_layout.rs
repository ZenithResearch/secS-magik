use async_trait::async_trait;
use libsec_core::ZenithPacket;
use server::gateway::{init_telemetry_schema, ConfigurableRouter, MachineProgram};
use server::manifest::ReceiverManifest;
use server::verifier::Verifier;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingProgram {
    calls: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

#[async_trait]
impl MachineProgram for CountingProgram {
    async fn execute(&self, payload: &[u8]) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(payload.len(), Ordering::SeqCst);
    }
}

async fn memory_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn gateway_router_lives_in_library_and_records_telemetry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::clone(&bytes),
        }),
    );

    router.route(0x10, b"payload".to_vec()).await;

    let row: (i64, i64) =
        sqlx::query_as("SELECT opcode, payload_size FROM node_telemetry ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (0x10, 7));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(bytes.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn gateway_router_rejects_unmapped_opcode_without_executing_program() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::new(AtomicUsize::new(0)),
        }),
    );

    router.route(0x99, b"ignored".to_vec()).await;

    let row: (i64, i64) =
        sqlx::query_as("SELECT opcode, payload_size FROM node_telemetry ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (0x99, 7));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gateway_router_executes_only_after_signed_verified_context_exists() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::clone(&bytes),
        }),
    );
    let packet = ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        proof: vec![1],
        claim_ttl: 600,
        encrypted_payload: b"payload".to_vec(),
        mac: [0u8; 16],
    };
    let signed = Verifier::verify_manifest_operation_and_sign(
        &packet,
        &ReceiverManifest::default_v0(),
        "secS://receiver-a",
        1_000,
        "verifier:local-test",
        &[7u8; 32],
    )
    .unwrap();

    router.route_verified(&signed, b"payload".to_vec()).await;

    let row: (i64, i64, String) = sqlx::query_as(
        "SELECT opcode, payload_size, operation FROM node_telemetry ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (0x10, 7, "candidate.dev.bash_echo".to_string()));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(bytes.load(Ordering::SeqCst), 7);
}
