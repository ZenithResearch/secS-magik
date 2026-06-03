use async_trait::async_trait;
use libsec_core::ZenithPacket;
use server::gateway::{
    init_telemetry_schema, ConfigurableRouter, ExecutionLimits, HandlerOutcome, MachineProgram,
};
use server::identity::{load_node_verifier_identity, VerifierIdentityConfig};
use server::manifest::ReceiverManifest;
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerifiedCallContext, Verifier};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct CountingProgram {
    calls: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
    handler_ids: Arc<Mutex<Vec<Option<String>>>>,
}

#[async_trait]
impl MachineProgram for CountingProgram {
    async fn execute(&self, context: &VerifiedCallContext, payload: &[u8]) -> HandlerOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(payload.len(), Ordering::SeqCst);
        self.handler_ids
            .lock()
            .unwrap()
            .push(context.handler_id.clone());
        HandlerOutcome::succeeded()
    }
}

struct SlowProgram;

#[async_trait]
impl MachineProgram for SlowProgram {
    async fn execute(&self, _context: &VerifiedCallContext, _payload: &[u8]) -> HandlerOutcome {
        tokio::time::sleep(Duration::from_millis(50)).await;
        HandlerOutcome::succeeded()
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

fn packet(opcode: u8, payload: &[u8]) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: vec![1],
        claim_ttl: 600,
        encrypted_payload: payload.to_vec(),
        mac: [0u8; 16],
    }
}

fn signed_context(opcode: u8, payload: &[u8]) -> server::verifier::SignedVerifiedCallContext {
    Verifier::verify_manifest_operation_and_sign(
        &packet(opcode, payload),
        &ReceiverManifest::default_v0(),
        "secS://receiver-a",
        1_000,
        "verifier:local-test",
        &[7u8; 32],
    )
    .unwrap()
}

fn unique_temp_key_path(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("secs-magik-{name}-{nanos}.key"))
}

fn write_key_file(bytes: [u8; 32]) -> std::path::PathBuf {
    let path = unique_temp_key_path("b3-router-identity");
    fs::write(
        &path,
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )
    .expect("key fixture should be writable");
    path
}

type CountingProgramParts = (
    Box<CountingProgram>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<Mutex<Vec<Option<String>>>>,
);

fn counting_program() -> CountingProgramParts {
    let calls = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let handler_ids = Arc::new(Mutex::new(Vec::new()));
    (
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::clone(&bytes),
            handler_ids: Arc::clone(&handler_ids),
        }),
        calls,
        bytes,
        handler_ids,
    )
}

#[tokio::test]
async fn gateway_router_records_unverified_packets_without_executing_handler() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);

    router.route(0x10, b"payload".to_vec()).await;

    let row: (i64, i64, String) = sqlx::query_as(
        "SELECT opcode, payload_size, operation FROM node_telemetry ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (0x10, 7, "unverified.prototype".to_string()));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn gateway_router_rejects_unmapped_opcode_without_executing_program() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);

    router
        .route_verified(&signed_context(0x10, b"ignored"), b"ignored".to_vec())
        .await;
    router
        .route_verified(&signed_context(0x20, b"ignored"), b"ignored".to_vec())
        .await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let receipt: (String, String, String) = sqlx::query_as(
        "SELECT kind, decision, reason FROM receipts WHERE kind = 'execute' AND decision = 'rejected' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        receipt,
        (
            "execute".to_string(),
            "rejected".to_string(),
            "handler_unavailable".to_string()
        )
    );
}

#[tokio::test]
async fn gateway_router_signs_receipts_with_loaded_production_identity() {
    let path = write_key_file([0x45; 32]);
    let identity = load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    })
    .expect("production identity should load from configured key path");
    let expected_key_id = identity.signer_key_id().to_string();
    let (program, _calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_identity(pool.clone(), identity);
    router.register(0x10, program);

    router
        .route_verified(&signed_context(0x10, b"payload"), b"payload".to_vec())
        .await;

    let receipt_rows: Vec<(String, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT kind, signer_key_id, authenticator_kind, signature FROM receipts ORDER BY timestamp, receipt_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(receipt_rows.iter().any(|row| {
        row.0 == "verify"
            && row.1 == expected_key_id
            && row.2 == "ed25519_node_and_verifier"
            && !row.3.is_empty()
    }));
    assert!(receipt_rows.iter().any(|row| {
        row.0 == "execute"
            && row.1 == expected_key_id
            && row.2 == "ed25519_node_and_verifier"
            && !row.3.is_empty()
    }));

    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn gateway_router_default_receipts_are_marked_local_dev_untrusted() {
    let (program, _calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);

    router
        .route_verified(&signed_context(0x10, b"payload"), b"payload".to_vec())
        .await;

    let auth_kinds: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT authenticator_kind FROM receipts WHERE kind IN ('verify', 'execute')",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(auth_kinds, vec![("local_dev_untrusted".to_string(),)]);
}

#[tokio::test]
async fn gateway_router_executes_only_with_verified_context_passed_to_handler() {
    let (program, calls, bytes, handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let signed = signed_context(0x10, b"payload");

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
    assert_eq!(
        handler_ids.lock().unwrap().as_slice(),
        &[Some("dev/bash-echo".to_string())]
    );

    let receipt_rows: Vec<(String, String, String, String, String, Vec<u8>)> = sqlx::query_as(
        "SELECT kind, decision, operation, handler_id, authenticator_kind, signature FROM receipts ORDER BY timestamp, receipt_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(receipt_rows.iter().any(|row| {
        row.0 == "verify"
            && row.1 == "accepted"
            && row.2 == "candidate.dev.bash_echo"
            && row.3 == "dev/bash-echo"
            && row.4 == "local_dev_untrusted"
            && !row.5.is_empty()
    }));
    assert!(receipt_rows.iter().any(|row| {
        row.0 == "execute"
            && row.1 == "accepted"
            && row.2 == "candidate.dev.bash_echo"
            && row.3 == "dev/bash-echo"
            && row.4 == "local_dev_untrusted"
            && !row.5.is_empty()
    }));
}

#[tokio::test]
async fn gateway_router_rejects_payloads_over_configured_limit_before_handler_execution() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_limits(
        pool.clone(),
        ExecutionLimits {
            max_payload_bytes: 4,
            handler_timeout: Duration::from_secs(1),
        },
    );
    router.register(0x10, program);

    router
        .route_verified(&signed_context(0x10, b"too-big"), b"too-big".to_vec())
        .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let receipt: (String, String, String, String) = sqlx::query_as(
        "SELECT kind, decision, reason, handler_id FROM receipts WHERE kind = 'execute' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        receipt,
        (
            "execute".to_string(),
            "rejected".to_string(),
            "payload_too_large".to_string(),
            "dev/bash-echo".to_string()
        )
    );
}

#[tokio::test]
async fn gateway_router_rejects_timed_out_handlers_and_records_failure_without_payload_content() {
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_limits(
        pool.clone(),
        ExecutionLimits {
            max_payload_bytes: 1024,
            handler_timeout: Duration::from_millis(1),
        },
    );
    router.register(0x10, Box::new(SlowProgram));

    router
        .route_verified(
            &signed_context(0x10, b"secret payload"),
            b"secret payload".to_vec(),
        )
        .await;

    let receipt: (String, String, String, String) = sqlx::query_as(
        "SELECT kind, decision, reason, handler_id FROM receipts WHERE kind = 'execute' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        receipt,
        (
            "execute".to_string(),
            "rejected".to_string(),
            "handler_timeout".to_string(),
            "dev/bash-echo".to_string()
        )
    );

    let leaked_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE reason LIKE '%secret payload%' OR operation LIKE '%secret payload%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let leaked_receipt_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE reason LIKE '%secret payload%' OR operation LIKE '%secret payload%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked_event_count.0, 0);
    assert_eq!(leaked_receipt_count.0, 0);
}
