use async_trait::async_trait;
use libsec_core::ZenithPacket;
use server::gateway::{
    init_telemetry_schema, ConfigurableRouter, ExecutionLimits, HandlerOutcome, MachineProgram,
};
use server::identity::{load_node_verifier_identity, NodeVerifierIdentity, VerifierIdentityConfig};
use server::manifest::ReceiverManifest;
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerificationError, VerifiedCallContext, Verifier};
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

struct DecliningProgram {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl MachineProgram for DecliningProgram {
    async fn execute(&self, _context: &VerifiedCallContext, _payload: &[u8]) -> HandlerOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        HandlerOutcome::rejected("handler_declined")
    }
}

struct OutputProgram {
    output_bytes: usize,
}

#[async_trait]
impl MachineProgram for OutputProgram {
    async fn execute(&self, _context: &VerifiedCallContext, _payload: &[u8]) -> HandlerOutcome {
        HandlerOutcome::succeeded_with_output_bytes(self.output_bytes)
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

async fn file_pool(name: &str) -> (SqlitePool, std::path::PathBuf) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("secs-magik-{name}-{nanos}.sqlite"));
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    (pool, path)
}

fn packet(opcode: u8, payload: &[u8]) -> ZenithPacket {
    packet_with([1u8; 16], [2u8; 12], opcode, payload)
}

fn packet_with(session_id: [u8; 16], nonce: [u8; 12], opcode: u8, payload: &[u8]) -> ZenithPacket {
    ZenithPacket {
        session_id,
        nonce,
        opcode,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: payload.to_vec(),
        mac: [0u8; 16],
    }
}

fn signed_context(opcode: u8, payload: &[u8]) -> server::verifier::SignedVerifiedCallContext {
    signed_context_from_packet(&packet(opcode, payload))
}

fn signed_context_from_packet(
    packet: &ZenithPacket,
) -> server::verifier::SignedVerifiedCallContext {
    signed_context_from_packet_at(packet, current_test_time())
}

fn signed_context_from_packet_at(
    packet: &ZenithPacket,
    issued_at: u64,
) -> server::verifier::SignedVerifiedCallContext {
    Verifier::verify_manifest_operation_and_sign(
        packet,
        &ReceiverManifest::default_v0(),
        "secS://receiver-a",
        issued_at,
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .unwrap()
}

fn expired_signed_context(
    opcode: u8,
    payload: &[u8],
) -> server::verifier::SignedVerifiedCallContext {
    let mut packet = packet(opcode, payload);
    packet.claim_ttl = 1;
    signed_context_from_packet_at(&packet, current_test_time().saturating_sub(2))
}

fn wrong_audience_signed_context(
    opcode: u8,
    payload: &[u8],
) -> server::verifier::SignedVerifiedCallContext {
    Verifier::verify_manifest_operation_and_sign(
        &packet(opcode, payload),
        &ReceiverManifest::default_v0(),
        "secS://other",
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .unwrap()
}

fn signed_context_with_fields(
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    payload: &[u8],
) -> server::verifier::SignedVerifiedCallContext {
    signed_context_from_packet(&packet_with(session_id, nonce, opcode, payload))
}

fn signed_context_with_identity(
    opcode: u8,
    payload: &[u8],
    identity: &NodeVerifierIdentity,
) -> server::verifier::SignedVerifiedCallContext {
    Verifier::verify_manifest_operation_and_sign_with_identity(
        &packet(opcode, payload),
        &ReceiverManifest::default_v0(),
        "secS://receiver-a",
        current_test_time(),
        identity,
    )
    .unwrap()
}

fn current_test_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("key fixture should be owner-private");
    }
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
async fn gateway_router_signs_preverification_reject_receipts_and_emits_events_without_payload() {
    let pool = memory_pool().await;
    let router = ConfigurableRouter::new(pool.clone());
    let packet = packet(0x10, b"secret payload");

    router
        .record_reject(&packet, VerificationError::BadMac)
        .await;

    let receipt: (String, String, String, String, String, Vec<u8>) = sqlx::query_as(
        "SELECT kind, decision, reason, authenticator_kind, signer_key_id, signature FROM receipts ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(receipt.0, "reject");
    assert_eq!(receipt.1, "rejected");
    assert_eq!(receipt.2, "bad_mac");
    assert_eq!(receipt.3, "local_dev_untrusted");
    assert_eq!(receipt.4, "verifier:local-prototype");
    assert!(!receipt.5.is_empty());

    let emitted_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'receipt_emitted' AND reason = 'reject'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(emitted_event_count.0, 1);

    let rejected_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'packet_rejected' AND reason = 'bad_mac'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected_event_count.0, 1);

    let leaked_receipt_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE reason LIKE '%secret payload%' OR operation LIKE '%secret payload%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let leaked_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE reason LIKE '%secret payload%' OR operation LIKE '%secret payload%'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(leaked_receipt_count.0, 0);
    assert_eq!(leaked_event_count.0, 0);
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
async fn gateway_router_uses_descriptor_handler_id_not_opcode_for_program_selection() {
    let (registered_program, registered_calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, registered_program);
    let mut signed = signed_context(0x10, b"payload");
    signed.context.handler_id = Some("dev/unregistered-handler".to_string());
    signed = router
        .identity()
        .sign_context(signed.context)
        .expect("mutated descriptor context should be re-signed by test identity");

    router.route_verified(&signed, b"payload".to_vec()).await;

    assert_eq!(registered_calls.load(Ordering::SeqCst), 0);
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
            "handler_unavailable".to_string(),
            "dev/unregistered-handler".to_string()
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

    let signed = signed_context_with_identity(0x10, b"payload", router.identity());
    router.route_verified(&signed, b"payload".to_vec()).await;

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
async fn gateway_router_rejects_untrusted_signed_context_before_receipts_or_handler() {
    let path = write_key_file([0x55; 32]);
    let identity = load_node_verifier_identity(&VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    })
    .expect("production identity should load from configured key path");
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_identity(pool.clone(), identity);
    router.register(0x10, program);

    router
        .route_verified(&signed_context(0x10, b"payload"), b"payload".to_vec())
        .await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let receipt_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM receipts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(receipt_count.0, 0);
    let telemetry_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node_telemetry")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(telemetry_count.0, 0);
    let replay_reservation_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replay_reservation_count.0, 0);

    let _ = fs::remove_file(path);
}

#[tokio::test]
async fn gateway_router_rejects_replayed_verified_context_before_handler_execution() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let signed = signed_context(0x10, b"payload");

    router.route_verified(&signed, b"payload".to_vec()).await;
    router.route_verified(&signed, b"payload".to_vec()).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reject_receipt: (String, String, String) = sqlx::query_as(
        "SELECT kind, decision, reason FROM receipts WHERE kind = 'reject' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        reject_receipt,
        (
            "reject".to_string(),
            "rejected".to_string(),
            "replay_detected".to_string()
        )
    );
    let rejected_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'packet_rejected' AND reason = 'replay_detected'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected_event_count.0, 1);
    let handler_started_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM events WHERE event_kind = 'handler_started'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(handler_started_count.0, 1);
    let operation_routed_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM events WHERE event_kind = 'operation_routed'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(operation_routed_count.0, 1);
    let telemetry_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM node_telemetry")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(telemetry_count.0, 1);
    let accepted_verify_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'verify' AND decision = 'accepted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accepted_verify_count.0, 1);
    let accepted_execute_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'execute' AND decision = 'accepted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accepted_execute_count.0, 1);
}

#[tokio::test]
async fn gateway_router_records_reject_receipt_for_expired_signed_context_before_handler_execution()
{
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let signed = expired_signed_context(0x10, b"payload");

    router.route_verified(&signed, b"payload".to_vec()).await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let reject_receipt: (String, String, String) = sqlx::query_as(
        "SELECT kind, decision, reason FROM receipts WHERE kind = 'reject' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        reject_receipt,
        (
            "reject".to_string(),
            "rejected".to_string(),
            "expired_claim".to_string()
        )
    );
    let rejected_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'packet_rejected' AND reason = 'expired_claim'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected_event_count.0, 1);
    let replay_reservation_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replay_reservation_count.0, 0);
    let handler_started_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM events WHERE event_kind = 'handler_started'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(handler_started_count.0, 0);
}

#[tokio::test]
async fn gateway_router_wrong_audience_signed_context_records_reject_without_replay_reservation() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let signed = wrong_audience_signed_context(0x10, b"payload");

    router.route_verified(&signed, b"payload".to_vec()).await;

    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let reject_receipt_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'reject' AND decision = 'rejected' AND reason = 'wrong_audience'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(reject_receipt_count.0, 1);
    let rejected_event_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM events WHERE event_kind = 'packet_rejected' AND reason = 'wrong_audience'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(rejected_event_count.0, 1);
    let replay_reservation_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(replay_reservation_count.0, 0);
}

#[tokio::test]
async fn gateway_router_replay_reservation_survives_first_handler_rejection() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(DecliningProgram {
            calls: Arc::clone(&calls),
        }),
    );
    let signed = signed_context(0x10, b"payload");

    router.route_verified(&signed, b"payload".to_vec()).await;
    router.route_verified(&signed, b"payload".to_vec()).await;

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reasons: Vec<(String, String)> = sqlx::query_as(
        "SELECT kind, reason FROM receipts WHERE reason IS NOT NULL ORDER BY timestamp, receipt_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(reasons
        .iter()
        .any(|row| row.0 == "execute" && row.1 == "handler_declined"));
    assert!(reasons
        .iter()
        .any(|row| row.0 == "reject" && row.1 == "replay_detected"));
}

#[tokio::test]
async fn gateway_router_replay_scope_is_session_opcode_nonce() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let (program_20, _calls_20, _bytes_20, _handler_ids_20) = counting_program();
    router.register(0x20, program_20);

    let exact = signed_context_with_fields([1u8; 16], [2u8; 12], 0x10, b"payload");
    let different_session_same_nonce =
        signed_context_with_fields([3u8; 16], [2u8; 12], 0x10, b"payload");
    let same_session_nonce_different_opcode =
        signed_context_with_fields([1u8; 16], [2u8; 12], 0x20, b"payload");

    router.route_verified(&exact, b"payload".to_vec()).await;
    router
        .route_verified(&different_session_same_nonce, b"payload".to_vec())
        .await;
    router
        .route_verified(&same_session_nonce_different_opcode, b"payload".to_vec())
        .await;
    router.route_verified(&exact, b"payload".to_vec()).await;

    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let reservation_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reservation_count.0, 3);
    let replay_reject_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'reject' AND reason = 'replay_detected'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_reject_count.0, 1);
}

#[tokio::test]
async fn gateway_router_concurrent_identical_replay_executes_once() {
    let (program, calls, _bytes, _handler_ids) = counting_program();
    let (pool, db_path) = file_pool("concurrent-replay").await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(0x10, program);
    let router = Arc::new(router);
    let signed = signed_context(0x10, b"payload");
    let first_router = Arc::clone(&router);
    let second_router = Arc::clone(&router);
    let first_signed = signed.clone();
    let second_signed = signed.clone();

    let ((), ()) = tokio::join!(
        async move {
            first_router
                .route_verified(&first_signed, b"payload".to_vec())
                .await;
        },
        async move {
            second_router
                .route_verified(&second_signed, b"payload".to_vec())
                .await;
        }
    );

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let reservation_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(reservation_count.0, 1);
    let replay_reject_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'reject' AND reason = 'replay_detected'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_reject_count.0, 1);
    let handler_started_count: (i64,) =
        sqlx::query_as("SELECT COUNT(*) FROM events WHERE event_kind = 'handler_started'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(handler_started_count.0, 1);

    drop(pool);
    let _ = fs::remove_file(db_path);
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
            max_output_bytes: 1024,
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
async fn gateway_router_emits_execution_receipts_for_all_handler_outcomes() {
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_limits(
        pool.clone(),
        ExecutionLimits {
            max_payload_bytes: 4,
            max_output_bytes: 4,
            handler_timeout: Duration::from_millis(1),
        },
    );
    let calls = Arc::new(AtomicUsize::new(0));
    router.register(
        0x10,
        Box::new(DecliningProgram {
            calls: Arc::clone(&calls),
        }),
    );
    router.register(0x20, Box::new(OutputProgram { output_bytes: 8 }));
    router.register(0x30, Box::new(SlowProgram));

    router
        .route_verified(
            &signed_context_with_fields([1u8; 16], [1u8; 12], 0x10, b"ok"),
            b"ok".to_vec(),
        )
        .await;
    router
        .route_verified(
            &signed_context_with_fields([2u8; 16], [2u8; 12], 0x10, b"oversized"),
            b"oversized".to_vec(),
        )
        .await;
    router
        .route_verified(
            &signed_context_with_fields([3u8; 16], [3u8; 12], 0x20, b"ok"),
            b"ok".to_vec(),
        )
        .await;
    router
        .route_verified(
            &signed_context_with_fields([4u8; 16], [4u8; 12], 0x30, b"ok"),
            b"ok".to_vec(),
        )
        .await;
    let mut unavailable = signed_context_with_fields([5u8; 16], [5u8; 12], 0x10, b"ok");
    unavailable.context.handler_id = Some("dev/unregistered-handler".to_string());
    unavailable = router
        .identity()
        .sign_context(unavailable.context)
        .expect("mutated unavailable handler context should re-sign");
    router.route_verified(&unavailable, b"ok".to_vec()).await;

    let rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT decision, reason FROM receipts WHERE kind = 'execute' ORDER BY timestamp, receipt_id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert!(rows.iter().any(|row| row == &("rejected".to_string(), Some("handler_declined".to_string()))));
    assert!(rows.iter().any(|row| row == &("rejected".to_string(), Some("payload_too_large".to_string()))));
    assert!(rows.iter().any(|row| row == &("rejected".to_string(), Some("output_too_large".to_string()))));
    assert!(rows.iter().any(|row| row == &("rejected".to_string(), Some("handler_timeout".to_string()))));
    assert!(rows.iter().any(|row| row == &("rejected".to_string(), Some("handler_unavailable".to_string()))));
    assert_eq!(rows.len(), 5);
}

#[tokio::test]
async fn gateway_router_rejects_handler_output_over_configured_limit_without_logging_output() {
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::with_limits(
        pool.clone(),
        ExecutionLimits {
            max_payload_bytes: 1024,
            max_output_bytes: 4,
            handler_timeout: Duration::from_secs(1),
        },
    );
    router.register(0x10, Box::new(OutputProgram { output_bytes: 8 }));

    router
        .route_verified(&signed_context(0x10, b"payload"), b"payload".to_vec())
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
            "output_too_large".to_string(),
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
            max_output_bytes: 1024,
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
