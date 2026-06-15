//! M13.3 — live ingress permission matrix for the sandboxed file-write demo.
//!
//! Drives a `demo.file.write` operation through the real gateway path
//! (verify → permission gate → handler → receipts) and proves the allowed and
//! denied cases each land with a stable typed reason and the right side effect.

use server::file_write::DemoFileWriteProgram;
use server::gateway::{init_telemetry_schema, ConfigurableRouter};
use server::manifest::{demo_file_write_descriptor, ReceiverManifest, DEMO_FILE_WRITE_HANDLER_ID};
use server::permissions::{
    AuthoritySource, PermissionEffect, PermissionPolicy, PermissionRecord, PermissionStatus,
    ResourceScope,
};
use server::verifier::Verifier;
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const OPCODE: u8 = 0x50;
const OPERATION: &str = "demo.file.write";
const CALLER: &str = "prototype.local-dev.subject";
const AUDIENCE: &str = "secS://receiver-a";
const SIGNER: &str = "verifier:local-prototype";
const SIGNING_KEY: [u8; 32] = [7u8; 32];

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

fn fresh_sandbox(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secs-perm-e2e-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create sandbox dir");
    dir
}

fn demo_manifest() -> ReceiverManifest {
    ReceiverManifest::default_v0().with_descriptor(demo_file_write_descriptor(OPCODE))
}

fn file_uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

/// Router with the demo manifest + handler + an installed permission policy.
fn router_with(
    pool: SqlitePool,
    sandbox: &Path,
    policy: Option<PermissionPolicy>,
) -> ConfigurableRouter {
    let mut router = ConfigurableRouter::new(pool);
    router.set_manifest(demo_manifest());
    router.register_handler(
        DEMO_FILE_WRITE_HANDLER_ID,
        Box::new(DemoFileWriteProgram::new(sandbox).expect("sandbox exists")),
    );
    if let Some(policy) = policy {
        router.set_permission_policy(policy);
    }
    router
}

fn packet(content: &[u8]) -> libsec_core::ZenithPacket {
    libsec_core::ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: OPCODE,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: content.to_vec(),
        mac: [0u8; 16],
    }
}

fn signed_for(
    pkt: &libsec_core::ZenithPacket,
    resource: &str,
    issued_at: u64,
) -> server::verifier::SignedVerifiedCallContext {
    Verifier::verify_manifest_operation_with_resource_and_sign(
        pkt,
        &demo_manifest(),
        AUDIENCE,
        Some(resource),
        issued_at,
        SIGNER,
        &SIGNING_KEY,
    )
    .expect("sign demo context with resource")
}

/// Latest execute receipt (kind, decision, reason).
async fn latest_execute_receipt(pool: &SqlitePool) -> (String, String, String) {
    sqlx::query_as(
        "SELECT kind, decision, reason FROM receipts WHERE kind = 'execute' ORDER BY timestamp DESC LIMIT 1",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

fn allow_record(resource: ResourceScope) -> PermissionRecord {
    PermissionRecord {
        caller_id: CALLER.to_string(),
        opcode: OPCODE,
        operation: OPERATION.to_string(),
        resource,
        effect: PermissionEffect::Allow,
        not_before: 0,
        not_after: u64::MAX,
        status: PermissionStatus::Active,
        authority_source: AuthoritySource::ReceiverLocal,
    }
}

#[tokio::test]
async fn allowed_caller_resource_writes_and_records_accepted_execute_receipt() {
    let sandbox = fresh_sandbox("happy");
    let target = sandbox.join("allowed.txt");
    let policy = PermissionPolicy::new(vec![allow_record(ResourceScope::Prefix {
        prefix: file_uri(&sandbox),
    })])
    .unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"granted content");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router
        .route_verified(&signed, b"granted content".to_vec())
        .await;

    assert_eq!(
        std::fs::read_to_string(&target).expect("file written"),
        "granted content"
    );
    let receipt = latest_execute_receipt(&pool).await;
    assert_eq!(receipt.0, "execute");
    assert_eq!(receipt.1, "accepted");

    // The verify receipt is also present (the inspectable chain).
    let verify_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'verify' AND decision = 'accepted'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(verify_count.0 >= 1, "verify receipt recorded");
}

#[tokio::test]
async fn wrong_resource_denies_before_write() {
    let sandbox = fresh_sandbox("wrong-resource");
    let granted = sandbox.join("allowed.txt");
    let other = sandbox.join("other.txt");
    // Grant only the exact allowed.txt.
    let policy = PermissionPolicy::new(vec![allow_record(ResourceScope::Exact {
        value: file_uri(&granted),
    })])
    .unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    // Sign a context for a different (in-sandbox) resource.
    let pkt = packet(b"should not write");
    let signed = signed_for(&pkt, &file_uri(&other), now());
    router
        .route_verified(&signed, b"should not write".to_vec())
        .await;

    assert!(!other.exists(), "denied resource must not be written");
    let receipt = latest_execute_receipt(&pool).await;
    assert_eq!(receipt.1, "rejected");
    assert_eq!(receipt.2, "permission_no_matching_grant");
}

#[tokio::test]
async fn revoked_grant_denies_before_write() {
    let sandbox = fresh_sandbox("revoked");
    let target = sandbox.join("allowed.txt");
    let mut record = allow_record(ResourceScope::Exact {
        value: file_uri(&target),
    });
    record.status = PermissionStatus::Revoked;
    let policy = PermissionPolicy::new(vec![record]).unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"revoked");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router.route_verified(&signed, b"revoked".to_vec()).await;

    assert!(!target.exists());
    let receipt = latest_execute_receipt(&pool).await;
    assert_eq!(receipt.1, "rejected");
    assert_eq!(receipt.2, "permission_revoked");
}

#[tokio::test]
async fn expired_grant_denies_before_write() {
    let sandbox = fresh_sandbox("expired");
    let target = sandbox.join("allowed.txt");
    let mut record = allow_record(ResourceScope::Exact {
        value: file_uri(&target),
    });
    record.not_before = 0;
    record.not_after = 1; // long past
    let policy = PermissionPolicy::new(vec![record]).unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"expired");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router.route_verified(&signed, b"expired".to_vec()).await;

    assert!(!target.exists());
    let receipt = latest_execute_receipt(&pool).await;
    assert_eq!(receipt.1, "rejected");
    assert_eq!(receipt.2, "permission_expired");
}

#[tokio::test]
async fn empty_policy_denies_everything_fail_closed() {
    let sandbox = fresh_sandbox("empty-policy");
    let target = sandbox.join("allowed.txt");
    let policy = PermissionPolicy::new(Vec::new()).unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"nope");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router.route_verified(&signed, b"nope".to_vec()).await;

    assert!(!target.exists());
    let receipt = latest_execute_receipt(&pool).await;
    assert_eq!(receipt.1, "rejected");
    assert_eq!(receipt.2, "permission_no_matching_grant");
}

#[tokio::test]
async fn replayed_context_denies_before_second_write() {
    let sandbox = fresh_sandbox("replay");
    let target = sandbox.join("allowed.txt");
    let policy = PermissionPolicy::new(vec![allow_record(ResourceScope::Prefix {
        prefix: file_uri(&sandbox),
    })])
    .unwrap();
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"first");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router.route_verified(&signed, b"first".to_vec()).await;
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "first");

    // Replay the identical signed context with different content; the replay
    // reservation rejects it before the handler runs, so the file is unchanged.
    router.route_verified(&signed, b"second".to_vec()).await;
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "first",
        "replayed context must not overwrite"
    );
    let replay_reject: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE decision = 'rejected' AND reason = 'replay_detected'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(replay_reject.0 >= 1, "replay was rejected with a receipt");
}

#[tokio::test]
async fn no_policy_means_no_permission_enforcement() {
    // Without an installed policy the router does not enforce permissions
    // (opt-in gate); the allowed write proceeds.
    let sandbox = fresh_sandbox("no-policy");
    let target = sandbox.join("allowed.txt");
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, None);

    let pkt = packet(b"unguarded");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router.route_verified(&signed, b"unguarded".to_vec()).await;

    assert_eq!(std::fs::read_to_string(&target).unwrap(), "unguarded");
}

#[tokio::test]
async fn permission_reject_receipt_does_not_leak_payload_or_path() {
    let sandbox = fresh_sandbox("redaction");
    let target = sandbox.join("secret-name.txt");
    let policy = PermissionPolicy::new(Vec::new()).unwrap(); // deny all
    let pool = pool().await;
    let router = router_with(pool.clone(), &sandbox, Some(policy));

    let pkt = packet(b"super secret payload bytes");
    let signed = signed_for(&pkt, &file_uri(&target), now());
    router
        .route_verified(&signed, b"super secret payload bytes".to_vec())
        .await;

    let rows: Vec<(String, String)> = sqlx::query_as("SELECT reason, operation FROM receipts")
        .fetch_all(&pool)
        .await
        .unwrap();
    let joined = rows
        .iter()
        .map(|(reason, op)| format!("{reason}|{op}"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !joined.contains("super secret payload"),
        "no payload in receipts"
    );
    assert!(
        !joined.contains("secret-name.txt"),
        "no raw target path in receipts"
    );
}
