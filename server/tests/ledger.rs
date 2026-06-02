use libsec_core::ZenithPacket;
use server::ledger::Ledger;
use server::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind, ReceiptKind};
use server::verifier::{VerificationError, Verifier};
use sqlx::sqlite::SqlitePoolOptions;

async fn memory_ledger() -> Ledger {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    ledger
}

fn packet() -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: b"secret payload that must not be stored".to_vec(),
        mac: [0u8; 16],
    }
}

#[tokio::test]
async fn ledger_schema_creates_events_and_receipts_tables() {
    let ledger = memory_ledger().await;

    let events_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'events'",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();
    let receipts_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'receipts'",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(events_count.0, 1);
    assert_eq!(receipts_count.0, 1);
}

#[tokio::test]
async fn ledger_records_events_without_payload_content() {
    let ledger = memory_ledger().await;

    ledger
        .record_event(
            ReceiptEventKind::PacketReceived,
            Some([9u8; 32]),
            Some(0x10),
            Some("candidate.dev.bash_echo"),
            Some("dev/bash-echo"),
            Some("payload_size:37"),
            123,
        )
        .await
        .unwrap();

    let row: (String, i64, String, String) = sqlx::query_as(
        "SELECT event_kind, opcode, operation, reason FROM events ORDER BY id DESC LIMIT 1",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(row.0, "packet_received");
    assert_eq!(row.1, 0x10);
    assert_eq!(row.2, "candidate.dev.bash_echo");
    assert_eq!(row.3, "payload_size:37");

    let dumped: Vec<(String,)> = sqlx::query_as("SELECT reason FROM events")
        .fetch_all(ledger.pool())
        .await
        .unwrap();
    assert!(!format!("{dumped:?}").contains("secret payload"));
}

#[tokio::test]
async fn ledger_persists_signed_receipt_metadata() {
    let ledger = memory_ledger().await;
    let packet = packet();
    let signed_context = Verifier::verify_manifest_operation_and_sign(
        &packet,
        &server::manifest::ReceiverManifest::default_v0(),
        "secS://receiver-a",
        1_000,
        "verifier:local-test",
        &[7u8; 32],
    )
    .unwrap();
    let receipt =
        Receipt::verify_from_signed_context("receipt-ledger-verify", &signed_context, 1_001)
            .sign_ed25519(
                "verifier:local-test",
                &[7u8; 32],
                AuthenticatorKind::Ed25519Verifier,
            )
            .unwrap();

    ledger.record_receipt(&receipt).await.unwrap();

    let row: (String, String, String, String, Vec<u8>) = sqlx::query_as(
        "SELECT kind, decision, authenticator_kind, signer_key_id, signature FROM receipts WHERE receipt_id = ?",
    )
    .bind("receipt-ledger-verify")
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(row.0, "verify");
    assert_eq!(row.1, "accepted");
    assert_eq!(row.2, "ed25519_verifier");
    assert_eq!(row.3, "verifier:local-test");
    assert!(!row.4.is_empty());
}

#[tokio::test]
async fn ledger_records_reject_receipt_from_verification_error_without_payload_content() {
    let ledger = memory_ledger().await;
    let packet = packet();
    let receipt = Receipt::reject_from_packet(
        "receipt-ledger-reject",
        &packet,
        VerificationError::UnknownOperation,
        1_010,
    );

    ledger.record_receipt(&receipt).await.unwrap();

    let row: (String, String, i64, Option<String>) =
        sqlx::query_as("SELECT kind, reason, opcode, operation FROM receipts WHERE receipt_id = ?")
            .bind("receipt-ledger-reject")
            .fetch_one(ledger.pool())
            .await
            .unwrap();

    assert_eq!(row.0, "reject");
    assert_eq!(row.1, "unknown_operation");
    assert_eq!(row.2, 0x10);
    assert_eq!(row.3, None);

    let dumped: Vec<(String,)> = sqlx::query_as("SELECT reason FROM receipts")
        .fetch_all(ledger.pool())
        .await
        .unwrap();
    assert!(!format!("{dumped:?}").contains("secret payload"));
}

#[test]
fn receipt_kinds_and_decisions_have_stable_storage_values() {
    assert_eq!(ReceiptKind::Reject.as_str(), "reject");
    assert_eq!(ReceiptKind::Verify.as_str(), "verify");
    assert_eq!(ReceiptKind::Execute.as_str(), "execute");
    assert_eq!(ReceiptKind::Forward.as_str(), "forward");
    assert_eq!(Decision::Accepted.as_str(), "accepted");
    assert_eq!(Decision::Rejected.as_str(), "rejected");
    assert_eq!(
        AuthenticatorKind::Ed25519Verifier.as_str(),
        "ed25519_verifier"
    );
}
