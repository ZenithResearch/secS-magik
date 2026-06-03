use libsec_core::ZenithPacket;
use server::ledger::{Ledger, ReplayReservationOutcome};
use server::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind, ReceiptKind};
use server::verifier::{VerificationError, VerifiedCallContext, VerifiedSubject, Verifier};
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

fn verified_context(session_id: [u8; 16], nonce: [u8; 12], opcode: u8) -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 1,
        context_id: format!("ctx-{opcode:02x}-{}", nonce[0]),
        packet_hash: [9u8; 32],
        session_id,
        nonce,
        opcode,
        operation: "candidate.dev.bash_echo".to_string(),
        subject: VerifiedSubject {
            subject_id: "prototype.local-dev.subject".to_string(),
            key_id: "subject-key:test".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec!["prototype".to_string()],
        capability_result: "accepted".to_string(),
        credential_result: "accepted".to_string(),
        issued_at: 1_000,
        expires_at: 1_300,
        replay_scope: "SessionOpcodeNonce".to_string(),
        handler_id: Some("dev/bash-echo".to_string()),
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
async fn ledger_schema_creates_replay_reservations_table() {
    let ledger = memory_ledger().await;

    let replay_count: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'replay_reservations'",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(replay_count.0, 1);
}

#[tokio::test]
async fn first_replay_reservation_returns_reserved_and_persists_one_row() {
    let ledger = memory_ledger().await;
    let context = verified_context([1u8; 16], [2u8; 12], 0x10);

    let outcome = ledger
        .reserve_replay(&context, "verifier:local-test", 1_001)
        .await
        .unwrap();

    assert_eq!(outcome, ReplayReservationOutcome::Reserved);
    let row: (i64, i64, i64, String, Vec<u8>, i64, Vec<u8>, Vec<u8>, String, String) = sqlx::query_as(
        "SELECT COUNT(*), reserved_at, expires_at, replay_scope, session_id, opcode, nonce, packet_hash, context_id, signer_key_id FROM replay_reservations",
    )
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(row.0, 1);
    assert_eq!(row.1, 1_001);
    assert_eq!(row.2, 1_300);
    assert_eq!(row.3, "SessionOpcodeNonce");
    assert_eq!(row.4, context.session_id.to_vec());
    assert_eq!(row.5, 0x10);
    assert_eq!(row.6, context.nonce.to_vec());
    assert_eq!(row.7, context.packet_hash.to_vec());
    assert_eq!(row.8, context.context_id);
    assert_eq!(row.9, "verifier:local-test");
}

#[tokio::test]
async fn duplicate_replay_reservation_same_session_opcode_nonce_scope_is_duplicate() {
    let ledger = memory_ledger().await;
    let context = verified_context([1u8; 16], [2u8; 12], 0x10);

    assert_eq!(
        ledger
            .reserve_replay(&context, "verifier:local-test", 1_001)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
    assert_eq!(
        ledger
            .reserve_replay(&context, "verifier:local-test", 1_002)
            .await
            .unwrap(),
        ReplayReservationOutcome::Duplicate
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(ledger.pool())
        .await
        .unwrap();
    assert_eq!(count.0, 1);
}

#[tokio::test]
async fn replay_reservation_allows_different_nonce_same_session_opcode() {
    let ledger = memory_ledger().await;
    let first = verified_context([1u8; 16], [2u8; 12], 0x10);
    let second = verified_context([1u8; 16], [3u8; 12], 0x10);

    assert_eq!(
        ledger
            .reserve_replay(&first, "verifier:local-test", 1_001)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
    assert_eq!(
        ledger
            .reserve_replay(&second, "verifier:local-test", 1_002)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
}

#[tokio::test]
async fn replay_reservation_allows_same_nonce_different_session_under_session_opcode_nonce_scope() {
    let ledger = memory_ledger().await;
    let first = verified_context([1u8; 16], [2u8; 12], 0x10);
    let second = verified_context([4u8; 16], [2u8; 12], 0x10);

    assert_eq!(
        ledger
            .reserve_replay(&first, "verifier:local-test", 1_001)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
    assert_eq!(
        ledger
            .reserve_replay(&second, "verifier:local-test", 1_002)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
}

#[tokio::test]
async fn replay_reservation_allows_same_nonce_same_session_different_opcode() {
    let ledger = memory_ledger().await;
    let first = verified_context([1u8; 16], [2u8; 12], 0x10);
    let second = verified_context([1u8; 16], [2u8; 12], 0x11);

    assert_eq!(
        ledger
            .reserve_replay(&first, "verifier:local-test", 1_001)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
    assert_eq!(
        ledger
            .reserve_replay(&second, "verifier:local-test", 1_002)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
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
