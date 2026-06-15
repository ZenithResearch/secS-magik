use libsec_core::ZenithPacket;
use server::ledger::{Ledger, OperatorReceiptInspection, ReplayReservationOutcome};
use server::receipt::{
    AuthenticatorKind, Decision, Receipt, ReceiptEventKind, ReceiptKind, RECEIPT_SCHEMA_VERSION,
};
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
        schema_version: 2,
        descriptor_fingerprint: String::new(),
        context_id: format!("ctx-{opcode:02x}-{}", nonce[0]),
        packet_hash: [9u8; 32],
        session_id,
        nonce,
        opcode,
        operation: "candidate.dev.bash_echo".to_string(),
        resource: None,
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
    type ReplayReservationRow = (
        i64,
        i64,
        i64,
        String,
        Vec<u8>,
        i64,
        Vec<u8>,
        Vec<u8>,
        String,
        String,
    );

    let row: ReplayReservationRow = sqlx::query_as(
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
async fn replay_reservation_prune_removes_only_expired_rows() {
    let ledger = memory_ledger().await;
    let expired = verified_context([1u8; 16], [2u8; 12], 0x10);
    let boundary = verified_context([3u8; 16], [4u8; 12], 0x10);
    let future = verified_context([5u8; 16], [6u8; 12], 0x10);

    for (context, expires_at) in [(&expired, 99), (&boundary, 100), (&future, 101)] {
        let mut context = context.clone();
        context.expires_at = expires_at;
        ledger
            .reserve_replay(&context, "verifier:local-test", 1)
            .await
            .unwrap();
    }

    let deleted = ledger.prune_expired_replay_reservations(100).await.unwrap();

    assert_eq!(deleted, 1);
    let rows: Vec<(Vec<u8>, i64)> =
        sqlx::query_as("SELECT nonce, expires_at FROM replay_reservations ORDER BY expires_at")
            .fetch_all(ledger.pool())
            .await
            .unwrap();
    assert_eq!(
        rows,
        vec![([4u8; 12].to_vec(), 100), ([6u8; 12].to_vec(), 101)]
    );
}

#[tokio::test]
async fn replay_reservation_can_be_reused_after_expiration_prune() {
    let ledger = memory_ledger().await;
    let mut context = verified_context([1u8; 16], [2u8; 12], 0x10);
    context.expires_at = 100;

    assert_eq!(
        ledger
            .reserve_replay(&context, "verifier:local-test", 1)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );
    assert_eq!(
        ledger
            .reserve_replay(&context, "verifier:local-test", 99)
            .await
            .unwrap(),
        ReplayReservationOutcome::Duplicate
    );
    assert_eq!(
        ledger
            .reserve_replay(&context, "verifier:local-test", 101)
            .await
            .unwrap(),
        ReplayReservationOutcome::Reserved
    );

    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM replay_reservations")
        .fetch_one(ledger.pool())
        .await
        .unwrap();
    assert_eq!(count.0, 1);
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

    let row: (i64, String, String, String, String, Vec<u8>, String) = sqlx::query_as(
        "SELECT schema_version, kind, decision, authenticator_kind, signer_key_id, signature, context_id FROM receipts WHERE receipt_id = ?",
    )
    .bind("receipt-ledger-verify")
    .fetch_one(ledger.pool())
    .await
    .unwrap();

    assert_eq!(row.0, i64::from(RECEIPT_SCHEMA_VERSION));
    assert_eq!(row.1, "verify");
    assert_eq!(row.2, "accepted");
    assert_eq!(row.3, "ed25519_verifier");
    assert_eq!(row.4, "verifier:local-test");
    assert!(!row.5.is_empty());
    assert_eq!(row.6, signed_context.context.context_id);
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

#[tokio::test]
async fn operator_can_inspect_redacted_receipt_accept_execute_chain_by_context_id() {
    let ledger = memory_ledger().await;
    let context = verified_context([1u8; 16], [2u8; 12], 0x10);
    let signed_context = context
        .clone()
        .sign_ed25519(
            "verifier:local-test",
            &[7u8; 32],
            AuthenticatorKind::Ed25519Verifier,
        )
        .unwrap();
    let verify_receipt =
        Receipt::verify_from_signed_context("receipt-chain-verify", &signed_context, 1_001)
            .sign_ed25519(
                "verifier:local-test",
                &[7u8; 32],
                AuthenticatorKind::Ed25519Verifier,
            )
            .unwrap();
    let execute_receipt = Receipt::execution(
        "receipt-chain-execute",
        &context,
        Decision::Accepted,
        Some("handler_succeeded"),
        1_002,
    );

    ledger.record_receipt(&verify_receipt).await.unwrap();
    ledger.record_receipt(&execute_receipt).await.unwrap();

    let chain = ledger
        .inspect_receipt_chain_by_context_id(&context.context_id)
        .await
        .unwrap();

    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].receipt_id, "receipt-chain-verify");
    assert_eq!(chain[0].kind, "verify");
    assert_eq!(chain[0].decision, "accepted");
    assert_eq!(chain[0].reason, None);
    assert_eq!(chain[0].schema_version, RECEIPT_SCHEMA_VERSION);
    assert_eq!(
        chain[0].export_schema_version,
        OperatorReceiptInspection::EXPORT_SCHEMA_VERSION
    );
    assert_eq!(
        chain[0].context_id.as_deref(),
        Some(context.context_id.as_str())
    );
    assert!(chain[0].signature_present);
    assert_eq!(chain[0].signature_len, 64);
    assert_eq!(chain[0].signature_sha256_hex.as_deref().unwrap().len(), 64);
    assert_eq!(chain[0].packet_hash_hex, "09".repeat(32));
    assert_eq!(chain[0].session_id_hex, "01".repeat(16));
    assert_eq!(chain[0].nonce_hex, "02".repeat(12));

    assert_eq!(chain[1].receipt_id, "receipt-chain-execute");
    assert_eq!(chain[1].kind, "execute");
    assert_eq!(chain[1].decision, "accepted");
    assert_eq!(chain[1].reason.as_deref(), Some("handler_succeeded"));
    assert!(!chain[1].signature_present);
    assert_eq!(chain[1].signature_len, 0);
    assert_eq!(chain[1].signature_sha256_hex, None);
    assert_eq!(
        chain[1].redaction_policy,
        "local_redacted_no_payload_or_private_evidence_by_default"
    );

    let exported_debug = format!("{chain:?}");
    assert!(!exported_debug.contains("secret payload"));
    assert!(!exported_debug.contains("prototype-proof-envelope"));
    assert!(!exported_debug.contains("private evidence"));
}

#[tokio::test]
async fn operator_can_inspect_reason_coded_reject_by_receipt_id_without_signature_bytes() {
    let ledger = memory_ledger().await;
    let packet = packet();
    let receipt = Receipt::reject_from_packet(
        "receipt-chain-reject",
        &packet,
        VerificationError::UnknownOperation,
        1_010,
    );

    ledger.record_receipt(&receipt).await.unwrap();

    let export = ledger
        .inspect_receipt_by_id("receipt-chain-reject")
        .await
        .unwrap()
        .expect("known receipt is inspectable");

    assert_eq!(export.receipt_id, "receipt-chain-reject");
    assert_eq!(export.kind, "reject");
    assert_eq!(export.decision, "rejected");
    assert_eq!(export.reason.as_deref(), Some("unknown_operation"));
    assert_eq!(export.context_id, None);
    assert_eq!(export.schema_version, RECEIPT_SCHEMA_VERSION);
    assert!(!export.signature_present);
    assert_eq!(export.signature_len, 0);
    assert_eq!(export.signature_sha256_hex, None);
    assert_eq!(export.packet_hash_hex.len(), 64);
    assert_eq!(export.session_id_hex, "01".repeat(16));
    assert_eq!(export.nonce_hex, "02".repeat(12));

    let exported_debug = format!("{export:?}");
    assert!(!exported_debug.contains("secret payload"));
    assert!(!exported_debug.contains("proof"));
    assert!(!exported_debug.contains("signature: ["));
}

#[tokio::test]
async fn operator_inspection_distinguishes_track_e_policy_failure_layers() {
    let ledger = memory_ledger().await;
    let packet = packet();
    let layer_failures = [
        (
            "receipt-wallet-layer",
            VerificationError::WrongOrigin,
            "wrong_origin",
        ),
        (
            "receipt-issuer-trust-layer",
            VerificationError::WrongTrustRoot,
            "wrong_trust_root",
        ),
        (
            "receipt-credential-status-layer",
            VerificationError::RevokedCredential,
            "revoked_credential",
        ),
        (
            "receipt-local-policy-layer",
            VerificationError::WrongResource,
            "wrong_resource",
        ),
    ];

    for (receipt_id, error, _) in &layer_failures {
        ledger
            .record_receipt(&Receipt::reject_from_packet(
                *receipt_id,
                &packet,
                error.clone(),
                1_717_000_000,
            ))
            .await
            .unwrap();
    }

    for (receipt_id, _, expected_reason) in &layer_failures {
        let export = ledger
            .inspect_receipt_by_id(receipt_id)
            .await
            .unwrap()
            .expect("reject receipt is inspectable");
        assert_eq!(export.kind, "reject");
        assert_eq!(export.decision, "rejected");
        assert_eq!(export.reason.as_deref(), Some(*expected_reason));
        assert!(!export.signature_present);
        assert_eq!(export.signature_sha256_hex, None);
    }
}

#[tokio::test]
async fn operator_inspection_rejects_invalid_persisted_receipt_metadata() {
    let ledger = memory_ledger().await;

    sqlx::query(
        "INSERT INTO receipts (
            receipt_id,
            schema_version,
            context_id,
            timestamp,
            kind,
            packet_hash,
            session_id,
            nonce,
            opcode,
            operation,
            decision,
            reason,
            handler_id,
            authenticator_kind,
            signer_key_id,
            signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("receipt-corrupt-schema")
    .bind(i64::from(u16::MAX) + 1)
    .bind("ctx-corrupt")
    .bind(1_020_i64)
    .bind("verify")
    .bind(vec![1u8; 32])
    .bind(vec![2u8; 16])
    .bind(vec![3u8; 12])
    .bind(0x10_i64)
    .bind("candidate.dev.bash_echo")
    .bind("accepted")
    .bind(Option::<String>::None)
    .bind("dev/bash-echo")
    .bind("ed25519_verifier")
    .bind("verifier:test")
    .bind(vec![4u8; 64])
    .execute(ledger.pool())
    .await
    .unwrap();

    assert!(ledger
        .inspect_receipt_by_id("receipt-corrupt-schema")
        .await
        .is_err());
}

#[tokio::test]
async fn ledger_schema_upgrade_preserves_old_receipts_and_adds_track_h_columns() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::query(
        "CREATE TABLE receipts (
            receipt_id TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL,
            kind TEXT NOT NULL,
            packet_hash BLOB NOT NULL,
            session_id BLOB NOT NULL,
            nonce BLOB NOT NULL,
            opcode INTEGER NOT NULL,
            operation TEXT,
            decision TEXT NOT NULL,
            reason TEXT,
            handler_id TEXT,
            authenticator_kind TEXT NOT NULL,
            signer_key_id TEXT NOT NULL,
            signature BLOB NOT NULL
        );",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO receipts (
            receipt_id, timestamp, kind, packet_hash, session_id, nonce, opcode,
            operation, decision, reason, handler_id, authenticator_kind, signer_key_id, signature
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind("receipt-old-v0")
    .bind(1_030_i64)
    .bind("reject")
    .bind(vec![1u8; 32])
    .bind(vec![2u8; 16])
    .bind(vec![3u8; 12])
    .bind(0x10_i64)
    .bind(Option::<String>::None)
    .bind("rejected")
    .bind("unknown_operation")
    .bind(Option::<String>::None)
    .bind("local_dev_untrusted")
    .bind("")
    .bind(Vec::<u8>::new())
    .execute(&pool)
    .await
    .unwrap();

    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();

    let export = ledger
        .inspect_receipt_by_id("receipt-old-v0")
        .await
        .unwrap()
        .expect("old receipt remains inspectable after schema upgrade");
    assert_eq!(export.schema_version, RECEIPT_SCHEMA_VERSION);
    assert_eq!(export.context_id, None);
    assert_eq!(export.reason.as_deref(), Some("unknown_operation"));
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
