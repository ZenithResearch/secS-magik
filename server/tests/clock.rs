use libsec_core::ZenithPacket;
use server::clock::{failclosed_unix_seconds, is_clock_read_failure, CLOCK_READ_FAILURE_SENTINEL};
use server::manifest::ReceiverManifest;
use server::runtime_mode::RuntimeMode;
use server::verifier::{
    AuthenticatorKind, VerificationError, VerifiedCallContext, VerifiedSubject, Verifier,
};

fn prototype_packet() -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        proof: vec![1],
        claim_ttl: 300,
        encrypted_payload: b"payload".to_vec(),
        mac: [0u8; 16],
    }
}

fn sample_context_with_expiry(expires_at: u64) -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 1,
        context_id: "ctx_clock_test".to_string(),
        packet_hash: [7u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        operation: "queue.enqueue".to_string(),
        subject: VerifiedSubject {
            subject_id: "did:example:alice".to_string(),
            key_id: "did:example:alice#key-1".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec!["local_static:test".to_string()],
        capability_result: "allowed".to_string(),
        credential_result: "accepted".to_string(),
        issued_at: 100,
        expires_at,
        replay_scope: "session:opcode:nonce".to_string(),
        handler_id: Some("local_queue_bridge".to_string()),
    }
}

#[test]
fn clock_read_failure_sentinel_is_u64_max_so_expiry_comparisons_fail_closed() {
    assert_eq!(CLOCK_READ_FAILURE_SENTINEL, u64::MAX);
    assert!(is_clock_read_failure(CLOCK_READ_FAILURE_SENTINEL));
    assert!(!is_clock_read_failure(0));
}

#[test]
fn failclosed_unix_seconds_reads_a_plausible_wall_clock() {
    let now = failclosed_unix_seconds();
    // 2020-01-01T00:00:00Z; a healthy host clock is well past this and a
    // failure would surface as the sentinel, never as a small value.
    assert!(now > 1_577_836_800);
    assert!(!is_clock_read_failure(now));
}

#[test]
fn manifest_verification_rejects_clock_read_failure_sentinel() {
    // With the pre-M12.5 `unwrap_or(0)` fallback this packet would route:
    // `now = 0` makes nothing look expired. With the sentinel, the verifier
    // must reject before any signed context is created.
    let packet = prototype_packet();
    let manifest = ReceiverManifest::default_v0();

    let result = Verifier::verify_manifest_operation_for_runtime(
        &packet,
        &manifest,
        "secS://receiver-a",
        CLOCK_READ_FAILURE_SENTINEL,
        RuntimeMode::LocalDevPlaintext,
    );

    assert_eq!(result.unwrap_err(), VerificationError::ExpiredClaim);
}

#[test]
fn prototype_manifest_verification_rejects_clock_read_failure_sentinel() {
    let packet = prototype_packet();
    let manifest = ReceiverManifest::default_v0();

    let result = Verifier::verify_manifest_operation(
        &packet,
        &manifest,
        "secS://receiver-a",
        CLOCK_READ_FAILURE_SENTINEL,
    );

    assert_eq!(result.unwrap_err(), VerificationError::ExpiredClaim);
}

#[test]
fn signed_context_verification_rejects_clock_read_failure_sentinel() {
    // A context created under a failed clock saturates `expires_at` to
    // u64::MAX, so the plain `now > expires_at` comparison alone would pass.
    // The sentinel must be rejected explicitly.
    let key = [9u8; 32];
    let context = sample_context_with_expiry(u64::MAX);
    let signed = context
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    assert_eq!(
        signed
            .verify_ed25519(&key, "secS://receiver-a", CLOCK_READ_FAILURE_SENTINEL)
            .unwrap_err(),
        VerificationError::ExpiredClaim
    );
}

#[test]
fn signed_context_with_real_now_still_verifies_after_sentinel_guard() {
    let key = [9u8; 32];
    let context = sample_context_with_expiry(200);
    let signed = context
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    signed
        .verify_ed25519(&key, "secS://receiver-a", 150)
        .unwrap();
}

mod prune_guard {
    use super::*;
    use server::ledger::{Ledger, ReplayReservationOutcome};
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

    #[tokio::test]
    async fn prune_with_clock_failure_sentinel_keeps_live_reservations() {
        let ledger = memory_ledger().await;
        let context = sample_context_with_expiry(2_000);

        assert_eq!(
            ledger
                .reserve_replay(&context, "verifier:local-test", 1_001)
                .await
                .unwrap(),
            ReplayReservationOutcome::Reserved
        );

        // Under the sentinel, prune must be a no-op rather than treating every
        // reservation as expired and deleting live replay protection.
        assert_eq!(
            ledger
                .prune_expired_replay_reservations(CLOCK_READ_FAILURE_SENTINEL)
                .await
                .unwrap(),
            0
        );

        // The live reservation still guards against replay.
        assert_eq!(
            ledger
                .reserve_replay(&context, "verifier:local-test", 1_002)
                .await
                .unwrap(),
            ReplayReservationOutcome::Duplicate
        );
    }
}
