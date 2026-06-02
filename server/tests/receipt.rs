use ed25519_dalek::{SigningKey, VerifyingKey};
use server::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind, ReceiptKind};
use server::verifier::{VerificationError, VerifiedCallContext, VerifiedSubject};

fn sample_context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 1,
        context_id: "ctx_receipt_test".to_string(),
        packet_hash: [7u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        operation: "candidate.dev.bash_echo".to_string(),
        subject: VerifiedSubject {
            subject_id: "did:example:alice".to_string(),
            key_id: "did:example:alice#key-1".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec!["prototype-proof-envelope".to_string()],
        capability_result: "dev.execute".to_string(),
        credential_result: "prototype.local-dev".to_string(),
        issued_at: 100,
        expires_at: 200,
        replay_scope: "session:opcode:nonce".to_string(),
        handler_id: Some("dev/bash-echo".to_string()),
    }
}

#[test]
fn reject_receipt_from_verification_error_has_typed_reason_without_payload_bytes() {
    let receipt = Receipt::reject_from_error(
        "receipt-reject-1",
        [9u8; 32],
        [1u8; 16],
        [2u8; 12],
        0x99,
        VerificationError::UnknownOperation,
        123,
    );

    assert_eq!(receipt.kind, ReceiptKind::Reject);
    assert_eq!(receipt.decision, Decision::Rejected);
    assert_eq!(receipt.reason.as_deref(), Some("unknown_operation"));
    assert_eq!(receipt.operation, None);
    assert_eq!(receipt.handler_id, None);
    assert_eq!(
        receipt.authenticator_kind,
        AuthenticatorKind::LocalDevUntrusted
    );
    assert!(receipt.signature.is_empty());

    let encoded = bincode::serialize(&receipt).unwrap();
    assert!(!encoded
        .windows(b"secret payload".len())
        .any(|w| w == b"secret payload"));
}

#[test]
fn verify_receipt_can_be_created_from_signed_verified_context_and_signed() {
    let key = [7u8; 32];
    let signed_context = sample_context()
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    let receipt = Receipt::verify_from_signed_context("receipt-verify-1", &signed_context, 150)
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    assert_eq!(receipt.kind, ReceiptKind::Verify);
    assert_eq!(receipt.decision, Decision::Accepted);
    assert_eq!(receipt.packet_hash, [7u8; 32]);
    assert_eq!(
        receipt.operation.as_deref(),
        Some("candidate.dev.bash_echo")
    );
    assert_eq!(receipt.handler_id.as_deref(), Some("dev/bash-echo"));
    assert_eq!(
        receipt.authenticator_kind,
        AuthenticatorKind::Ed25519Verifier
    );
    assert_eq!(receipt.signer_key_id, "verifier:test");
    assert!(!receipt.signature.is_empty());

    let public_key = VerifyingKey::from(&SigningKey::from_bytes(&key));
    receipt.verify_ed25519_with_key(&public_key).unwrap();
    receipt.verify_ed25519(&key).unwrap();
}

#[test]
fn execution_receipt_references_handler_decision_and_never_payload_content() {
    let receipt = Receipt::execution(
        "receipt-exec-1",
        &sample_context(),
        Decision::Rejected,
        Some("handler_failed"),
        175,
    );

    assert_eq!(receipt.kind, ReceiptKind::Execute);
    assert_eq!(receipt.decision, Decision::Rejected);
    assert_eq!(receipt.handler_id.as_deref(), Some("dev/bash-echo"));
    assert_eq!(receipt.reason.as_deref(), Some("handler_failed"));

    let debug = format!("{receipt:?}");
    assert!(!debug.contains("secret payload"));
}

#[test]
fn receipt_signature_rejects_tampering_and_wrong_key() {
    let key = [3u8; 32];
    let signed_context = sample_context()
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();
    let signed_receipt =
        Receipt::verify_from_signed_context("receipt-verify-2", &signed_context, 150)
            .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
            .unwrap();

    signed_receipt.verify_ed25519(&key).unwrap();

    let mut tampered = signed_receipt.clone();
    tampered.reason = Some("changed_after_signing".to_string());
    assert_eq!(
        tampered.verify_ed25519(&key).unwrap_err(),
        VerificationError::InvalidSignature
    );

    assert_eq!(
        signed_receipt.verify_ed25519(&[4u8; 32]).unwrap_err(),
        VerificationError::InvalidSignature
    );
}

#[test]
fn receipt_event_names_are_typed_and_stable() {
    assert_eq!(ReceiptEventKind::PacketReceived.as_str(), "packet_received");
    assert_eq!(ReceiptEventKind::PacketRejected.as_str(), "packet_rejected");
    assert_eq!(ReceiptEventKind::PacketVerified.as_str(), "packet_verified");
    assert_eq!(
        ReceiptEventKind::OperationDescribed.as_str(),
        "operation_described"
    );
    assert_eq!(
        ReceiptEventKind::OperationRouted.as_str(),
        "operation_routed"
    );
    assert_eq!(ReceiptEventKind::HandlerStarted.as_str(), "handler_started");
    assert_eq!(
        ReceiptEventKind::HandlerSucceeded.as_str(),
        "handler_succeeded"
    );
    assert_eq!(ReceiptEventKind::HandlerFailed.as_str(), "handler_failed");
    assert_eq!(ReceiptEventKind::ReceiptEmitted.as_str(), "receipt_emitted");
}
