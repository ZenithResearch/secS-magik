use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::Deserialize;
use server::receipt::{
    AuthenticatorKind, Decision, Receipt, ReceiptEventKind, ReceiptKind, ReceiptOutputProjection,
    RECEIPT_SCHEMA_VERSION,
};
use server::verifier::{VerificationError, VerifiedCallContext, VerifiedSubject};

#[derive(Deserialize)]
struct SignedReceiptFixture {
    discriminator: String,
    unsigned_hex: String,
    public_key_hex: String,
    signer_key_id: String,
    signature_hex: String,
    receipt: Receipt,
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    std::array::from_fn(|index| u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap())
}

fn sample_context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 2,
        descriptor_fingerprint: String::new(),
        context_id: "ctx_receipt_test".to_string(),
        packet_hash: [7u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x10,
        operation: "candidate.dev.bash_echo".to_string(),
        resource: None,
        subject: VerifiedSubject {
            subject_id: "did:example:alice".to_string(),
            key_id: "did:example:alice#key-1".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec!["prototype-proof-envelope".to_string()],
        proof_metadata: None,
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
    assert_eq!(receipt.schema_version, RECEIPT_SCHEMA_VERSION);
    assert_eq!(receipt.context_id.as_deref(), Some("ctx_receipt_test"));
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
fn receipt_schema_version_is_explicit_and_stable_for_migrations() {
    assert_eq!(RECEIPT_SCHEMA_VERSION, 3);

    let receipt = Receipt::execution(
        "receipt-exec-versioned",
        &sample_context(),
        Decision::Accepted,
        Some("handler_succeeded"),
        176,
    );

    assert_eq!(receipt.schema_version, RECEIPT_SCHEMA_VERSION);
    assert_eq!(receipt.context_id.as_deref(), Some("ctx_receipt_test"));
}

#[test]
fn accepted_execution_output_projects_exact_domain_digest_without_raw_bytes() {
    use sha2::{Digest, Sha256};
    let output = b"SENTINEL_RAW_EXECUTION_OUTPUT";
    let receipt = Receipt::execution_with_output(
        "receipt-output-v3",
        &sample_context(),
        Decision::Accepted,
        None,
        177,
        Some("fixture.response.v1"),
        Some(output),
    )
    .unwrap();
    let projection = receipt.output_projection.as_ref().unwrap();
    let mut preimage = b"secs-execution-output-v1/digest".to_vec();
    preimage.extend_from_slice(&(output.len() as u64).to_le_bytes());
    preimage.extend_from_slice(output);
    assert_eq!(
        projection,
        &ReceiptOutputProjection {
            schema_id: "fixture.response.v1".into(),
            byte_count: output.len() as u64,
            digest_sha256: Sha256::digest(preimage).into(),
        }
    );
    assert!(!format!("{receipt:?}").contains("SENTINEL_RAW_EXECUTION_OUTPUT"));
}

#[test]
fn output_projection_is_allowed_only_on_accepted_execute_receipts() {
    assert!(Receipt::execution_with_output(
        "receipt-rejected-output",
        &sample_context(),
        Decision::Rejected,
        Some("handler_rejected"),
        178,
        Some("fixture.response.v1"),
        Some(b"forbidden"),
    )
    .is_err());
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
fn immutable_receipt_fixtures_verify_only_their_exact_historical_layouts() {
    let fixtures = [
        include_str!("fixtures/receipts/pre_c4b6218_signed.json"),
        include_str!("fixtures/receipts/schema_v1_signed.json"),
        include_str!("fixtures/receipts/schema_v2_signed.json"),
        include_str!("fixtures/receipts/schema_v3_signed.json"),
    ];
    let parsed: Vec<SignedReceiptFixture> = fixtures
        .into_iter()
        .map(|json| serde_json::from_str(json).unwrap())
        .collect();
    for fixture in &parsed {
        assert!(!fixture.discriminator.is_empty());
        assert!(!fixture.unsigned_hex.is_empty());
        assert_eq!(fixture.receipt.signer_key_id, fixture.signer_key_id);
        assert_eq!(
            fixture.receipt.signature,
            decode_hex::<64>(&fixture.signature_hex)
        );
        let key = VerifyingKey::from_bytes(&decode_hex::<32>(&fixture.public_key_hex)).unwrap();
        fixture.receipt.verify_ed25519_with_key(&key).unwrap();
        let mut tampered = fixture.receipt.clone();
        tampered.opcode ^= 1;
        assert_eq!(
            tampered.verify_ed25519_with_key(&key).unwrap_err(),
            VerificationError::InvalidSignature
        );
    }
    let key = VerifyingKey::from_bytes(&decode_hex::<32>(&parsed[0].public_key_hex)).unwrap();
    let mut ineligible_fallback = parsed[1].receipt.clone();
    ineligible_fallback.signature = parsed[0].receipt.signature.clone();
    assert!(ineligible_fallback.context_id.is_some());
    assert_eq!(
        ineligible_fallback
            .verify_ed25519_with_key(&key)
            .unwrap_err(),
        VerificationError::InvalidSignature
    );
    let mut later_layout_value = parsed[1].receipt.clone();
    later_layout_value.evidence_summary.push("not-v1".into());
    assert_eq!(
        later_layout_value
            .verify_ed25519_with_key(&key)
            .unwrap_err(),
        VerificationError::InternalError
    );
    let mut cross_version = parsed[2].receipt.clone();
    cross_version.schema_version = 3;
    assert_eq!(
        cross_version.verify_ed25519_with_key(&key).unwrap_err(),
        VerificationError::InvalidSignature
    );
    let mut unknown = parsed[3].receipt.clone();
    unknown.schema_version = 99;
    assert_eq!(
        unknown.verify_ed25519_with_key(&key).unwrap_err(),
        VerificationError::InternalError
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

#[test]
fn evidence_reject_reasons_use_stable_verification_error_codes() {
    let expected_codes = [
        (VerificationError::WrongOrigin, "wrong_origin"),
        (VerificationError::WrongTrustRoot, "wrong_trust_root"),
        (VerificationError::WrongRegistryRoot, "wrong_registry_root"),
        (VerificationError::UnknownIssuer, "unknown_issuer"),
        (VerificationError::WrongIssuerKey, "wrong_issuer_key"),
        (VerificationError::RevokedIssuer, "revoked_issuer"),
        (
            VerificationError::ExpiredVerifierKey,
            "expired_verifier_key",
        ),
        (
            VerificationError::NotYetValidVerifierKey,
            "not_yet_valid_verifier_key",
        ),
        (VerificationError::RevokedCredential, "revoked_credential"),
        (VerificationError::ExpiredClaim, "expired_claim"),
        (VerificationError::NotYetValidClaim, "not_yet_valid_claim"),
        (VerificationError::WrongSubject, "wrong_subject"),
        (VerificationError::WrongAudience, "wrong_audience"),
        (VerificationError::WrongOperation, "wrong_operation"),
        (VerificationError::WrongResource, "wrong_resource"),
        (
            VerificationError::InsufficientEvidence,
            "insufficient_evidence",
        ),
        (
            VerificationError::InvalidPresentation,
            "invalid_presentation",
        ),
        (VerificationError::InvalidSignature, "invalid_signature"),
        (
            VerificationError::UnsupportedSignatureSuite,
            "unsupported_signature_suite",
        ),
    ];

    for (error, expected) in expected_codes {
        let reason_code = error.reason_code();
        assert_eq!(reason_code, expected);
        assert!(!reason_code.is_empty());
        assert!(reason_code
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch == '_'));

        let receipt = Receipt::reject_from_error(
            format!("receipt-{expected}"),
            [9u8; 32],
            [1u8; 16],
            [2u8; 12],
            0x42,
            error,
            1_717_000_000,
        );
        assert_eq!(receipt.reason.as_deref(), Some(expected));
    }
}

#[test]
fn verify_receipt_carries_signed_redacted_evidence_summary_for_operator_inspection() {
    let key = [7u8; 32];
    let mut context = sample_context();
    context.evidence_summary = vec![
        "evidence_kind:dregg_authority".to_string(),
        "authority_class:dregg_authority".to_string(),
        "root_ref_sha256:abc123".to_string(),
        "token:dga1_[redacted]".to_string(),
    ];
    let signed_context = context
        .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
        .unwrap();

    let mut receipt =
        Receipt::verify_from_signed_context("receipt-dregg-summary", &signed_context, 151)
            .sign_ed25519("verifier:test", &key, AuthenticatorKind::Ed25519Verifier)
            .unwrap();

    assert!(receipt
        .evidence_summary
        .iter()
        .any(|field| field == "authority_class:dregg_authority"));
    assert!(receipt.verify_ed25519(&key).is_ok());

    receipt
        .evidence_summary
        .push("root_ref:dregg-root:raw".to_string());
    assert_eq!(
        receipt.verify_ed25519(&key),
        Err(VerificationError::InvalidSignature)
    );
}
