#[allow(dead_code)]
#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use libsec_core::ZenithPacket;
use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, LocalStaticEvidenceAdapter,
    LocalStaticGrant, WalletPresentationAdapter,
};
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, ReceiverManifest, ReplayScope, TargetKind,
};
use server::receipt::Receipt;
use server::verifier::{VerificationError, Verifier};
use wallet_fixtures::{
    origin_input, wallet_descriptor, wallet_fixture, WALLET_AUDIENCE, WALLET_EVIDENCE_REF,
    WALLET_ISSUED_AT, WALLET_OPCODE, WALLET_ORIGIN, WALLET_SUBJECT,
};

fn evidence_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.dev.local_static"),
        payload_schema: Some("application/json".to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["local_static.subject".to_string()],
        required_capabilities: vec!["dev.execute".to_string()],
        accepted_evidence: vec![EvidenceKind::LocalStatic.as_str().to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/local-static".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

fn packet(opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: b"prototype-proof-envelope".to_vec(),
        claim_ttl: 60,
        encrypted_payload: br#"{"hello":"world"}"#.to_vec(),
        mac: [3u8; 16],
    }
}

fn request_for(descriptor: &OperationDescriptor) -> EvidenceRequest {
    EvidenceRequest::from_descriptor(
        descriptor,
        "prototype.local-dev.subject",
        "secS://local-test",
        Some("local-static:test-grant"),
    )
}

fn adapter() -> LocalStaticEvidenceAdapter {
    LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: "prototype.local-dev.subject".to_string(),
        audience: "secS://local-test".to_string(),
        operation: "candidate.dev.local_static".to_string(),
        resource: Some("application/json".to_string()),
        evidence_ref: "local-static:test-grant".to_string(),
    }])
}

#[test]
fn local_static_adapter_satisfies_matching_descriptor_requirement() {
    let descriptor = evidence_descriptor(0x40);
    let result = adapter().verify(&request_for(&descriptor));

    match result {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::LocalStatic);
            assert!(summary.local_dev_test_only);
            assert!(!summary.public_proof);
            assert_eq!(summary.subject, "prototype.local-dev.subject");
            assert_eq!(summary.audience, "secS://local-test");
            assert_eq!(summary.operation, "candidate.dev.local_static");
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "authority:local_dev_test_only"));
        }
        EvidenceResult::Rejected(error) => panic!("expected satisfied evidence, got {error:?}"),
    }
}

#[test]
fn local_static_missing_required_evidence_fails_closed() {
    let descriptor = evidence_descriptor(0x40);
    let request = EvidenceRequest::from_descriptor(
        &descriptor,
        "prototype.local-dev.subject",
        "secS://local-test",
        None,
    );

    assert_eq!(
        adapter().verify(&request),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        VerificationError::InsufficientEvidence.reason_code(),
        "insufficient_evidence"
    );
}

#[test]
fn local_static_wrong_subject_and_wrong_audience_are_typed_failures() {
    let descriptor = evidence_descriptor(0x40);
    let wrong_subject = EvidenceRequest::from_descriptor(
        &descriptor,
        "other.subject",
        "secS://local-test",
        Some("local-static:test-grant"),
    );
    let wrong_audience = EvidenceRequest::from_descriptor(
        &descriptor,
        "prototype.local-dev.subject",
        "secS://other-target",
        Some("local-static:test-grant"),
    );

    assert_eq!(
        adapter().verify(&wrong_subject),
        EvidenceResult::Rejected(VerificationError::WrongSubject)
    );
    assert_eq!(
        adapter().verify(&wrong_audience),
        EvidenceResult::Rejected(VerificationError::WrongAudience)
    );
}

#[test]
fn verifier_signed_context_includes_local_static_summary_without_public_proof_claim() {
    let manifest = ReceiverManifest::new([evidence_descriptor(0x40)]);
    let packet = packet(0x40);
    let signed = Verifier::verify_manifest_operation_with_evidence_and_sign(
        &packet,
        &manifest,
        "secS://local-test",
        "prototype.local-dev.subject",
        Some("local-static:test-grant"),
        &adapter(),
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect("local_static evidence should produce signed context");

    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:local_static"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "authority:local_dev_test_only"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:false"));
    assert!(!signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:true"));

    let receipt =
        Receipt::verify_from_signed_context("verify-local-static", &signed, 1_700_000_001);
    assert_eq!(
        receipt.operation.as_deref(),
        Some("candidate.dev.local_static")
    );
    assert_eq!(receipt.signer_key_id, "secs-verifier-test-key");
}

#[test]
fn verifier_rejects_missing_local_static_evidence_before_signing_context() {
    let manifest = ReceiverManifest::new([evidence_descriptor(0x40)]);
    let packet = packet(0x40);

    let error = Verifier::verify_manifest_operation_with_evidence_and_sign(
        &packet,
        &manifest,
        "secS://local-test",
        "prototype.local-dev.subject",
        None,
        &adapter(),
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect_err("missing local_static evidence should fail closed");

    assert_eq!(error, VerificationError::InsufficientEvidence);
}

#[test]
fn verifier_signed_context_can_pass_wallet_public_inputs_for_origin_bound_evidence() {
    let manifest = ReceiverManifest::new([wallet_descriptor(WALLET_OPCODE)]);
    let packet = packet(WALLET_OPCODE);
    let adapter =
        WalletPresentationAdapter::with_validation_time([wallet_fixture()], WALLET_ISSUED_AT + 60);

    assert_eq!(
        Verifier::verify_manifest_operation_with_evidence_and_sign(
            &packet,
            &manifest,
            WALLET_AUDIENCE,
            WALLET_SUBJECT,
            Some(WALLET_EVIDENCE_REF),
            &adapter,
            1_700_000_000,
            "secs-verifier-test-key",
            &[7u8; 32],
        )
        .expect_err("legacy evidence API does not supply wallet origin"),
        VerificationError::InvalidPresentation
    );

    let signed = Verifier::verify_manifest_operation_with_evidence_inputs_and_sign(
        &packet,
        &manifest,
        WALLET_AUDIENCE,
        WALLET_SUBJECT,
        Some(WALLET_EVIDENCE_REF),
        [origin_input(WALLET_ORIGIN)],
        &adapter,
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect("wallet evidence with explicit origin public input should produce signed context");

    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:wallet_presentation"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == &origin_input(WALLET_ORIGIN)));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:true"));
}
