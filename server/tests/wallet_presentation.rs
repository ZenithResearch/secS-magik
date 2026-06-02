use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, WalletPresentationAdapter,
    WalletPresentationFixture, WalletPresentationShellStatus,
};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::verifier::VerificationError;

fn wallet_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.wallet.present"),
        payload_schema: Some("application/json".to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["wallet.presentation".to_string()],
        required_capabilities: vec!["wallet.present".to_string()],
        accepted_evidence: vec![EvidenceKind::WalletPresentation.as_str().to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/wallet-presentation".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

fn request_with_ref(evidence_ref: Option<&str>) -> EvidenceRequest {
    EvidenceRequest::from_descriptor(
        &wallet_descriptor(0x41),
        "did:example:alice#key-1",
        "secS://local-test",
        evidence_ref,
    )
}

fn adapter() -> WalletPresentationAdapter {
    WalletPresentationAdapter::new([WalletPresentationFixture {
        evidence_ref: "wallet-presentation:alice-local".to_string(),
        subject: "did:example:alice#key-1".to_string(),
        audience: "secS://local-test".to_string(),
        origin: "https://gallery.localhost".to_string(),
        challenge_ref: "challenge:phase4-test".to_string(),
        signature_ref: "signature:fixture-only".to_string(),
        public_key_ref: "pubkey:fixture-only".to_string(),
        replay_nonce_ref: "nonce:wallet-present-0001".to_string(),
        issued_at: 1_717_000_000,
        expires_at: 1_717_000_300,
    }])
}

#[test]
fn wallet_presentation_missing_presentation_returns_typed_failure() {
    assert_eq!(
        adapter().verify(&request_with_ref(None)),
        EvidenceResult::Rejected(VerificationError::InvalidPresentation)
    );
    assert_eq!(
        VerificationError::InvalidPresentation.reason_code(),
        "invalid_presentation"
    );
}

#[test]
fn wallet_presentation_wrong_audience_and_wrong_origin_are_distinguishable() {
    let wrong_audience = EvidenceRequest::from_descriptor(
        &wallet_descriptor(0x41),
        "did:example:alice#key-1",
        "secS://other-target",
        Some("wallet-presentation:alice-local"),
    );
    let mut wrong_origin = request_with_ref(Some("wallet-presentation:alice-local"));
    wrong_origin
        .public_inputs
        .push("origin:https://evil.example".to_string());

    assert_eq!(
        adapter().verify(&wrong_audience),
        EvidenceResult::Rejected(VerificationError::WrongAudience)
    );
    assert_eq!(
        adapter().verify(&wrong_origin),
        EvidenceResult::Rejected(VerificationError::WrongOrigin)
    );
    assert_eq!(VerificationError::WrongOrigin.reason_code(), "wrong_origin");
}

#[test]
fn wallet_presentation_shell_accepts_fixture_shape_without_claiming_public_proof() {
    let mut request = request_with_ref(Some("wallet-presentation:alice-local"));
    request
        .public_inputs
        .push("origin:https://gallery.localhost".to_string());

    match adapter().verify(&request) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::WalletPresentation);
            assert_eq!(summary.subject, "did:example:alice#key-1");
            assert_eq!(summary.audience, "secS://local-test");
            assert!(!summary.local_dev_test_only);
            assert!(!summary.public_proof);
            assert!(summary.summary_fields.iter().any(|field| {
                field
                    == WalletPresentationShellStatus::ShapeValidatedSignatureUnsupported
                        .as_summary_field()
            }));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "origin:https://gallery.localhost"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "replay_nonce_ref:nonce:wallet-present-0001"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "issued_at:1717000000"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "expires_at:1717000300"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected shell-shaped wallet evidence, got {error:?}")
        }
    }
}
#[test]
fn wallet_presentation_incomplete_fixture_fails_closed_with_invalid_presentation() {
    let incomplete = WalletPresentationAdapter::new([WalletPresentationFixture {
        evidence_ref: "wallet-presentation:missing-shape".to_string(),
        subject: "did:example:alice#key-1".to_string(),
        audience: "secS://local-test".to_string(),
        origin: "https://gallery.localhost".to_string(),
        challenge_ref: "".to_string(),
        signature_ref: "signature:fixture-only".to_string(),
        public_key_ref: "pubkey:fixture-only".to_string(),
        replay_nonce_ref: "nonce:wallet-present-0001".to_string(),
        issued_at: 1_717_000_000,
        expires_at: 1_717_000_300,
    }]);
    let mut request = request_with_ref(Some("wallet-presentation:missing-shape"));
    request
        .public_inputs
        .push("origin:https://gallery.localhost".to_string());

    assert_eq!(
        incomplete.verify(&request),
        EvidenceResult::Rejected(VerificationError::InvalidPresentation)
    );
}
