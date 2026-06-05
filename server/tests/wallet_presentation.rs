#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::{
    public_key_ref_for_bytes, EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult,
    WalletPresentationAdapter, WalletPresentationShellStatus,
};
use server::verifier::VerificationError;
use wallet_fixtures::{
    expires_at_summary_field, incomplete_wallet_fixture, issued_at_summary_field, origin_input,
    origin_summary_field, replay_nonce_summary_field, sign_wallet_fixture, wallet_descriptor,
    wallet_fixture, wallet_request_with_origin, wallet_request_with_ref, WALLET_AUDIENCE,
    WALLET_EVIDENCE_REF, WALLET_EXPIRES_AT, WALLET_INCOMPLETE_EVIDENCE_REF, WALLET_ISSUED_AT,
    WALLET_OPCODE, WALLET_OPERATION, WALLET_ORIGIN, WALLET_OTHER_AUDIENCE, WALLET_REPLAY_NONCE_REF,
    WALLET_RESOURCE, WALLET_SUBJECT, WALLET_WRONG_ORIGIN,
};

fn adapter() -> WalletPresentationAdapter {
    fixed_time_adapter(wallet_fixture())
}

fn fixed_time_adapter(
    fixture: server::evidence::WalletPresentationFixture,
) -> WalletPresentationAdapter {
    WalletPresentationAdapter::with_validation_time([fixture], WALLET_ISSUED_AT + 60)
}

fn assert_rejected(result: EvidenceResult, expected: VerificationError) {
    assert_eq!(result, EvidenceResult::Rejected(expected));
}

#[test]
fn wallet_presentation_missing_presentation_returns_typed_failure() {
    assert_eq!(
        adapter().verify(&wallet_request_with_ref(None)),
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
        &wallet_descriptor(WALLET_OPCODE),
        WALLET_SUBJECT,
        WALLET_OTHER_AUDIENCE,
        Some(WALLET_EVIDENCE_REF),
    );
    let mut wrong_origin = wallet_request_with_ref(Some(WALLET_EVIDENCE_REF));
    wrong_origin
        .public_inputs
        .push(origin_input(WALLET_WRONG_ORIGIN));

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
fn wallet_presentation_accepts_valid_cryptographic_fixture_as_public_proof() {
    match adapter().verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::WalletPresentation);
            assert_eq!(summary.subject, WALLET_SUBJECT);
            assert_eq!(summary.audience, WALLET_AUDIENCE);
            assert!(!summary.local_dev_test_only);
            assert!(summary.public_proof);
            assert!(!summary.summary_fields.iter().any(|field| {
                field
                    == WalletPresentationShellStatus::ShapeValidatedSignatureUnsupported
                        .as_summary_field()
            }));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == &origin_summary_field()));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == &replay_nonce_summary_field()));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == &issued_at_summary_field()));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == &expires_at_summary_field()));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "signature_suite:Ed25519"));
            assert!(!summary
                .summary_fields
                .iter()
                .any(|field| field.contains("signature_bytes") || field.contains("private_key")));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected cryptographically verified wallet evidence, got {error:?}")
        }
    }
}

#[test]
fn wallet_presentation_incomplete_fixture_fails_closed_with_invalid_presentation() {
    let incomplete = WalletPresentationAdapter::new([incomplete_wallet_fixture()]);
    let request = wallet_request_with_origin(Some(WALLET_INCOMPLETE_EVIDENCE_REF));

    assert_eq!(
        incomplete.verify(&request),
        EvidenceResult::Rejected(VerificationError::InvalidPresentation)
    );
}

#[test]
fn wallet_presentation_valid_fixture_verifies_cryptographically() {
    match adapter().verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert!(summary.public_proof);
            assert!(!summary.summary_fields.iter().any(|field| {
                field
                    == WalletPresentationShellStatus::ShapeValidatedSignatureUnsupported
                        .as_summary_field()
            }));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected cryptographically verified wallet evidence, got {error:?}")
        }
    }
}

#[test]
fn wallet_presentation_challenge_contract_requires_public_proof_without_shell_status() {
    let result = adapter().verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF)));

    let EvidenceResult::Satisfied(summary) = result else {
        panic!("expected accepted wallet challenge fixture, got {result:?}");
    };

    assert!(summary.public_proof);
    assert_eq!(summary.subject, WALLET_SUBJECT);
    assert_eq!(summary.audience, WALLET_AUDIENCE);
    assert!(summary.resource.is_some());
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == &origin_input(WALLET_ORIGIN)));
    assert!(!summary.summary_fields.iter().any(|field| {
        field
            == WalletPresentationShellStatus::ShapeValidatedSignatureUnsupported.as_summary_field()
    }));
}

#[test]
fn wallet_presentation_shape_only_fixture_fails_closed_without_crypto() {
    let mut shape_only = wallet_fixture();
    shape_only.signature_bytes.clear();
    let shape_only = WalletPresentationAdapter::new([shape_only]);

    assert_eq!(
        shape_only.verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InvalidPresentation)
    );
}

#[test]
fn wallet_presentation_rejects_missing_and_unknown_evidence_ref() {
    assert_rejected(
        adapter().verify(&wallet_request_with_origin(None)),
        VerificationError::InvalidPresentation,
    );
    assert_rejected(
        adapter().verify(&wallet_request_with_origin(Some(
            "wallet-presentation:not-found",
        ))),
        VerificationError::InvalidPresentation,
    );
}

#[test]
fn wallet_presentation_rejects_wrong_signature_and_wrong_public_key() {
    let mut wrong_signature = wallet_fixture();
    wrong_signature.signature_bytes[0] ^= 0x01;
    assert_rejected(
        fixed_time_adapter(wrong_signature)
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidSignature,
    );

    let mut wrong_public_key = wallet_fixture();
    wrong_public_key.public_key_bytes = vec![0x11; 32];
    wrong_public_key.public_key_ref = public_key_ref_for_bytes(&wrong_public_key.public_key_bytes);
    assert_rejected(
        fixed_time_adapter(wrong_public_key)
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidSignature,
    );
}

#[test]
fn wallet_presentation_rejects_mismatched_public_key_ref_and_public_key_material() {
    let mut mismatched_ref = wallet_fixture();
    mismatched_ref.public_key_ref = "pubkey:sha256:not-the-presented-key".to_string();
    sign_wallet_fixture(&mut mismatched_ref);

    assert_rejected(
        fixed_time_adapter(mismatched_ref)
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidPresentation,
    );
}

#[test]
fn wallet_presentation_rejects_wrong_subject_audience_origin_operation_and_resource() {
    let wrong_subject = EvidenceRequest::from_descriptor(
        &wallet_descriptor(WALLET_OPCODE),
        "did:example:bob#key-1",
        WALLET_AUDIENCE,
        Some(WALLET_EVIDENCE_REF),
    );
    assert_rejected(
        adapter().verify(&wrong_subject),
        VerificationError::WrongSubject,
    );

    let wrong_audience = EvidenceRequest::from_descriptor(
        &wallet_descriptor(WALLET_OPCODE),
        WALLET_SUBJECT,
        WALLET_OTHER_AUDIENCE,
        Some(WALLET_EVIDENCE_REF),
    );
    assert_rejected(
        adapter().verify(&wrong_audience),
        VerificationError::WrongAudience,
    );

    let mut wrong_origin = wallet_request_with_ref(Some(WALLET_EVIDENCE_REF));
    wrong_origin
        .public_inputs
        .push(origin_input(WALLET_WRONG_ORIGIN));
    assert_rejected(
        adapter().verify(&wrong_origin),
        VerificationError::WrongOrigin,
    );

    let mut wrong_operation = wallet_request_with_origin(Some(WALLET_EVIDENCE_REF));
    wrong_operation.operation = format!("{WALLET_OPERATION}.rotated");
    assert_rejected(
        adapter().verify(&wrong_operation),
        VerificationError::WrongOperation,
    );
    assert_eq!(
        VerificationError::WrongOperation.reason_code(),
        "wrong_operation"
    );

    let mut wrong_resource = wallet_request_with_origin(Some(WALLET_EVIDENCE_REF));
    wrong_resource.resource = Some("application/cbor".to_string());
    assert_rejected(
        adapter().verify(&wrong_resource),
        VerificationError::WrongResource,
    );
    assert_eq!(
        VerificationError::WrongResource.reason_code(),
        "wrong_resource"
    );
}

#[test]
fn wallet_presentation_rejects_changed_challenge_fields_bound_by_signature() {
    let mut changed_nonce = wallet_fixture();
    changed_nonce.replay_nonce_ref = format!("{WALLET_REPLAY_NONCE_REF}-replayed");
    assert_rejected(
        fixed_time_adapter(changed_nonce)
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidSignature,
    );

    let mut changed_resource = wallet_fixture();
    changed_resource.resource = "application/cbor".to_string();
    assert_rejected(
        WalletPresentationAdapter::new([changed_resource])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::WrongResource,
    );

    let mut changed_operation = wallet_fixture();
    changed_operation.operation = format!("{WALLET_OPERATION}.rotated");
    assert_rejected(
        WalletPresentationAdapter::new([changed_operation])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::WrongOperation,
    );
}

#[test]
fn wallet_presentation_rejects_expired_and_not_yet_valid_challenges_deterministically() {
    let mut expired = wallet_fixture();
    expired.issued_at = WALLET_ISSUED_AT - 600;
    expired.expires_at = WALLET_ISSUED_AT + 59;
    sign_wallet_fixture(&mut expired);
    assert_rejected(
        fixed_time_adapter(expired).verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::ExpiredClaim,
    );

    let mut future_issued = wallet_fixture();
    future_issued.issued_at = WALLET_ISSUED_AT + 61;
    future_issued.expires_at = WALLET_EXPIRES_AT;
    sign_wallet_fixture(&mut future_issued);
    assert_rejected(
        fixed_time_adapter(future_issued)
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::NotYetValidClaim,
    );
    assert_eq!(
        VerificationError::NotYetValidClaim.reason_code(),
        "not_yet_valid_claim"
    );
}

#[test]
fn wallet_presentation_default_runtime_time_fails_closed_for_expired_and_future_issued() {
    let mut expired = wallet_fixture();
    expired.issued_at = 1;
    expired.expires_at = 2;
    sign_wallet_fixture(&mut expired);
    assert_rejected(
        WalletPresentationAdapter::new([expired])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::ExpiredClaim,
    );

    let mut future_issued = wallet_fixture();
    future_issued.issued_at = u64::MAX - 1;
    future_issued.expires_at = u64::MAX;
    sign_wallet_fixture(&mut future_issued);
    assert_rejected(
        WalletPresentationAdapter::new([future_issued])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::NotYetValidClaim,
    );
}

#[test]
fn wallet_presentation_rejects_malformed_bytes_and_unsupported_signature_suite() {
    let mut malformed_public_key = wallet_fixture();
    malformed_public_key.public_key_bytes.truncate(31);
    assert_rejected(
        WalletPresentationAdapter::new([malformed_public_key])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidPresentation,
    );

    let mut malformed_signature = wallet_fixture();
    malformed_signature.signature_bytes.truncate(63);
    assert_rejected(
        WalletPresentationAdapter::new([malformed_signature])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidPresentation,
    );

    let mut unsupported_suite = wallet_fixture();
    unsupported_suite.signature_suite = "Ed25519ph".to_string();
    assert_rejected(
        WalletPresentationAdapter::new([unsupported_suite])
            .verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))),
        VerificationError::UnsupportedSignatureSuite,
    );
    assert_eq!(
        VerificationError::UnsupportedSignatureSuite.reason_code(),
        "unsupported_signature_suite"
    );
}

#[test]
fn wallet_presentation_valid_summary_redacts_signature_and_private_key_material() {
    let EvidenceResult::Satisfied(summary) =
        adapter().verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF)))
    else {
        panic!("expected valid wallet presentation");
    };

    assert_eq!(summary.resource.as_deref(), Some(WALLET_RESOURCE));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == &format!("replay_nonce_ref:{WALLET_REPLAY_NONCE_REF}")));
    assert!(!summary.summary_fields.iter().any(|field| {
        field.contains("signature_bytes")
            || field.contains("private_key")
            || field.contains("public_key_bytes")
    }));
}
