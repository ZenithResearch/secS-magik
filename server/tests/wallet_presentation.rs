#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, WalletPresentationAdapter,
    WalletPresentationShellStatus,
};
use server::verifier::VerificationError;
use wallet_fixtures::{
    expires_at_summary_field, incomplete_wallet_fixture, issued_at_summary_field, origin_input,
    origin_summary_field, replay_nonce_summary_field, wallet_descriptor, wallet_fixture,
    wallet_request_with_origin, wallet_request_with_ref, WALLET_AUDIENCE, WALLET_EVIDENCE_REF,
    WALLET_INCOMPLETE_EVIDENCE_REF, WALLET_OPCODE, WALLET_ORIGIN, WALLET_OTHER_AUDIENCE,
    WALLET_SUBJECT, WALLET_WRONG_ORIGIN,
};

fn adapter() -> WalletPresentationAdapter {
    WalletPresentationAdapter::new([wallet_fixture()])
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
fn wallet_presentation_shell_accepts_fixture_shape_without_claiming_public_proof() {
    match adapter().verify(&wallet_request_with_origin(Some(WALLET_EVIDENCE_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::WalletPresentation);
            assert_eq!(summary.subject, WALLET_SUBJECT);
            assert_eq!(summary.audience, WALLET_AUDIENCE);
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
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected shell-shaped wallet evidence, got {error:?}")
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
#[ignore = "RED Track D D1/D2: unignore once wallet-core cryptographic verification returns a public proof"]
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
#[ignore = "RED Track D D1/D2: unignore when canonical challenge contract binds secS wallet proof fields"]
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
