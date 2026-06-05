#[allow(dead_code)]
#[path = "support/trust_fixtures.rs"]
mod trust_fixtures;
#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, LocalStaticEvidenceAdapter,
    LocalStaticGrant, WalletPresentationAdapter,
};
use server::verifier::VerificationError;
use trust_fixtures::{
    membership_descriptor, MEMBERSHIP_CREDENTIAL_REF, MEMBERSHIP_OPCODE, MEMBERSHIP_OPERATION,
    TRUSTED_AUDIENCE, TRUSTED_ORIGIN, TRUSTED_RESOURCE, TRUSTED_SUBJECT,
};
use wallet_fixtures::{
    origin_input, wallet_fixture, WALLET_EVIDENCE_REF, WALLET_ISSUED_AT, WALLET_OPCODE,
};

fn production_request(evidence_ref: Option<&str>) -> EvidenceRequest {
    let mut request = EvidenceRequest::from_descriptor(
        &membership_descriptor(MEMBERSHIP_OPCODE),
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        evidence_ref,
    );
    request.public_inputs.push(origin_input(TRUSTED_ORIGIN));
    request
}

#[test]
fn evidence_kind_names_include_first_path_federated_credentials() {
    assert_eq!(
        EvidenceKind::MembershipCredential.as_str(),
        "membership_credential"
    );
    assert_eq!(
        EvidenceKind::ProvisioningCredential.as_str(),
        "provisioning_credential"
    );
}

#[test]
fn production_policy_rejects_local_static() {
    let adapter = LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: TRUSTED_SUBJECT.to_string(),
        audience: TRUSTED_AUDIENCE.to_string(),
        operation: MEMBERSHIP_OPERATION.to_string(),
        resource: Some(TRUSTED_RESOURCE.to_string()),
        evidence_ref: "local-static:test-grant".to_string(),
    }]);

    assert_eq!(
        adapter.verify(&production_request(Some("local-static:test-grant"))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

#[test]
fn production_policy_rejects_wallet_only_authority() {
    let adapter =
        WalletPresentationAdapter::with_validation_time([wallet_fixture()], WALLET_ISSUED_AT + 60);

    assert_eq!(
        adapter.verify(&production_request(Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

#[test]
fn prototype_proof_envelope_is_not_a_federated_production_evidence_kind() {
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::PrototypeProofEnvelope.as_str()));
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::LocalStatic.as_str()));
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::WalletPresentation.as_str()));
    assert!(wallet_fixtures::wallet_descriptor(WALLET_OPCODE).dev_binding);
}

#[test]
fn track_e_fixture_constants_share_track_d_subject_audience_origin_and_resource() {
    assert_eq!(TRUSTED_SUBJECT, wallet_fixtures::WALLET_SUBJECT);
    assert_eq!(TRUSTED_AUDIENCE, wallet_fixtures::WALLET_AUDIENCE);
    assert_eq!(TRUSTED_ORIGIN, wallet_fixtures::WALLET_ORIGIN);
    assert_eq!(TRUSTED_RESOURCE, wallet_fixtures::WALLET_RESOURCE);
    assert!(MEMBERSHIP_CREDENTIAL_REF.starts_with("membership-credential:"));
}
