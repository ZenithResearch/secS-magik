#[allow(dead_code)]
#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, LocalStaticEvidenceAdapter,
    LocalStaticGrant, WalletPresentationAdapter,
};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::verifier::VerificationError;
use wallet_fixtures::{
    origin_input, wallet_fixture, WALLET_AUDIENCE, WALLET_EVIDENCE_REF, WALLET_ISSUED_AT,
    WALLET_OPCODE, WALLET_ORIGIN, WALLET_RESOURCE, WALLET_SUBJECT,
};

const MEMBERSHIP_OPCODE: u8 = 0x42;
const MEMBERSHIP_OPERATION: &str = "membership.provision";

fn production_membership_descriptor() -> OperationDescriptor {
    OperationDescriptor {
        opcode: MEMBERSHIP_OPCODE,
        name: OperationName::new(MEMBERSHIP_OPERATION),
        payload_schema: Some(WALLET_RESOURCE.to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["membership.credential".to_string()],
        required_capabilities: vec!["membership.provision".to_string()],
        accepted_evidence: vec![EvidenceKind::MembershipCredential.as_str().to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "membership/provision-fixture".to_string(),
        dev_binding: false,
        range: OpcodeRange::classify(MEMBERSHIP_OPCODE),
    }
}

fn production_request(evidence_ref: Option<&str>) -> EvidenceRequest {
    let mut request = EvidenceRequest::from_descriptor(
        &production_membership_descriptor(),
        WALLET_SUBJECT,
        WALLET_AUDIENCE,
        evidence_ref,
    );
    request.public_inputs.push(origin_input(WALLET_ORIGIN));
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
        subject: WALLET_SUBJECT.to_string(),
        audience: WALLET_AUDIENCE.to_string(),
        operation: MEMBERSHIP_OPERATION.to_string(),
        resource: Some(WALLET_RESOURCE.to_string()),
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
    assert!(!production_membership_descriptor()
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::PrototypeProofEnvelope.as_str()));
    assert!(!production_membership_descriptor()
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::LocalStatic.as_str()));
    assert!(!production_membership_descriptor()
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::WalletPresentation.as_str()));
    assert_eq!(
        wallet_fixtures::wallet_descriptor(WALLET_OPCODE).dev_binding,
        true
    );
}
