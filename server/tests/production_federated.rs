#[allow(dead_code)]
#[path = "support/trust_fixtures.rs"]
mod trust_fixtures;
#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use server::evidence::{
    CompositeEvidenceAdapter, EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult,
    FederatedCredentialAdapter, FederatedCredentialStatus, LocalStaticEvidenceAdapter,
    LocalStaticGrant, TrustedIssuerRegistry, TrustedIssuerStatus, WalletPresentationAdapter,
};
use server::verifier::VerificationError;
use trust_fixtures::{
    issuer_entry, malformed_credential_fixture, membership_credential_fixture,
    membership_descriptor, provisioning_credential_fixture, provisioning_descriptor,
    resign_credential, trusted_registry, wallet_and_membership_descriptor,
    MEMBERSHIP_CREDENTIAL_REF, MEMBERSHIP_OPCODE, MEMBERSHIP_OPERATION,
    PROVISIONING_CREDENTIAL_REF, PROVISIONING_OPCODE, TRUSTED_AUDIENCE, TRUSTED_ORIGIN,
    TRUSTED_RESOURCE, TRUSTED_SUBJECT, TRUSTED_VALIDATION_TIME, WALLET_AND_MEMBERSHIP_OPCODE,
    WRONG_REGISTRY_ROOT_REF, WRONG_TRUST_ROOT_REF,
};
use wallet_fixtures::{
    origin_input, sign_wallet_fixture, wallet_fixture, WALLET_EVIDENCE_REF, WALLET_ISSUED_AT,
    WALLET_OPCODE,
};

fn production_request(evidence_ref: Option<&str>) -> EvidenceRequest {
    request_for(&membership_descriptor(MEMBERSHIP_OPCODE), evidence_ref)
}

fn request_for(
    descriptor: &server::manifest::OperationDescriptor,
    evidence_ref: Option<&str>,
) -> EvidenceRequest {
    request_with_refs(descriptor, evidence_ref.into_iter())
}

fn request_with_refs<'a>(
    descriptor: &server::manifest::OperationDescriptor,
    evidence_refs: impl IntoIterator<Item = &'a str>,
) -> EvidenceRequest {
    let mut request = EvidenceRequest::from_descriptor_with_refs(
        descriptor,
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        evidence_refs,
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

#[test]
fn valid_membership_credential_verifies() {
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    match adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::MembershipCredential);
            assert_eq!(summary.subject, TRUSTED_SUBJECT);
            assert!(summary.public_proof);
            assert!(!summary.local_dev_test_only);
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:membership_credential"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "proof:redacted_ed25519_signature"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected valid membership credential, got {error:?}")
        }
    }
}

#[test]
fn valid_provisioning_credential_verifies_when_descriptor_permits_it() {
    let adapter = FederatedCredentialAdapter::new(
        [provisioning_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    match adapter.verify(&request_for(
        &provisioning_descriptor(PROVISIONING_OPCODE),
        Some(PROVISIONING_CREDENTIAL_REF),
    )) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::ProvisioningCredential);
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:provisioning_credential"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected valid provisioning credential, got {error:?}")
        }
    }
}

fn assert_credential_rejected(
    fixture: server::evidence::FederatedCredentialFixture,
    request: EvidenceRequest,
    expected: VerificationError,
) {
    let adapter =
        FederatedCredentialAdapter::new([fixture], trusted_registry(), TRUSTED_VALIDATION_TIME);
    assert_eq!(adapter.verify(&request), EvidenceResult::Rejected(expected));
}

#[test]
fn reject_matrix_missing_unknown_malformed_suite_signature_and_embedded_key() {
    assert_eq!(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(None)),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(Some("membership-credential:missing"))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_credential_rejected(
        malformed_credential_fixture(),
        production_request(Some(trust_fixtures::MALFORMED_CREDENTIAL_REF)),
        VerificationError::InvalidPresentation,
    );

    let mut unsupported_suite = membership_credential_fixture();
    unsupported_suite
        .credential
        .as_mut()
        .expect("credential")
        .signature_suite = "FixtureSuite-v0".to_string();
    resign_credential(&mut unsupported_suite);
    assert_credential_rejected(
        unsupported_suite,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::UnsupportedSignatureSuite,
    );

    let mut wrong_signature = membership_credential_fixture();
    wrong_signature.signature_bytes[0] ^= 0x01;
    assert_credential_rejected(
        wrong_signature,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::InvalidSignature,
    );

    let mut wrong_embedded_key = membership_credential_fixture();
    wrong_embedded_key.embedded_issuer_public_key_bytes = vec![0x99; 32];
    assert_credential_rejected(
        wrong_embedded_key,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::WrongIssuerKey,
    );
}

#[test]
fn reject_matrix_issuer_roots_status_and_validity_fail_closed() {
    for (fixture, expected) in [
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").issuer_id =
                    "did:example:missing".to_string();
                fixture
            },
            VerificationError::UnknownIssuer,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture
                    .credential
                    .as_mut()
                    .expect("credential")
                    .trust_root_ref = WRONG_TRUST_ROOT_REF.to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongTrustRoot,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture
                    .credential
                    .as_mut()
                    .expect("credential")
                    .registry_root_ref = WRONG_REGISTRY_ROOT_REF.to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongRegistryRoot,
        ),
    ] {
        assert_credential_rejected(
            fixture,
            production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
            expected,
        );
    }

    let mut revoked = issuer_entry();
    revoked.status = TrustedIssuerStatus::Revoked;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([revoked]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::RevokedIssuer)
    );

    let mut expired = issuer_entry();
    expired.not_after = TRUSTED_VALIDATION_TIME - 1;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([expired]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::ExpiredVerifierKey)
    );

    let mut future = issuer_entry();
    future.not_before = TRUSTED_VALIDATION_TIME + 1;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([future]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::NotYetValidVerifierKey)
    );
}

#[test]
fn reject_matrix_credential_claim_and_descriptor_policy_fields_fail_closed() {
    for (fixture, expected) in [
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").status =
                    FederatedCredentialStatus::Revoked;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::RevokedCredential,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").expires_at =
                    TRUSTED_VALIDATION_TIME;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::ExpiredClaim,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").issued_at =
                    TRUSTED_VALIDATION_TIME + 1;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::NotYetValidClaim,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").subject =
                    "did:example:bob#key-1".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongSubject,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").audience =
                    "secS://other".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongAudience,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").origin =
                    Some("https://evil.example".to_string());
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongOrigin,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").operation =
                    "membership.other".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongOperation,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").resource =
                    "application/not-json".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongResource,
        ),
    ] {
        assert_credential_rejected(
            fixture,
            production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
            expected,
        );
    }

    assert_eq!(
        FederatedCredentialAdapter::new(
            [provisioning_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(Some(PROVISIONING_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

fn composite_adapter<'a>(
    wallet: &'a WalletPresentationAdapter,
    credential: &'a FederatedCredentialAdapter,
) -> CompositeEvidenceAdapter<'a> {
    CompositeEvidenceAdapter::new([
        wallet as &dyn EvidenceAdapter,
        credential as &dyn EvidenceAdapter,
    ])
}

fn membership_wallet_adapter() -> WalletPresentationAdapter {
    let mut fixture = wallet_fixture();
    fixture.operation = MEMBERSHIP_OPERATION.to_string();
    sign_wallet_fixture(&mut fixture);
    WalletPresentationAdapter::with_validation_time([fixture], WALLET_ISSUED_AT + 60)
}

#[test]
fn wallet_and_issuer_composition_requires_both_layers() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );

    match composite.verify(&request_with_refs(
        &descriptor,
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    )) {
        EvidenceResult::Satisfied(summary) => {
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "evidence_kind:wallet_presentation"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "evidence_kind:membership_credential"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:membership_credential"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected both evidence layers to satisfy, got {error:?}")
        }
    }
}

#[test]
fn wallet_and_issuer_composition_preserves_layer_specific_failures() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let mut wrong_root = membership_credential_fixture();
    wrong_root
        .credential
        .as_mut()
        .expect("credential")
        .trust_root_ref = WRONG_TRUST_ROOT_REF.to_string();
    resign_credential(&mut wrong_root);
    let credential =
        FederatedCredentialAdapter::new([wrong_root], trusted_registry(), TRUSTED_VALIDATION_TIME);
    let composite = composite_adapter(&wallet, &credential);

    assert_eq!(
        composite.verify(&request_with_refs(
            &descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongTrustRoot)
    );

    let valid_credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &valid_credential);
    let mut wrong_origin = request_with_refs(
        &descriptor,
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    );
    wrong_origin
        .public_inputs
        .retain(|input| !input.starts_with("origin:"));
    wrong_origin
        .public_inputs
        .push(origin_input("https://evil.example"));
    assert_eq!(
        composite.verify(&wrong_origin),
        EvidenceResult::Rejected(VerificationError::WrongOrigin)
    );
}

#[test]
fn valid_evidence_policy_accepts_only_when_descriptor_allows_it() {
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    assert!(matches!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Satisfied(_)
    ));
}

#[test]
fn valid_evidence_local_policy_rejects_disallowed_descriptor_operation_scope_and_audience() {
    let mut wrong_operation_descriptor = membership_descriptor(MEMBERSHIP_OPCODE);
    wrong_operation_descriptor.name =
        server::manifest::OperationName::new("membership.not-permitted");
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&request_for(
            &wrong_operation_descriptor,
            Some(MEMBERSHIP_CREDENTIAL_REF),
        )),
        EvidenceResult::Rejected(VerificationError::WrongOperation)
    );

    let mut wrong_resource_descriptor = membership_descriptor(MEMBERSHIP_OPCODE);
    wrong_resource_descriptor.payload_schema = Some("application/not-json".to_string());
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&request_for(
            &wrong_resource_descriptor,
            Some(MEMBERSHIP_CREDENTIAL_REF),
        )),
        EvidenceResult::Rejected(VerificationError::WrongResource)
    );

    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let mut wrong_audience = EvidenceRequest::from_descriptor(
        &membership_descriptor(MEMBERSHIP_OPCODE),
        TRUSTED_SUBJECT,
        "secS://other-target",
        Some(MEMBERSHIP_CREDENTIAL_REF),
    );
    wrong_audience
        .public_inputs
        .push(origin_input(TRUSTED_ORIGIN));
    assert_eq!(
        adapter.verify(&wrong_audience),
        EvidenceResult::Rejected(VerificationError::WrongAudience)
    );
}
