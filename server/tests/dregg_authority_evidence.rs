use server::dregg_authority::{
    DreggAuthorityEntry, DreggAuthorityFinalityMode, DreggAuthorityFinalityStatus,
    DreggAuthorityLookup, DreggAuthorityRegistry, DreggAuthorityRevocationStatus,
    DreggAuthorityRevocationVerifierMode, DreggAuthorityStatus, DreggAuthorityStatusPolicy,
};
use server::evidence::{
    DreggAuthorityEvidenceAdapter, DreggAuthorityGrantFixture, DreggReceiptFixture,
    DreggShapedEvidenceAdapter, EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult,
};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::verifier::VerificationError;

const SUBJECT: &str = "did:castalia:member:alice";
const AUDIENCE: &str = "secS://operator-receiver";
const OPERATION: &str = "membership.provision";
const RESOURCE: &str = "application/json";
const EVIDENCE_REF: &str = "dregg-authority:fixture:alice";
const VALIDATION_TIME: u64 = 1_770_000_300;
const STATUS_CHECKED_AT: u64 = 1_770_000_200;

fn descriptor() -> OperationDescriptor {
    OperationDescriptor {
        opcode: 0x44,
        name: OperationName::new(OPERATION),
        payload_schema: Some(RESOURCE.to_string()),
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec![],
        required_capabilities: vec!["dregg_authority".to_string()],
        accepted_evidence: vec![EvidenceKind::DreggAuthority.as_str().to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: "membership/provision".to_string(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
    }
}

fn request() -> EvidenceRequest {
    let mut request = EvidenceRequest::from_descriptor_with_refs(
        &descriptor(),
        SUBJECT,
        AUDIENCE,
        [EVIDENCE_REF],
    );
    request
        .public_inputs
        .push("origin:https://gallery.local".to_string());
    request
}

fn registry_entry() -> DreggAuthorityEntry {
    DreggAuthorityEntry {
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        issuer_public_key_hex: "1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        federation_id: "dregg-federation:fixture".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        epoch_not_before: 1_770_000_000,
        epoch_not_after: 1_777_776_000,
        accepted_audiences: vec![AUDIENCE.to_string()],
        accepted_operations: vec![OPERATION.to_string()],
        accepted_resources: vec![RESOURCE.to_string()],
        accepted_suites: vec!["dregg_authority_fixture_v1".to_string()],
        status_policy: DreggAuthorityStatusPolicy {
            require_status: true,
            max_status_age_seconds: 300,
            require_revocation_check: true,
            require_finality: false,
            revocation_verifier_mode: DreggAuthorityRevocationVerifierMode::ExpectedRootBinding,
            finality_mode: DreggAuthorityFinalityMode::FixtureStatusOnly,
            expected_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
        },
        root_status: DreggAuthorityStatus::Active,
        issuer_status: DreggAuthorityStatus::Active,
    }
}

fn registry() -> DreggAuthorityRegistry {
    DreggAuthorityRegistry::new([registry_entry()]).unwrap()
}

fn valid_grant() -> DreggAuthorityGrantFixture {
    DreggAuthorityGrantFixture {
        evidence_ref: EVIDENCE_REF.to_string(),
        token: DreggAuthorityGrantFixture::fixture_token(SUBJECT, OPERATION, 1_777_000_000),
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        suite: "dregg_authority_fixture_v1".to_string(),
        status_checked_at: Some(STATUS_CHECKED_AT),
        revocation_status: Some(DreggAuthorityRevocationStatus::Active),
        finality_status: None,
        attested_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
    }
}

fn adapter(fixture: DreggAuthorityGrantFixture) -> DreggAuthorityEvidenceAdapter {
    DreggAuthorityEvidenceAdapter::new([fixture], registry(), VALIDATION_TIME)
}

fn shape_only_receipt_fixture() -> DreggReceiptFixture {
    DreggReceiptFixture {
        evidence_ref: EVIDENCE_REF.to_string(),
        subject: SUBJECT.to_string(),
        audience: AUDIENCE.to_string(),
        origin: "https://gallery.local".to_string(),
        operation: OPERATION.to_string(),
        resource: RESOURCE.to_string(),
        receipt_kind: DreggReceiptFixture::RECEIPT_KIND.to_string(),
        strand_ref: "dregg-strand:fixture".to_string(),
        sequence: 7,
        issued_at: VALIDATION_TIME - 10,
        expires_at: VALIDATION_TIME + 10,
        signature_suite: "Ed25519".to_string(),
        public_key_ref: "pubkey:sha256:shape-only".to_string(),
        author_public_key_bytes: vec![0; 32],
        signature_bytes: vec![0; 64],
    }
}

#[test]
fn dregg_receipt_shape_only_adapter_cannot_satisfy_dregg_authority() {
    let adapter = DreggShapedEvidenceAdapter::with_validation_time(
        [shape_only_receipt_fixture()],
        VALIDATION_TIME,
    );

    assert_eq!(
        adapter.verify(&request()),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

#[test]
fn dregg_authority_rejects_non_dga1_shape_valid_token() {
    let mut fixture = valid_grant();
    fixture.token = DreggReceiptFixture::VERSION.to_string();

    assert_eq!(
        adapter(fixture).verify(&request()),
        EvidenceResult::Rejected(VerificationError::MalformedDreggAuthority)
    );
}

#[test]
fn dregg_authority_accepts_grant_only_after_receiver_held_policy() {
    let EvidenceResult::Satisfied(summary) = adapter(valid_grant()).verify(&request()) else {
        panic!("valid authority grant should satisfy dregg_authority");
    };

    assert_eq!(summary.kind, EvidenceKind::DreggAuthority);
    assert!(
        !summary.public_proof,
        "#139 does not claim finality/public auditability"
    );
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == "admission:admitted"));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == "issuer_id:did:dregg:issuer:fixture"));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field.starts_with("epoch_id_sha256:")));
    assert!(
        summary
            .summary_fields
            .iter()
            .all(|field| !field.contains(&valid_grant().token)),
        "raw Dregg authority token must not be disclosed in summaries"
    );
}

#[test]
fn dregg_authority_rejects_amplified_trusted_requested_resource_outside_delegated_scope() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_prefix(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/",
        1_777_000_000,
    );
    let mut amplified = request();
    amplified.trusted_requested_resource = Some("urn:secs:member:bob/profile".to_string());

    assert_eq!(
        adapter(fixture).verify(&amplified),
        EvidenceResult::Rejected(VerificationError::AuthorityAmplification),
        "a trusted requested resource outside the delegated prefix must fail closed before any authority summary is minted"
    );
}

#[test]
fn dregg_authority_rejects_attenuated_grant_without_requested_resource() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_prefix(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/",
        1_777_000_000,
    );

    assert_eq!(
        adapter(fixture).verify(&request()),
        EvidenceResult::Rejected(VerificationError::AuthorityAmplification),
        "an attenuated grant must fail closed when the live request omits the requested authority/resource it is trying to exercise"
    );
}

#[test]
fn dregg_authority_ignores_caller_declared_requested_resource_without_trusted_binding() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_prefix(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/",
        1_777_000_000,
    );
    let mut spoofed = request();
    spoofed
        .public_inputs
        .push("requested_resource:urn:secs:member:alice/profile".to_string());

    assert_eq!(
        adapter(fixture).verify(&spoofed),
        EvidenceResult::Rejected(VerificationError::AuthorityAmplification),
        "caller-declared requested_resource public inputs must not satisfy trusted attenuation"
    );
}

#[test]
fn dregg_authority_rejects_requested_resource_outside_resource_lock() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_lock(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/profile",
        1_777_000_000,
    );
    let mut request = request();
    request.trusted_requested_resource = Some("urn:secs:member:bob/profile".to_string());

    assert_eq!(
        adapter(fixture).verify(&request),
        EvidenceResult::Rejected(VerificationError::ResourceLockViolation),
        "Dregg resource locks must reject a trusted requested resource outside the locked mutation target"
    );
}

#[test]
fn dregg_authority_summary_binds_resource_lock_without_raw_disclosure() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_lock(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/profile",
        1_777_000_000,
    );
    let mut request = request();
    request.trusted_requested_resource = Some("urn:secs:member:alice/profile".to_string());

    let EvidenceResult::Satisfied(summary) = adapter(fixture).verify(&request) else {
        panic!(
            "trusted requested resource matching the Dregg resource lock should satisfy authority"
        );
    };
    assert_eq!(
        summary.resource.as_deref(),
        Some("urn:secs:member:alice/profile")
    );
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == "resource_lock:verified"));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field.starts_with("resource_lock_sha256:")));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field.starts_with("locked_resource_sha256:")));
    assert!(
        summary
            .summary_fields
            .iter()
            .all(|field| !field.contains("urn:secs:member:alice/profile")),
        "raw locked resource must stay out of summaries"
    );
}

#[test]
fn dregg_authority_accepts_requested_resource_inside_delegated_scope() {
    let mut fixture = valid_grant();
    fixture.token = DreggAuthorityGrantFixture::fixture_token_with_resource_prefix(
        SUBJECT,
        OPERATION,
        "urn:secs:member:alice/",
        1_777_000_000,
    );
    let mut narrowed = request();
    narrowed.trusted_requested_resource = Some("urn:secs:member:alice/profile".to_string());

    let EvidenceResult::Satisfied(summary) = adapter(fixture).verify(&narrowed) else {
        panic!("requested resource inside the delegated prefix should satisfy dregg_authority");
    };
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field == "attenuation:non_amplifying"));
    assert!(summary
        .summary_fields
        .iter()
        .any(|field| field.starts_with("requested_resource_sha256:")));
    assert!(
        summary
            .summary_fields
            .iter()
            .all(|field| !field.contains("urn:secs:member:alice/profile")),
        "requested resource scope must be redacted before it reaches signed contexts/receipts"
    );
}

#[test]
fn dregg_authority_rejects_binding_root_epoch_status_and_suite_failures() {
    let mut lookup = DreggAuthorityLookup {
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        audience: AUDIENCE.to_string(),
        operation: OPERATION.to_string(),
        resource: RESOURCE.to_string(),
        suite: "dregg_authority_fixture_v1".to_string(),
        validation_time: VALIDATION_TIME,
        status_checked_at: Some(STATUS_CHECKED_AT),
        revocation_status: Some(DreggAuthorityRevocationStatus::Active),
        finality_status: None,
        attested_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
    };
    assert!(registry().lookup_active_policy(&lookup).is_ok());

    let mut wrong_subject = valid_grant();
    wrong_subject.token = DreggAuthorityGrantFixture::fixture_token(
        "did:castalia:member:bob",
        OPERATION,
        1_777_000_000,
    );
    assert_eq!(
        adapter(wrong_subject).verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongSubject)
    );

    let mut wrong_operation = valid_grant();
    wrong_operation.token =
        DreggAuthorityGrantFixture::fixture_token(SUBJECT, "admin.delete", 1_777_000_000);
    assert_eq!(
        adapter(wrong_operation).verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongOperation)
    );

    let mut wrong_root = valid_grant();
    wrong_root.root_ref = "dregg-root:wrong".to_string();
    assert_eq!(
        adapter(wrong_root).verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongRoot)
    );

    let mut stale = valid_grant();
    stale.status_checked_at = Some(VALIDATION_TIME - 301);
    assert_eq!(
        adapter(stale).verify(&request()),
        EvidenceResult::Rejected(VerificationError::Stale)
    );

    let mut unsupported_suite = valid_grant();
    unsupported_suite.suite = "dregg_authority_unknown_v9".to_string();
    assert_eq!(
        adapter(unsupported_suite).verify(&request()),
        EvidenceResult::Rejected(VerificationError::UnsupportedSuite)
    );

    lookup.epoch_id = "epoch:wrong".to_string();
    assert_eq!(
        registry().lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongEpoch
    );
}

#[test]
fn dregg_authority_binds_receiver_held_revocation_root_not_public_inputs() {
    let mut missing_root = valid_grant();
    missing_root.attested_revocation_root_ref = None;
    let mut request_with_caller_root = request();
    request_with_caller_root
        .public_inputs
        .push("revocation_root:dregg-revocation-root:fixture-2026q2".to_string());
    assert_eq!(
        adapter(missing_root).verify(&request_with_caller_root),
        EvidenceResult::Rejected(VerificationError::MissingRevocationRoot),
        "caller-supplied public_inputs must not satisfy receiver-held revocation-root binding"
    );

    let mut wrong_root = valid_grant();
    wrong_root.attested_revocation_root_ref =
        Some("dregg-revocation-root:caller-supplied".to_string());
    assert_eq!(
        adapter(wrong_root).verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongRevocationRoot)
    );

    let EvidenceResult::Satisfied(summary) = adapter(valid_grant()).verify(&request()) else {
        panic!("matching receiver-held revocation root should satisfy bounded root binding");
    };
    assert!(
        !summary.public_proof,
        "root binding is not live public proof"
    );
    let joined = summary.summary_fields.join(
        "
",
    );
    assert!(joined.contains("revocation_verifier_mode:expected_root_binding"));
    assert!(joined.contains("revocation_root_ref_sha256:"));
    assert!(
        !joined.contains("dregg-revocation-root:fixture-2026q2"),
        "raw revocation root refs must be digested in summaries"
    );
}

#[test]
fn live_revocation_bls_finality_and_rotated_replay_modes_fail_closed_without_verifiers() {
    let base = registry()
        .lookup_active_policy(&DreggAuthorityLookup {
            issuer_id: "did:dregg:issuer:fixture".to_string(),
            issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
            root_ref: "dregg-root:fixture-root-2026q2".to_string(),
            root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
            epoch_id: "epoch:2026q2".to_string(),
            audience: AUDIENCE.to_string(),
            operation: OPERATION.to_string(),
            resource: RESOURCE.to_string(),
            suite: "dregg_authority_fixture_v1".to_string(),
            validation_time: VALIDATION_TIME,
            status_checked_at: Some(STATUS_CHECKED_AT),
            revocation_status: Some(DreggAuthorityRevocationStatus::Active),
            finality_status: Some(DreggAuthorityFinalityStatus::Final),
            attested_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
        })
        .unwrap()
        .clone();

    let live_revocation_registry = DreggAuthorityRegistry::new([DreggAuthorityEntry {
        status_policy: DreggAuthorityStatusPolicy {
            revocation_verifier_mode:
                DreggAuthorityRevocationVerifierMode::LiveRevocationVerifierRequired,
            ..base.status_policy.clone()
        },
        ..base.clone()
    }])
    .unwrap();
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new(
            [valid_grant()],
            live_revocation_registry,
            VALIDATION_TIME
        )
        .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRevocationVerifier),
        "fixture root/status material must not fake a live Dregg RevocationVerifier/RevocationTree"
    );

    let bls_registry = DreggAuthorityRegistry::new([DreggAuthorityEntry {
        status_policy: DreggAuthorityStatusPolicy {
            require_finality: true,
            finality_mode: DreggAuthorityFinalityMode::BlsThresholdRequired,
            ..base.status_policy.clone()
        },
        ..base.clone()
    }])
    .unwrap();
    let mut final_fixture = valid_grant();
    final_fixture.finality_status = Some(DreggAuthorityFinalityStatus::Final);
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([final_fixture], bls_registry, VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggBlsThresholdVerifier),
        "final fixture status must not fake ReceiptQc::Threshold/BLS FederationCommittee finality"
    );

    let rotated_registry = DreggAuthorityRegistry::new([DreggAuthorityEntry {
        status_policy: DreggAuthorityStatusPolicy {
            require_finality: true,
            finality_mode: DreggAuthorityFinalityMode::RotatedReplayRequired,
            ..base.status_policy
        },
        ..base
    }])
    .unwrap();
    let mut final_fixture = valid_grant();
    final_fixture.finality_status = Some(DreggAuthorityFinalityStatus::Final);
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([final_fixture], rotated_registry, VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRotatedReplayVerifier),
        "final fixture status must not fake rotated_replay::verify_rotated_replay_chain"
    );
}

#[test]
fn dregg_authority_enforces_revocation_check_finality_and_time_boundaries() {
    let mut missing_revocation = valid_grant();
    missing_revocation.revocation_status = None;
    assert_eq!(
        adapter(missing_revocation).verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingStatus),
        "require_revocation_check must be a fail-closed runtime gate, not a registry-only label"
    );

    let mut revoked = valid_grant();
    revoked.revocation_status = Some(DreggAuthorityRevocationStatus::Revoked);
    assert_eq!(
        adapter(revoked).verify(&request()),
        EvidenceResult::Rejected(VerificationError::Revoked)
    );

    let mut future_status = valid_grant();
    future_status.status_checked_at = Some(VALIDATION_TIME + 1);
    assert_eq!(
        adapter(future_status).verify(&request()),
        EvidenceResult::Rejected(VerificationError::Stale),
        "caller-supplied future status timestamps must not satisfy freshness"
    );

    let mut expires_now = valid_grant();
    expires_now.token =
        DreggAuthorityGrantFixture::fixture_token(SUBJECT, OPERATION, VALIDATION_TIME);
    assert_eq!(
        adapter(expires_now).verify(&request()),
        EvidenceResult::Rejected(VerificationError::InvalidAdmission),
        "authority tokens expire at the validation instant, matching fail-closed credential expiry semantics"
    );
}

#[test]
fn dregg_authority_finality_policy_fails_closed_or_rejects_equivocation() {
    let registry = DreggAuthorityRegistry::new([DreggAuthorityEntry {
        status_policy: DreggAuthorityStatusPolicy {
            require_status: true,
            max_status_age_seconds: 300,
            require_revocation_check: true,
            require_finality: true,
            revocation_verifier_mode: DreggAuthorityRevocationVerifierMode::ExpectedRootBinding,
            finality_mode: DreggAuthorityFinalityMode::FixtureStatusOnly,
            expected_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
        },
        ..registry()
            .lookup_active_policy(&DreggAuthorityLookup {
                issuer_id: "did:dregg:issuer:fixture".to_string(),
                issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
                root_ref: "dregg-root:fixture-root-2026q2".to_string(),
                root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
                epoch_id: "epoch:2026q2".to_string(),
                audience: AUDIENCE.to_string(),
                operation: OPERATION.to_string(),
                resource: RESOURCE.to_string(),
                suite: "dregg_authority_fixture_v1".to_string(),
                validation_time: VALIDATION_TIME,
                status_checked_at: Some(STATUS_CHECKED_AT),
                revocation_status: Some(DreggAuthorityRevocationStatus::Active),
                finality_status: Some(DreggAuthorityFinalityStatus::Final),
                attested_revocation_root_ref: Some(
                    "dregg-revocation-root:fixture-2026q2".to_string(),
                ),
            })
            .unwrap()
            .clone()
    }])
    .unwrap();

    let mut no_finality = valid_grant();
    no_finality.finality_status = None;
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([no_finality], registry.clone(), VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::NotFinal),
        "require_finality must become a named blocker when no finality proof/check is present"
    );

    let mut not_final = valid_grant();
    not_final.finality_status = Some(DreggAuthorityFinalityStatus::NotFinal);
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([not_final], registry.clone(), VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::NotFinal)
    );

    let mut equivocated = valid_grant();
    equivocated.finality_status = Some(DreggAuthorityFinalityStatus::Equivocated);
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([equivocated], registry.clone(), VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::Equivocated)
    );

    let mut final_grant = valid_grant();
    final_grant.finality_status = Some(DreggAuthorityFinalityStatus::Final);
    assert!(matches!(
        DreggAuthorityEvidenceAdapter::new([final_grant], registry, VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Satisfied(_)
    ));
}

#[test]
fn dregg_authority_summary_follows_m15_6_disclosure_boundary() {
    let grant = valid_grant();
    let EvidenceResult::Satisfied(summary) = adapter(grant.clone()).verify(&request()) else {
        panic!("valid authority grant should satisfy dregg_authority");
    };
    let joined = summary.summary_fields.join("\n");

    assert!(joined.contains("authority_class:dregg_authority"));
    assert!(joined.contains("tier:m15_production_shaped"));
    assert!(joined.contains("root_fingerprint:root:sha256:fixture-root-2026q2"));
    assert!(joined.contains("revocation_status:active"));
    assert!(joined.contains("finality_status:not_required"));
    assert!(joined.contains("issuer_key_id_sha256:"));
    assert!(joined.contains("root_ref_sha256:"));
    assert!(joined.contains("federation_id_sha256:"));

    for forbidden in [
        grant.token.as_str(),
        EVIDENCE_REF,
        grant.issuer_key_id.as_str(),
        grant.root_ref.as_str(),
        "dregg-federation:fixture",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "revocation_status:Active",
        "finality_status:Final",
    ] {
        assert!(
            !joined.contains(forbidden),
            "Dregg authority disclosure summary leaked forbidden raw value: {forbidden}"
        );
    }
}

#[test]
fn live_revocation_required_rejects_with_missing_live_verifier_not_fixture_status() {
    let mut entry = registry_entry();
    entry.status_policy.revocation_verifier_mode =
        DreggAuthorityRevocationVerifierMode::LiveRevocationVerifierRequired;
    let live_registry = DreggAuthorityRegistry::new([entry]).unwrap();
    let live_adapter =
        DreggAuthorityEvidenceAdapter::new([valid_grant()], live_registry, VALIDATION_TIME);

    assert_eq!(
        live_adapter.verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRevocationVerifier),
        "live revocation-required policies must fail closed instead of falling back to fixture status"
    );
}

#[test]
fn live_bls_finality_required_rejects_with_missing_live_verifier() {
    let mut entry = registry_entry();
    entry.status_policy.require_finality = true;
    entry.status_policy.finality_mode = DreggAuthorityFinalityMode::BlsThresholdRequired;
    let live_registry = DreggAuthorityRegistry::new([entry]).unwrap();
    let mut grant = valid_grant();
    grant.finality_status = Some(DreggAuthorityFinalityStatus::Final);
    let live_adapter = DreggAuthorityEvidenceAdapter::new([grant], live_registry, VALIDATION_TIME);

    assert_eq!(
        live_adapter.verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggBlsThresholdVerifier),
        "BLS-required policies must fail closed instead of accepting fixture finality flags"
    );
}

#[test]
fn live_rotated_replay_required_rejects_with_missing_live_verifier() {
    let mut entry = registry_entry();
    entry.status_policy.require_finality = true;
    entry.status_policy.finality_mode = DreggAuthorityFinalityMode::RotatedReplayRequired;
    let live_registry = DreggAuthorityRegistry::new([entry]).unwrap();
    let mut grant = valid_grant();
    grant.finality_status = Some(DreggAuthorityFinalityStatus::Final);
    let live_adapter = DreggAuthorityEvidenceAdapter::new([grant], live_registry, VALIDATION_TIME);

    assert_eq!(
        live_adapter.verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRotatedReplayVerifier),
        "rotated-replay-required policies must fail closed instead of accepting fixture finality flags"
    );
}
