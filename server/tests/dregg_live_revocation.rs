use server::dregg_authority::{
    DreggAuthorityEntry, DreggAuthorityFinalityMode, DreggAuthorityRegistry,
    DreggAuthorityRevocationVerifierMode, DreggAuthorityStatusPolicy,
};
use server::evidence::{
    DreggAuthorityEvidenceAdapter, DreggAuthorityGrantFixture, EvidenceAdapter, EvidenceKind,
    EvidenceRequest, EvidenceResult, LiveDreggRevocationVerifier,
    LiveDreggRevocationVerifierConfig,
};
use server::verifier::VerificationError;

const SUBJECT: &str = "did:castalia:member:alice";
const AUDIENCE: &str = "secS://operator-receiver";
const OPERATION: &str = "membership.provision";
const RESOURCE: &str = "urn:secs:member:alice/profile";
const VALIDATION_TIME: u64 = 1_775_000_100;
const STATUS_CHECKED_AT: u64 = 1_775_000_000;
const EXPIRES_AT: u64 = 1_775_001_000;

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
        epoch_not_before: 1_774_999_000,
        epoch_not_after: 1_775_999_000,
        accepted_audiences: vec![AUDIENCE.to_string()],
        accepted_operations: vec![OPERATION.to_string()],
        accepted_resources: vec![RESOURCE.to_string()],
        accepted_suites: vec!["dregg_authority_fixture_v1".to_string()],
        status_policy: DreggAuthorityStatusPolicy {
            require_status: true,
            max_status_age_seconds: 300,
            require_revocation_check: true,
            require_finality: false,
            revocation_verifier_mode:
                DreggAuthorityRevocationVerifierMode::LiveRevocationVerifierRequired,
            finality_mode: DreggAuthorityFinalityMode::NotRequired,
            expected_revocation_root_ref: None,
        },
        root_status: server::dregg_authority::DreggAuthorityStatus::Active,
        issuer_status: server::dregg_authority::DreggAuthorityStatus::Active,
    }
}

fn grant() -> DreggAuthorityGrantFixture {
    DreggAuthorityGrantFixture {
        evidence_ref: "dga-live-ref:fixture-secret".to_string(),
        token: DreggAuthorityGrantFixture::fixture_token(SUBJECT, OPERATION, EXPIRES_AT),
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        suite: "dregg_authority_fixture_v1".to_string(),
        status_checked_at: Some(STATUS_CHECKED_AT),
        revocation_status: Some(server::dregg_authority::DreggAuthorityRevocationStatus::Active),
        finality_status: None,
        attested_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
    }
}

fn request() -> EvidenceRequest {
    EvidenceRequest {
        accepted_evidence: vec![EvidenceKind::DreggAuthority.as_str().to_string()],
        subject: SUBJECT.to_string(),
        audience: AUDIENCE.to_string(),
        operation: OPERATION.to_string(),
        resource: Some(RESOURCE.to_string()),
        evidence_refs: vec!["dga-live-ref:fixture-secret".to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    }
}

fn registry() -> DreggAuthorityRegistry {
    DreggAuthorityRegistry::new([registry_entry()]).unwrap()
}

#[test]
fn live_revocation_config_parses_trusted_roots_and_rejects_missing_or_stale_roots() {
    let config = LiveDreggRevocationVerifierConfig::from_json_str(
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:issuer:fixture","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .expect("valid trusted root config should parse");

    let verifier = LiveDreggRevocationVerifier::new(config, VALIDATION_TIME);
    assert!(verifier.trusts_root(
        "dregg-federation:fixture",
        "did:dregg:issuer:fixture",
        "dregg-root:fixture-root-2026q2",
        "root:sha256:fixture-root-2026q2",
        "epoch:2026q2",
    ));

    let stale = LiveDreggRevocationVerifierConfig::from_json_str(
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:issuer:fixture","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1774000000,"not_after":1774000100}]}"#,
    )
    .unwrap();
    let stale_verifier = LiveDreggRevocationVerifier::new(stale, VALIDATION_TIME);
    assert!(!stale_verifier.trusts_root(
        "dregg-federation:fixture",
        "did:dregg:issuer:fixture",
        "dregg-root:fixture-root-2026q2",
        "root:sha256:fixture-root-2026q2",
        "epoch:2026q2",
    ));
}

#[test]
fn live_revocation_required_accepts_only_with_real_verifier_and_rejects_wrong_bindings() {
    let config = LiveDreggRevocationVerifierConfig::from_json_str(
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:issuer:fixture","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .unwrap();
    let verifier = LiveDreggRevocationVerifier::new(config, VALIDATION_TIME)
        .with_non_membership_proof_ref("dregg-revocation-root:fixture-2026q2".to_string());

    let accepted = DreggAuthorityEvidenceAdapter::new([grant()], registry(), VALIDATION_TIME)
        .with_live_verifier(verifier.clone())
        .verify(&request());
    let EvidenceResult::Satisfied(summary) = accepted else {
        panic!("valid live revocation proof should satisfy: {accepted:?}");
    };
    let fields = summary.summary_fields.join("\n");
    assert!(fields.contains("live_dregg_proof_kind:revocation"));
    assert!(fields.contains("live_revocation_status:non_member"));
    assert!(fields.contains("proof_ref_sha256:"));
    assert!(!fields.contains("proof:revocation:alice-active"));
    assert!(summary.public_proof);

    let mut wrong_root = grant();
    wrong_root.root_fingerprint = "root:sha256:wrong".to_string();
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([wrong_root], registry(), VALIDATION_TIME)
            .with_live_verifier(verifier)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongRoot)
    );
}

#[test]
fn fixture_status_cannot_satisfy_live_revocation_without_installed_verifier() {
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(), VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRevocationVerifier)
    );
}

#[test]
fn live_revocation_enforces_descriptor_audience_operation_and_resource_policy() {
    let config = LiveDreggRevocationVerifierConfig::from_json_str(
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:issuer:fixture","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .unwrap();
    let verifier = LiveDreggRevocationVerifier::new(config, VALIDATION_TIME)
        .with_non_membership_proof_ref("dregg-revocation-root:fixture-2026q2".to_string());

    let wrong_resource = EvidenceRequest {
        accepted_evidence: vec![EvidenceKind::DreggAuthority.as_str().to_string()],
        subject: SUBJECT.to_string(),
        audience: AUDIENCE.to_string(),
        operation: OPERATION.to_string(),
        resource: Some("urn:secs:member:alice/other".to_string()),
        evidence_refs: vec!["dga-live-ref:fixture-secret".to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    };

    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(), VALIDATION_TIME)
            .with_live_verifier(verifier)
            .verify(&wrong_resource),
        EvidenceResult::Rejected(VerificationError::WrongResource)
    );
}
