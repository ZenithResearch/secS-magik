use server::dregg_authority::{
    DreggAuthorityEntry, DreggAuthorityFinalityMode, DreggAuthorityRegistry,
    DreggAuthorityRevocationVerifierMode, DreggAuthorityStatusPolicy,
};
use server::evidence::{
    DreggAuthorityEvidenceAdapter, DreggAuthorityGrantFixture, EvidenceAdapter, EvidenceKind,
    EvidenceRequest, EvidenceResult, LiveDreggBlsFinalityVerifier,
    LiveDreggBlsFinalityVerifierConfig, LiveDreggCompositeVerifier, LiveDreggRevocationVerifier,
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
const EVIDENCE_REF: &str = "dga-live-finality-ref:fixture-secret";

fn registry_entry(require_revocation: bool) -> DreggAuthorityEntry {
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
            require_revocation_check: require_revocation,
            require_finality: true,
            revocation_verifier_mode: if require_revocation {
                DreggAuthorityRevocationVerifierMode::LiveRevocationVerifierRequired
            } else {
                DreggAuthorityRevocationVerifierMode::FixtureStatusOnly
            },
            finality_mode: DreggAuthorityFinalityMode::BlsThresholdRequired,
            expected_revocation_root_ref: None,
        },
        root_status: server::dregg_authority::DreggAuthorityStatus::Active,
        issuer_status: server::dregg_authority::DreggAuthorityStatus::Active,
    }
}

fn registry(require_revocation: bool) -> DreggAuthorityRegistry {
    DreggAuthorityRegistry::new([registry_entry(require_revocation)]).unwrap()
}

fn grant() -> DreggAuthorityGrantFixture {
    DreggAuthorityGrantFixture {
        evidence_ref: EVIDENCE_REF.to_string(),
        token: DreggAuthorityGrantFixture::fixture_token(SUBJECT, OPERATION, EXPIRES_AT),
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        suite: "dregg_authority_fixture_v1".to_string(),
        status_checked_at: Some(STATUS_CHECKED_AT),
        revocation_status: Some(server::dregg_authority::DreggAuthorityRevocationStatus::Active),
        finality_status: Some(server::dregg_authority::DreggAuthorityFinalityStatus::Final),
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
        evidence_refs: vec![EVIDENCE_REF.to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    }
}

fn bls_verifier() -> LiveDreggBlsFinalityVerifier {
    let config = LiveDreggBlsFinalityVerifierConfig::from_json_str(
        r#"{"committees":[{"federation_id":"dregg-federation:fixture","committee_id":"committee:fixture-2026q2","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","quorum_threshold":3,"member_count":4,"not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .unwrap();
    LiveDreggBlsFinalityVerifier::new(config, VALIDATION_TIME)
        .with_threshold_qc_ref(EVIDENCE_REF.to_string())
}

fn revocation_verifier() -> LiveDreggRevocationVerifier {
    let config = LiveDreggRevocationVerifierConfig::from_json_str(
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:issuer:fixture","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .unwrap();
    LiveDreggRevocationVerifier::new(config, VALIDATION_TIME)
        .with_non_membership_proof_ref("dregg-revocation-root:fixture-2026q2".to_string())
}

#[test]
fn bls_finality_config_parses_committees_and_rejects_unsupported_quorum() {
    let config = LiveDreggBlsFinalityVerifierConfig::from_json_str(
        r#"{"committees":[{"federation_id":"dregg-federation:fixture","committee_id":"committee:fixture-2026q2","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","quorum_threshold":3,"member_count":4,"not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .expect("valid committee config should parse");
    let verifier = LiveDreggBlsFinalityVerifier::new(config, VALIDATION_TIME);
    assert!(verifier.trusts_committee(
        "dregg-federation:fixture",
        "committee:fixture-2026q2",
        "epoch:2026q2",
        "root:sha256:fixture-root-2026q2",
    ));

    assert!(LiveDreggBlsFinalityVerifierConfig::from_json_str(
        r#"{"committees":[{"federation_id":"dregg-federation:fixture","committee_id":"committee:bad","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","quorum_threshold":0,"member_count":4,"not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .is_err());
}

#[test]
fn bls_finality_required_accepts_only_verified_qc_not_finality_flag() {
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggBlsThresholdVerifier),
        "a Final receipt flag must not satisfy BLS-required finality without a live verifier"
    );

    let accepted = DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
        .with_live_verifier(bls_verifier())
        .verify(&request());
    let EvidenceResult::Satisfied(summary) = accepted else {
        panic!("valid BLS threshold QC should satisfy: {accepted:?}");
    };
    let fields = summary.summary_fields.join("\n");
    assert!(fields.contains("live_dregg_proof_kind:bls_threshold_finality"));
    assert!(fields.contains("bls_finality_status:threshold_qc_verified"));
    assert!(fields.contains("committee_id_sha256:"));
    assert!(fields.contains("threshold_qc_ref_sha256:"));
    assert!(!fields.contains(EVIDENCE_REF));
    assert!(summary.public_proof);
}

#[test]
fn bls_finality_rejects_wrong_epoch_root_and_unknown_qc() {
    let verifier = bls_verifier();
    let mut wrong_epoch = grant();
    wrong_epoch.epoch_id = "epoch:wrong".to_string();
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([wrong_epoch], registry(false), VALIDATION_TIME)
            .with_live_verifier(verifier.clone())
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::WrongEpoch)
    );

    let unknown_qc = LiveDreggBlsFinalityVerifier::new(
        LiveDreggBlsFinalityVerifierConfig::from_json_str(
            r#"{"committees":[{"federation_id":"dregg-federation:fixture","committee_id":"committee:fixture-2026q2","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","quorum_threshold":3,"member_count":4,"not_before":1774999000,"not_after":1775999000}]}"#,
        ).unwrap(),
        VALIDATION_TIME,
    );
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .with_live_verifier(unknown_qc)
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::InvalidDreggFinalityQc)
    );
}

#[test]
fn bls_finality_composes_after_live_revocation_when_both_are_required() {
    let composite = LiveDreggCompositeVerifier::new()
        .with_revocation_verifier(revocation_verifier())
        .with_bls_finality_verifier(bls_verifier());
    let accepted = DreggAuthorityEvidenceAdapter::new([grant()], registry(true), VALIDATION_TIME)
        .with_live_verifier(composite)
        .verify(&request());
    let EvidenceResult::Satisfied(summary) = accepted else {
        panic!("revocation + BLS finality should satisfy together: {accepted:?}");
    };
    let fields = summary.summary_fields.join("\n");
    assert!(fields.contains("live_revocation_status:non_member"));
    assert!(fields.contains("bls_finality_status:threshold_qc_verified"));

    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(true), VALIDATION_TIME)
            .with_live_verifier(bls_verifier())
            .verify(&request()),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRevocationVerifier),
        "BLS verifier must not bypass #178 live revocation when registry requires both"
    );
}
