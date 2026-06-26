use server::dregg_authority::{
    DreggAuthorityEntry, DreggAuthorityFinalityMode, DreggAuthorityRegistry,
    DreggAuthorityRevocationVerifierMode, DreggAuthorityStatusPolicy,
};
use server::evidence::{
    DreggAuthorityEvidenceAdapter, DreggAuthorityGrantFixture, EvidenceAdapter, EvidenceKind,
    EvidenceRequest, EvidenceResult, LiveDreggBlsFinalityVerifier,
    LiveDreggBlsFinalityVerifierConfig, LiveDreggCompositeVerifier, LiveDreggRevocationVerifier,
    LiveDreggRevocationVerifierConfig, LiveDreggRotatedReplayVerifier,
    LiveDreggRotatedReplayVerifierConfig,
};
use server::verifier::VerificationError;

const SUBJECT: &str = "did:castalia:member:alice";
const AUDIENCE: &str = "secS://operator-receiver";
const OPERATION: &str = "membership.provision";
const RESOURCE: &str = "urn:secs:member:alice/profile";
const VALIDATION_TIME: u64 = 1_775_000_100;
const STATUS_CHECKED_AT: u64 = 1_775_000_000;
const EXPIRES_AT: u64 = 1_775_001_000;
const EVIDENCE_REF: &str = "dga-rotated-proof-ref:fixture-secret";

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
            finality_mode: DreggAuthorityFinalityMode::RotatedReplayRequired,
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

fn request(resource: &str) -> EvidenceRequest {
    EvidenceRequest {
        accepted_evidence: vec![EvidenceKind::DreggAuthority.as_str().to_string()],
        subject: SUBJECT.to_string(),
        audience: AUDIENCE.to_string(),
        operation: OPERATION.to_string(),
        resource: Some(resource.to_string()),
        evidence_refs: vec![EVIDENCE_REF.to_string()],
        public_inputs: vec![
            "resource_hash:attacker_declared".to_string(),
            "turn_hash:attacker_declared".to_string(),
        ],
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

fn rotated_verifier() -> LiveDreggRotatedReplayVerifier {
    let resource_hash = LiveDreggRotatedReplayVerifier::resource_hash(RESOURCE);
    let turn_hash = LiveDreggRotatedReplayVerifier::turn_hash(SUBJECT, OPERATION, RESOURCE);
    let config = LiveDreggRotatedReplayVerifierConfig::from_json_str(&format!(
        r#"{{"proofs":[{{"federation_id":"dregg-federation:fixture","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","verifier_version":"rotated-replay-fixture-v1","proof_ref":"{EVIDENCE_REF}","old_commitment":"commitment:old:fixture","new_commitment":"commitment:new:fixture","nullifiers":["nullifier:fixture:1","nullifier:fixture:2"],"resource_hash":"{resource_hash}","turn_hash":"{turn_hash}","proof_digest":"proof:sha256:rotated-fixture","not_before":1774999000,"not_after":1775999000}}]}}"#
    ))
    .unwrap();
    LiveDreggRotatedReplayVerifier::new(config, VALIDATION_TIME)
}

#[test]
fn rotated_replay_config_parses_typed_fixtures_and_rejects_duplicate_nullifiers() {
    let verifier = rotated_verifier();
    assert!(verifier.trusts_rotated_proof(
        "dregg-federation:fixture",
        "epoch:2026q2",
        "root:sha256:fixture-root-2026q2",
        EVIDENCE_REF,
        &LiveDreggRotatedReplayVerifier::resource_hash(RESOURCE),
        &LiveDreggRotatedReplayVerifier::turn_hash(SUBJECT, OPERATION, RESOURCE),
    ));

    assert!(LiveDreggRotatedReplayVerifierConfig::from_json_str(
        r#"{"proofs":[{"federation_id":"dregg-federation:fixture","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","verifier_version":"rotated-replay-fixture-v1","proof_ref":"dga-rotated-proof-ref:fixture-secret","old_commitment":"commitment:old:fixture","new_commitment":"commitment:new:fixture","nullifiers":["dup","dup"],"resource_hash":"resource:sha256:x","turn_hash":"turn:sha256:y","proof_digest":"proof:sha256:rotated-fixture","not_before":1774999000,"not_after":1775999000}]}"#,
    )
    .is_err());
}

#[test]
fn rotated_replay_required_accepts_only_verified_typed_proof_not_public_input_shortcuts() {
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .verify(&request(RESOURCE)),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRotatedReplayVerifier),
        "RotatedReplayRequired must not accept a Final flag or caller-declared public inputs without live BLS + rotated verifiers"
    );

    let composite = LiveDreggCompositeVerifier::new()
        .with_bls_finality_verifier(bls_verifier())
        .with_rotated_replay_verifier(rotated_verifier());
    let accepted = DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
        .with_live_verifier(composite)
        .verify(&request(RESOURCE));
    let EvidenceResult::Satisfied(summary) = accepted else {
        panic!("valid rotated replay proof should satisfy: {accepted:?}");
    };
    let fields = summary.summary_fields.join("\n");
    assert!(fields.contains("live_dregg_proof_kind:bls_threshold_finality"));
    assert!(fields.contains("live_dregg_proof_kind:rotated_replay"));
    assert!(fields.contains("rotated_replay_status:proof_verified"));
    assert!(fields.contains("nullifier_sha256:"));
    assert!(fields.contains("old_commitment_sha256:"));
    assert!(fields.contains("new_commitment_sha256:"));
    assert!(fields.contains("proof_digest_sha256:"));
    assert!(!fields.contains("nullifier:fixture"));
    assert!(!fields.contains(EVIDENCE_REF));
    assert!(!fields.contains("attacker_declared"));
    assert!(summary.public_proof);
}

#[test]
fn rotated_replay_rejects_wrong_resource_unknown_proof_and_missing_rails() {
    let composite = LiveDreggCompositeVerifier::new()
        .with_bls_finality_verifier(bls_verifier())
        .with_rotated_replay_verifier(rotated_verifier());
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .with_live_verifier(composite)
            .verify(&request("urn:secs:member:alice/other")),
        EvidenceResult::Rejected(VerificationError::WrongResource)
    );

    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .with_live_verifier(bls_verifier())
            .verify(&request(RESOURCE)),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRotatedReplayVerifier)
    );

    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(false), VALIDATION_TIME)
            .with_live_verifier(rotated_verifier())
            .verify(&request(RESOURCE)),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggBlsThresholdVerifier)
    );
}

#[test]
fn rotated_replay_composes_after_live_revocation_and_bls_finality_when_all_are_required() {
    let composite = LiveDreggCompositeVerifier::new()
        .with_revocation_verifier(revocation_verifier())
        .with_bls_finality_verifier(bls_verifier())
        .with_rotated_replay_verifier(rotated_verifier());
    let accepted = DreggAuthorityEvidenceAdapter::new([grant()], registry(true), VALIDATION_TIME)
        .with_live_verifier(composite)
        .verify(&request(RESOURCE));
    let EvidenceResult::Satisfied(summary) = accepted else {
        panic!("revocation + BLS finality + rotated replay should satisfy together: {accepted:?}");
    };
    let fields = summary.summary_fields.join("\n");
    assert!(fields.contains("live_revocation_status:non_member"));
    assert!(fields.contains("bls_finality_status:threshold_qc_verified"));
    assert!(fields.contains("rotated_replay_status:proof_verified"));

    let without_revocation = LiveDreggCompositeVerifier::new()
        .with_bls_finality_verifier(bls_verifier())
        .with_rotated_replay_verifier(rotated_verifier());
    assert_eq!(
        DreggAuthorityEvidenceAdapter::new([grant()], registry(true), VALIDATION_TIME)
            .with_live_verifier(without_revocation)
            .verify(&request(RESOURCE)),
        EvidenceResult::Rejected(VerificationError::MissingLiveDreggRevocationVerifier)
    );
}
