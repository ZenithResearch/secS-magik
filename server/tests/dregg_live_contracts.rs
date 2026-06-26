use server::evidence::{
    EvidenceKind, LiveDreggEvidenceEnvelope, LiveDreggProofKind, LiveDreggVerifier,
    MissingLiveDreggVerifier,
};
use server::verifier::VerificationError;

fn live_envelope(proof_kind: LiveDreggProofKind) -> LiveDreggEvidenceEnvelope {
    LiveDreggEvidenceEnvelope {
        version: LiveDreggEvidenceEnvelope::VERSION,
        proof_kind,
        evidence_ref: "dregg-live:raw-proof-ref-secret".to_string(),
        federation_id: "dregg-federation:fixture".to_string(),
        issuer_id: "did:dregg:issuer:fixture".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        proof_ref: "proof-ref:do-not-leak".to_string(),
        verifier_mode: "live_revocation_verifier_required".to_string(),
    }
}

#[test]
fn live_dregg_contracts_are_versioned_typed_and_redacted() {
    let envelope = live_envelope(LiveDreggProofKind::Revocation);

    assert_eq!(envelope.version, "secs-dregg-live-evidence-v1");
    assert_eq!(envelope.evidence_kind(), EvidenceKind::DreggAuthority);

    let fields = envelope.redacted_summary_fields();
    assert!(fields
        .iter()
        .any(|field| field == "live_dregg_contract:secs-dregg-live-evidence-v1"));
    assert!(fields
        .iter()
        .any(|field| field == "live_dregg_proof_kind:revocation"));
    assert!(fields
        .iter()
        .any(|field| field.starts_with("federation_id_sha256:")));
    assert!(fields
        .iter()
        .any(|field| field.starts_with("epoch_id_sha256:")));
    assert!(fields
        .iter()
        .any(|field| field.starts_with("proof_ref_sha256:")));

    let joined = fields.join("\n");
    assert!(!joined.contains("raw-proof-ref-secret"));
    assert!(!joined.contains("proof-ref:do-not-leak"));
    assert!(!joined.contains("epoch:2026q2"));
}

#[test]
fn live_dregg_reason_codes_are_specific_not_generic_invalid_presentation() {
    let cases = [
        (
            VerificationError::MissingLiveDreggVerifier,
            "missing_live_dregg_verifier",
        ),
        (
            VerificationError::MissingLiveDreggRevocationVerifier,
            "missing_live_dregg_revocation_verifier",
        ),
        (
            VerificationError::MissingLiveDreggBlsThresholdVerifier,
            "missing_live_dregg_bls_threshold_verifier",
        ),
        (
            VerificationError::MissingLiveDreggRotatedReplayVerifier,
            "missing_live_dregg_rotated_replay_verifier",
        ),
        (
            VerificationError::StaleDreggRevocationRoot,
            "stale_dregg_revocation_root",
        ),
        (
            VerificationError::InvalidDreggFinalityQc,
            "invalid_dregg_finality_qc",
        ),
        (
            VerificationError::InvalidDreggRotatedProof,
            "invalid_dregg_rotated_proof",
        ),
    ];

    for (error, expected) in cases {
        assert_eq!(error.reason_code(), expected);
        assert_ne!(error.reason_code(), "invalid_presentation");
    }
}

#[test]
fn missing_live_dregg_verifier_trait_fails_closed_per_proof_kind() {
    let missing = MissingLiveDreggVerifier;

    assert_eq!(
        missing.verify_revocation(&live_envelope(LiveDreggProofKind::Revocation)),
        Err(VerificationError::MissingLiveDreggRevocationVerifier)
    );
    assert_eq!(
        missing.verify_bls_threshold_finality(&live_envelope(
            LiveDreggProofKind::BlsThresholdFinality
        )),
        Err(VerificationError::MissingLiveDreggBlsThresholdVerifier)
    );
    assert_eq!(
        missing.verify_rotated_replay(&live_envelope(LiveDreggProofKind::RotatedReplay)),
        Err(VerificationError::MissingLiveDreggRotatedReplayVerifier)
    );
}
