use libsec_core::ZenithPacket;
use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceMaturityProfile, EvidenceRequest, EvidenceSupportStatus,
    EvidenceTier, LocalStaticEvidenceAdapter, LocalStaticGrant,
};
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, ReceiverManifest, ReplayScope, TargetKind,
};
use server::receipt::Receipt;
use server::verifier::{VerificationError, Verifier};

fn descriptor(opcode: u8, accepted_evidence: Vec<&str>) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.dev.evidence_tier"),
        payload_schema: Some("application/json".to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["tier.fixture".to_string()],
        required_capabilities: vec!["dev.execute".to_string()],
        accepted_evidence: accepted_evidence.into_iter().map(str::to_string).collect(),
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/evidence-tier".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

fn packet(opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: b"prototype-proof-envelope".to_vec(),
        claim_ttl: 60,
        encrypted_payload: br#"{"hello":"world"}"#.to_vec(),
        mac: [3u8; 16],
    }
}

fn local_static_adapter() -> LocalStaticEvidenceAdapter {
    LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: "did:example:tier-subject".to_string(),
        audience: "secS://tier-test".to_string(),
        operation: "candidate.dev.evidence_tier".to_string(),
        resource: Some("application/json".to_string()),
        evidence_ref: "local-static:tier-grant".to_string(),
    }])
}

fn verify_with(
    accepted_evidence: Vec<&str>,
    adapter: &dyn EvidenceAdapter,
) -> Result<server::verifier::SignedVerifiedCallContext, VerificationError> {
    let manifest = ReceiverManifest::new([descriptor(0x51, accepted_evidence)]);
    Verifier::verify_manifest_operation_with_evidence_and_sign(
        &packet(0x51),
        &manifest,
        "secS://tier-test",
        "did:example:tier-subject",
        Some("local-static:tier-grant"),
        adapter,
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
}

#[test]
fn canonical_evidence_tiers_and_support_statuses_round_trip() {
    let tiers = [
        EvidenceTier::ShapeOnly,
        EvidenceTier::LocalVerified,
        EvidenceTier::SignedSource,
        EvidenceTier::FederationCheckpoint,
        EvidenceTier::SuccinctProof,
        EvidenceTier::RecursiveProofCarryingState,
    ];
    let tier_labels = [
        "shape_only",
        "local_verified",
        "signed_source",
        "federation_checkpoint",
        "succinct_proof",
        "recursive_proof_carrying_state",
    ];
    for (tier, label) in tiers.into_iter().zip(tier_labels) {
        assert_eq!(tier.as_str(), label);
        assert_eq!(label.parse::<EvidenceTier>().unwrap(), tier);
    }

    let statuses = [
        EvidenceSupportStatus::Supported,
        EvidenceSupportStatus::LocalDev,
        EvidenceSupportStatus::Fixture,
        EvidenceSupportStatus::ReservedUnsupported,
        EvidenceSupportStatus::UnknownUnsupported,
    ];
    let status_labels = [
        "supported",
        "local_dev",
        "fixture",
        "reserved_unsupported",
        "unknown_unsupported",
    ];
    for (status, label) in statuses.into_iter().zip(status_labels) {
        assert_eq!(status.as_str(), label);
        assert_eq!(label.parse::<EvidenceSupportStatus>().unwrap(), status);
    }

    assert!("future_magic".parse::<EvidenceTier>().is_err());
    assert!("future_magic".parse::<EvidenceSupportStatus>().is_err());
}

#[test]
fn evidence_kind_and_dregg_proof_mappings_are_conservative() {
    assert_eq!(
        EvidenceKind::PrototypeProofEnvelope.maturity_profile(),
        EvidenceMaturityProfile::new(EvidenceTier::ShapeOnly, EvidenceSupportStatus::LocalDev)
    );
    assert_eq!(
        EvidenceKind::LocalStatic.maturity_profile(),
        EvidenceMaturityProfile::new(EvidenceTier::LocalVerified, EvidenceSupportStatus::LocalDev)
    );
    assert_eq!(
        EvidenceKind::MembershipCredential.maturity_profile(),
        EvidenceMaturityProfile::new(EvidenceTier::SignedSource, EvidenceSupportStatus::Fixture)
    );
    assert_eq!(
        EvidenceKind::DreggAuthority.maturity_profile(),
        EvidenceMaturityProfile::new(EvidenceTier::SignedSource, EvidenceSupportStatus::Fixture)
    );
    assert_eq!(
        EvidenceKind::MidnightProof.maturity_profile(),
        EvidenceMaturityProfile::new(
            EvidenceTier::SuccinctProof,
            EvidenceSupportStatus::ReservedUnsupported
        )
    );
    assert_eq!(
        EvidenceKind::CardanoSettlement.maturity_profile(),
        EvidenceMaturityProfile::new(
            EvidenceTier::FederationCheckpoint,
            EvidenceSupportStatus::ReservedUnsupported
        )
    );
}

#[test]
fn rejects_shape_only_when_local_verified_required() {
    let request = EvidenceRequest {
        accepted_evidence: vec![EvidenceKind::LocalStatic.as_str().to_string()],
        subject: "did:example:tier-subject".to_string(),
        audience: "secS://tier-test".to_string(),
        operation: "candidate.dev.evidence_tier".to_string(),
        resource: Some("application/json".to_string()),
        evidence_refs: vec!["prototype:tier-grant".to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    };
    let summary = server::evidence::EvidenceSummary {
        kind: EvidenceKind::PrototypeProofEnvelope,
        subject: request.subject.clone(),
        audience: request.audience.clone(),
        operation: request.operation.clone(),
        resource: request.resource.clone(),
        local_dev_test_only: true,
        public_proof: false,
        summary_fields: Vec::new(),
    };

    assert_eq!(
        request.validate_satisfied_summary(&summary).unwrap_err(),
        VerificationError::EvidenceTierTooWeak
    );
}

#[test]
fn rejects_local_verified_when_signed_source_required_before_handler_context_exists() {
    let error = verify_with(
        vec![EvidenceKind::MembershipCredential.as_str()],
        &local_static_adapter(),
    )
    .expect_err("local_static must not satisfy signed_source policy");
    assert_eq!(error, VerificationError::EvidenceTierTooWeak);
    assert_eq!(error.reason_code(), "evidence_tier_too_weak");
}

#[test]
fn rejects_signed_source_when_federation_checkpoint_required() {
    let request = EvidenceRequest {
        accepted_evidence: vec!["cardano_settlement".to_string()],
        subject: "did:example:tier-subject".to_string(),
        audience: "secS://tier-test".to_string(),
        operation: "candidate.dev.evidence_tier".to_string(),
        resource: Some("application/json".to_string()),
        evidence_refs: vec!["membership:tier-grant".to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    };
    let summary = server::evidence::EvidenceSummary {
        kind: EvidenceKind::MembershipCredential,
        subject: request.subject.clone(),
        audience: request.audience.clone(),
        operation: request.operation.clone(),
        resource: request.resource.clone(),
        local_dev_test_only: false,
        public_proof: true,
        summary_fields: Vec::new(),
    };

    assert_eq!(
        request.validate_satisfied_summary(&summary).unwrap_err(),
        VerificationError::UnsupportedEvidenceKind
    );
}

#[test]
fn reserved_succinct_and_recursive_tiers_fail_closed_before_ordering() {
    let proof_required = EvidenceRequest {
        accepted_evidence: vec![EvidenceKind::MidnightProof.as_str().to_string()],
        subject: "did:example:tier-subject".to_string(),
        audience: "secS://tier-test".to_string(),
        operation: "candidate.dev.evidence_tier".to_string(),
        resource: Some("application/json".to_string()),
        evidence_refs: vec!["local-static:tier-grant".to_string()],
        public_inputs: Vec::new(),
        trusted_requested_resource: None,
    };
    let summary = server::evidence::EvidenceSummary {
        kind: EvidenceKind::LocalStatic,
        subject: proof_required.subject.clone(),
        audience: proof_required.audience.clone(),
        operation: proof_required.operation.clone(),
        resource: proof_required.resource.clone(),
        local_dev_test_only: true,
        public_proof: false,
        summary_fields: Vec::new(),
    };
    assert_eq!(
        proof_required
            .validate_satisfied_summary(&summary)
            .unwrap_err(),
        VerificationError::UnsupportedEvidenceKind
    );

    assert_eq!(
        EvidenceMaturityProfile::new(
            EvidenceTier::SuccinctProof,
            EvidenceSupportStatus::ReservedUnsupported
        )
        .supported_for_policy(EvidenceTier::RecursiveProofCarryingState)
        .unwrap_err(),
        VerificationError::UnsupportedEvidenceTier
    );
}

#[test]
fn unsupported_midnight_or_cardano_evidence_does_not_downgrade_to_local_acceptance() {
    for reserved in [
        EvidenceKind::MidnightProof.as_str(),
        EvidenceKind::CardanoSettlement.as_str(),
    ] {
        let error = verify_with(
            vec![EvidenceKind::LocalStatic.as_str(), reserved],
            &local_static_adapter(),
        )
        .expect_err("reserved evidence required beside local evidence must not fallback accept");
        assert_eq!(error, VerificationError::UnsupportedEvidenceKind);
        assert_eq!(error.reason_code(), "unsupported_evidence_kind");
    }
}

#[test]
fn unknown_evidence_label_fails_closed_without_downgrade() {
    let error = verify_with(
        vec![
            EvidenceKind::LocalStatic.as_str(),
            "future_unknown_evidence",
        ],
        &local_static_adapter(),
    )
    .expect_err("unknown evidence label must not fallback accept");
    assert_eq!(error, VerificationError::UnsupportedEvidenceKind);
}

#[test]
fn accepted_receipt_includes_evidence_kind_accepted_tier_required_tier_and_support_status() {
    let signed = verify_with(
        vec![EvidenceKind::LocalStatic.as_str()],
        &local_static_adapter(),
    )
    .expect("local_static should satisfy local_verified policy");
    let receipt =
        Receipt::verify_from_signed_context("receipt-tier-labels", &signed, 1_700_000_001);

    for expected in [
        "evidence_kind:local_static",
        "accepted_evidence_tier:local_verified",
        "policy_required_evidence_tier:local_verified",
        "evidence_support_status:local_dev",
    ] {
        assert!(
            receipt
                .evidence_summary
                .iter()
                .any(|field| field == expected),
            "missing {expected} from {:?}",
            receipt.evidence_summary
        );
    }

    let joined = receipt.evidence_summary.join("\n");
    for forbidden in [
        "wallet_id",
        "holder_id",
        "credential_id:",
        "raw_proof",
        "source_auth_token",
        "stable_nullifier",
    ] {
        assert!(
            !joined.contains(forbidden),
            "leaked forbidden field {forbidden}"
        );
    }
}
