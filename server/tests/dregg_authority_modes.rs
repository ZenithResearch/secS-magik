use server::dregg_authority::{AuthorityMode, TopologyAuthorityObservation};
use server::verifier::VerificationError;
use std::str::FromStr;

#[test]
fn canonical_authority_mode_labels_parse_and_serialize_without_legacy_aliases() {
    let cases = [
        (AuthorityMode::LocalFixture, "local_fixture"),
        (AuthorityMode::SignedSource, "signed_source"),
        (AuthorityMode::SoloVerifiedReceipt, "solo_verified_receipt"),
        (AuthorityMode::FederationCheckpoint, "federation_checkpoint"),
        (AuthorityMode::LightClientVerified, "light_client_verified"),
        (
            AuthorityMode::RecursiveProofCarryingState,
            "recursive_proof_carrying_state",
        ),
    ];

    for (mode, label) in cases {
        assert_eq!(mode.as_str(), label);
        assert_eq!(AuthorityMode::from_str(label), Ok(mode));
    }

    for legacy_or_forbidden in [
        "solo",
        "fixture_snapshot",
        "federation_final",
        "delegated_federated_under_node",
        "bls_threshold_required",
        "rotated_replay_required",
    ] {
        assert_eq!(
            AuthorityMode::from_str(legacy_or_forbidden),
            Err(VerificationError::UnsupportedAuthorityMode),
            "legacy or topology/finality labels must not silently map to canonical authority modes"
        );
    }
}

#[test]
fn federation_checkpoint_policy_rejects_weaker_unknown_missing_and_topology_modes() {
    for weaker in [
        AuthorityMode::LocalFixture,
        AuthorityMode::SignedSource,
        AuthorityMode::SoloVerifiedReceipt,
    ] {
        assert_eq!(
            weaker.satisfies_required_mode(AuthorityMode::FederationCheckpoint),
            Err(VerificationError::AuthorityModeDowngrade),
            "{weaker:?} must not satisfy a federation checkpoint requirement"
        );
    }

    for missing_unknown_or_topology in [
        "",
        "unknown",
        "legacy_solo",
        "delegated_federated_under_node",
        "recognized_federated_node",
    ] {
        assert_eq!(
            AuthorityMode::from_str(missing_unknown_or_topology),
            Err(VerificationError::UnsupportedAuthorityMode)
        );
    }
}

#[test]
fn signed_source_policy_rejects_local_fixture_unknown_and_missing_modes() {
    assert_eq!(
        AuthorityMode::LocalFixture.satisfies_required_mode(AuthorityMode::SignedSource),
        Err(VerificationError::AuthorityModeDowngrade)
    );
    assert_eq!(
        AuthorityMode::SignedSource.satisfies_required_mode(AuthorityMode::SignedSource),
        Ok(())
    );

    for label in ["", "unknown", "fixture_snapshot"] {
        assert_eq!(
            AuthorityMode::from_str(label),
            Err(VerificationError::UnsupportedAuthorityMode)
        );
    }
}

#[test]
fn light_client_and_recursive_policy_remain_reserved_fail_closed() {
    for reserved in [
        AuthorityMode::LightClientVerified,
        AuthorityMode::RecursiveProofCarryingState,
    ] {
        assert_eq!(
            reserved.satisfies_required_mode(reserved),
            Err(VerificationError::ReservedAuthorityMode),
            "reserved labels cannot satisfy policy until their real verifier issues land"
        );
    }
}

#[test]
fn delegated_under_node_topology_metadata_is_not_federation_checkpoint_evidence() {
    let observation = TopologyAuthorityObservation {
        node_status: Some("recognized_federated_node".to_string()),
        downstream_federation_id: Some("dregg-federation:downstream".to_string()),
        downstream_committee_label: Some("committee-looking-label".to_string()),
    };

    assert_eq!(
        observation.observed_authority_mode(),
        AuthorityMode::SoloVerifiedReceipt,
        "node/topology metadata is at most a solo receipt relationship, never checkpoint finality"
    );
    assert_eq!(
        observation
            .observed_authority_mode()
            .satisfies_required_mode(AuthorityMode::FederationCheckpoint),
        Err(VerificationError::AuthorityModeDowngrade)
    );

    let fields = observation.redacted_summary_fields().join("\n");
    assert!(fields.contains("topology_relationship:delegated_under_node"));
    assert!(fields.contains("node_status:recognized_federated_node"));
    assert!(fields.contains("downstream_federation_id_sha256:"));
    assert!(fields.contains("downstream_committee_label_sha256:"));
    assert!(!fields.contains("authority_mode:federation_checkpoint"));
    assert!(!fields.contains("finality_status:final"));
    assert!(!fields.contains("dregg-federation:downstream"));
    assert!(!fields.contains("committee-looking-label"));
}

#[test]
fn delegated_under_node_topology_can_only_satisfy_explicit_weaker_policy() {
    let observation = TopologyAuthorityObservation {
        node_status: Some("listed_node".to_string()),
        downstream_federation_id: Some("dregg-federation:downstream".to_string()),
        downstream_committee_label: None,
    };

    assert_eq!(
        observation
            .observed_authority_mode()
            .satisfies_required_mode(AuthorityMode::SoloVerifiedReceipt),
        Ok(()),
        "topology metadata requires an explicitly weaker solo receipt policy"
    );
    assert!(
        !observation
            .redacted_summary_fields()
            .join("\n")
            .contains("checkpoint"),
        "accepted topology summaries must not relabel listed-node metadata as checkpoint evidence"
    );
}
