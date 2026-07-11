//! I08 proof-key registry and proof-tier metadata gate regression coverage.
//!
//! A registry match is metadata binding only. It is never evidence that a
//! light-client, recursive, ZK, STARK/SNARK, or other cryptographic verifier
//! executed.

use server::proof_keys::{
    ObservedProofMetadata, ProofGateReason, ProofKeyEntry, ProofKeyLifecycle, ProofKeyRegistry,
    ProofKeyRegistryError, ProofMetadataGate, RequiredProofTier,
};

use std::collections::HashMap;

fn active_entry() -> ProofKeyEntry {
    ProofKeyEntry {
        vk_id: "castalia-membership-vk".into(),
        vk_version: 1,
        proof_system: "fixture-proof-system".into(),
        circuit_id: "membership-transition".into(),
        circuit_version: 1,
        vk_fingerprint_algorithm: "sha256".into(),
        vk_fingerprint: "11".repeat(32),
        public_input_schema_id: "secs-unified-verification-context-v1".into(),
        public_input_schema_hash_algorithm: "sha256".into(),
        public_input_schema_hash: "22".repeat(32),
        lifecycle: ProofKeyLifecycle::Active,
        not_before: 1_700_000_000,
        not_after: Some(1_900_000_000),
        allowed_tiers: vec![RequiredProofTier::MetadataBound],
        supersedes: None,
        deprecated_historical_only: false,
        claim_label: "proof_metadata_bound".into(),
    }
}

fn matching_observation() -> ObservedProofMetadata {
    ObservedProofMetadata {
        vk_id: "castalia-membership-vk".into(),
        vk_version: 1,
        proof_system: "fixture-proof-system".into(),
        circuit_id: "membership-transition".into(),
        circuit_version: 1,
        vk_fingerprint_algorithm: "sha256".into(),
        vk_fingerprint: "11".repeat(32),
        public_input_schema_id: "secs-unified-verification-context-v1".into(),
        public_input_schema_hash_algorithm: "sha256".into(),
        public_input_schema_hash: "22".repeat(32),
        observed_tier: RequiredProofTier::MetadataBound,
        adapter_claim_label: Some("light_client_verified".into()),
    }
}

fn registry() -> ProofKeyRegistry {
    ProofKeyRegistry::from_entries(vec![active_entry()]).expect("valid registry fixture")
}

#[test]
fn registry_match_is_metadata_bound_not_light_client_verified() {
    let result = ProofMetadataGate::new(&registry(), 1_800_000_000)
        .evaluate(
            Some(&matching_observation()),
            RequiredProofTier::LightClientVerified,
            true,
        )
        .expect_err("metadata matching cannot prove a light-client verifier ran");

    assert_eq!(result, ProofGateReason::ProofVerifierNotExecuted);
}

#[test]
fn registry_match_cannot_satisfy_recursive_proof_carrying_state() {
    let result = ProofMetadataGate::new(&registry(), 1_800_000_000)
        .evaluate(
            Some(&matching_observation()),
            RequiredProofTier::RecursiveProofCarryingState,
            true,
        )
        .expect_err("metadata matching cannot prove recursive verification ran");

    assert_eq!(result, ProofGateReason::ProofVerifierNotExecuted);
}

#[test]
fn registry_loads_active_deprecated_revoked_entries() {
    let mut deprecated = active_entry();
    deprecated.vk_id = "deprecated-vk".into();
    deprecated.lifecycle = ProofKeyLifecycle::Deprecated;
    deprecated.deprecated_historical_only = true;

    let mut revoked = active_entry();
    revoked.vk_id = "revoked-vk".into();
    revoked.lifecycle = ProofKeyLifecycle::Revoked;

    let json = serde_json::to_string(&vec![active_entry(), deprecated, revoked])
        .expect("serialize registry fixture");
    let registry = ProofKeyRegistry::from_json_str(&json).expect("load registry fixture");

    assert_eq!(registry.entries().len(), 3);
    assert_eq!(
        registry
            .lookup(
                "fixture-proof-system",
                "membership-transition",
                "deprecated-vk",
                1
            )
            .expect("deprecated entry remains inspectable")
            .lifecycle,
        ProofKeyLifecycle::Deprecated
    );
    assert_eq!(
        registry
            .lookup(
                "fixture-proof-system",
                "membership-transition",
                "revoked-vk",
                1
            )
            .expect("revoked entry remains inspectable")
            .lifecycle,
        ProofKeyLifecycle::Revoked
    );
}

#[test]
fn registry_rejects_malformed_or_overclaiming_entries() {
    let mut malformed_hash = active_entry();
    malformed_hash.vk_fingerprint = "raw-vk-material".into();
    assert_eq!(
        ProofKeyRegistry::from_entries(vec![malformed_hash]).unwrap_err(),
        ProofKeyRegistryError::InvalidVkFingerprint
    );

    let mut invalid_window = active_entry();
    invalid_window.not_after = Some(invalid_window.not_before);
    assert_eq!(
        ProofKeyRegistry::from_entries(vec![invalid_window]).unwrap_err(),
        ProofKeyRegistryError::InvalidValidityWindow
    );

    let mut overclaim = active_entry();
    overclaim.claim_label = "cryptographic_proof_verified".into();
    assert_eq!(
        ProofKeyRegistry::from_entries(vec![overclaim]).unwrap_err(),
        ProofKeyRegistryError::OverclaimingClaimLabel
    );

    assert_eq!(
        ProofKeyRegistry::from_entries(vec![active_entry(), active_entry()]).unwrap_err(),
        ProofKeyRegistryError::DuplicateRegistryEntry
    );
}

#[test]
fn proof_metadata_lookup_matches_registry_entry() {
    let registry = registry();
    let matched = registry
        .match_observed(&matching_observation())
        .expect("matching metadata should resolve to the pinned entry");

    assert_eq!(matched.vk_id, "castalia-membership-vk");
    assert_eq!(matched.claim_label, "proof_metadata_bound");
}

#[test]
fn adapter_labels_do_not_upgrade_observed_proof_tier() {
    let registry = registry();
    let observed = matching_observation();
    assert_eq!(
        observed.adapter_claim_label.as_deref(),
        Some("light_client_verified")
    );

    let matched = registry
        .match_observed(&observed)
        .expect("untrusted adapter wording does not alter metadata comparison");

    assert_eq!(
        matched.allowed_tiers,
        vec![RequiredProofTier::MetadataBound]
    );
    assert!(!matched
        .allowed_tiers
        .contains(&RequiredProofTier::LightClientVerified));
}

#[test]
fn proof_required_rejects_untrusted_or_mismatched_registry_metadata() {
    let cases = vec![
        (
            "missing",
            None,
            ProofGateReason::MissingProofKeyRegistryEntry,
        ),
        (
            "unknown",
            Some({
                let mut value = matching_observation();
                value.vk_id = "unknown".into();
                value
            }),
            ProofGateReason::UnknownVerificationKey,
        ),
        (
            "system",
            Some({
                let mut value = matching_observation();
                value.proof_system = "other".into();
                value
            }),
            ProofGateReason::ProofSystemMismatch,
        ),
        (
            "circuit",
            Some({
                let mut value = matching_observation();
                value.circuit_id = "other".into();
                value
            }),
            ProofGateReason::ProofCircuitMismatch,
        ),
        (
            "fingerprint",
            Some({
                let mut value = matching_observation();
                value.vk_fingerprint = "33".repeat(32);
                value
            }),
            ProofGateReason::ProofVkFingerprintMismatch,
        ),
        (
            "schema",
            Some({
                let mut value = matching_observation();
                value.public_input_schema_id = "other".into();
                value
            }),
            ProofGateReason::ProofPublicInputSchemaMismatch,
        ),
    ];

    for (name, observed, expected) in cases {
        let mut handler_calls = 0;
        let decision = ProofMetadataGate::new(&registry(), 1_800_000_000).evaluate(
            observed.as_ref(),
            RequiredProofTier::MetadataBound,
            true,
        );
        if decision.is_ok() {
            handler_calls += 1;
        }
        assert_eq!(decision, Err(expected), "case {name}");
        assert_eq!(handler_calls, 0, "case {name} reached the handler");
    }
}

#[test]
fn proof_gate_rejects_lifecycle_and_validity_before_handler_execution() {
    let cases = vec![
        (
            ProofKeyLifecycle::Deprecated,
            1_800_000_000,
            ProofGateReason::ProofKeyDeprecated,
        ),
        (
            ProofKeyLifecycle::Revoked,
            1_800_000_000,
            ProofGateReason::ProofKeyRevoked,
        ),
        (
            ProofKeyLifecycle::Active,
            1_600_000_000,
            ProofGateReason::ProofKeyNotYetValid,
        ),
        (
            ProofKeyLifecycle::Active,
            2_000_000_000,
            ProofGateReason::ProofKeyExpired,
        ),
    ];

    for (lifecycle, evaluated_at, expected) in cases {
        let mut entry = active_entry();
        entry.lifecycle = lifecycle;
        let registry = ProofKeyRegistry::from_entries(vec![entry]).expect("valid fixture");
        let decision = ProofMetadataGate::new(&registry, evaluated_at).evaluate(
            Some(&matching_observation()),
            RequiredProofTier::MetadataBound,
            true,
        );
        assert_eq!(decision, Err(expected));
    }
}

#[test]
fn metadata_bound_positive_path_uses_claim_safe_receipt_summary() {
    let registry = registry();
    let binding = ProofMetadataGate::new(&registry, 1_800_000_000)
        .evaluate_metadata(
            Some(&matching_observation()),
            RequiredProofTier::MetadataBound,
            true,
        )
        .expect("active matching metadata should pass the metadata-only gate");

    assert!(binding.proof_registry_checked);
    assert!(binding.proof_metadata_bound);
    assert_eq!(binding.claim_label, "proof_metadata_bound");
    assert_eq!(binding.vk_fingerprint_sha256_prefix, "1111111111111111");
    assert_eq!(
        binding.public_input_schema_hash_sha256_prefix,
        "2222222222222222"
    );

    let outward = serde_json::to_string(&binding).expect("serialize safe receipt summary");
    for forbidden in [
        "light_client_verified",
        "recursive_proof_carrying_state",
        "cryptographic_proof_verified",
        "raw_proof",
        "raw_vk",
        "witness",
        "private_input",
        "source_auth_token",
    ] {
        assert!(
            !outward.contains(forbidden),
            "leaked/overclaimed {forbidden}"
        );
    }
}

#[test]
fn registry_rotation_and_revocation_rules_are_fail_closed() {
    let mut old = active_entry();
    old.lifecycle = ProofKeyLifecycle::Deprecated;
    old.deprecated_historical_only = true;

    let mut current = active_entry();
    current.vk_version = 2;
    current.supersedes = Some(server::proof_keys::ProofKeyRef {
        vk_id: old.vk_id.clone(),
        vk_version: old.vk_version,
    });

    let registry = ProofKeyRegistry::from_entries(vec![current.clone(), old])
        .expect("explicit rotation chain should load");
    let mut current_observation = matching_observation();
    current_observation.vk_version = 2;
    assert!(ProofMetadataGate::new(&registry, 1_800_000_000)
        .evaluate(
            Some(&current_observation),
            RequiredProofTier::MetadataBound,
            true,
        )
        .is_ok());
    assert_eq!(
        ProofMetadataGate::new(&registry, 1_800_000_000).evaluate(
            Some(&matching_observation()),
            RequiredProofTier::MetadataBound,
            true,
        ),
        Err(ProofGateReason::ProofKeyDeprecated)
    );

    let mut dangling = current;
    dangling.supersedes = Some(server::proof_keys::ProofKeyRef {
        vk_id: "missing-vk".into(),
        vk_version: 9,
    });
    assert_eq!(
        ProofKeyRegistry::from_entries(vec![dangling]).unwrap_err(),
        ProofKeyRegistryError::InvalidSupersession
    );
}

#[test]
fn weaker_evidence_cannot_be_relabelled_as_proof_verified() {
    for label in [
        "signed_source",
        "local_fixture",
        "proof_shaped",
        "light_client_verified",
        "recursive_proof_carrying_state",
    ] {
        let mut observed = matching_observation();
        observed.adapter_claim_label = Some(label.into());
        observed.observed_tier = RequiredProofTier::LightClientVerified;
        assert_eq!(
            ProofMetadataGate::new(&registry(), 1_800_000_000).evaluate(
                Some(&observed),
                RequiredProofTier::MetadataBound,
                true,
            ),
            Err(ProofGateReason::ProofTierBelowPolicy),
            "untrusted label {label} upgraded evidence"
        );
    }
}

#[test]
fn i08_current_docs_pin_metadata_only_claim_and_future_gates() {
    let readme = include_str!("../../README.md");
    let status = include_str!("../../docs/implementation-status.md");
    for text in [readme, status] {
        assert!(text.contains("trusted verification-key/circuit/public-input-schema registry"));
        assert!(text.contains("proof_metadata_bound"));
        assert!(text.contains("I18"));
        assert!(text.contains("I19"));
        assert!(text.contains("not light-client or recursive proof verification"));
    }
}

#[test]
fn receiver_held_runtime_config_loads_registry_and_route_policy() {
    let json = serde_json::json!({
        "entries": [active_entry()],
        "routes": [{"opcode": 64, "required_tier": "metadata_bound", "require_active": true}]
    });
    let config = server::proof_keys::ProofMetadataRuntimeConfig::from_json_str(&json.to_string())
        .expect("receiver-held proof metadata config should load");
    assert_eq!(config.registry().entries().len(), 1);
    assert_eq!(
        config.route_policies(),
        &HashMap::from([(
            64,
            server::proof_keys::ProofMetadataRoutePolicy {
                required_tier: RequiredProofTier::MetadataBound,
                require_active: true,
            },
        )])
    );
}
