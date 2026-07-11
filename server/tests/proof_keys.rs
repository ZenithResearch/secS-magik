//! I08 proof-key registry and proof-tier metadata gate regression coverage.
//!
//! A registry match is metadata binding only. It is never evidence that a
//! light-client, recursive, ZK, STARK/SNARK, or other cryptographic verifier
//! executed.

use server::proof_keys::{
    ObservedProofMetadata, ProofGateReason, ProofKeyEntry, ProofKeyLifecycle, ProofKeyRegistry,
    ProofKeyRegistryError, ProofMetadataGate, RequiredProofTier,
};

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
