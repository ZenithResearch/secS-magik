//! I08 proof-key registry and proof-tier metadata gate regression coverage.
//!
//! A registry match is metadata binding only. It is never evidence that a
//! light-client, recursive, ZK, STARK/SNARK, or other cryptographic verifier
//! executed.

use server::proof_keys::{
    ObservedProofMetadata, ProofGateReason, ProofKeyEntry, ProofKeyLifecycle, ProofKeyRegistry,
    ProofMetadataGate, RequiredProofTier,
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
