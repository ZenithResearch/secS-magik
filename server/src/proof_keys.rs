use serde::{Deserialize, Serialize};
use std::collections::HashSet;

const SHA256_HEX_LENGTH: usize = 64;
const METADATA_CLAIM_LABELS: [&str; 2] = ["proof_metadata_bound", "proof_registry_checked"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredProofTier {
    MetadataBound,
    LightClientVerified,
    RecursiveProofCarryingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKeyLifecycle {
    Active,
    Deprecated,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofKeyRef {
    pub vk_id: String,
    pub vk_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofKeyEntry {
    pub vk_id: String,
    pub vk_version: u64,
    pub proof_system: String,
    pub circuit_id: String,
    pub circuit_version: u64,
    pub vk_fingerprint_algorithm: String,
    pub vk_fingerprint: String,
    pub public_input_schema_id: String,
    pub public_input_schema_hash_algorithm: String,
    pub public_input_schema_hash: String,
    pub lifecycle: ProofKeyLifecycle,
    pub not_before: u64,
    pub not_after: Option<u64>,
    pub allowed_tiers: Vec<RequiredProofTier>,
    pub supersedes: Option<ProofKeyRef>,
    pub deprecated_historical_only: bool,
    pub claim_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedProofMetadata {
    pub vk_id: String,
    pub vk_version: u64,
    pub proof_system: String,
    pub circuit_id: String,
    pub circuit_version: u64,
    pub vk_fingerprint_algorithm: String,
    pub vk_fingerprint: String,
    pub public_input_schema_id: String,
    pub public_input_schema_hash_algorithm: String,
    pub public_input_schema_hash: String,
    pub observed_tier: RequiredProofTier,
    /// Untrusted adapter wording retained only so normalization can prove it
    /// cannot upgrade the observed metadata tier.
    pub adapter_claim_label: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofKeyRegistryError {
    EmptyRegistry,
    MissingRequiredField,
    InvalidHashAlgorithm,
    InvalidVkFingerprint,
    InvalidPublicInputSchemaHash,
    InvalidValidityWindow,
    InvalidAllowedTier,
    InvalidSupersession,
    OverclaimingClaimLabel,
    DuplicateRegistryEntry,
    InvalidJson,
}

impl ProofKeyRegistryError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::EmptyRegistry => "empty_proof_key_registry",
            Self::MissingRequiredField => "missing_proof_key_registry_field",
            Self::InvalidHashAlgorithm => "invalid_proof_key_hash_algorithm",
            Self::InvalidVkFingerprint => "invalid_proof_vk_fingerprint",
            Self::InvalidPublicInputSchemaHash => "invalid_proof_public_input_schema_hash",
            Self::InvalidValidityWindow => "invalid_proof_key_validity_window",
            Self::InvalidAllowedTier => "invalid_proof_key_allowed_tier",
            Self::InvalidSupersession => "invalid_proof_key_supersession",
            Self::OverclaimingClaimLabel => "overclaiming_proof_key_claim_label",
            Self::DuplicateRegistryEntry => "duplicate_proof_key_registry_entry",
            Self::InvalidJson => "invalid_proof_key_registry_json",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProofKeyRegistry {
    entries: Vec<ProofKeyEntry>,
}

impl ProofKeyRegistry {
    pub fn from_json_str(json: &str) -> Result<Self, ProofKeyRegistryError> {
        let entries: Vec<ProofKeyEntry> =
            serde_json::from_str(json).map_err(|_| ProofKeyRegistryError::InvalidJson)?;
        Self::from_entries(entries)
    }

    pub fn from_entries(mut entries: Vec<ProofKeyEntry>) -> Result<Self, ProofKeyRegistryError> {
        if entries.is_empty() {
            return Err(ProofKeyRegistryError::EmptyRegistry);
        }

        let mut lookup_keys = HashSet::new();
        for entry in &entries {
            validate_entry(entry)?;
            let key = (
                entry.proof_system.as_str(),
                entry.circuit_id.as_str(),
                entry.vk_id.as_str(),
                entry.vk_version,
            );
            if !lookup_keys.insert(key) {
                return Err(ProofKeyRegistryError::DuplicateRegistryEntry);
            }
        }

        entries.sort_by(|left, right| {
            (
                left.proof_system.as_str(),
                left.circuit_id.as_str(),
                left.vk_id.as_str(),
                left.vk_version,
            )
                .cmp(&(
                    right.proof_system.as_str(),
                    right.circuit_id.as_str(),
                    right.vk_id.as_str(),
                    right.vk_version,
                ))
        });
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[ProofKeyEntry] {
        &self.entries
    }

    pub fn lookup(
        &self,
        proof_system: &str,
        circuit_id: &str,
        vk_id: &str,
        vk_version: u64,
    ) -> Option<&ProofKeyEntry> {
        self.entries.iter().find(|entry| {
            entry.proof_system == proof_system
                && entry.circuit_id == circuit_id
                && entry.vk_id == vk_id
                && entry.vk_version == vk_version
        })
    }

    pub fn match_observed(
        &self,
        observed: &ObservedProofMetadata,
    ) -> Result<&ProofKeyEntry, ProofGateReason> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.vk_id == observed.vk_id && entry.vk_version == observed.vk_version)
            .ok_or(ProofGateReason::UnknownVerificationKey)?;

        if entry.proof_system != observed.proof_system {
            return Err(ProofGateReason::ProofSystemMismatch);
        }
        if entry.circuit_id != observed.circuit_id
            || entry.circuit_version != observed.circuit_version
        {
            return Err(ProofGateReason::ProofCircuitMismatch);
        }
        if entry.vk_fingerprint_algorithm != observed.vk_fingerprint_algorithm
            || entry.vk_fingerprint != observed.vk_fingerprint
        {
            return Err(ProofGateReason::ProofVkFingerprintMismatch);
        }
        if entry.public_input_schema_id != observed.public_input_schema_id
            || entry.public_input_schema_hash_algorithm
                != observed.public_input_schema_hash_algorithm
            || entry.public_input_schema_hash != observed.public_input_schema_hash
        {
            return Err(ProofGateReason::ProofPublicInputSchemaMismatch);
        }
        Ok(entry)
    }
}

fn validate_entry(entry: &ProofKeyEntry) -> Result<(), ProofKeyRegistryError> {
    if [
        entry.vk_id.as_str(),
        entry.proof_system.as_str(),
        entry.circuit_id.as_str(),
        entry.public_input_schema_id.as_str(),
        entry.claim_label.as_str(),
    ]
    .iter()
    .any(|value| value.trim().is_empty())
        || entry.vk_version == 0
        || entry.circuit_version == 0
    {
        return Err(ProofKeyRegistryError::MissingRequiredField);
    }
    if entry.vk_fingerprint_algorithm != "sha256"
        || entry.public_input_schema_hash_algorithm != "sha256"
    {
        return Err(ProofKeyRegistryError::InvalidHashAlgorithm);
    }
    if !is_lower_hex_sha256(&entry.vk_fingerprint) {
        return Err(ProofKeyRegistryError::InvalidVkFingerprint);
    }
    if !is_lower_hex_sha256(&entry.public_input_schema_hash) {
        return Err(ProofKeyRegistryError::InvalidPublicInputSchemaHash);
    }
    if entry
        .not_after
        .is_some_and(|not_after| not_after <= entry.not_before)
    {
        return Err(ProofKeyRegistryError::InvalidValidityWindow);
    }
    if entry.allowed_tiers.is_empty()
        || entry
            .allowed_tiers
            .iter()
            .any(|tier| *tier != RequiredProofTier::MetadataBound)
    {
        return Err(ProofKeyRegistryError::InvalidAllowedTier);
    }
    if entry.supersedes.as_ref().is_some_and(|supersedes| {
        supersedes.vk_id.trim().is_empty()
            || supersedes.vk_version == 0
            || (supersedes.vk_id == entry.vk_id && supersedes.vk_version >= entry.vk_version)
    }) {
        return Err(ProofKeyRegistryError::InvalidSupersession);
    }
    if !METADATA_CLAIM_LABELS.contains(&entry.claim_label.as_str()) {
        return Err(ProofKeyRegistryError::OverclaimingClaimLabel);
    }
    Ok(())
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofGateReason {
    MissingProofKeyRegistryEntry,
    UnknownVerificationKey,
    ProofSystemMismatch,
    ProofCircuitMismatch,
    ProofVkFingerprintMismatch,
    ProofPublicInputSchemaMismatch,
    ProofVerifierNotExecuted,
    RegistryMetadataGateNotImplemented,
}

impl ProofGateReason {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::MissingProofKeyRegistryEntry => "missing_proof_key_registry_entry",
            Self::UnknownVerificationKey => "unknown_verification_key",
            Self::ProofSystemMismatch => "proof_system_mismatch",
            Self::ProofCircuitMismatch => "proof_circuit_mismatch",
            Self::ProofVkFingerprintMismatch => "proof_vk_fingerprint_mismatch",
            Self::ProofPublicInputSchemaMismatch => "proof_public_input_schema_mismatch",
            Self::ProofVerifierNotExecuted => "proof_verifier_not_executed",
            Self::RegistryMetadataGateNotImplemented => "proof_metadata_gate_not_implemented",
        }
    }
}

pub struct ProofMetadataGate<'a> {
    #[allow(dead_code)]
    registry: &'a ProofKeyRegistry,
    #[allow(dead_code)]
    evaluated_at: u64,
}

impl<'a> ProofMetadataGate<'a> {
    pub fn new(registry: &'a ProofKeyRegistry, evaluated_at: u64) -> Self {
        Self {
            registry,
            evaluated_at,
        }
    }

    pub fn evaluate(
        &self,
        _observed: Option<&ObservedProofMetadata>,
        required_tier: RequiredProofTier,
        _require_active: bool,
    ) -> Result<(), ProofGateReason> {
        match required_tier {
            RequiredProofTier::LightClientVerified
            | RequiredProofTier::RecursiveProofCarryingState => {
                Err(ProofGateReason::ProofVerifierNotExecuted)
            }
            RequiredProofTier::MetadataBound => {
                Err(ProofGateReason::RegistryMetadataGateNotImplemented)
            }
        }
    }
}
