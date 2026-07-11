use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;

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
pub struct ProofMetadataRoutePolicy {
    pub required_tier: RequiredProofTier,
    pub require_active: bool,
}

#[derive(Debug, Deserialize)]
struct ProofMetadataRuntimeConfigFile {
    entries: Vec<ProofKeyEntry>,
    routes: Vec<ProofMetadataRouteConfig>,
}

#[derive(Debug, Deserialize)]
struct ProofMetadataRouteConfig {
    opcode: u8,
    required_tier: RequiredProofTier,
    require_active: bool,
}

#[derive(Debug, Clone)]
pub struct ProofMetadataRuntimeConfig {
    registry: ProofKeyRegistry,
    route_policies: HashMap<u8, ProofMetadataRoutePolicy>,
}

impl ProofMetadataRuntimeConfig {
    pub fn from_json_str(json: &str) -> Result<Self, ProofKeyRegistryError> {
        let file: ProofMetadataRuntimeConfigFile =
            serde_json::from_str(json).map_err(|_| ProofKeyRegistryError::InvalidJson)?;
        let registry = ProofKeyRegistry::from_entries(file.entries)?;
        let mut route_policies = HashMap::new();
        for route in file.routes {
            if route.required_tier != RequiredProofTier::MetadataBound {
                return Err(ProofKeyRegistryError::InvalidAllowedTier);
            }
            if route_policies
                .insert(
                    route.opcode,
                    ProofMetadataRoutePolicy {
                        required_tier: route.required_tier,
                        require_active: route.require_active,
                    },
                )
                .is_some()
            {
                return Err(ProofKeyRegistryError::DuplicateRegistryEntry);
            }
        }
        if route_policies.is_empty() {
            return Err(ProofKeyRegistryError::InvalidAllowedTier);
        }
        Ok(Self {
            registry,
            route_policies,
        })
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, ProofKeyRegistryError> {
        let bytes = std::fs::read(path).map_err(|_| ProofKeyRegistryError::InvalidJson)?;
        let json = std::str::from_utf8(&bytes).map_err(|_| ProofKeyRegistryError::InvalidJson)?;
        Self::from_json_str(json)
    }

    pub fn registry(&self) -> &ProofKeyRegistry {
        &self.registry
    }

    pub fn route_policies(&self) -> &HashMap<u8, ProofMetadataRoutePolicy> {
        &self.route_policies
    }

    pub fn into_parts(self) -> (ProofKeyRegistry, HashMap<u8, ProofMetadataRoutePolicy>) {
        (self.registry, self.route_policies)
    }
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

        let identity_keys: HashSet<_> = entries
            .iter()
            .map(|entry| (entry.vk_id.as_str(), entry.vk_version))
            .collect();
        for entry in &entries {
            if entry.supersedes.as_ref().is_some_and(|supersedes| {
                !identity_keys.contains(&(supersedes.vk_id.as_str(), supersedes.vk_version))
            }) {
                return Err(ProofKeyRegistryError::InvalidSupersession);
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
    ProofKeyDeprecated,
    ProofKeyRevoked,
    ProofKeyNotYetValid,
    ProofKeyExpired,
    ProofTierBelowPolicy,
    ProofVerifierNotExecuted,
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
            Self::ProofKeyDeprecated => "proof_key_deprecated",
            Self::ProofKeyRevoked => "proof_key_revoked",
            Self::ProofKeyNotYetValid => "proof_key_not_yet_valid",
            Self::ProofKeyExpired => "proof_key_expired",
            Self::ProofTierBelowPolicy => "proof_tier_below_policy",
            Self::ProofVerifierNotExecuted => "proof_verifier_not_executed",
        }
    }
}

pub struct ProofMetadataGate<'a> {
    registry: &'a ProofKeyRegistry,
    evaluated_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofMetadataBinding {
    pub proof_registry_checked: bool,
    pub proof_metadata_bound: bool,
    pub claim_label: String,
    pub vk_id: String,
    pub vk_version: u64,
    pub proof_system: String,
    pub circuit_id: String,
    pub circuit_version: u64,
    pub vk_fingerprint_sha256_prefix: String,
    pub public_input_schema_id: String,
    pub public_input_schema_hash_sha256_prefix: String,
}

impl ProofMetadataBinding {
    pub fn redaction_safe_summary_fields(&self) -> Vec<String> {
        vec![
            format!("proof_registry_checked:{}", self.proof_registry_checked),
            format!("proof_metadata_bound:{}", self.proof_metadata_bound),
            format!("proof_claim_label:{}", self.claim_label),
            format!("proof_vk_id:{}", self.vk_id),
            format!("proof_vk_version:{}", self.vk_version),
            format!("proof_system:{}", self.proof_system),
            format!("proof_circuit_id:{}", self.circuit_id),
            format!("proof_circuit_version:{}", self.circuit_version),
            format!(
                "proof_vk_fingerprint_sha256_prefix:{}",
                self.vk_fingerprint_sha256_prefix
            ),
            format!(
                "proof_public_input_schema_id:{}",
                self.public_input_schema_id
            ),
            format!(
                "proof_public_input_schema_hash_sha256_prefix:{}",
                self.public_input_schema_hash_sha256_prefix
            ),
        ]
    }
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
        observed: Option<&ObservedProofMetadata>,
        required_tier: RequiredProofTier,
        require_active: bool,
    ) -> Result<(), ProofGateReason> {
        self.evaluate_metadata(observed, required_tier, require_active)
            .map(|_| ())
    }

    pub fn evaluate_metadata(
        &self,
        observed: Option<&ObservedProofMetadata>,
        required_tier: RequiredProofTier,
        require_active: bool,
    ) -> Result<ProofMetadataBinding, ProofGateReason> {
        match required_tier {
            RequiredProofTier::LightClientVerified
            | RequiredProofTier::RecursiveProofCarryingState => {
                return Err(ProofGateReason::ProofVerifierNotExecuted);
            }
            RequiredProofTier::MetadataBound => {}
        }

        let observed = observed.ok_or(ProofGateReason::MissingProofKeyRegistryEntry)?;
        let entry = self.registry.match_observed(observed)?;
        match entry.lifecycle {
            ProofKeyLifecycle::Revoked => return Err(ProofGateReason::ProofKeyRevoked),
            ProofKeyLifecycle::Deprecated if require_active => {
                return Err(ProofGateReason::ProofKeyDeprecated);
            }
            ProofKeyLifecycle::Active | ProofKeyLifecycle::Deprecated => {}
        }
        if self.evaluated_at < entry.not_before {
            return Err(ProofGateReason::ProofKeyNotYetValid);
        }
        if entry
            .not_after
            .is_some_and(|not_after| self.evaluated_at >= not_after)
        {
            return Err(ProofGateReason::ProofKeyExpired);
        }
        if observed.observed_tier != RequiredProofTier::MetadataBound
            || !entry
                .allowed_tiers
                .contains(&RequiredProofTier::MetadataBound)
        {
            return Err(ProofGateReason::ProofTierBelowPolicy);
        }
        Ok(ProofMetadataBinding {
            proof_registry_checked: true,
            proof_metadata_bound: true,
            claim_label: entry.claim_label.clone(),
            vk_id: entry.vk_id.clone(),
            vk_version: entry.vk_version,
            proof_system: entry.proof_system.clone(),
            circuit_id: entry.circuit_id.clone(),
            circuit_version: entry.circuit_version,
            vk_fingerprint_sha256_prefix: entry.vk_fingerprint[..16].to_string(),
            public_input_schema_id: entry.public_input_schema_id.clone(),
            public_input_schema_hash_sha256_prefix: entry.public_input_schema_hash[..16]
                .to_string(),
        })
    }
}
