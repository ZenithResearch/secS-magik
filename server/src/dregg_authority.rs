use crate::verifier::VerificationError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DreggAuthorityStatus {
    Active,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreggAuthorityStatusPolicy {
    pub require_status: bool,
    pub max_status_age_seconds: u64,
    pub require_revocation_check: bool,
    pub require_finality: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DreggAuthorityEntry {
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub issuer_public_key_hex: String,
    pub federation_id: String,
    pub root_ref: String,
    pub root_fingerprint: String,
    pub epoch_id: String,
    pub epoch_not_before: u64,
    pub epoch_not_after: u64,
    pub accepted_audiences: Vec<String>,
    pub accepted_operations: Vec<String>,
    pub accepted_resources: Vec<String>,
    pub accepted_suites: Vec<String>,
    pub status_policy: DreggAuthorityStatusPolicy,
    pub root_status: DreggAuthorityStatus,
    pub issuer_status: DreggAuthorityStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggAuthorityLookup {
    pub issuer_id: String,
    pub issuer_key_id: String,
    pub root_ref: String,
    pub root_fingerprint: String,
    pub epoch_id: String,
    pub audience: String,
    pub operation: String,
    pub resource: String,
    pub suite: String,
    pub validation_time: u64,
    pub status_checked_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DreggAuthorityRegistryError {
    Empty,
    Malformed(String),
    InvalidEntry(String),
    DuplicateIssuer(String),
    DuplicateEpochRoot(String),
    Unreadable(String),
}

impl fmt::Display for DreggAuthorityRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(
                formatter,
                "production Dregg authority registry has no issuer/root entries"
            ),
            Self::Malformed(error) => {
                write!(formatter, "malformed Dregg authority registry: {error}")
            }
            Self::InvalidEntry(error) => {
                write!(formatter, "invalid Dregg authority registry entry: {error}")
            }
            Self::DuplicateIssuer(issuer) => {
                write!(formatter, "duplicate Dregg issuer id {issuer:?}")
            }
            Self::DuplicateEpochRoot(root) => {
                write!(formatter, "duplicate Dregg federation/root/epoch {root:?}")
            }
            Self::Unreadable(error) => {
                write!(formatter, "unreadable Dregg authority registry: {error}")
            }
        }
    }
}

impl std::error::Error for DreggAuthorityRegistryError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DreggAuthorityRegistry {
    entries: Vec<DreggAuthorityEntry>,
}

impl DreggAuthorityRegistry {
    pub fn from_json_str(json: &str) -> Result<Self, DreggAuthorityRegistryError> {
        if json.trim().is_empty() {
            return Err(DreggAuthorityRegistryError::Empty);
        }
        let entries: Vec<DreggAuthorityEntry> = serde_json::from_str(json)
            .map_err(|error| DreggAuthorityRegistryError::Malformed(error.to_string()))?;
        Self::new(entries)
    }

    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, DreggAuthorityRegistryError> {
        let json = std::fs::read_to_string(path)
            .map_err(|error| DreggAuthorityRegistryError::Unreadable(error.to_string()))?;
        Self::from_json_str(&json)
    }

    pub fn new(
        entries: impl IntoIterator<Item = DreggAuthorityEntry>,
    ) -> Result<Self, DreggAuthorityRegistryError> {
        let entries: Vec<_> = entries.into_iter().collect();
        if entries.is_empty() {
            return Err(DreggAuthorityRegistryError::Empty);
        }
        let mut issuer_ids = BTreeSet::new();
        let mut epoch_roots = BTreeSet::new();
        for entry in &entries {
            validate_entry(entry)?;
            if !issuer_ids.insert(entry.issuer_id.clone()) {
                return Err(DreggAuthorityRegistryError::DuplicateIssuer(
                    entry.issuer_id.clone(),
                ));
            }
            let epoch_root_key = format!(
                "{}|{}|{}",
                entry.federation_id, entry.root_ref, entry.epoch_id
            );
            if !epoch_roots.insert(epoch_root_key.clone()) {
                return Err(DreggAuthorityRegistryError::DuplicateEpochRoot(
                    epoch_root_key,
                ));
            }
        }
        Ok(Self { entries })
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lookup_active_policy(
        &self,
        lookup: &DreggAuthorityLookup,
    ) -> Result<&DreggAuthorityEntry, VerificationError> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.issuer_id == lookup.issuer_id)
            .ok_or(VerificationError::UnknownIssuer)?;
        if entry.issuer_key_id != lookup.issuer_key_id {
            return Err(VerificationError::WrongIssuerKey);
        }
        if entry.root_ref != lookup.root_ref || entry.root_fingerprint != lookup.root_fingerprint {
            return Err(VerificationError::WrongRoot);
        }
        if entry.epoch_id != lookup.epoch_id
            || lookup.validation_time < entry.epoch_not_before
            || lookup.validation_time > entry.epoch_not_after
        {
            return Err(VerificationError::WrongEpoch);
        }
        if entry.root_status != DreggAuthorityStatus::Active
            || entry.issuer_status != DreggAuthorityStatus::Active
        {
            return Err(VerificationError::Revoked);
        }
        if entry.status_policy.require_status {
            let checked_at = lookup
                .status_checked_at
                .ok_or(VerificationError::MissingStatus)?;
            if lookup.validation_time.saturating_sub(checked_at)
                > entry.status_policy.max_status_age_seconds
            {
                return Err(VerificationError::Stale);
            }
        }
        if !entry
            .accepted_audiences
            .iter()
            .any(|accepted| accepted == &lookup.audience)
        {
            return Err(VerificationError::WrongAudience);
        }
        if !entry
            .accepted_operations
            .iter()
            .any(|accepted| accepted == &lookup.operation)
        {
            return Err(VerificationError::WrongOperation);
        }
        if !entry
            .accepted_resources
            .iter()
            .any(|accepted| accepted == &lookup.resource)
        {
            return Err(VerificationError::WrongResource);
        }
        if !entry
            .accepted_suites
            .iter()
            .any(|accepted| accepted == &lookup.suite)
        {
            return Err(VerificationError::UnsupportedSuite);
        }
        Ok(entry)
    }
}

fn validate_entry(entry: &DreggAuthorityEntry) -> Result<(), DreggAuthorityRegistryError> {
    if entry.issuer_id.trim().is_empty() {
        return Err(DreggAuthorityRegistryError::InvalidEntry(
            "issuer_id is required".to_string(),
        ));
    }
    if entry.issuer_key_id.trim().is_empty() {
        return Err(DreggAuthorityRegistryError::InvalidEntry(
            "issuer_key_id is required".to_string(),
        ));
    }
    if entry.issuer_public_key_hex.len() != 64
        || !entry
            .issuer_public_key_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(DreggAuthorityRegistryError::InvalidEntry(
            "issuer_public_key_hex must be 32-byte lowercase hex".to_string(),
        ));
    }
    for (field, value) in [
        ("federation_id", &entry.federation_id),
        ("root_ref", &entry.root_ref),
        ("root_fingerprint", &entry.root_fingerprint),
        ("epoch_id", &entry.epoch_id),
    ] {
        if value.trim().is_empty() {
            return Err(DreggAuthorityRegistryError::InvalidEntry(format!(
                "{field} is required"
            )));
        }
    }
    if entry.epoch_not_before >= entry.epoch_not_after {
        return Err(DreggAuthorityRegistryError::InvalidEntry(
            "epoch_not_before must be less than epoch_not_after".to_string(),
        ));
    }
    if entry.status_policy.require_status && entry.status_policy.max_status_age_seconds == 0 {
        return Err(DreggAuthorityRegistryError::InvalidEntry(
            "max_status_age_seconds is required when status is required".to_string(),
        ));
    }
    for (field, values) in [
        ("accepted_audiences", &entry.accepted_audiences),
        ("accepted_operations", &entry.accepted_operations),
        ("accepted_resources", &entry.accepted_resources),
        ("accepted_suites", &entry.accepted_suites),
    ] {
        if values.is_empty() || values.iter().any(|value| value.trim().is_empty()) {
            return Err(DreggAuthorityRegistryError::InvalidEntry(format!(
                "{field} must contain at least one non-empty value"
            )));
        }
    }
    Ok(())
}
