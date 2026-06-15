//! Operator CLI logic for authoring and inspecting receiver-local permission
//! policies (M13.4a). The `secs-permctl` binary is a thin clap wrapper over
//! these pure functions, so the authoring/evaluation logic stays unit-testable
//! without spawning a process. The eventual WASM control panel (M13.4b) wraps
//! the same model.
//!
//! Receiver-local policy only: records are authored with
//! `authority_source = receiver_local`. This tool makes no Dregg authority,
//! deployment-proof, or public-auditability claims.

use crate::permissions::{
    AuthoritySource, DenyReason, PermissionEffect, PermissionPolicy, PermissionRecord,
    PermissionStatus, ResourceScope,
};
use std::path::Path;

/// Policy file I/O / parse errors, surfaced to the CLI as messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermctlError {
    Unreadable,
    Malformed,
    Unwritable,
}

impl PermctlError {
    pub fn message(&self) -> &'static str {
        match self {
            PermctlError::Unreadable => "policy file could not be read",
            PermctlError::Malformed => {
                "policy file is not a valid JSON array of permission records"
            }
            PermctlError::Unwritable => "policy file could not be written",
        }
    }
}

/// Load the raw record list from a policy file. A missing file is an empty
/// policy (so `grant` can create the first record); a present-but-malformed
/// file is an error (fail-closed: never silently treat it as empty).
pub fn load_records(path: impl AsRef<Path>) -> Result<Vec<PermissionRecord>, PermctlError> {
    match std::fs::read_to_string(&path) {
        Ok(json) if json.trim().is_empty() => Ok(Vec::new()),
        Ok(json) => serde_json::from_str(&json).map_err(|_| PermctlError::Malformed),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(PermctlError::Unreadable),
    }
}

/// Write the record list back as pretty JSON.
pub fn save_records(
    path: impl AsRef<Path>,
    records: &[PermissionRecord],
) -> Result<(), PermctlError> {
    let json = serde_json::to_string_pretty(records).map_err(|_| PermctlError::Unwritable)?;
    std::fs::write(&path, json).map_err(|_| PermctlError::Unwritable)
}

/// Build a permission record from CLI inputs. `prefix` selects a prefix scope;
/// otherwise the resource is an exact match.
#[allow(clippy::too_many_arguments)]
pub fn build_record(
    caller_id: String,
    opcode: u8,
    operation: String,
    resource: String,
    prefix: bool,
    deny: bool,
    not_before: u64,
    not_after: u64,
) -> PermissionRecord {
    PermissionRecord {
        caller_id,
        opcode,
        operation,
        resource: if prefix {
            ResourceScope::Prefix { prefix: resource }
        } else {
            ResourceScope::Exact { value: resource }
        },
        effect: if deny {
            PermissionEffect::Deny
        } else {
            PermissionEffect::Allow
        },
        not_before,
        not_after,
        status: PermissionStatus::Active,
        authority_source: AuthoritySource::ReceiverLocal,
    }
}

/// Append a record, returning the new list.
pub fn grant(
    mut records: Vec<PermissionRecord>,
    record: PermissionRecord,
) -> Vec<PermissionRecord> {
    records.push(record);
    records
}

/// Set every record matching `caller × opcode × operation × resource-value` to
/// revoked. Returns the updated list and how many records were revoked.
pub fn revoke(
    mut records: Vec<PermissionRecord>,
    caller_id: &str,
    opcode: u8,
    operation: &str,
    resource_value: &str,
) -> (Vec<PermissionRecord>, usize) {
    let mut revoked = 0;
    for record in &mut records {
        let value = match &record.resource {
            ResourceScope::Exact { value } => value.as_str(),
            ResourceScope::Prefix { prefix } => prefix.as_str(),
        };
        if record.caller_id == caller_id
            && record.opcode == opcode
            && record.operation == operation
            && value == resource_value
            && record.status != PermissionStatus::Revoked
        {
            record.status = PermissionStatus::Revoked;
            revoked += 1;
        }
    }
    (records, revoked)
}

/// Evaluate a request against the records. Returns `Ok(())` for allow, or the
/// typed [`DenyReason`] for deny. An invalid record set is treated as a
/// fail-closed deny.
pub fn evaluate(
    records: Vec<PermissionRecord>,
    caller_id: &str,
    opcode: u8,
    operation: &str,
    resource: &str,
    now: u64,
) -> Result<(), DenyReason> {
    let policy = PermissionPolicy::new(records).map_err(|_| DenyReason::NoMatchingGrant)?;
    policy
        .evaluate(caller_id, opcode, operation, resource, now)
        .map(|_| ())
}

/// Human-readable one-line summaries of each record, for `list`.
pub fn list_lines(records: &[PermissionRecord]) -> Vec<String> {
    records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let (scope_kind, scope_value) = match &record.resource {
                ResourceScope::Exact { value } => ("exact", value.as_str()),
                ResourceScope::Prefix { prefix } => ("prefix", prefix.as_str()),
            };
            let effect = match record.effect {
                PermissionEffect::Allow => "allow",
                PermissionEffect::Deny => "deny",
            };
            let status = match record.status {
                PermissionStatus::Active => "active",
                PermissionStatus::Revoked => "revoked",
            };
            format!(
                "{index}: {effect} {status} caller={} opcode={:#04x} op={} {scope_kind}={scope_value} valid=[{}..{}) source=receiver_local",
                record.caller_id, record.opcode, record.operation, record.not_before, record.not_after
            )
        })
        .collect()
}
