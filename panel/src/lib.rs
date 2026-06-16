//! Vanilla WASM browser control panel for receiver-local secS permissions
//! (M13.4b). A `wasm-bindgen` wrapper over the shared [`secs_permissions`]
//! model — the same model the gateway enforces and `secs-permctl` authors.
//!
//! The browser holds the policy as a JSON string; every function takes that
//! string and returns either an updated policy JSON string or a decision. There
//! is no server and no network: this is local receiver-local policy authoring
//! and evaluation only, with no Dregg authority, deployment-proof, or
//! public-auditability claims.

use secs_permissions::{
    AuthoritySource, PermissionEffect, PermissionPolicy, PermissionRecord, PermissionStatus,
    ResourceScope,
};
use wasm_bindgen::prelude::*;

fn parse(policy_json: &str) -> Result<Vec<PermissionRecord>, JsValue> {
    if policy_json.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(policy_json)
        .map_err(|_| JsValue::from_str("policy is not a valid JSON array of permission records"))
}

fn dump(records: &[PermissionRecord]) -> Result<String, JsValue> {
    serde_json::to_string_pretty(records)
        .map_err(|_| JsValue::from_str("failed to serialize policy"))
}

/// Append a permission record to the policy and return the updated policy JSON.
#[allow(clippy::too_many_arguments)]
#[wasm_bindgen]
pub fn grant(
    policy_json: &str,
    caller: &str,
    opcode: u8,
    operation: &str,
    resource: &str,
    prefix: bool,
    deny: bool,
    not_before: u64,
    not_after: u64,
) -> Result<String, JsValue> {
    let mut records = parse(policy_json)?;
    records.push(PermissionRecord {
        caller_id: caller.to_string(),
        opcode,
        operation: operation.to_string(),
        resource: if prefix {
            ResourceScope::Prefix {
                prefix: resource.to_string(),
            }
        } else {
            ResourceScope::Exact {
                value: resource.to_string(),
            }
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
    });
    dump(&records)
}

/// Revoke every record matching caller/opcode/operation/resource-value and
/// return the updated policy JSON.
#[wasm_bindgen]
pub fn revoke(
    policy_json: &str,
    caller: &str,
    opcode: u8,
    operation: &str,
    resource: &str,
) -> Result<String, JsValue> {
    let mut records = parse(policy_json)?;
    for record in &mut records {
        let value = match &record.resource {
            ResourceScope::Exact { value } => value.as_str(),
            ResourceScope::Prefix { prefix } => prefix.as_str(),
        };
        if record.caller_id == caller
            && record.opcode == opcode
            && record.operation == operation
            && value == resource
        {
            record.status = PermissionStatus::Revoked;
        }
    }
    dump(&records)
}

/// Evaluate a request against the policy. Returns `ALLOW` or `DENY:<reason>`.
#[wasm_bindgen]
pub fn evaluate(
    policy_json: &str,
    caller: &str,
    opcode: u8,
    operation: &str,
    resource: &str,
    now: u64,
) -> Result<String, JsValue> {
    let records = parse(policy_json)?;
    let policy = PermissionPolicy::new(records)
        .map_err(|_| JsValue::from_str("policy contains an invalid record"))?;
    Ok(
        match policy.evaluate(caller, opcode, operation, resource, now) {
            Ok(_) => "ALLOW".to_string(),
            Err(reason) => format!("DENY:{}", reason.code()),
        },
    )
}

/// One-line human-readable summaries of the records, newline-separated.
#[wasm_bindgen]
pub fn list(policy_json: &str) -> Result<String, JsValue> {
    let records = parse(policy_json)?;
    let lines: Vec<String> = records
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
                "{index}: {effect} {status} {} {:#04x} {} {scope_kind}={scope_value}",
                record.caller_id, record.opcode, record.operation
            )
        })
        .collect();
    Ok(lines.join("\n"))
}
