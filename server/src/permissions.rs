//! Receiver-local permission policy (M13.1).
//!
//! A [`PermissionRecord`] is the receiver-local instantiation of a capability:
//! it binds a caller to an opcode, operation, resource scope, validity window,
//! and status. The [`PermissionPolicy`] evaluator is **fail-closed**
//! (default-deny) and **deny-wins**.
//!
//! Authority model (M13.0 decision, all-A): every record carries a typed
//! [`AuthoritySource`]. M13 implements `receiver_local` only; `dregg_backed`
//! (M14) and `dregg_authority` (M15) are reserved so the schema, evaluator,
//! control panel, and receipts do not change when the authority source is
//! swapped — a non-`receiver_local` source is simply not evaluable here and
//! fails closed. This module is receiver-local policy only: it does not claim
//! Dregg capability/revocation authority, deployment proof, or public
//! auditability.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Where a permission record's authority comes from.
///
/// M13 evaluates `ReceiverLocal` only. `DreggBacked` / `DreggAuthority` are the
/// M14 / M15 handoff seam: the evaluator is source-agnostic, so adding their
/// verification later does not alter this schema or the evaluation of existing
/// receiver-local records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoritySource {
    #[default]
    ReceiverLocal,
    /// Reserved for M14 — a Dregg macaroon/credential verified against a
    /// fixture root. Not evaluable in M13.
    DreggBacked,
    /// Reserved for M15 (#73) — a Dregg credential verified against a
    /// receiver-held federation/revocation root. Not evaluable in M13.
    DreggAuthority,
}

/// Active vs revoked grant. Validity (`not_before`/`not_after`) is separate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionStatus {
    Active,
    Revoked,
}

/// Grant or deny. Defaults to `Allow` so a record without an explicit effect is
/// a grant; explicit `Deny` records take precedence (deny-wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionEffect {
    #[default]
    Allow,
    Deny,
}

/// Resource scope: attenuation-only — `Exact` matches one resource; `Prefix`
/// matches any resource under the prefix. A prefix narrows what was granted; it
/// never widens beyond the prefix string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceScope {
    Exact { value: String },
    Prefix { prefix: String },
}

impl ResourceScope {
    /// Whether this scope covers `resource`.
    pub fn matches(&self, resource: &str) -> bool {
        match self {
            ResourceScope::Exact { value } => value == resource,
            ResourceScope::Prefix { prefix } => resource.starts_with(prefix.as_str()),
        }
    }

    fn declared_value(&self) -> &str {
        match self {
            ResourceScope::Exact { value } => value,
            ResourceScope::Prefix { prefix } => prefix,
        }
    }
}

/// A receiver-local permission record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionRecord {
    pub caller_id: String,
    pub opcode: u8,
    pub operation: String,
    pub resource: ResourceScope,
    #[serde(default)]
    pub effect: PermissionEffect,
    /// Inclusive lower bound of the validity window (unix seconds).
    pub not_before: u64,
    /// Exclusive upper bound of the validity window (unix seconds).
    pub not_after: u64,
    pub status: PermissionStatus,
    #[serde(default)]
    pub authority_source: AuthoritySource,
}

impl PermissionRecord {
    /// Whether this record's caller/opcode/operation/resource matches the
    /// request, ignoring validity/status/source.
    fn matches_request(
        &self,
        caller_id: &str,
        opcode: u8,
        operation: &str,
        resource: &str,
    ) -> bool {
        self.caller_id == caller_id
            && self.opcode == opcode
            && self.operation == operation
            && self.resource.matches(resource)
    }

    /// Whether this record can currently grant or deny: active, within its
    /// validity window, and a source M13 can evaluate.
    fn is_applicable(&self, now: u64) -> bool {
        self.status == PermissionStatus::Active
            && self.authority_source == AuthoritySource::ReceiverLocal
            && now >= self.not_before
            && now < self.not_after
    }
}

/// A permitted decision. Allow is the only positive outcome; everything else is
/// a typed [`DenyReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionDecision {
    Allow,
}

/// Why a request was not allowed. Stable codes via [`DenyReason::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// No record matched the caller/opcode/operation/resource at all.
    NoMatchingGrant,
    /// A matching, applicable record explicitly denies (deny-wins).
    ExplicitDeny,
    /// The only matching grant is revoked.
    Revoked,
    /// The only matching grant's validity window has passed.
    Expired,
    /// The only matching grant is not yet valid.
    NotYetValid,
    /// The only matching grant uses an authority source M13 cannot evaluate
    /// (`dregg_backed` / `dregg_authority`); reserved for M14/M15.
    AuthoritySourceUnsupported,
}

impl DenyReason {
    /// Stable string code for receipts/logs/debugging.
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::NoMatchingGrant => "permission_no_matching_grant",
            DenyReason::ExplicitDeny => "permission_explicit_deny",
            DenyReason::Revoked => "permission_revoked",
            DenyReason::Expired => "permission_expired",
            DenyReason::NotYetValid => "permission_not_yet_valid",
            DenyReason::AuthoritySourceUnsupported => "permission_authority_source_unsupported",
        }
    }
}

/// Receiver-local permission policy: an ordered set of [`PermissionRecord`]s and
/// a fail-closed evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionPolicy {
    records: Vec<PermissionRecord>,
}

/// Policy construction/load failure (fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// The policy source was empty.
    Empty,
    /// The policy JSON could not be parsed.
    Malformed,
    /// A record failed validation (empty field or `not_before >= not_after`).
    InvalidRecord,
    /// The policy file could not be read.
    Unreadable,
}

impl PermissionPolicy {
    /// Build a policy from records, validating each. Fail-closed: any invalid
    /// record rejects the whole policy.
    pub fn new(records: impl IntoIterator<Item = PermissionRecord>) -> Result<Self, PolicyError> {
        let records: Vec<_> = records.into_iter().collect();
        for record in &records {
            if record.caller_id.is_empty()
                || record.operation.is_empty()
                || record.resource.declared_value().is_empty()
                || record.not_before >= record.not_after
            {
                return Err(PolicyError::InvalidRecord);
            }
        }
        Ok(Self { records })
    }

    /// Parse a policy from a JSON array of records. Empty input fails closed.
    pub fn from_json_str(json: &str) -> Result<Self, PolicyError> {
        if json.trim().is_empty() {
            return Err(PolicyError::Empty);
        }
        let records: Vec<PermissionRecord> =
            serde_json::from_str(json).map_err(|_| PolicyError::Malformed)?;
        Self::new(records)
    }

    /// Load a policy from a JSON file. Unreadable/empty/malformed all fail
    /// closed.
    pub fn from_json_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let json = fs::read_to_string(path).map_err(|_| PolicyError::Unreadable)?;
        Self::from_json_str(&json)
    }

    /// Number of records (operator/test introspection).
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Fail-closed, deny-wins evaluation. Returns `Ok(Allow)` only when an
    /// applicable `Allow` record matches and no applicable `Deny` record
    /// matches. Otherwise returns the most informative [`DenyReason`].
    pub fn evaluate(
        &self,
        caller_id: &str,
        opcode: u8,
        operation: &str,
        resource: &str,
        now: u64,
    ) -> Result<PermissionDecision, DenyReason> {
        let matching: Vec<&PermissionRecord> = self
            .records
            .iter()
            .filter(|record| record.matches_request(caller_id, opcode, operation, resource))
            .collect();

        if matching.is_empty() {
            return Err(DenyReason::NoMatchingGrant);
        }

        // Deny-wins: any applicable explicit Deny rejects immediately.
        if matching
            .iter()
            .any(|record| record.effect == PermissionEffect::Deny && record.is_applicable(now))
        {
            return Err(DenyReason::ExplicitDeny);
        }

        // Any applicable Allow grants.
        if matching
            .iter()
            .any(|record| record.effect == PermissionEffect::Allow && record.is_applicable(now))
        {
            return Ok(PermissionDecision::Allow);
        }

        // Matching records exist but none apply — report the most informative
        // reason from a matching Allow record's failure.
        Err(most_informative_inapplicable_reason(&matching, now))
    }
}

/// Pick the clearest deny reason among matching-but-inapplicable records.
/// Prefers status/validity/source failures over a generic no-grant.
fn most_informative_inapplicable_reason(matching: &[&PermissionRecord], now: u64) -> DenyReason {
    let allows = matching
        .iter()
        .filter(|record| record.effect == PermissionEffect::Allow);

    let mut reason = DenyReason::NoMatchingGrant;
    for record in allows {
        let candidate = if record.status == PermissionStatus::Revoked {
            DenyReason::Revoked
        } else if record.authority_source != AuthoritySource::ReceiverLocal {
            DenyReason::AuthoritySourceUnsupported
        } else if now >= record.not_after {
            DenyReason::Expired
        } else if now < record.not_before {
            DenyReason::NotYetValid
        } else {
            DenyReason::NoMatchingGrant
        };
        // Revoked is the strongest signal; otherwise keep the first specific one.
        if candidate == DenyReason::Revoked {
            return DenyReason::Revoked;
        }
        if reason == DenyReason::NoMatchingGrant {
            reason = candidate;
        }
    }
    reason
}
