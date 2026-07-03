//! Scoped nullifier/use-state primitives for I04.
//!
//! The v0 contract treats nullifier values as opaque verifier/evidence-supplied
//! commitments or usage markers. This module does not derive real ZK
//! nullifiers and does not expose wallet/holder/raw subject material.

use crate::verifier::VerifiedCallContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

pub const NULLIFIER_DOMAIN_VERSION: &str = "nullifier-domain-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceKind {
    Directory,
    File,
}

impl ResourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
        }
    }

    pub fn for_context(context: &VerifiedCallContext) -> Result<Self, NullifierReason> {
        if context.operation.contains("file") {
            Ok(Self::File)
        } else if context.operation.contains("directory") || context.operation.contains("dir") {
            Ok(Self::Directory)
        } else {
            Err(NullifierReason::UnsupportedScope)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NullifierReason {
    DuplicateNullifier,
    DomainMismatch,
    MissingScopedNullifier,
    UnsupportedScope,
}

impl NullifierReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuplicateNullifier => "duplicate_nullifier",
            Self::DomainMismatch => "nullifier_domain_mismatch",
            Self::MissingScopedNullifier => "missing_scoped_nullifier",
            Self::UnsupportedScope => "unsupported_nullifier_scope",
        }
    }
}

impl fmt::Display for NullifierReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NullifierOutcome {
    ScopedUseRecorded,
    DuplicateNullifier,
    DomainMismatch,
    MissingScopedNullifier,
    UnsupportedScope,
}

impl NullifierOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ScopedUseRecorded => "scoped_use_recorded",
            Self::DuplicateNullifier => NullifierReason::DuplicateNullifier.as_str(),
            Self::DomainMismatch => NullifierReason::DomainMismatch.as_str(),
            Self::MissingScopedNullifier => NullifierReason::MissingScopedNullifier.as_str(),
            Self::UnsupportedScope => NullifierReason::UnsupportedScope.as_str(),
        }
    }
}

impl From<NullifierReason> for NullifierOutcome {
    fn from(value: NullifierReason) -> Self {
        match value {
            NullifierReason::DuplicateNullifier => Self::DuplicateNullifier,
            NullifierReason::DomainMismatch => Self::DomainMismatch,
            NullifierReason::MissingScopedNullifier => Self::MissingScopedNullifier,
            NullifierReason::UnsupportedScope => Self::UnsupportedScope,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierCommitment(String);

impl NullifierCommitment {
    pub fn new(value: impl Into<String>) -> Result<Self, NullifierReason> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(NullifierReason::MissingScopedNullifier);
        }
        if value.starts_with("global:") || value == "global" || value == "domainless" {
            return Err(NullifierReason::UnsupportedScope);
        }
        Ok(Self(value))
    }

    pub fn fingerprint(&self) -> String {
        redacted_fingerprint("nullifier-commitment", self.0.as_bytes())
    }

    pub(crate) fn raw_for_storage(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for NullifierCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierCommitment")
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl fmt::Display for NullifierCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.fingerprint())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullifierDomainV1Inputs {
    pub resource_kind: ResourceKind,
    pub epoch_or_window: String,
    pub issuer_or_authority_source_id: String,
    pub root_or_checkpoint_id: String,
    pub subject_commitment: String,
    pub allowance_id: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierDomainV1 {
    pub domain_version: String,
    pub audience: String,
    pub operation: String,
    pub resource_kind: ResourceKind,
    pub canonical_resource_id: String,
    pub epoch_or_window: String,
    pub issuer_or_authority_source_id: String,
    pub root_or_checkpoint_id: String,
    pub subject_commitment: String,
    pub allowance_id: Option<String>,
}

impl fmt::Debug for NullifierDomainV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NullifierDomainV1")
            .field("domain_version", &self.domain_version)
            .field("resource_kind", &self.resource_kind.as_str())
            .field("fingerprint", &self.fingerprint())
            .finish()
    }
}

impl NullifierDomainV1 {
    pub fn from_verified_context(
        context: &VerifiedCallContext,
        inputs: NullifierDomainV1Inputs,
    ) -> Result<Self, NullifierReason> {
        let resource = context
            .resource
            .as_deref()
            .ok_or(NullifierReason::MissingScopedNullifier)?;
        reject_empty(&context.audience)?;
        reject_empty(&context.operation)?;
        reject_empty(&inputs.epoch_or_window)?;
        reject_empty(&inputs.issuer_or_authority_source_id)?;
        reject_empty(&inputs.root_or_checkpoint_id)?;
        reject_subject_commitment(&inputs.subject_commitment)?;
        if let Some(allowance_id) = &inputs.allowance_id {
            reject_empty(allowance_id)?;
        }
        Ok(Self {
            domain_version: NULLIFIER_DOMAIN_VERSION.to_string(),
            audience: context.audience.clone(),
            operation: context.operation.clone(),
            resource_kind: inputs.resource_kind,
            canonical_resource_id: canonical_resource_id(resource)?,
            epoch_or_window: inputs.epoch_or_window,
            issuer_or_authority_source_id: inputs.issuer_or_authority_source_id,
            root_or_checkpoint_id: inputs.root_or_checkpoint_id,
            subject_commitment: inputs.subject_commitment,
            allowance_id: inputs.allowance_id,
        })
    }

    pub fn fingerprint(&self) -> String {
        redacted_fingerprint("nullifier-domain", &self.canonical_bytes())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let allowance = self.allowance_id.as_deref().unwrap_or("");
        format!(
            "v={}|aud={}|op={}|kind={}|res={}|epoch={}|issuer={}|root={}|subject={}|allowance={}",
            self.domain_version,
            self.audience,
            self.operation,
            self.resource_kind.as_str(),
            self.canonical_resource_id,
            self.epoch_or_window,
            self.issuer_or_authority_source_id,
            self.root_or_checkpoint_id,
            self.subject_commitment,
            allowance
        )
        .into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedNullifierEvidence {
    pub domain: NullifierDomainV1,
    pub commitment: NullifierCommitment,
}

impl ScopedNullifierEvidence {
    pub fn from_context(context: &VerifiedCallContext) -> Result<Self, NullifierReason> {
        let scope = evidence_value(context, "nullifier_scope");
        if matches!(scope.as_deref(), Some("global") | Some("domainless")) {
            return Err(NullifierReason::UnsupportedScope);
        }
        if !context
            .evidence_summary
            .iter()
            .any(|field| field == "scoped_use_required")
        {
            return Err(NullifierReason::MissingScopedNullifier);
        }
        let commitment = NullifierCommitment::new(
            evidence_value(context, "nullifier_commitment")
                .ok_or(NullifierReason::MissingScopedNullifier)?,
        )?;
        let domain = NullifierDomainV1::from_verified_context(
            context,
            NullifierDomainV1Inputs {
                resource_kind: ResourceKind::for_context(context)?,
                epoch_or_window: evidence_value(context, "nullifier_epoch")
                    .ok_or(NullifierReason::MissingScopedNullifier)?,
                issuer_or_authority_source_id: evidence_value(context, "nullifier_issuer")
                    .ok_or(NullifierReason::MissingScopedNullifier)?,
                root_or_checkpoint_id: evidence_value(context, "nullifier_root")
                    .ok_or(NullifierReason::MissingScopedNullifier)?,
                subject_commitment: evidence_value(context, "subject_commitment")
                    .ok_or(NullifierReason::MissingScopedNullifier)?,
                allowance_id: evidence_value(context, "allowance_id"),
            },
        )?;
        if let Some(expected) = evidence_value(context, "nullifier_domain_fingerprint") {
            if expected != domain.fingerprint() {
                return Err(NullifierReason::DomainMismatch);
            }
        }
        Ok(Self { domain, commitment })
    }
}

pub fn privacy_safe_summary(
    outcome: NullifierOutcome,
    domain_fingerprint: Option<&str>,
    commitment_fingerprint: Option<&str>,
) -> Vec<String> {
    let mut summary = vec![
        "scoped_use_enforced:true".to_string(),
        format!("nullifier_domain_version:{NULLIFIER_DOMAIN_VERSION}"),
        format!("nullifier_outcome:{}", outcome.as_str()),
    ];
    if let Some(value) = domain_fingerprint {
        summary.push(format!("nullifier_domain_fingerprint:{value}"));
    }
    if let Some(value) = commitment_fingerprint {
        summary.push(format!("nullifier_commitment_fingerprint:{value}"));
    }
    summary
}

pub fn canonical_resource_id(resource: &str) -> Result<String, NullifierReason> {
    let Some(rest) = resource.strip_prefix("file://") else {
        return Err(NullifierReason::DomainMismatch);
    };
    if rest.trim().is_empty() {
        return Err(NullifierReason::MissingScopedNullifier);
    }
    let absolute = rest.starts_with('/');
    let mut parts = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let path = parts.join("/");
    Ok(if absolute {
        format!("file:///{path}")
    } else {
        format!("file://{path}")
    })
}

fn reject_empty(value: &str) -> Result<(), NullifierReason> {
    if value.trim().is_empty() {
        Err(NullifierReason::MissingScopedNullifier)
    } else {
        Ok(())
    }
}

fn reject_subject_commitment(value: &str) -> Result<(), NullifierReason> {
    reject_empty(value)?;
    let lower = value.to_ascii_lowercase();
    if lower.starts_with("wallet:")
        || lower.starts_with("holder:")
        || lower.starts_with("subject_id:")
        || lower.starts_with("credential_id:")
    {
        return Err(NullifierReason::UnsupportedScope);
    }
    Ok(())
}

pub fn evidence_value(context: &VerifiedCallContext, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    context
        .evidence_summary
        .iter()
        .find_map(|field| field.strip_prefix(&prefix).map(ToString::to_string))
}

fn redacted_fingerprint(label: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(label.as_bytes());
    hasher.update(b"\0");
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest[..12]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
