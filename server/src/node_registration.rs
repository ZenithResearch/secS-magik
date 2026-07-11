//! First-class, receiver-local node registration contract (I14).
//!
//! This module proves a local/fixture operation and does not confer listing,
//! federation, finality, live-source, or production-deployment status.

use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceTier;
use crate::manifest::OperationDescriptor;

pub const NODE_REGISTRATION_OPCODE: u8 = 0x45;
pub const NODE_REGISTRATION_OPERATION: &str = "node.registration.v0";
pub const NODE_REGISTRATION_DESCRIPTOR_ID: &str = "secs.node_registration.v0";
pub const NODE_REGISTRATION_HANDLER_ID: &str = "node_registration/register/v0";
pub const NODE_REGISTRATION_PAYLOAD_SCHEMA: &str = "secs-node-registration-request-v0";
pub const NODE_REGISTRATION_DISCLOSURE_POLICY_ID: &str = "registration_public_directory_v0";
pub const NODE_REGISTRATION_AUTHORITY_SOURCE_ID: &str = "receiver-held-fixture";
pub const NODE_REGISTRATION_MAX_AGE_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeRegistrationRequestV0 {
    pub schema_version: u16,
    pub operation: String,
    pub opcode: u8,
    pub request_id: String,
    pub audience: String,
    pub resource: String,
    pub node_public_key_fingerprint: String,
    pub endpoint_hash: String,
    pub authority_source_id: String,
    pub evidence_ref: String,
    pub evidence_tier: String,
    pub descriptor_fingerprint: String,
    pub disclosure_policy_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub requested_disclosure: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeRegistrationPolicy {
    operation: String,
    opcode: u8,
    audience: String,
    resource: String,
    descriptor_fingerprint: String,
    disclosure_policy_id: String,
    authority_source_id: String,
    minimum_evidence_tier: EvidenceTier,
    max_age_seconds: u64,
    now: u64,
}

impl NodeRegistrationPolicy {
    pub fn from_descriptor(
        descriptor: &OperationDescriptor,
        audience: impl Into<String>,
        resource: impl Into<String>,
        now: u64,
    ) -> Self {
        Self {
            operation: descriptor.name.as_str().to_string(),
            opcode: descriptor.opcode,
            audience: audience.into(),
            resource: resource.into(),
            descriptor_fingerprint: descriptor.authorization_fingerprint(),
            disclosure_policy_id: descriptor.disclosure_policy.policy_id.clone(),
            authority_source_id: NODE_REGISTRATION_AUTHORITY_SOURCE_ID.to_string(),
            minimum_evidence_tier: EvidenceTier::LocalVerified,
            max_age_seconds: descriptor.max_ttl_seconds,
            now,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRegistrationReason {
    WrongOperation,
    WrongAudience,
    WrongResource,
    ManifestMismatch,
    PrivacyPolicyViolation,
    InsufficientEvidence,
    UnauthorizedSource,
    MissingAuthority,
    StaleEvidence,
}

pub fn verify_node_registration(
    request: &NodeRegistrationRequestV0,
    policy: &NodeRegistrationPolicy,
) -> Result<(), NodeRegistrationReason> {
    if request.operation != policy.operation || request.opcode != policy.opcode {
        return Err(NodeRegistrationReason::WrongOperation);
    }
    if request.audience != policy.audience {
        return Err(NodeRegistrationReason::WrongAudience);
    }
    if request.resource != policy.resource {
        return Err(NodeRegistrationReason::WrongResource);
    }
    if request.schema_version != 0
        || request.descriptor_fingerprint != policy.descriptor_fingerprint
    {
        return Err(NodeRegistrationReason::ManifestMismatch);
    }
    if request.disclosure_policy_id != policy.disclosure_policy_id
        || request
            .requested_disclosure
            .iter()
            .any(|field| !matches!(field.as_str(), "public_node_id" | "endpoint_hash"))
    {
        return Err(NodeRegistrationReason::PrivacyPolicyViolation);
    }
    let evidence_tier = request
        .evidence_tier
        .parse::<EvidenceTier>()
        .map_err(|_| NodeRegistrationReason::InsufficientEvidence)?;
    if evidence_tier != policy.minimum_evidence_tier {
        return Err(NodeRegistrationReason::InsufficientEvidence);
    }
    if request.authority_source_id != policy.authority_source_id {
        return Err(NodeRegistrationReason::UnauthorizedSource);
    }
    if request.evidence_ref.is_empty() {
        return Err(NodeRegistrationReason::MissingAuthority);
    }
    if request.issued_at > policy.now
        || request.expires_at < policy.now
        || request.expires_at < request.issued_at
        || request.expires_at - request.issued_at > policy.max_age_seconds
    {
        return Err(NodeRegistrationReason::StaleEvidence);
    }
    Ok(())
}
