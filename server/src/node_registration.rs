//! First-class, receiver-local node registration contract (I14).
//!
//! This module proves a local/fixture operation and does not confer listing,
//! federation, finality, live-source, or production-deployment status.

use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceTier;
use crate::manifest::OperationDescriptor;
use crate::privacy::PrivacySurface;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

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
    ReplayDetected,
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
    if request.resource != policy.resource || !request_fields_match_node_resource(request) {
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
    if request.evidence_ref.trim().is_empty() || !request.evidence_ref.starts_with("fixture:") {
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

fn request_fields_match_node_resource(request: &NodeRegistrationRequestV0) -> bool {
    let fields: Vec<&str> = request.resource.split(':').collect();
    fields.len() == 6
        && fields[0] == "node"
        && !fields[1].is_empty()
        && !fields[2].is_empty()
        && fields[3] == request.node_public_key_fingerprint
        && fields[4] == request.endpoint_hash
        && fields[5] == "v0"
}

#[derive(Debug, Default)]
pub struct NodeRegistrationHandler {
    handled_request_ids: BTreeSet<String>,
    execution_count: u64,
}

impl NodeRegistrationHandler {
    pub fn execution_count(&self) -> u64 {
        self.execution_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistrationReceipt {
    pub receipt_id: String,
    pub operation: String,
    pub opcode: u8,
    pub decision: String,
    pub handler_id: String,
    pub handler_ran: bool,
    pub evidence_tier: String,
    pub resource_hash: String,
    pub descriptor_fingerprint: String,
    pub schema_version: u16,
    pub disclosure_policy_id: String,
    pub replay_scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRegistrationRejection {
    pub reason: NodeRegistrationReason,
    pub handler_ran: bool,
}

pub fn process_node_registration(
    request: &NodeRegistrationRequestV0,
    policy: &NodeRegistrationPolicy,
    handler: &mut NodeRegistrationHandler,
) -> Result<NodeRegistrationReceipt, NodeRegistrationRejection> {
    verify_node_registration(request, policy).map_err(|reason| NodeRegistrationRejection {
        reason,
        handler_ran: false,
    })?;
    if handler.handled_request_ids.contains(&request.request_id) {
        return Err(NodeRegistrationRejection {
            reason: NodeRegistrationReason::ReplayDetected,
            handler_ran: false,
        });
    }

    handler
        .handled_request_ids
        .insert(request.request_id.clone());
    handler.execution_count += 1;

    Ok(NodeRegistrationReceipt {
        receipt_id: digest_label("registration-receipt", &request.request_id),
        operation: request.operation.clone(),
        opcode: request.opcode,
        decision: "accepted".to_string(),
        handler_id: NODE_REGISTRATION_HANDLER_ID.to_string(),
        handler_ran: true,
        evidence_tier: request.evidence_tier.clone(),
        resource_hash: digest_label("resource", &request.resource),
        descriptor_fingerprint: request.descriptor_fingerprint.clone(),
        schema_version: request.schema_version,
        disclosure_policy_id: request.disclosure_policy_id.clone(),
        replay_scope: "request_id_in_memory".to_string(),
    })
}

fn digest_label(label: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{label}:sha256:{hex}")
}

pub fn registration_surface_projection(
    receipt: &NodeRegistrationReceipt,
    surface: PrivacySurface,
) -> serde_json::Value {
    serde_json::json!({
        "surface": surface.as_str(),
        "scope": "local_registration_only",
        "receipt_id": receipt.receipt_id,
        "operation": receipt.operation,
        "opcode": receipt.opcode,
        "decision": receipt.decision,
        "handler_id": receipt.handler_id,
        "handler_ran": receipt.handler_ran,
        "evidence_tier": receipt.evidence_tier,
        "resource_hash": receipt.resource_hash,
        "descriptor_fingerprint": receipt.descriptor_fingerprint,
        "schema_version": receipt.schema_version,
        "disclosure_policy_id": receipt.disclosure_policy_id,
        "replay_scope": receipt.replay_scope,
    })
}

pub fn registration_rejection_projection(
    rejection: &NodeRegistrationRejection,
) -> serde_json::Value {
    serde_json::json!({
        "scope": "local_registration_only",
        "decision": "rejected",
        "reason": rejection.reason,
        "handler_ran": rejection.handler_ran,
    })
}
