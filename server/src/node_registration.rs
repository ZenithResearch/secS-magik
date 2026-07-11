//! First-class, receiver-local node registration contract (I14).
//!
//! This module proves a local/fixture operation and does not confer listing,
//! federation, finality, live-source, or production-deployment status.

use serde::{Deserialize, Serialize};

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
    pub requested_disclosure: Vec<String>,
}
