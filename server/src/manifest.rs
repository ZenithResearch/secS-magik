//! Receiver-local operation descriptors and opcode governance.
//!
//! The manifest is receiver-local: opcodes are compact `u8` routing keys, while
//! `OperationDescriptor` carries the semantic operation contract the receiver
//! assigns to each key.

use crate::verifier::VerificationError;
use std::collections::BTreeMap;

pub const CORE_STANDARDIZED_START: u8 = 0x01;
pub const CORE_STANDARDIZED_END: u8 = 0x0A;
pub const CASTALIA_STANDARD_CANDIDATE_START: u8 = 0x0B;
pub const CASTALIA_STANDARD_CANDIDATE_END: u8 = 0x3F;
pub const OPERATOR_DEFINED_START: u8 = 0x40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeRange {
    Reserved,
    CoreStandardized,
    CastaliaStandardCandidate,
    OperatorDefined,
}

impl OpcodeRange {
    pub fn classify(opcode: u8) -> Self {
        match opcode {
            CORE_STANDARDIZED_START..=CORE_STANDARDIZED_END => Self::CoreStandardized,
            CASTALIA_STANDARD_CANDIDATE_START..=CASTALIA_STANDARD_CANDIDATE_END => {
                Self::CastaliaStandardCandidate
            }
            OPERATOR_DEFINED_START..=u8::MAX => Self::OperatorDefined,
            _ => Self::Reserved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationName(String);

impl OperationName {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    LegacyCoreExample,
    LocalDevProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayScope {
    SessionOpcodeNonce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationDescriptor {
    pub opcode: u8,
    pub name: OperationName,
    pub payload_schema: Option<String>,
    pub target_kind: TargetKind,
    pub required_credentials: Vec<String>,
    pub required_capabilities: Vec<String>,
    pub accepted_evidence: Vec<String>,
    pub replay_scope: ReplayScope,
    pub max_ttl_seconds: u64,
    pub handler_id: String,
    pub dev_binding: bool,
    pub range: OpcodeRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverManifest {
    descriptors: BTreeMap<u8, OperationDescriptor>,
}

impl ReceiverManifest {
    pub fn new(descriptors: impl IntoIterator<Item = OperationDescriptor>) -> Self {
        let descriptors = descriptors
            .into_iter()
            .map(|descriptor| (descriptor.opcode, descriptor))
            .collect();
        Self { descriptors }
    }

    pub fn default_v0() -> Self {
        Self::new([
            legacy_descriptor(0x01, "legacy.generate", "legacy/generate"),
            legacy_descriptor(0x02, "legacy.chat", "legacy/chat"),
            dev_candidate_descriptor(0x10, "candidate.dev.bash_echo", None, "dev/bash-echo"),
            dev_candidate_descriptor(
                0x20,
                "candidate.dev.json_validate",
                Some("application/json"),
                "dev/json-validate",
            ),
            dev_candidate_descriptor(0x30, "candidate.dev.jq_identity", None, "dev/jq-identity"),
            membership_provision_descriptor(),
        ])
    }

    pub fn lookup(&self, opcode: u8) -> Result<&OperationDescriptor, VerificationError> {
        self.descriptors
            .get(&opcode)
            .ok_or(VerificationError::UnknownOperation)
    }
}

fn legacy_descriptor(opcode: u8, name: &str, handler_id: &str) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new(name),
        payload_schema: None,
        target_kind: TargetKind::LegacyCoreExample,
        required_credentials: vec!["legacy.prototype".to_string()],
        required_capabilities: vec!["legacy.execute".to_string()],
        accepted_evidence: vec!["prototype-proof-envelope".to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 3600,
        handler_id: handler_id.to_string(),
        dev_binding: false,
        range: OpcodeRange::classify(opcode),
    }
}

/// Fixture/dev-bounded demo descriptor accepting Dregg-shaped receipt
/// evidence (M12.3.5). **Not** part of [`ReceiverManifest::default_v0`]: a
/// demo or test installs it explicitly, and `dev_binding: true` means
/// `production_verified` rejects it like every other dev descriptor — the
/// existing descriptors are never weakened by the Dregg-shaped seam.
pub fn dregg_demo_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.dev.dregg_receipt_demo"),
        payload_schema: Some("application/json".to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["prototype.local-dev".to_string()],
        required_capabilities: vec!["dev.execute".to_string()],
        accepted_evidence: vec!["dregg_receipt".to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/bash-echo".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

fn dev_candidate_descriptor(
    opcode: u8,
    name: &str,
    payload_schema: Option<&str>,
    handler_id: &str,
) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new(name),
        payload_schema: payload_schema.map(ToString::to_string),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["prototype.local-dev".to_string()],
        required_capabilities: vec!["dev.execute".to_string()],
        accepted_evidence: vec!["prototype-proof-envelope".to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: handler_id.to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

/// Canonical `0x44 membership.provision` descriptor (#80): the single
/// constructor shared by `ReceiverManifest::default_v0()` and the Track I
/// test fixtures, so the active manifest and tests cannot drift apart.
pub fn membership_provision_descriptor() -> OperationDescriptor {
    const OPCODE: u8 = 0x44;
    OperationDescriptor {
        opcode: OPCODE,
        name: OperationName::new("membership.provision"),
        payload_schema: Some("application/json".to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec![
            "trusted.membership".to_string(),
            "wallet.presentation".to_string(),
        ],
        required_capabilities: vec!["membership.provision".to_string()],
        accepted_evidence: vec![
            "wallet_presentation".to_string(),
            "membership_credential".to_string(),
        ],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "membership/provision".to_string(),
        dev_binding: false,
        range: OpcodeRange::classify(OPCODE),
    }
}
