//! Receiver-local operation descriptors and opcode governance.
//!
//! The manifest is receiver-local: opcodes are compact `u8` routing keys, while
//! `OperationDescriptor` carries the semantic operation contract the receiver
//! assigns to each key.

use crate::verifier::VerificationError;
use sha2::{Digest, Sha256};
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
    /// Legacy prototype example handlers (`0x01`/`0x02`): prototype-evidence
    /// only, rejected by `production_verified`.
    LegacyCoreExample,
    /// Local-dev / dev-subprocess handlers (`dev/*`, `candidate.dev.*`):
    /// always `dev_binding: true`, never registered in production runtime.
    LocalDevProcess,
    /// Production-shaped receiver handler (#82): a non-dev, non-legacy target
    /// whose authority still requires verifier signatures, evidence policy,
    /// descriptor-local checks, replay/expiry/session checks, and #77's
    /// fail-closed descriptor-only runtime guard where applicable. Target kind
    /// alone is never sufficient authority — it only stops production-shaped
    /// descriptors like canonical `0x44 membership.provision` from being
    /// mislabeled as local-dev process targets.
    ReceiverProductionHandler,
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

impl OperationDescriptor {
    /// Canonical authorization fingerprint (#81): a deterministic SHA-256
    /// over every routing/authorization-relevant descriptor field, computed
    /// from canonical length-prefixed bytes (declared Vec order; no map
    /// iteration, no Debug formatting). Carried in `VerifiedCallContext` at
    /// verification time and re-checked against the active manifest before
    /// any route side effects, so a signed context cannot ride on stale
    /// descriptor semantics. Contains no payload or evidence material.
    pub fn authorization_fingerprint(&self) -> String {
        const VERSION: &str = "secs-descriptor-fingerprint-v1";
        let mut bytes = Vec::new();
        let mut field = |name: &str, value: &str| {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(value.len().to_string().as_bytes());
            bytes.push(b':');
            bytes.extend_from_slice(value.as_bytes());
            bytes.push(b'\n');
        };
        field("version", VERSION);
        field("opcode", &format!("{:02x}", self.opcode));
        field("operation", self.name.as_str());
        field(
            "payload_schema",
            self.payload_schema.as_deref().unwrap_or(""),
        );
        field("target_kind", target_kind_label(self.target_kind));
        for credential in &self.required_credentials {
            field("required_credential", credential);
        }
        for capability in &self.required_capabilities {
            field("required_capability", capability);
        }
        for evidence in &self.accepted_evidence {
            field("accepted_evidence", evidence);
        }
        field(
            "replay_scope",
            replay_scope_fingerprint_label(self.replay_scope),
        );
        field("max_ttl_seconds", &self.max_ttl_seconds.to_string());
        field("handler_id", &self.handler_id);
        field(
            "dev_binding",
            if self.dev_binding { "true" } else { "false" },
        );
        field("range", opcode_range_label(self.range));

        let digest = Sha256::digest(&bytes);
        let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("descriptor:sha256:{hex}")
    }
}

fn target_kind_label(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::LegacyCoreExample => "legacy_core_example",
        TargetKind::LocalDevProcess => "local_dev_process",
        TargetKind::ReceiverProductionHandler => "receiver_production_handler",
    }
}

fn replay_scope_fingerprint_label(scope: ReplayScope) -> &'static str {
    match scope {
        ReplayScope::SessionOpcodeNonce => "session_opcode_nonce",
    }
}

fn opcode_range_label(range: OpcodeRange) -> &'static str {
    match range {
        OpcodeRange::Reserved => "reserved",
        OpcodeRange::CoreStandardized => "core_standardized",
        OpcodeRange::CastaliaStandardCandidate => "castalia_standard_candidate",
        OpcodeRange::OperatorDefined => "operator_defined",
    }
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
