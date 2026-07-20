//! Signed receipt and audit event boundary.
//!
//! Receipts are in-memory typed audit objects in this slice. Persistence is
//! deliberately delegated to the ledger slice, and payload bytes are not part of
//! the versioned receipt schema by default.

use crate::nullifier::{privacy_safe_summary, NullifierOutcome, ScopedNullifierEvidence};
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as SignatureVerifier, VerifyingKey};
use libsec_core::ZenithPacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RECEIPT_SCHEMA_VERSION: u16 = 3;
const OUTPUT_DIGEST_DOMAIN: &[u8] = b"secs-execution-output-v1/digest";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptOutputProjection {
    pub schema_id: String,
    pub byte_count: u64,
    pub digest_sha256: [u8; 32],
}

impl ReceiptOutputProjection {
    pub fn from_output(schema_id: &str, output: &[u8]) -> Result<Self, VerificationError> {
        if schema_id.is_empty() {
            return Err(VerificationError::InternalError);
        }
        let byte_count =
            u64::try_from(output.len()).map_err(|_| VerificationError::InternalError)?;
        let mut hasher = Sha256::new();
        hasher.update(OUTPUT_DIGEST_DOMAIN);
        hasher.update(byte_count.to_le_bytes());
        hasher.update(output);
        Ok(Self {
            schema_id: schema_id.to_string(),
            byte_count,
            digest_sha256: hasher.finalize().into(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptKind {
    Reject,
    Verify,
    Execute,
    Forward,
}

impl ReceiptKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::Verify => "verify",
            Self::Execute => "execute",
            Self::Forward => "forward",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Accepted,
    Rejected,
}

impl Decision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticatorKind {
    LocalDevUntrusted,
    LocalMac,
    Ed25519Node,
    Ed25519Verifier,
    Ed25519NodeAndVerifier,
    ExternalAnchor,
}

impl AuthenticatorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalDevUntrusted => "local_dev_untrusted",
            Self::LocalMac => "local_mac",
            Self::Ed25519Node => "ed25519_node",
            Self::Ed25519Verifier => "ed25519_verifier",
            Self::Ed25519NodeAndVerifier => "ed25519_node_and_verifier",
            Self::ExternalAnchor => "external_anchor",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReceiptEventKind {
    PacketReceived,
    PacketRejected,
    PacketVerified,
    OperationDescribed,
    OperationRouted,
    HandlerStarted,
    HandlerSucceeded,
    HandlerFailed,
    ReceiptEmitted,
}

impl ReceiptEventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PacketReceived => "packet_received",
            Self::PacketRejected => "packet_rejected",
            Self::PacketVerified => "packet_verified",
            Self::OperationDescribed => "operation_described",
            Self::OperationRouted => "operation_routed",
            Self::HandlerStarted => "handler_started",
            Self::HandlerSucceeded => "handler_succeeded",
            Self::HandlerFailed => "handler_failed",
            Self::ReceiptEmitted => "receipt_emitted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub schema_version: u16,
    pub receipt_id: String,
    pub context_id: Option<String>,
    pub kind: ReceiptKind,
    pub packet_hash: [u8; 32],
    pub session_id: [u8; 16],
    pub nonce: [u8; 12],
    pub opcode: u8,
    pub operation: Option<String>,
    pub decision: Decision,
    pub reason: Option<String>,
    pub handler_id: Option<String>,
    pub timestamp: u64,
    pub authenticator_kind: AuthenticatorKind,
    pub signer_key_id: String,
    pub evidence_summary: Vec<String>,
    pub output_projection: Option<ReceiptOutputProjection>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct LegacyReceiptUnsignedPreC4b6218 {
    receipt_id: String,
    kind: ReceiptKind,
    packet_hash: [u8; 32],
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    operation: Option<String>,
    decision: Decision,
    reason: Option<String>,
    handler_id: Option<String>,
    timestamp: u64,
    authenticator_kind: AuthenticatorKind,
    signer_key_id: String,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct ReceiptUnsignedV1 {
    schema_version: u16,
    receipt_id: String,
    context_id: Option<String>,
    kind: ReceiptKind,
    packet_hash: [u8; 32],
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    operation: Option<String>,
    decision: Decision,
    reason: Option<String>,
    handler_id: Option<String>,
    timestamp: u64,
    authenticator_kind: AuthenticatorKind,
    signer_key_id: String,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct ReceiptUnsignedV2 {
    schema_version: u16,
    receipt_id: String,
    context_id: Option<String>,
    kind: ReceiptKind,
    packet_hash: [u8; 32],
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    operation: Option<String>,
    decision: Decision,
    reason: Option<String>,
    handler_id: Option<String>,
    timestamp: u64,
    authenticator_kind: AuthenticatorKind,
    signer_key_id: String,
    evidence_summary: Vec<String>,
    signature: Vec<u8>,
}

#[derive(Serialize)]
struct ReceiptUnsignedV3 {
    schema_version: u16,
    receipt_id: String,
    context_id: Option<String>,
    kind: ReceiptKind,
    packet_hash: [u8; 32],
    session_id: [u8; 16],
    nonce: [u8; 12],
    opcode: u8,
    operation: Option<String>,
    decision: Decision,
    reason: Option<String>,
    handler_id: Option<String>,
    timestamp: u64,
    authenticator_kind: AuthenticatorKind,
    signer_key_id: String,
    evidence_summary: Vec<String>,
    output_projection: Option<ReceiptOutputProjection>,
    signature: Vec<u8>,
}

impl Receipt {
    #[allow(clippy::too_many_arguments)]
    pub fn reject_from_error(
        receipt_id: impl Into<String>,
        packet_hash: [u8; 32],
        session_id: [u8; 16],
        nonce: [u8; 12],
        opcode: u8,
        error: VerificationError,
        timestamp: u64,
    ) -> Self {
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            context_id: None,
            kind: ReceiptKind::Reject,
            packet_hash,
            session_id,
            nonce,
            opcode,
            operation: None,
            decision: Decision::Rejected,
            reason: Some(error.reason_code().to_string()),
            handler_id: None,
            timestamp,
            authenticator_kind: AuthenticatorKind::LocalDevUntrusted,
            signer_key_id: String::new(),
            evidence_summary: Vec::new(),
            output_projection: None,
            signature: Vec::new(),
        }
    }

    pub fn reject_from_packet(
        receipt_id: impl Into<String>,
        packet: &ZenithPacket,
        error: VerificationError,
        timestamp: u64,
    ) -> Self {
        Self::reject_from_error(
            receipt_id,
            packet_hash(packet),
            packet.session_id,
            packet.nonce,
            packet.opcode,
            error,
            timestamp,
        )
    }

    pub fn verify_from_signed_context(
        receipt_id: impl Into<String>,
        signed_context: &SignedVerifiedCallContext,
        timestamp: u64,
    ) -> Self {
        let context = &signed_context.context;
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            context_id: Some(context.context_id.clone()),
            kind: ReceiptKind::Verify,
            packet_hash: context.packet_hash,
            session_id: context.session_id,
            nonce: context.nonce,
            opcode: context.opcode,
            operation: Some(context.operation.clone()),
            decision: Decision::Accepted,
            reason: None,
            handler_id: context.handler_id.clone(),
            timestamp,
            authenticator_kind: signed_context.authenticator_kind,
            signer_key_id: signed_context.signer_key_id.clone(),
            evidence_summary: receipt_evidence_summary(context, Decision::Accepted, None),
            output_projection: None,
            signature: Vec::new(),
        }
    }

    pub fn reject_from_verified_context(
        receipt_id: impl Into<String>,
        context: &VerifiedCallContext,
        reason: &str,
        timestamp: u64,
    ) -> Self {
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            context_id: Some(context.context_id.clone()),
            kind: ReceiptKind::Reject,
            packet_hash: context.packet_hash,
            session_id: context.session_id,
            nonce: context.nonce,
            opcode: context.opcode,
            operation: Some(context.operation.clone()),
            decision: Decision::Rejected,
            reason: Some(reason.to_string()),
            handler_id: context.handler_id.clone(),
            timestamp,
            authenticator_kind: AuthenticatorKind::LocalDevUntrusted,
            signer_key_id: String::new(),
            evidence_summary: Vec::new(),
            output_projection: None,
            signature: Vec::new(),
        }
    }

    pub fn execution(
        receipt_id: impl Into<String>,
        context: &VerifiedCallContext,
        decision: Decision,
        reason: Option<&str>,
        timestamp: u64,
    ) -> Self {
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            receipt_id: receipt_id.into(),
            context_id: Some(context.context_id.clone()),
            kind: ReceiptKind::Execute,
            packet_hash: context.packet_hash,
            session_id: context.session_id,
            nonce: context.nonce,
            opcode: context.opcode,
            operation: Some(context.operation.clone()),
            decision,
            reason: reason.map(ToString::to_string),
            handler_id: context.handler_id.clone(),
            timestamp,
            authenticator_kind: AuthenticatorKind::LocalDevUntrusted,
            signer_key_id: String::new(),
            evidence_summary: receipt_evidence_summary(context, decision, reason),
            output_projection: None,
            signature: Vec::new(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn execution_with_output(
        receipt_id: impl Into<String>,
        context: &VerifiedCallContext,
        decision: Decision,
        reason: Option<&str>,
        timestamp: u64,
        output_schema: Option<&str>,
        output: Option<&[u8]>,
    ) -> Result<Self, VerificationError> {
        let output_projection = match (decision, output_schema, output) {
            (Decision::Accepted, Some(schema_id), Some(output)) => {
                Some(ReceiptOutputProjection::from_output(schema_id, output)?)
            }
            (_, None, None) => None,
            _ => return Err(VerificationError::InternalError),
        };
        let mut receipt = Self::execution(receipt_id, context, decision, reason, timestamp);
        receipt.output_projection = output_projection;
        Ok(receipt)
    }

    pub fn sign_ed25519(
        mut self,
        signer_key_id: &str,
        secret_key: &[u8; 32],
        authenticator_kind: AuthenticatorKind,
    ) -> Result<Self, VerificationError> {
        self.signer_key_id = signer_key_id.to_string();
        self.authenticator_kind = authenticator_kind;
        self.signature.clear();

        let signing_key = SigningKey::from_bytes(secret_key);
        let bytes = self.signed_payload_bytes()?;
        let signature = signing_key.sign(&bytes);
        self.signature = signature.to_bytes().to_vec();
        Ok(self)
    }

    pub fn verify_ed25519(&self, secret_key: &[u8; 32]) -> Result<(), VerificationError> {
        let signing_key = SigningKey::from_bytes(secret_key);
        let verifying_key = VerifyingKey::from(&signing_key);
        self.verify_ed25519_with_key(&verifying_key)
    }

    pub fn verify_ed25519_with_key(
        &self,
        verifying_key: &VerifyingKey,
    ) -> Result<(), VerificationError> {
        self.validate_output_projection()?;
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| VerificationError::InvalidSignature)?;
        if self.schema_version == 1 {
            let v1 = bincode::serialize(&receipt_unsigned_v1(self))
                .map_err(|_| VerificationError::InternalError)?;
            if verifying_key.verify(&v1, &signature).is_ok() {
                return Ok(());
            }
            if !self.legacy_fallback_eligible() {
                return Err(VerificationError::InvalidSignature);
            }
            let legacy = bincode::serialize(&legacy_receipt_unsigned(self))
                .map_err(|_| VerificationError::InternalError)?;
            return verifying_key
                .verify(&legacy, &signature)
                .map_err(|_| VerificationError::InvalidSignature);
        }
        let bytes = self.signed_payload_bytes()?;
        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }

    fn signed_payload_bytes(&self) -> Result<Vec<u8>, VerificationError> {
        self.validate_output_projection()?;
        let bytes = match self.schema_version {
            1 => bincode::serialize(&receipt_unsigned_v1(self)),
            2 if self.output_projection.is_none() => bincode::serialize(&receipt_unsigned_v2(self)),
            3 => bincode::serialize(&receipt_unsigned_v3(self)),
            _ => return Err(VerificationError::InternalError),
        };
        bytes.map_err(|_| VerificationError::InternalError)
    }

    fn legacy_fallback_eligible(&self) -> bool {
        self.schema_version == 1
            && self.context_id.is_none()
            && self.evidence_summary.is_empty()
            && self.output_projection.is_none()
    }

    fn validate_output_projection(&self) -> Result<(), VerificationError> {
        match self.schema_version {
            1 if !self.evidence_summary.is_empty() || self.output_projection.is_some() => {
                return Err(VerificationError::InternalError)
            }
            2 if self.output_projection.is_some() => return Err(VerificationError::InternalError),
            1..=3 => {}
            _ => return Err(VerificationError::InternalError),
        }
        if let Some(projection) = &self.output_projection {
            if self.kind != ReceiptKind::Execute
                || self.decision != Decision::Accepted
                || self.reason.is_some()
                || projection.schema_id.is_empty()
            {
                return Err(VerificationError::InternalError);
            }
        }
        Ok(())
    }
}

fn legacy_receipt_unsigned(receipt: &Receipt) -> LegacyReceiptUnsignedPreC4b6218 {
    LegacyReceiptUnsignedPreC4b6218 {
        receipt_id: receipt.receipt_id.clone(),
        kind: receipt.kind,
        packet_hash: receipt.packet_hash,
        session_id: receipt.session_id,
        nonce: receipt.nonce,
        opcode: receipt.opcode,
        operation: receipt.operation.clone(),
        decision: receipt.decision,
        reason: receipt.reason.clone(),
        handler_id: receipt.handler_id.clone(),
        timestamp: receipt.timestamp,
        authenticator_kind: receipt.authenticator_kind,
        signer_key_id: receipt.signer_key_id.clone(),
        signature: Vec::new(),
    }
}

fn receipt_unsigned_v1(receipt: &Receipt) -> ReceiptUnsignedV1 {
    ReceiptUnsignedV1 {
        schema_version: receipt.schema_version,
        receipt_id: receipt.receipt_id.clone(),
        context_id: receipt.context_id.clone(),
        kind: receipt.kind,
        packet_hash: receipt.packet_hash,
        session_id: receipt.session_id,
        nonce: receipt.nonce,
        opcode: receipt.opcode,
        operation: receipt.operation.clone(),
        decision: receipt.decision,
        reason: receipt.reason.clone(),
        handler_id: receipt.handler_id.clone(),
        timestamp: receipt.timestamp,
        authenticator_kind: receipt.authenticator_kind,
        signer_key_id: receipt.signer_key_id.clone(),
        signature: Vec::new(),
    }
}

fn receipt_unsigned_v2(receipt: &Receipt) -> ReceiptUnsignedV2 {
    ReceiptUnsignedV2 {
        schema_version: receipt.schema_version,
        receipt_id: receipt.receipt_id.clone(),
        context_id: receipt.context_id.clone(),
        kind: receipt.kind,
        packet_hash: receipt.packet_hash,
        session_id: receipt.session_id,
        nonce: receipt.nonce,
        opcode: receipt.opcode,
        operation: receipt.operation.clone(),
        decision: receipt.decision,
        reason: receipt.reason.clone(),
        handler_id: receipt.handler_id.clone(),
        timestamp: receipt.timestamp,
        authenticator_kind: receipt.authenticator_kind,
        signer_key_id: receipt.signer_key_id.clone(),
        evidence_summary: receipt.evidence_summary.clone(),
        signature: Vec::new(),
    }
}

fn receipt_unsigned_v3(receipt: &Receipt) -> ReceiptUnsignedV3 {
    ReceiptUnsignedV3 {
        schema_version: receipt.schema_version,
        receipt_id: receipt.receipt_id.clone(),
        context_id: receipt.context_id.clone(),
        kind: receipt.kind,
        packet_hash: receipt.packet_hash,
        session_id: receipt.session_id,
        nonce: receipt.nonce,
        opcode: receipt.opcode,
        operation: receipt.operation.clone(),
        decision: receipt.decision,
        reason: receipt.reason.clone(),
        handler_id: receipt.handler_id.clone(),
        timestamp: receipt.timestamp,
        authenticator_kind: receipt.authenticator_kind,
        signer_key_id: receipt.signer_key_id.clone(),
        evidence_summary: receipt.evidence_summary.clone(),
        output_projection: receipt.output_projection.clone(),
        signature: Vec::new(),
    }
}

fn packet_hash(packet: &ZenithPacket) -> [u8; 32] {
    let bytes = bincode::serialize(packet).unwrap_or_default();
    Sha256::digest(bytes).into()
}

fn receipt_evidence_summary(
    context: &VerifiedCallContext,
    decision: Decision,
    reason: Option<&str>,
) -> Vec<String> {
    if !context
        .evidence_summary
        .iter()
        .any(|field| field == "scoped_use_required")
    {
        return context.evidence_summary.clone();
    }

    let outcome = match (decision, reason) {
        (Decision::Accepted, None) => NullifierOutcome::ScopedUseRecorded,
        (_, Some(reason)) if reason == NullifierOutcome::DuplicateNullifier.as_str() => {
            NullifierOutcome::DuplicateNullifier
        }
        (_, Some(reason)) if reason == NullifierOutcome::DomainMismatch.as_str() => {
            NullifierOutcome::DomainMismatch
        }
        (_, Some(reason)) if reason == NullifierOutcome::MissingScopedNullifier.as_str() => {
            NullifierOutcome::MissingScopedNullifier
        }
        (_, Some(reason)) if reason == NullifierOutcome::UnsupportedScope.as_str() => {
            NullifierOutcome::UnsupportedScope
        }
        (Decision::Rejected, _) => NullifierOutcome::MissingScopedNullifier,
        (Decision::Accepted, Some(_)) => NullifierOutcome::ScopedUseRecorded,
    };

    match ScopedNullifierEvidence::from_context(context) {
        Ok(evidence) => privacy_safe_summary(
            outcome,
            Some(&evidence.domain.fingerprint()),
            Some(&evidence.commitment.fingerprint()),
        ),
        Err(_) => privacy_safe_summary(outcome, None, None),
    }
}
