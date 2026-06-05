//! Signed receipt and audit event boundary.
//!
//! Receipts are in-memory typed audit objects in this slice. Persistence is
//! deliberately delegated to the ledger slice, and payload bytes are not part of
//! the versioned receipt schema by default.

use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as SignatureVerifier, VerifyingKey};
use libsec_core::ZenithPacket;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const RECEIPT_SCHEMA_VERSION: u16 = 1;

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
    pub signature: Vec<u8>,
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
            signature: Vec::new(),
        }
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
        let signature = Signature::from_slice(&self.signature)
            .map_err(|_| VerificationError::InvalidSignature)?;
        let bytes = self.signed_payload_bytes()?;

        verifying_key
            .verify(&bytes, &signature)
            .map_err(|_| VerificationError::InvalidSignature)
    }

    fn signed_payload_bytes(&self) -> Result<Vec<u8>, VerificationError> {
        let mut unsigned = self.clone();
        unsigned.signature.clear();
        bincode::serialize(&unsigned).map_err(|_| VerificationError::InternalError)
    }
}

fn packet_hash(packet: &ZenithPacket) -> [u8; 32] {
    let bytes = bincode::serialize(packet).unwrap_or_default();
    Sha256::digest(bytes).into()
}
