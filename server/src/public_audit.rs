//! Public audit bundle contract boundary.
//!
//! Public audit bundles are redacted, export-oriented projections of local
//! receipts. They are intentionally distinct from the local/operator SQLite
//! ledger and from any future external anchoring or publication rail.

use crate::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptKind};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PUBLIC_AUDIT_BUNDLE_VERSION: &str = "secs-public-audit-bundle-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditRedactionPolicy {
    DefaultNoPayloadOrPrivateEvidence,
}

impl PublicAuditRedactionPolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DefaultNoPayloadOrPrivateEvidence => "default_no_payload_or_private_evidence",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicAuditBundleStatus {
    Complete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAuditSignerKey {
    pub signer_key_id: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAuditChainMetadata {
    pub root_hash_hex: String,
    pub first_receipt_id: String,
    pub last_receipt_id: String,
    pub receipt_count: usize,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAuditReceiptEntry {
    pub receipt_id: String,
    pub schema_version: u16,
    pub context_id: Option<String>,
    pub timestamp: u64,
    pub kind: String,
    pub decision: String,
    pub reason: Option<String>,
    pub operation: Option<String>,
    pub handler_id: Option<String>,
    pub opcode: u8,
    pub packet_hash_hex: String,
    pub session_id_hex: String,
    pub nonce_hex: String,
    pub authenticator_kind: String,
    pub signer_key_id: String,
    pub signature_hex: String,
    pub evidence_summary: Vec<String>,
    pub entry_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAuditBundle {
    pub version: String,
    pub redaction_policy: PublicAuditRedactionPolicy,
    pub status: PublicAuditBundleStatus,
    pub exported_at: u64,
    pub chain: PublicAuditChainMetadata,
    pub signer_keys: Vec<PublicAuditSignerKey>,
    pub receipts: Vec<PublicAuditReceiptEntry>,
}

impl PublicAuditBundle {
    pub const VERSION: &'static str = PUBLIC_AUDIT_BUNDLE_VERSION;
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

pub fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn public_audit_entry_hash(entry: &PublicAuditReceiptEntry) -> String {
    let mut entry = entry.clone();
    entry.entry_hash_hex.clear();
    let bytes = serde_json::to_vec(&entry).unwrap_or_default();
    sha256_hex(&bytes)
}

pub fn public_audit_root_hash(entries: &[PublicAuditReceiptEntry]) -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(PUBLIC_AUDIT_BUNDLE_VERSION.as_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry.entry_hash_hex.as_bytes());
    }
    sha256_hex(&bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicAuditVerificationError {
    UnsupportedBundleVersion,
    IncompleteBundle,
    ReceiptCountMismatch,
    ChainEndpointMismatch,
    ChainRootMismatch,
    ReceiptEntryHashMismatch,
    UnknownSignerKey,
    InvalidSignerPublicKey,
    InvalidReceiptField,
    InvalidReceiptSignature,
    RedactionViolation,
}

impl PublicAuditBundle {
    pub fn verify_local_public_audit(&self) -> Result<(), PublicAuditVerificationError> {
        if self.version != Self::VERSION {
            return Err(PublicAuditVerificationError::UnsupportedBundleVersion);
        }
        if self.status != PublicAuditBundleStatus::Complete || !self.chain.complete {
            return Err(PublicAuditVerificationError::IncompleteBundle);
        }
        if self.chain.receipt_count != self.receipts.len() {
            return Err(PublicAuditVerificationError::ReceiptCountMismatch);
        }
        let first = self
            .receipts
            .first()
            .ok_or(PublicAuditVerificationError::IncompleteBundle)?;
        let last = self
            .receipts
            .last()
            .ok_or(PublicAuditVerificationError::IncompleteBundle)?;
        if self.chain.first_receipt_id != first.receipt_id
            || self.chain.last_receipt_id != last.receipt_id
        {
            return Err(PublicAuditVerificationError::ChainEndpointMismatch);
        }
        for entry in &self.receipts {
            if entry.entry_hash_hex != public_audit_entry_hash(entry) {
                return Err(PublicAuditVerificationError::ReceiptEntryHashMismatch);
            }
            let json = serde_json::to_string(entry).unwrap_or_default();
            if json.contains("raw_payload") || json.contains("raw_private_evidence") {
                return Err(PublicAuditVerificationError::RedactionViolation);
            }
            let signer = self
                .signer_keys
                .iter()
                .find(|signer| signer.signer_key_id == entry.signer_key_id)
                .ok_or(PublicAuditVerificationError::UnknownSignerKey)?;
            let public_key = verifying_key_from_hex(&signer.public_key_hex)?;
            let receipt = entry.to_receipt()?;
            receipt
                .verify_ed25519_with_key(&public_key)
                .map_err(|_| PublicAuditVerificationError::InvalidReceiptSignature)?;
        }
        if self.chain.root_hash_hex != public_audit_root_hash(&self.receipts) {
            return Err(PublicAuditVerificationError::ChainRootMismatch);
        }
        Ok(())
    }
}

impl PublicAuditReceiptEntry {
    fn to_receipt(&self) -> Result<Receipt, PublicAuditVerificationError> {
        Ok(Receipt {
            schema_version: self.schema_version,
            receipt_id: self.receipt_id.clone(),
            context_id: self.context_id.clone(),
            kind: parse_kind(&self.kind)?,
            packet_hash: fixed_hex::<32>(&self.packet_hash_hex)?,
            session_id: fixed_hex::<16>(&self.session_id_hex)?,
            nonce: fixed_hex::<12>(&self.nonce_hex)?,
            opcode: self.opcode,
            operation: self.operation.clone(),
            decision: parse_decision(&self.decision)?,
            reason: self.reason.clone(),
            handler_id: self.handler_id.clone(),
            timestamp: self.timestamp,
            authenticator_kind: parse_authenticator_kind(&self.authenticator_kind)?,
            signer_key_id: self.signer_key_id.clone(),
            evidence_summary: self.evidence_summary.clone(),
            signature: decode_hex(&self.signature_hex)?,
        })
    }
}

fn parse_kind(value: &str) -> Result<ReceiptKind, PublicAuditVerificationError> {
    match value {
        "reject" => Ok(ReceiptKind::Reject),
        "verify" => Ok(ReceiptKind::Verify),
        "execute" => Ok(ReceiptKind::Execute),
        "forward" => Ok(ReceiptKind::Forward),
        _ => Err(PublicAuditVerificationError::InvalidReceiptField),
    }
}

fn parse_decision(value: &str) -> Result<Decision, PublicAuditVerificationError> {
    match value {
        "accepted" => Ok(Decision::Accepted),
        "rejected" => Ok(Decision::Rejected),
        _ => Err(PublicAuditVerificationError::InvalidReceiptField),
    }
}

fn parse_authenticator_kind(
    value: &str,
) -> Result<AuthenticatorKind, PublicAuditVerificationError> {
    match value {
        "local_dev_untrusted" => Ok(AuthenticatorKind::LocalDevUntrusted),
        "local_mac" => Ok(AuthenticatorKind::LocalMac),
        "ed25519_node" => Ok(AuthenticatorKind::Ed25519Node),
        "ed25519_verifier" => Ok(AuthenticatorKind::Ed25519Verifier),
        "ed25519_node_and_verifier" => Ok(AuthenticatorKind::Ed25519NodeAndVerifier),
        "external_anchor" => Ok(AuthenticatorKind::ExternalAnchor),
        _ => Err(PublicAuditVerificationError::InvalidReceiptField),
    }
}

fn verifying_key_from_hex(value: &str) -> Result<VerifyingKey, PublicAuditVerificationError> {
    let bytes = fixed_hex::<32>(value)?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|_| PublicAuditVerificationError::InvalidSignerPublicKey)
}

fn fixed_hex<const N: usize>(value: &str) -> Result<[u8; N], PublicAuditVerificationError> {
    let bytes = decode_hex(value)?;
    bytes
        .try_into()
        .map_err(|_| PublicAuditVerificationError::InvalidReceiptField)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, PublicAuditVerificationError> {
    if !value.len().is_multiple_of(2) {
        return Err(PublicAuditVerificationError::InvalidReceiptField);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let chars: Vec<u8> = value.as_bytes().to_vec();
    for pair in chars.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, PublicAuditVerificationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(PublicAuditVerificationError::InvalidReceiptField),
    }
}
