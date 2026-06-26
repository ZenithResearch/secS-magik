//! Public audit bundle contract boundary.
//!
//! Public audit bundles are redacted, export-oriented projections of local
//! receipts. They are intentionally distinct from the local/operator SQLite
//! ledger and from any future external anchoring or publication rail.

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
