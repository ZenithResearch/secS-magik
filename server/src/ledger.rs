//! Event and receipt persistence boundary.
//!
//! This module owns the local audit ledger and versioned operator inspection
//! export. It uses runtime SQL so the repo does not need to maintain SQLx
//! offline metadata yet.

use crate::receipt::{Receipt, ReceiptEventKind};
use crate::schema::{apply_schema, LEDGER_TABLES};
use crate::verifier::VerifiedCallContext;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;

pub const OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION: u16 = 1;
pub const LEDGER_REDACTION_POLICY: &str =
    "local_redacted_no_payload_or_private_evidence_by_default";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorReceiptInspection {
    pub export_schema_version: u16,
    pub schema_version: u16,
    pub redaction_policy: &'static str,
    pub retention_policy: &'static str,
    pub receipt_id: String,
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
    pub signature_present: bool,
    pub signature_len: usize,
    pub signature_sha256_hex: Option<String>,
}

impl OperatorReceiptInspection {
    pub const EXPORT_SCHEMA_VERSION: u16 = OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReservationOutcome {
    Reserved,
    Duplicate,
}

#[derive(Clone)]
pub struct Ledger {
    pool: SqlitePool,
}

impl Ledger {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn init_schema(&self) -> Result<(), sqlx::Error> {
        apply_schema(&self.pool, LEDGER_TABLES).await
    }

    pub async fn reserve_replay(
        &self,
        context: &VerifiedCallContext,
        signer_key_id: &str,
        reserved_at: u64,
    ) -> Result<ReplayReservationOutcome, sqlx::Error> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO replay_reservations (
                reserved_at,
                expires_at,
                replay_scope,
                session_id,
                opcode,
                nonce,
                packet_hash,
                context_id,
                signer_key_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(reserved_at as i64)
        .bind(context.expires_at as i64)
        .bind(&context.replay_scope)
        .bind(context.session_id.to_vec())
        .bind(i64::from(context.opcode))
        .bind(context.nonce.to_vec())
        .bind(context.packet_hash.to_vec())
        .bind(&context.context_id)
        .bind(signer_key_id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            Ok(ReplayReservationOutcome::Duplicate)
        } else {
            Ok(ReplayReservationOutcome::Reserved)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_event(
        &self,
        event_kind: ReceiptEventKind,
        packet_hash: Option<[u8; 32]>,
        opcode: Option<u8>,
        operation: Option<&str>,
        handler_id: Option<&str>,
        reason: Option<&str>,
        timestamp: u64,
    ) -> Result<(), sqlx::Error> {
        let packet_hash = packet_hash.map(|hash| hash.to_vec());
        sqlx::query(
            "INSERT INTO events (
                timestamp, event_kind, packet_hash, opcode, operation, handler_id, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(timestamp as i64)
        .bind(event_kind.as_str())
        .bind(packet_hash)
        .bind(opcode.map(i64::from))
        .bind(operation)
        .bind(handler_id)
        .bind(reason)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    pub async fn record_receipt(&self, receipt: &Receipt) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO receipts (
                receipt_id,
                schema_version,
                context_id,
                timestamp,
                kind,
                packet_hash,
                session_id,
                nonce,
                opcode,
                operation,
                decision,
                reason,
                handler_id,
                authenticator_kind,
                signer_key_id,
                signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&receipt.receipt_id)
        .bind(i64::from(receipt.schema_version))
        .bind(receipt.context_id.as_deref())
        .bind(receipt.timestamp as i64)
        .bind(receipt.kind.as_str())
        .bind(receipt.packet_hash.to_vec())
        .bind(receipt.session_id.to_vec())
        .bind(receipt.nonce.to_vec())
        .bind(i64::from(receipt.opcode))
        .bind(receipt.operation.as_deref())
        .bind(receipt.decision.as_str())
        .bind(receipt.reason.as_deref())
        .bind(receipt.handler_id.as_deref())
        .bind(receipt.authenticator_kind.as_str())
        .bind(&receipt.signer_key_id)
        .bind(&receipt.signature)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    pub async fn inspect_receipt_by_id(
        &self,
        receipt_id: &str,
    ) -> Result<Option<OperatorReceiptInspection>, sqlx::Error> {
        let row = sqlx::query(OPERATOR_RECEIPT_SELECT_SQL)
            .bind(receipt_id)
            .fetch_optional(&self.pool)
            .await?;

        row.map(operator_inspection_from_row).transpose()
    }

    pub async fn inspect_receipt_chain_by_context_id(
        &self,
        context_id: &str,
    ) -> Result<Vec<OperatorReceiptInspection>, sqlx::Error> {
        let rows = sqlx::query(
            "SELECT
                receipt_id,
                schema_version,
                context_id,
                timestamp,
                kind,
                packet_hash,
                session_id,
                nonce,
                opcode,
                operation,
                decision,
                reason,
                handler_id,
                authenticator_kind,
                signer_key_id,
                signature
            FROM receipts
            WHERE context_id = ?
            ORDER BY timestamp ASC,
                CASE kind
                    WHEN 'verify' THEN 0
                    WHEN 'execute' THEN 1
                    WHEN 'reject' THEN 2
                    WHEN 'forward' THEN 3
                    ELSE 4
                END,
                receipt_id ASC",
        )
        .bind(context_id)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(operator_inspection_from_row).collect()
    }
}

const OPERATOR_RECEIPT_SELECT_SQL: &str = "SELECT
    receipt_id,
    schema_version,
    context_id,
    timestamp,
    kind,
    packet_hash,
    session_id,
    nonce,
    opcode,
    operation,
    decision,
    reason,
    handler_id,
    authenticator_kind,
    signer_key_id,
    signature
FROM receipts
WHERE receipt_id = ?";

fn operator_inspection_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<OperatorReceiptInspection, sqlx::Error> {
    let signature: Vec<u8> = row.try_get("signature")?;
    let signature_sha256_hex = if signature.is_empty() {
        None
    } else {
        Some(hex_lower(&Sha256::digest(&signature)))
    };
    let schema_version: i64 = row.try_get("schema_version")?;
    let opcode: i64 = row.try_get("opcode")?;
    let timestamp: i64 = row.try_get("timestamp")?;
    let packet_hash: Vec<u8> = row.try_get("packet_hash")?;
    let session_id: Vec<u8> = row.try_get("session_id")?;
    let nonce: Vec<u8> = row.try_get("nonce")?;

    let schema_version = u16::try_from(schema_version)
        .map_err(|_| invalid_ledger_data("receipt schema_version is outside u16 range"))?;
    let timestamp = u64::try_from(timestamp)
        .map_err(|_| invalid_ledger_data("receipt timestamp is negative"))?;
    let opcode = u8::try_from(opcode)
        .map_err(|_| invalid_ledger_data("receipt opcode is outside u8 range"))?;
    require_blob_len("packet_hash", &packet_hash, 32)?;
    require_blob_len("session_id", &session_id, 16)?;
    require_blob_len("nonce", &nonce, 12)?;

    Ok(OperatorReceiptInspection {
        export_schema_version: OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION,
        schema_version,
        redaction_policy: LEDGER_REDACTION_POLICY,
        retention_policy: "local_sqlite_operator_retained_until_database_rotation_or_deletion",
        receipt_id: row.try_get("receipt_id")?,
        context_id: row.try_get("context_id")?,
        timestamp,
        kind: row.try_get("kind")?,
        decision: row.try_get("decision")?,
        reason: row.try_get("reason")?,
        operation: row.try_get("operation")?,
        handler_id: row.try_get("handler_id")?,
        opcode,
        packet_hash_hex: hex_lower(&packet_hash),
        session_id_hex: hex_lower(&session_id),
        nonce_hex: hex_lower(&nonce),
        authenticator_kind: row.try_get("authenticator_kind")?,
        signer_key_id: row.try_get("signer_key_id")?,
        signature_present: !signature.is_empty(),
        signature_len: signature.len(),
        signature_sha256_hex,
    })
}

fn require_blob_len(field: &str, bytes: &[u8], expected: usize) -> Result<(), sqlx::Error> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(invalid_ledger_data(&format!(
            "receipt {field} length {} does not match expected {expected}",
            bytes.len()
        )))
    }
}

fn invalid_ledger_data(message: &str) -> sqlx::Error {
    sqlx::Error::Protocol(message.to_string())
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}
