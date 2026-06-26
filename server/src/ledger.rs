//! Event and receipt persistence boundary.
//!
//! This module owns the local audit ledger and versioned operator inspection
//! export. It uses runtime SQL so the repo does not need to maintain SQLx
//! offline metadata yet.

use crate::public_audit::{
    public_audit_entry_hash, public_audit_root_hash, PublicAuditBundle, PublicAuditBundleStatus,
    PublicAuditChainMetadata, PublicAuditReceiptEntry, PublicAuditRedactionPolicy,
    PublicAuditSignerKey,
};
use crate::receipt::{Receipt, ReceiptEventKind};
use crate::schema::{apply_schema, LEDGER_TABLES};
use crate::verifier::VerifiedCallContext;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;

pub const OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION: u16 = 2;
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
    pub evidence_summary: Vec<String>,
}

impl OperatorReceiptInspection {
    pub const EXPORT_SCHEMA_VERSION: u16 = OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReservationOutcome {
    Reserved,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicAuditExportError {
    NotFound,
    IncompleteReceiptChain,
    UnknownSignerKey,
    Database(String),
}

impl From<sqlx::Error> for PublicAuditExportError {
    fn from(error: sqlx::Error) -> Self {
        Self::Database(error.to_string())
    }
}

#[derive(Debug, Clone)]
struct PublicAuditReceiptRow {
    receipt_id: String,
    schema_version: u16,
    context_id: Option<String>,
    timestamp: u64,
    kind: String,
    packet_hash: Vec<u8>,
    session_id: Vec<u8>,
    nonce: Vec<u8>,
    opcode: u8,
    operation: Option<String>,
    decision: String,
    reason: Option<String>,
    handler_id: Option<String>,
    authenticator_kind: String,
    signer_key_id: String,
    evidence_summary: Vec<String>,
    signature: Vec<u8>,
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
        apply_schema(&self.pool, LEDGER_TABLES).await?;
        // Prune expired replay reservations on schema init (e.g. at startup / process
        // restart). Uses wall-clock time so that any reservations whose claims expired
        // before this restart are removed. This is one of the documented trigger points
        // for #57 retention. Tests that rely on small historical timestamps insert
        // *after* the final init_schema call (or use explicit prune with controlled
        // `now`); re-calling init_schema in a retention test after inserting past data
        // will trigger prune using real now.
        // A clock-read failure makes this a safe no-op: the prune guard skips
        // deletion under the sentinel, and skipping prune never accepts
        // anything — rows are removed on the next healthy-clock trigger.
        let now = crate::clock::failclosed_unix_seconds();
        let _ = self.prune_expired_replay_reservations(now).await;
        Ok(())
    }

    pub async fn reserve_replay(
        &self,
        context: &VerifiedCallContext,
        signer_key_id: &str,
        reserved_at: u64,
    ) -> Result<ReplayReservationOutcome, sqlx::Error> {
        // Prune using the reservation's `reserved_at` as the cutoff (as-of time).
        // This is the primary "on reserve" trigger point for bounding replay
        // reservations. Errors in prune are ignored (non-fatal cleanup); a failing
        // prune should not block a legitimate new reservation.
        let _ = self.prune_expired_replay_reservations(reserved_at).await;
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

    /// Prune (DELETE) any replay reservations whose `expires_at` is strictly before `now`.
    /// Returns the number of rows deleted. This is the explicit cleanup API and is
    /// also invoked from `init_schema` (wall time) and `reserve_replay` (using call time).
    /// Used to implement #57: ensure no unbounded growth of the replay_reservations table.
    pub async fn prune_expired_replay_reservations(&self, now: u64) -> Result<u64, sqlx::Error> {
        // Under the clock-read failure sentinel every reservation would compare
        // as expired and live reservations would be mass-deleted, weakening
        // replay protection (a replayed packet would reserve afresh and execute
        // again). Skipping prune is the safe no-op; do not rely on the i64 cast
        // below wrapping the sentinel negative.
        if crate::clock::is_clock_read_failure(now) {
            return Ok(0);
        }
        let result = sqlx::query("DELETE FROM replay_reservations WHERE expires_at < ?")
            .bind(now as i64)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
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
                evidence_summary,
                signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(serde_json::to_string(&receipt.evidence_summary).unwrap_or_else(|_| "[]".to_string()))
        .bind(&receipt.signature)
        .execute(&self.pool)
        .await
        .map(|_| ())
    }

    /// Atomic (tx-wrapped) persist of a signed receipt + its ReceiptEmitted (or equivalent) event.
    /// Implements core of #25: receipt + event groups are atomic (both or neither on error).
    /// Used by record_signed_receipt paths for verify/execute/reject receipts.
    /// Does not wrap handler execution itself (per locked decision).
    /// On failure, caller sees error and can surface incomplete/audit failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_receipt_with_emitted_event(
        &self,
        receipt: &Receipt,
        event_kind: ReceiptEventKind,
        packet_hash: Option<[u8; 32]>,
        opcode: Option<u8>,
        operation: Option<&str>,
        handler_id: Option<&str>,
        reason: Option<&str>,
        timestamp: u64,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Receipt insert (dupe of record_receipt query for tx; keeps record_receipt available for other uses)
        sqlx::query(
            "INSERT INTO receipts (
                receipt_id, schema_version, context_id, timestamp, kind, packet_hash, session_id, nonce, opcode, operation, decision, reason, handler_id, authenticator_kind, signer_key_id, evidence_summary, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(serde_json::to_string(&receipt.evidence_summary).unwrap_or_else(|_| "[]".to_string()))
        .bind(&receipt.signature)
        .execute(&mut *tx)
        .await?;

        // Event insert
        let ph = packet_hash.map(|h| h.to_vec());
        sqlx::query(
            "INSERT INTO events (
                timestamp, event_kind, packet_hash, opcode, operation, handler_id, reason
            ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(timestamp as i64)
        .bind(event_kind.as_str())
        .bind(ph)
        .bind(opcode.map(i64::from))
        .bind(operation)
        .bind(handler_id)
        .bind(reason)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn export_public_audit_bundle_for_context<'a>(
        &self,
        context_id: &str,
        signer_keys: impl IntoIterator<Item = (&'a str, &'a [u8; 32])>,
        exported_at: u64,
    ) -> Result<PublicAuditBundle, PublicAuditExportError> {
        let mut signer_keys: Vec<PublicAuditSignerKey> = signer_keys
            .into_iter()
            .map(|(signer_key_id, public_key)| PublicAuditSignerKey {
                signer_key_id: signer_key_id.to_string(),
                public_key_hex: hex_lower(public_key),
            })
            .collect();
        signer_keys.sort_by(|left, right| left.signer_key_id.cmp(&right.signer_key_id));

        let rows = self.public_audit_receipts_for_context(context_id).await?;
        if rows.is_empty() {
            return Err(PublicAuditExportError::NotFound);
        }
        if rows.iter().any(|row| row.signature.is_empty()) {
            return Err(PublicAuditExportError::IncompleteReceiptChain);
        }
        if rows.iter().any(|row| {
            !signer_keys
                .iter()
                .any(|signer| signer.signer_key_id == row.signer_key_id)
        }) {
            return Err(PublicAuditExportError::UnknownSignerKey);
        }

        let mut receipts = Vec::with_capacity(rows.len());
        for row in rows {
            let mut entry = PublicAuditReceiptEntry {
                receipt_id: row.receipt_id,
                schema_version: row.schema_version,
                context_id: row.context_id,
                timestamp: row.timestamp,
                kind: row.kind,
                decision: row.decision,
                reason: row.reason,
                operation: row.operation,
                handler_id: row.handler_id,
                opcode: row.opcode,
                packet_hash_hex: hex_lower(&row.packet_hash),
                session_id_hex: hex_lower(&row.session_id),
                nonce_hex: hex_lower(&row.nonce),
                authenticator_kind: row.authenticator_kind,
                signer_key_id: row.signer_key_id,
                signature_hex: hex_lower(&row.signature),
                evidence_summary: row.evidence_summary,
                entry_hash_hex: String::new(),
            };
            entry.entry_hash_hex = public_audit_entry_hash(&entry);
            receipts.push(entry);
        }
        let first_receipt_id = receipts
            .first()
            .map(|entry| entry.receipt_id.clone())
            .ok_or(PublicAuditExportError::NotFound)?;
        let last_receipt_id = receipts
            .last()
            .map(|entry| entry.receipt_id.clone())
            .ok_or(PublicAuditExportError::NotFound)?;
        let root_hash_hex = public_audit_root_hash(&receipts);
        Ok(PublicAuditBundle {
            version: PublicAuditBundle::VERSION.to_string(),
            redaction_policy: PublicAuditRedactionPolicy::DefaultNoPayloadOrPrivateEvidence,
            status: PublicAuditBundleStatus::Complete,
            exported_at,
            chain: PublicAuditChainMetadata {
                root_hash_hex,
                first_receipt_id,
                last_receipt_id,
                receipt_count: receipts.len(),
                complete: true,
            },
            signer_keys,
            receipts,
        })
    }

    async fn public_audit_receipts_for_context(
        &self,
        context_id: &str,
    ) -> Result<Vec<PublicAuditReceiptRow>, sqlx::Error> {
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
                evidence_summary,
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

        rows.into_iter()
            .map(|row| {
                let evidence_summary = row.try_get::<String, _>("evidence_summary")?;
                let evidence_summary =
                    serde_json::from_str::<Vec<String>>(&evidence_summary).unwrap_or_default();
                Ok(PublicAuditReceiptRow {
                    receipt_id: row.try_get("receipt_id")?,
                    schema_version: row.try_get::<i64, _>("schema_version")? as u16,
                    context_id: row.try_get("context_id")?,
                    timestamp: row.try_get::<i64, _>("timestamp")? as u64,
                    kind: row.try_get("kind")?,
                    packet_hash: row.try_get("packet_hash")?,
                    session_id: row.try_get("session_id")?,
                    nonce: row.try_get("nonce")?,
                    opcode: row.try_get::<i64, _>("opcode")? as u8,
                    operation: row.try_get("operation")?,
                    decision: row.try_get("decision")?,
                    reason: row.try_get("reason")?,
                    handler_id: row.try_get("handler_id")?,
                    authenticator_kind: row.try_get("authenticator_kind")?,
                    signer_key_id: row.try_get("signer_key_id")?,
                    evidence_summary,
                    signature: row.try_get("signature")?,
                })
            })
            .collect()
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
                evidence_summary,
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
    evidence_summary,
    signature
FROM receipts
WHERE receipt_id = ?";

fn operator_inspection_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<OperatorReceiptInspection, sqlx::Error> {
    let signature: Vec<u8> = row.try_get("signature")?;
    let evidence_summary_json: String = row.try_get("evidence_summary")?;
    let evidence_summary: Vec<String> = serde_json::from_str(&evidence_summary_json)
        .map_err(|_| invalid_ledger_data("receipt evidence_summary is not valid JSON array"))?;
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
        evidence_summary,
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
