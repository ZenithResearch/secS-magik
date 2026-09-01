//! Event and receipt persistence boundary.
//!
//! This module owns the local audit ledger and versioned operator inspection
//! export. It uses runtime SQL so the repo does not need to maintain SQLx
//! offline metadata yet.

use crate::devgraph_authority::DevgraphAuthorityReplayBindingV1;
use crate::nullifier::{NullifierCommitment, NullifierDomainV1, NullifierReason};
use crate::public_audit::{
    public_audit_entry_hash, public_audit_root_hash, sha256_hex, AuditPublisher, PublicAuditBundle,
    PublicAuditBundleStatus, PublicAuditChainMetadata, PublicAuditOutputProjection,
    PublicAuditPublicationRecord, PublicAuditPublicationStatus, PublicAuditReceiptEntry,
    PublicAuditRedactionPolicy, PublicAuditSignerKey, PUBLIC_AUDIT_CHAIN_ALGORITHM_VERSION,
};
use crate::receipt::{Receipt, ReceiptEventKind};
use crate::schema::{apply_schema, LEDGER_TABLES};
use crate::verifier::VerifiedCallContext;
use sha2::{Digest, Sha256};
use sqlx::Row;
use sqlx::SqlitePool;

pub const OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION: u16 = 3;
pub const LEDGER_REDACTION_POLICY: &str =
    "local_redacted_no_payload_or_private_evidence_by_default";

fn checked_sqlite_integer(value: u64) -> Result<i64, sqlx::Error> {
    i64::try_from(value)
        .map_err(|_| sqlx::Error::Protocol("unsigned timestamp exceeds SQLite INTEGER".into()))
}

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
    pub output_projection: Option<OperatorReceiptOutputProjection>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorReceiptOutputProjection {
    pub schema_id: String,
    pub byte_count: u64,
    pub digest_sha256_hex: String,
}

impl OperatorReceiptInspection {
    pub const EXPORT_SCHEMA_VERSION: u16 = OPERATOR_RECEIPT_EXPORT_SCHEMA_VERSION;
}

#[derive(serde::Serialize)]
struct OperatorReceiptWireV1<'a> {
    export_schema_version: u16,
    schema_version: u16,
    redaction_policy: &'static str,
    retention_policy: &'static str,
    receipt_id: &'a str,
    context_id: Option<&'a str>,
    timestamp: u64,
    kind: &'a str,
    decision: &'a str,
    reason: Option<&'a str>,
    operation: Option<&'a str>,
    handler_id: Option<&'a str>,
    opcode: u8,
    packet_hash_hex: &'a str,
    session_id_hex: &'a str,
    nonce_hex: &'a str,
    authenticator_kind: &'a str,
    signer_key_id: &'a str,
    signature_present: bool,
    signature_len: usize,
    signature_sha256_hex: Option<&'a str>,
}

#[derive(serde::Serialize)]
struct OperatorReceiptWireV2<'a> {
    export_schema_version: u16,
    schema_version: u16,
    redaction_policy: &'static str,
    retention_policy: &'static str,
    receipt_id: &'a str,
    context_id: Option<&'a str>,
    timestamp: u64,
    kind: &'a str,
    decision: &'a str,
    reason: Option<&'a str>,
    operation: Option<&'a str>,
    handler_id: Option<&'a str>,
    opcode: u8,
    packet_hash_hex: &'a str,
    session_id_hex: &'a str,
    nonce_hex: &'a str,
    authenticator_kind: &'a str,
    signer_key_id: &'a str,
    signature_present: bool,
    signature_len: usize,
    signature_sha256_hex: Option<&'a str>,
    evidence_summary: &'a [String],
}

#[derive(serde::Serialize)]
struct OperatorReceiptWireV3<'a> {
    export_schema_version: u16,
    schema_version: u16,
    redaction_policy: &'static str,
    retention_policy: &'static str,
    receipt_id: &'a str,
    context_id: Option<&'a str>,
    timestamp: u64,
    kind: &'a str,
    decision: &'a str,
    reason: Option<&'a str>,
    operation: Option<&'a str>,
    handler_id: Option<&'a str>,
    opcode: u8,
    packet_hash_hex: &'a str,
    session_id_hex: &'a str,
    nonce_hex: &'a str,
    authenticator_kind: &'a str,
    signer_key_id: &'a str,
    signature_present: bool,
    signature_len: usize,
    signature_sha256_hex: Option<&'a str>,
    evidence_summary: &'a [String],
    output_projection: Option<&'a OperatorReceiptOutputProjection>,
}

impl OperatorReceiptInspection {
    fn wire_v1(&self) -> OperatorReceiptWireV1<'_> {
        OperatorReceiptWireV1 {
            export_schema_version: self.schema_version,
            schema_version: self.schema_version,
            redaction_policy: self.redaction_policy,
            retention_policy: self.retention_policy,
            receipt_id: &self.receipt_id,
            context_id: self.context_id.as_deref(),
            timestamp: self.timestamp,
            kind: &self.kind,
            decision: &self.decision,
            reason: self.reason.as_deref(),
            operation: self.operation.as_deref(),
            handler_id: self.handler_id.as_deref(),
            opcode: self.opcode,
            packet_hash_hex: &self.packet_hash_hex,
            session_id_hex: &self.session_id_hex,
            nonce_hex: &self.nonce_hex,
            authenticator_kind: &self.authenticator_kind,
            signer_key_id: &self.signer_key_id,
            signature_present: self.signature_present,
            signature_len: self.signature_len,
            signature_sha256_hex: self.signature_sha256_hex.as_deref(),
        }
    }

    fn wire_v2(&self) -> OperatorReceiptWireV2<'_> {
        let v1 = self.wire_v1();
        OperatorReceiptWireV2 {
            export_schema_version: v1.export_schema_version,
            schema_version: v1.schema_version,
            redaction_policy: v1.redaction_policy,
            retention_policy: v1.retention_policy,
            receipt_id: v1.receipt_id,
            context_id: v1.context_id,
            timestamp: v1.timestamp,
            kind: v1.kind,
            decision: v1.decision,
            reason: v1.reason,
            operation: v1.operation,
            handler_id: v1.handler_id,
            opcode: v1.opcode,
            packet_hash_hex: v1.packet_hash_hex,
            session_id_hex: v1.session_id_hex,
            nonce_hex: v1.nonce_hex,
            authenticator_kind: v1.authenticator_kind,
            signer_key_id: v1.signer_key_id,
            signature_present: v1.signature_present,
            signature_len: v1.signature_len,
            signature_sha256_hex: v1.signature_sha256_hex,
            evidence_summary: &self.evidence_summary,
        }
    }

    fn wire_v3(&self) -> OperatorReceiptWireV3<'_> {
        let v2 = self.wire_v2();
        OperatorReceiptWireV3 {
            export_schema_version: v2.export_schema_version,
            schema_version: v2.schema_version,
            redaction_policy: v2.redaction_policy,
            retention_policy: v2.retention_policy,
            receipt_id: v2.receipt_id,
            context_id: v2.context_id,
            timestamp: v2.timestamp,
            kind: v2.kind,
            decision: v2.decision,
            reason: v2.reason,
            operation: v2.operation,
            handler_id: v2.handler_id,
            opcode: v2.opcode,
            packet_hash_hex: v2.packet_hash_hex,
            session_id_hex: v2.session_id_hex,
            nonce_hex: v2.nonce_hex,
            authenticator_kind: v2.authenticator_kind,
            signer_key_id: v2.signer_key_id,
            signature_present: v2.signature_present,
            signature_len: v2.signature_len,
            signature_sha256_hex: v2.signature_sha256_hex,
            evidence_summary: v2.evidence_summary,
            output_projection: self.output_projection.as_ref(),
        }
    }
}

impl serde::Serialize for OperatorReceiptInspection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error;

        if self.export_schema_version != self.schema_version {
            return Err(S::Error::custom(
                "operator export version does not match persisted receipt schema",
            ));
        }
        match self.schema_version {
            1 if self.evidence_summary.is_empty() && self.output_projection.is_none() => {
                serde::Serialize::serialize(&self.wire_v1(), serializer)
            }
            1 => Err(S::Error::custom(
                "operator v1 cannot disclose evidence or output projection",
            )),
            2 if self.output_projection.is_none() => {
                serde::Serialize::serialize(&self.wire_v2(), serializer)
            }
            2 => Err(S::Error::custom(
                "operator v2 cannot disclose output projection",
            )),
            3 if self.output_projection.is_none()
                || (self.kind == "execute" && self.decision == "accepted") =>
            {
                serde::Serialize::serialize(&self.wire_v3(), serializer)
            }
            3 => Err(S::Error::custom(
                "operator v3 projection requires an accepted execute receipt",
            )),
            _ => Err(S::Error::custom(
                "unsupported persisted receipt schema for operator export",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperatorReceiptExportError {
    Malformed,
    UnsupportedVersion,
    CrossVersionShape,
    InvalidProjection,
}

pub fn validate_operator_receipt_export_json(json: &str) -> Result<(), OperatorReceiptExportError> {
    use std::collections::BTreeSet;
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|_| OperatorReceiptExportError::Malformed)?;
    let object = value
        .as_object()
        .ok_or(OperatorReceiptExportError::Malformed)?;
    let version = object
        .get("export_schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(OperatorReceiptExportError::Malformed)?;
    let common = [
        "export_schema_version",
        "schema_version",
        "redaction_policy",
        "retention_policy",
        "receipt_id",
        "context_id",
        "timestamp",
        "kind",
        "decision",
        "reason",
        "operation",
        "handler_id",
        "opcode",
        "packet_hash_hex",
        "session_id_hex",
        "nonce_hex",
        "authenticator_kind",
        "signer_key_id",
        "signature_present",
        "signature_len",
        "signature_sha256_hex",
    ];
    let mut expected: BTreeSet<&str> = common.into_iter().collect();
    match version {
        1 => {}
        2 => {
            expected.insert("evidence_summary");
        }
        3 => {
            expected.insert("evidence_summary");
            expected.insert("output_projection");
        }
        _ => return Err(OperatorReceiptExportError::UnsupportedVersion),
    }
    let receipt_schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or(OperatorReceiptExportError::Malformed)?;
    if receipt_schema_version != version {
        return Err(OperatorReceiptExportError::CrossVersionShape);
    }
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if actual != expected {
        return Err(OperatorReceiptExportError::CrossVersionShape);
    }
    if version == 3 {
        if let Some(projection) = object["output_projection"].as_object() {
            let projection_keys: BTreeSet<&str> = projection.keys().map(String::as_str).collect();
            let schema_valid = projection["schema_id"]
                .as_str()
                .is_some_and(|schema| !schema.is_empty());
            let digest_valid = projection["digest_sha256_hex"]
                .as_str()
                .is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                });
            if projection_keys != BTreeSet::from(["schema_id", "byte_count", "digest_sha256_hex"])
                || !schema_valid
                || projection["byte_count"].as_u64().is_none()
                || !digest_valid
                || object["kind"].as_str() != Some("execute")
                || object["decision"].as_str() != Some("accepted")
            {
                return Err(OperatorReceiptExportError::InvalidProjection);
            }
        } else if !object["output_projection"].is_null() {
            return Err(OperatorReceiptExportError::InvalidProjection);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReservationOutcome {
    Reserved,
    Duplicate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevgraphReplayReservationOutcome {
    Reserved,
    ExactDuplicate,
    ScopeConflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopedNullifierUseOutcome {
    Recorded,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicAuditPublicationError {
    BundleVerificationFailed,
    Database(String),
}

impl From<sqlx::Error> for PublicAuditPublicationError {
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
    output_projection: Option<PublicAuditOutputProjection>,
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
        let _ = self
            .prune_expired_devgraph_authority_replay_reservations(now)
            .await;
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

    /// Atomically reserves the exact operation-scoped replay key for the
    /// portable `devgraph.issue.create.v1` producer. A duplicate is retryable
    /// only when every persisted authority binding is byte-for-byte identical.
    pub(crate) async fn reserve_devgraph_authority_replay(
        &self,
        binding: &DevgraphAuthorityReplayBindingV1,
        reserved_at: u64,
    ) -> Result<DevgraphReplayReservationOutcome, sqlx::Error> {
        self.prune_expired_devgraph_authority_replay_reservations(reserved_at)
            .await?;
        let reserved_at = checked_sqlite_integer(reserved_at)?;
        let expires_at = checked_sqlite_integer(binding.expires_at)?;
        let issued_at = checked_sqlite_integer(binding.issued_at)?;
        let receiver_policy_version = checked_sqlite_integer(binding.receiver_policy_version)?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO devgraph_authority_replay_reservations (
                reserved_at,
                expires_at,
                replay_scope,
                session_id,
                operation,
                nonce,
                actor_id,
                audience,
                resource,
                request_digest_sha256,
                idempotency_key_digest_sha256,
                receiver_policy_id,
                receiver_policy_version,
                receiver_policy_digest_sha256,
                wallet_presentation_digest_sha256,
                secs_context_id,
                secs_verifier_key_id,
                issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(reserved_at)
        .bind(expires_at)
        .bind(&binding.replay_scope)
        .bind(binding.session_id.to_vec())
        .bind(&binding.operation)
        .bind(binding.nonce.to_vec())
        .bind(&binding.actor_id)
        .bind(&binding.audience)
        .bind(&binding.resource)
        .bind(&binding.request_digest_sha256)
        .bind(&binding.idempotency_key_digest_sha256)
        .bind(&binding.receiver_policy_id)
        .bind(receiver_policy_version)
        .bind(&binding.receiver_policy_digest_sha256)
        .bind(&binding.wallet_presentation_digest_sha256)
        .bind(&binding.secs_context_id)
        .bind(&binding.secs_verifier_key_id)
        .bind(issued_at)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 1 {
            return Ok(DevgraphReplayReservationOutcome::Reserved);
        }

        let row = sqlx::query(
            "SELECT expires_at, replay_scope, actor_id, audience, resource,
                    request_digest_sha256, idempotency_key_digest_sha256,
                    receiver_policy_id, receiver_policy_version,
                    receiver_policy_digest_sha256,
                    wallet_presentation_digest_sha256, secs_context_id,
                    secs_verifier_key_id, issued_at
             FROM devgraph_authority_replay_reservations
             WHERE session_id = ? AND operation = ? AND nonce = ?",
        )
        .bind(binding.session_id.to_vec())
        .bind(&binding.operation)
        .bind(binding.nonce.to_vec())
        .fetch_one(&self.pool)
        .await?;
        let exact_duplicate = row.try_get::<i64, _>("expires_at")? == expires_at
            && row.try_get::<String, _>("replay_scope")? == binding.replay_scope
            && row.try_get::<String, _>("actor_id")? == binding.actor_id
            && row.try_get::<String, _>("audience")? == binding.audience
            && row.try_get::<String, _>("resource")? == binding.resource
            && row.try_get::<String, _>("request_digest_sha256")? == binding.request_digest_sha256
            && row.try_get::<String, _>("idempotency_key_digest_sha256")?
                == binding.idempotency_key_digest_sha256
            && row.try_get::<String, _>("receiver_policy_id")? == binding.receiver_policy_id
            && row.try_get::<i64, _>("receiver_policy_version")? == receiver_policy_version
            && row.try_get::<String, _>("receiver_policy_digest_sha256")?
                == binding.receiver_policy_digest_sha256
            && row.try_get::<String, _>("wallet_presentation_digest_sha256")?
                == binding.wallet_presentation_digest_sha256
            && row.try_get::<String, _>("secs_context_id")? == binding.secs_context_id
            && row.try_get::<String, _>("secs_verifier_key_id")? == binding.secs_verifier_key_id
            && row.try_get::<i64, _>("issued_at")? == issued_at;
        Ok(if exact_duplicate {
            DevgraphReplayReservationOutcome::ExactDuplicate
        } else {
            DevgraphReplayReservationOutcome::ScopeConflict
        })
    }

    pub async fn record_scoped_nullifier_use(
        &self,
        domain: &NullifierDomainV1,
        commitment: &NullifierCommitment,
        context: &VerifiedCallContext,
        recorded_at: u64,
    ) -> Result<ScopedNullifierUseOutcome, sqlx::Error> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO scoped_nullifier_uses (
                recorded_at,
                domain_fingerprint,
                commitment_fingerprint,
                commitment_storage_hash,
                context_id,
                operation,
                resource_kind,
                domain_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(recorded_at as i64)
        .bind(domain.fingerprint())
        .bind(commitment.fingerprint())
        .bind(commitment.storage_hash())
        .bind(&context.context_id)
        .bind(&context.operation)
        .bind(domain.resource_kind.as_str())
        .bind(&domain.domain_version)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            Ok(ScopedNullifierUseOutcome::Duplicate)
        } else {
            Ok(ScopedNullifierUseOutcome::Recorded)
        }
    }

    pub async fn scoped_nullifier_use_count(
        &self,
        domain: &NullifierDomainV1,
        commitment: &NullifierCommitment,
    ) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM scoped_nullifier_uses
             WHERE domain_fingerprint = ? AND commitment_storage_hash = ?",
        )
        .bind(domain.fingerprint())
        .bind(commitment.storage_hash())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    pub fn duplicate_nullifier_reason() -> &'static str {
        NullifierReason::DuplicateNullifier.as_str()
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

    /// Removes DG-P reservations at the contract's exact expiry boundary.
    /// A clock failure remains a safe no-op and cannot weaken replay defense.
    pub async fn prune_expired_devgraph_authority_replay_reservations(
        &self,
        now: u64,
    ) -> Result<u64, sqlx::Error> {
        if crate::clock::is_clock_read_failure(now) {
            return Ok(0);
        }
        let now = checked_sqlite_integer(now)?;
        let result =
            sqlx::query("DELETE FROM devgraph_authority_replay_reservations WHERE expires_at <= ?")
                .bind(now)
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
        let output_schema_id = receipt
            .output_projection
            .as_ref()
            .map(|value| value.schema_id.as_str());
        let output_byte_count = receipt
            .output_projection
            .as_ref()
            .and_then(|value| i64::try_from(value.byte_count).ok());
        let output_digest_sha256 = receipt
            .output_projection
            .as_ref()
            .map(|value| value.digest_sha256.to_vec());
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
                output_schema_id,
                output_byte_count,
                output_digest_sha256,
                signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(output_schema_id)
        .bind(output_byte_count)
        .bind(output_digest_sha256)
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
        let output_schema_id = receipt
            .output_projection
            .as_ref()
            .map(|value| value.schema_id.as_str());
        let output_byte_count = receipt
            .output_projection
            .as_ref()
            .and_then(|value| i64::try_from(value.byte_count).ok());
        let output_digest_sha256 = receipt
            .output_projection
            .as_ref()
            .map(|value| value.digest_sha256.to_vec());

        // Receipt insert (dupe of record_receipt query for tx; keeps record_receipt available for other uses)
        sqlx::query(
            "INSERT INTO receipts (
                receipt_id, schema_version, context_id, timestamp, kind, packet_hash, session_id, nonce, opcode, operation, decision, reason, handler_id, authenticator_kind, signer_key_id, evidence_summary, output_schema_id, output_byte_count, output_digest_sha256, signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .bind(output_schema_id)
        .bind(output_byte_count)
        .bind(output_digest_sha256)
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
        let rows = self.public_audit_receipts_for_context(context_id).await?;
        self.public_audit_bundle_from_rows(context_id, signer_keys, exported_at, rows)
    }

    pub async fn export_public_audit_bundle_for_context_range<'a>(
        &self,
        context_id: &str,
        first_receipt_id: &str,
        last_receipt_id: &str,
        signer_keys: impl IntoIterator<Item = (&'a str, &'a [u8; 32])>,
        exported_at: u64,
    ) -> Result<PublicAuditBundle, PublicAuditExportError> {
        let rows = self.public_audit_receipts_for_context(context_id).await?;
        let start = rows
            .iter()
            .position(|row| row.receipt_id == first_receipt_id)
            .ok_or(PublicAuditExportError::IncompleteReceiptChain)?;
        let end = rows
            .iter()
            .position(|row| row.receipt_id == last_receipt_id)
            .ok_or(PublicAuditExportError::IncompleteReceiptChain)?;
        if end < start {
            return Err(PublicAuditExportError::IncompleteReceiptChain);
        }
        let rows = rows[start..=end].to_vec();
        self.public_audit_bundle_from_rows(context_id, signer_keys, exported_at, rows)
    }

    fn public_audit_bundle_from_rows<'a>(
        &self,
        context_id: &str,
        signer_keys: impl IntoIterator<Item = (&'a str, &'a [u8; 32])>,
        exported_at: u64,
        rows: Vec<PublicAuditReceiptRow>,
    ) -> Result<PublicAuditBundle, PublicAuditExportError> {
        let mut signer_keys: Vec<PublicAuditSignerKey> = signer_keys
            .into_iter()
            .map(|(signer_key_id, public_key)| PublicAuditSignerKey {
                signer_key_id: signer_key_id.to_string(),
                public_key_hex: hex_lower(public_key),
            })
            .collect();
        signer_keys.sort_by(|left, right| left.signer_key_id.cmp(&right.signer_key_id));

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
        let mut previous_entry_hash_hex = None;
        for (chain_index, row) in rows.into_iter().enumerate() {
            let mut entry = PublicAuditReceiptEntry {
                chain_index,
                previous_entry_hash_hex: previous_entry_hash_hex.clone(),
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
                output_projection: row.output_projection,
                entry_hash_hex: String::new(),
            };
            entry.entry_hash_hex = public_audit_entry_hash(&entry);
            previous_entry_hash_hex = Some(entry.entry_hash_hex.clone());
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
                algorithm_version: PUBLIC_AUDIT_CHAIN_ALGORITHM_VERSION.to_string(),
                chain_scope: format!("context:{context_id}"),
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
                output_schema_id,
                output_byte_count,
                output_digest_sha256,
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
                let kind: String = row.try_get("kind")?;
                let decision: String = row.try_get("decision")?;
                let output_projection =
                    output_projection_from_row(&row, &kind, &decision)?.map(|projection| {
                        PublicAuditOutputProjection {
                            schema_id: projection.schema_id,
                            byte_count: projection.byte_count,
                            digest_sha256_hex: projection.digest_sha256_hex,
                        }
                    });
                Ok(PublicAuditReceiptRow {
                    receipt_id: row.try_get("receipt_id")?,
                    schema_version: row.try_get::<i64, _>("schema_version")? as u16,
                    context_id: row.try_get("context_id")?,
                    timestamp: row.try_get::<i64, _>("timestamp")? as u64,
                    kind,
                    packet_hash: row.try_get("packet_hash")?,
                    session_id: row.try_get("session_id")?,
                    nonce: row.try_get("nonce")?,
                    opcode: row.try_get::<i64, _>("opcode")? as u8,
                    operation: row.try_get("operation")?,
                    decision,
                    reason: row.try_get("reason")?,
                    handler_id: row.try_get("handler_id")?,
                    authenticator_kind: row.try_get("authenticator_kind")?,
                    signer_key_id: row.try_get("signer_key_id")?,
                    evidence_summary,
                    output_projection,
                    signature: row.try_get("signature")?,
                })
            })
            .collect()
    }

    pub async fn publish_public_audit_bundle(
        &self,
        bundle: &PublicAuditBundle,
        publisher: &impl AuditPublisher,
        now: u64,
    ) -> Result<PublicAuditPublicationRecord, PublicAuditPublicationError> {
        bundle
            .verify_local_public_audit()
            .map_err(|_| PublicAuditPublicationError::BundleVerificationFailed)?;
        let outcome = publisher.publish_public_audit_bundle(bundle);
        let idempotency_key = public_audit_publication_idempotency_key(
            &bundle.version,
            &bundle.chain.algorithm_version,
            &bundle.chain.chain_scope,
            &bundle.chain.root_hash_hex,
            bundle.chain.receipt_count,
            &outcome.target_kind,
        );
        let published_at = if outcome.status == PublicAuditPublicationStatus::Published {
            Some(now)
        } else {
            None
        };
        sqlx::query(
            "INSERT INTO audit_publication_status (
                idempotency_key,
                bundle_version,
                chain_algorithm_version,
                chain_scope,
                root_hash_hex,
                receipt_count,
                target_kind,
                target_ref_digest_hex,
                status,
                attempt_count,
                last_error,
                published_at,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
            ON CONFLICT(idempotency_key) DO UPDATE SET
                target_ref_digest_hex = excluded.target_ref_digest_hex,
                status = excluded.status,
                attempt_count = audit_publication_status.attempt_count + 1,
                last_error = excluded.last_error,
                published_at = COALESCE(excluded.published_at, audit_publication_status.published_at),
                updated_at = excluded.updated_at",
        )
        .bind(&idempotency_key)
        .bind(&bundle.version)
        .bind(&bundle.chain.algorithm_version)
        .bind(&bundle.chain.chain_scope)
        .bind(&bundle.chain.root_hash_hex)
        .bind(bundle.chain.receipt_count as i64)
        .bind(&outcome.target_kind)
        .bind(&outcome.target_ref_digest_hex)
        .bind(outcome.status.as_str())
        .bind(&outcome.error)
        .bind(published_at.map(|value| value as i64))
        .bind(now as i64)
        .execute(&self.pool)
        .await?;
        self.audit_publication_status_by_idempotency_key(&idempotency_key)
            .await?
            .ok_or_else(|| {
                PublicAuditPublicationError::Database(
                    "missing publication status after upsert".to_string(),
                )
            })
    }

    pub async fn audit_publication_statuses_for_root(
        &self,
        root_hash_hex: &str,
    ) -> Result<Vec<PublicAuditPublicationRecord>, PublicAuditPublicationError> {
        let rows = sqlx::query(
            "SELECT
                idempotency_key,
                bundle_version,
                chain_algorithm_version,
                chain_scope,
                root_hash_hex,
                receipt_count,
                target_kind,
                target_ref_digest_hex,
                status,
                attempt_count,
                last_error,
                published_at,
                updated_at
            FROM audit_publication_status
            WHERE root_hash_hex = ?
            ORDER BY target_kind ASC, idempotency_key ASC",
        )
        .bind(root_hash_hex)
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(publication_record_from_row).collect()
    }

    async fn audit_publication_status_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<PublicAuditPublicationRecord>, PublicAuditPublicationError> {
        let row = sqlx::query(
            "SELECT
                idempotency_key,
                bundle_version,
                chain_algorithm_version,
                chain_scope,
                root_hash_hex,
                receipt_count,
                target_kind,
                target_ref_digest_hex,
                status,
                attempt_count,
                last_error,
                published_at,
                updated_at
            FROM audit_publication_status
            WHERE idempotency_key = ?",
        )
        .bind(idempotency_key)
        .fetch_optional(&self.pool)
        .await?;
        row.map(publication_record_from_row).transpose()
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
                output_schema_id,
                output_byte_count,
                output_digest_sha256,
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
    output_schema_id,
    output_byte_count,
    output_digest_sha256,
    signature
FROM receipts
WHERE receipt_id = ?";

fn public_audit_publication_idempotency_key(
    bundle_version: &str,
    chain_algorithm_version: &str,
    chain_scope: &str,
    root_hash_hex: &str,
    receipt_count: usize,
    target_kind: &str,
) -> String {
    sha256_hex(
        format!(
            "{bundle_version}|{chain_algorithm_version}|{chain_scope}|{root_hash_hex}|{receipt_count}|{target_kind}"
        )
        .as_bytes(),
    )
}

fn publication_record_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<PublicAuditPublicationRecord, PublicAuditPublicationError> {
    let status: String = row.try_get("status")?;
    let status = match status.as_str() {
        "pending" => PublicAuditPublicationStatus::Pending,
        "published" => PublicAuditPublicationStatus::Published,
        "failed" => PublicAuditPublicationStatus::Failed,
        other => {
            return Err(PublicAuditPublicationError::Database(format!(
                "unknown audit publication status: {other}"
            )))
        }
    };
    Ok(PublicAuditPublicationRecord {
        idempotency_key: row.try_get("idempotency_key")?,
        bundle_version: row.try_get("bundle_version")?,
        chain_algorithm_version: row.try_get("chain_algorithm_version")?,
        chain_scope: row.try_get("chain_scope")?,
        root_hash_hex: row.try_get("root_hash_hex")?,
        receipt_count: row.try_get::<i64, _>("receipt_count")? as usize,
        target_kind: row.try_get("target_kind")?,
        target_ref_digest_hex: row.try_get("target_ref_digest_hex")?,
        status,
        attempt_count: row.try_get::<i64, _>("attempt_count")? as u64,
        last_error: row.try_get("last_error")?,
        published_at: row
            .try_get::<Option<i64>, _>("published_at")?
            .map(|value| value as u64),
        updated_at: row.try_get::<i64, _>("updated_at")? as u64,
    })
}

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
    let kind: String = row.try_get("kind")?;
    let decision: String = row.try_get("decision")?;
    let output_projection = output_projection_from_row(&row, &kind, &decision)?;

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
        export_schema_version: schema_version,
        schema_version,
        redaction_policy: LEDGER_REDACTION_POLICY,
        retention_policy: "local_sqlite_operator_retained_until_database_rotation_or_deletion",
        receipt_id: row.try_get("receipt_id")?,
        context_id: row.try_get("context_id")?,
        timestamp,
        kind,
        decision,
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
        output_projection,
    })
}

fn output_projection_from_row(
    row: &sqlx::sqlite::SqliteRow,
    kind: &str,
    decision: &str,
) -> Result<Option<OperatorReceiptOutputProjection>, sqlx::Error> {
    let schema_id: Option<String> = row.try_get("output_schema_id")?;
    let byte_count: Option<i64> = row.try_get("output_byte_count")?;
    let digest: Option<Vec<u8>> = row.try_get("output_digest_sha256")?;
    match (schema_id, byte_count, digest) {
        (None, None, None) => Ok(None),
        (Some(schema_id), Some(byte_count), Some(digest)) => {
            if schema_id.is_empty() || kind != "execute" || decision != "accepted" {
                return Err(invalid_ledger_data(
                    "receipt output projection is not valid for this receipt",
                ));
            }
            let byte_count = u64::try_from(byte_count)
                .map_err(|_| invalid_ledger_data("receipt output byte count is negative"))?;
            require_blob_len("output_digest_sha256", &digest, 32)?;
            Ok(Some(OperatorReceiptOutputProjection {
                schema_id,
                byte_count,
                digest_sha256_hex: hex_lower(&digest),
            }))
        }
        _ => Err(invalid_ledger_data(
            "receipt output projection triple is incomplete",
        )),
    }
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
