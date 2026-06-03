//! Event and receipt persistence boundary.
//!
//! This module owns the v0 local audit ledger. It uses runtime SQL so the repo
//! does not need to maintain SQLx offline metadata yet.

use crate::receipt::{Receipt, ReceiptEventKind};
use crate::verifier::VerifiedCallContext;
use sqlx::SqlitePool;

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
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                event_kind TEXT NOT NULL,
                packet_hash BLOB,
                opcode INTEGER,
                operation TEXT,
                handler_id TEXT,
                reason TEXT
            );",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                kind TEXT NOT NULL,
                packet_hash BLOB NOT NULL,
                session_id BLOB NOT NULL,
                nonce BLOB NOT NULL,
                opcode INTEGER NOT NULL,
                operation TEXT,
                decision TEXT NOT NULL,
                reason TEXT,
                handler_id TEXT,
                authenticator_kind TEXT NOT NULL,
                signer_key_id TEXT NOT NULL,
                signature BLOB NOT NULL
            );",
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS replay_reservations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reserved_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                replay_scope TEXT NOT NULL,
                session_id BLOB NOT NULL,
                opcode INTEGER NOT NULL,
                nonce BLOB NOT NULL,
                packet_hash BLOB NOT NULL,
                context_id TEXT NOT NULL,
                signer_key_id TEXT NOT NULL,
                UNIQUE(session_id, opcode, nonce, replay_scope)
            );",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
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
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&receipt.receipt_id)
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
}
