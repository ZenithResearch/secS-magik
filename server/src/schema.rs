//! Runtime schema ontology for local SQLite-backed server surfaces.
//!
//! DDL lives here so runtime modules do not carry inline table definitions. This
//! is intentionally still runtime SQL: secS-magik is not using SQLx offline
//! metadata or migrations yet, but table ownership and uniqueness boundaries are
//! named in one place.

use sqlx::SqlitePool;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeTable {
    pub name: &'static str,
    pub ddl: &'static str,
}

pub const EVENTS_TABLE: RuntimeTable = RuntimeTable {
    name: "events",
    ddl: "CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER NOT NULL,
        event_kind TEXT NOT NULL,
        packet_hash BLOB,
        opcode INTEGER,
        operation TEXT,
        handler_id TEXT,
        reason TEXT
    );",
};

pub const RECEIPTS_TABLE: RuntimeTable = RuntimeTable {
    name: "receipts",
    ddl: "CREATE TABLE IF NOT EXISTS receipts (
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
};

pub const REPLAY_RESERVATIONS_TABLE: RuntimeTable = RuntimeTable {
    name: "replay_reservations",
    ddl: "CREATE TABLE IF NOT EXISTS replay_reservations (
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
};

pub const NODE_TELEMETRY_TABLE: RuntimeTable = RuntimeTable {
    name: "node_telemetry",
    ddl: "CREATE TABLE IF NOT EXISTS node_telemetry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        opcode INTEGER NOT NULL,
        payload_size INTEGER NOT NULL,
        operation TEXT NOT NULL DEFAULT 'unverified.prototype'
    );",
};

pub const LEDGER_TABLES: &[RuntimeTable] =
    &[EVENTS_TABLE, RECEIPTS_TABLE, REPLAY_RESERVATIONS_TABLE];
pub const TELEMETRY_TABLES: &[RuntimeTable] = &[NODE_TELEMETRY_TABLE];

pub async fn apply_schema(pool: &SqlitePool, tables: &[RuntimeTable]) -> Result<(), sqlx::Error> {
    for table in tables {
        sqlx::query(table.ddl).execute(pool).await?;
    }
    Ok(())
}
