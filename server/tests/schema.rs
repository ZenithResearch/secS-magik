use server::ontology::{DEFAULT_RECEIVER_AUDIENCE, PROTOTYPE_LOCAL_SUBJECT};
use server::schema::{LEDGER_TABLES, REPLAY_RESERVATIONS_TABLE};
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn ledger_schema_ontology_names_all_runtime_tables() {
    assert_eq!(DEFAULT_RECEIVER_AUDIENCE, "secS://receiver-a");
    assert_eq!(PROTOTYPE_LOCAL_SUBJECT, "prototype.local-dev.subject");
    assert_eq!(REPLAY_RESERVATIONS_TABLE.name, "replay_reservations");

    let names: Vec<&str> = LEDGER_TABLES.iter().map(|table| table.name).collect();
    assert_eq!(names, vec!["events", "receipts", "replay_reservations"]);
}

#[tokio::test]
async fn ledger_schema_ontology_contains_unique_replay_boundary() {
    let replay = REPLAY_RESERVATIONS_TABLE;

    assert!(
        replay
            .ddl
            .contains("UNIQUE(session_id, opcode, nonce, replay_scope)"),
        "replay DDL must preserve the Track C replay uniqueness boundary"
    );
    assert!(
        !replay
            .ddl
            .contains("CREATE TABLE IF NOT EXISTS node_telemetry"),
        "telemetry schema should remain separate from the replay/receipt ledger ontology"
    );
}

#[tokio::test]
async fn ledger_schema_ontology_applies_as_a_unit() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();

    for table in LEDGER_TABLES {
        sqlx::query(table.ddl).execute(&pool).await.unwrap();
    }

    for table in LEDGER_TABLES {
        let exists: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?")
                .bind(table.name)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            exists.0, 1,
            "{} should be created by schema ontology",
            table.name
        );
    }
}
