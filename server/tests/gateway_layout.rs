use async_trait::async_trait;
use server::gateway::{init_telemetry_schema, ConfigurableRouter, MachineProgram};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

struct CountingProgram {
    calls: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
}

#[async_trait]
impl MachineProgram for CountingProgram {
    async fn execute(&self, payload: &[u8]) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.bytes.fetch_add(payload.len(), Ordering::SeqCst);
    }
}

async fn memory_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

#[tokio::test]
async fn gateway_router_lives_in_library_and_records_telemetry() {
    let calls = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::clone(&bytes),
        }),
    );

    router.route(0x10, b"payload".to_vec()).await;

    let row: (i64, i64) =
        sqlx::query_as("SELECT opcode, payload_size FROM node_telemetry ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (0x10, 7));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(bytes.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn gateway_router_rejects_unmapped_opcode_without_executing_program() {
    let calls = Arc::new(AtomicUsize::new(0));
    let pool = memory_pool().await;
    let mut router = ConfigurableRouter::new(pool.clone());
    router.register(
        0x10,
        Box::new(CountingProgram {
            calls: Arc::clone(&calls),
            bytes: Arc::new(AtomicUsize::new(0)),
        }),
    );

    router.route(0x99, b"ignored".to_vec()).await;

    let row: (i64, i64) =
        sqlx::query_as("SELECT opcode, payload_size FROM node_telemetry ORDER BY id DESC LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(row, (0x99, 7));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
