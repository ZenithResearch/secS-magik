use server::config::{GatewayRuntimeConfig, ReadinessStatus};
use server::gateway::init_telemetry_schema;
use sqlx::sqlite::SqlitePoolOptions;

#[tokio::test]
async fn readiness_reports_config_loaded_and_ledger_ready() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let config = GatewayRuntimeConfig::local_fixture();

    let readiness = config.readiness(&pool).await.unwrap();

    assert_eq!(readiness.config_loaded, ReadinessStatus::Ready);
    assert_eq!(readiness.ledger_ready, ReadinessStatus::Ready);
    assert_eq!(readiness.trust_registry_ready, ReadinessStatus::FixtureOnly);
    assert!(readiness.is_ready_for_local_smoke());
}

#[tokio::test]
async fn readiness_fails_when_ledger_schema_is_missing() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let config = GatewayRuntimeConfig::local_fixture();

    let readiness = config.readiness(&pool).await.unwrap();

    assert_eq!(readiness.ledger_ready, ReadinessStatus::NotReady);
    assert!(!readiness.is_ready_for_local_smoke());
}

#[test]
fn production_startup_validation_fails_before_binding_with_missing_trust_registry() {
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        "",
        "local_static",
    );

    assert!(config.is_err());
}
