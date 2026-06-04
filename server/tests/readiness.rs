use server::config::{
    validate_production_startup_readiness, GatewayRuntimeConfig, ReadinessStatus,
    StartupReadinessError,
};
use server::gateway::init_telemetry_schema;
use sqlx::sqlite::SqlitePoolOptions;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

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

#[test]
fn production_startup_validation_rejects_nonexistent_nonregular_and_malformed_registry() {
    let missing = temp_path("missing-trust-registry.json");
    let mut config = production_config_with_registry(&missing);
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::TrustRegistryNotReady { .. })
    ));

    let dir = temp_path("trust-registry-dir");
    fs::create_dir_all(&dir).unwrap();
    config.trust_registry_path = Some(dir.clone());
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::TrustRegistryNotReady { .. })
    ));
    let _ = fs::remove_dir_all(&dir);

    let malformed = temp_path("malformed-trust-registry.json");
    fs::write(&malformed, b"not-json").unwrap();
    config.trust_registry_path = Some(malformed.clone());
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::TrustRegistryNotReady { .. })
    ));
    let _ = fs::remove_file(&malformed);
}

#[test]
fn production_startup_validation_accepts_regular_json_registry() {
    let registry = temp_path("trust-registry.json");
    fs::write(&registry, br#"{"issuers":[]}"#).unwrap();
    let config = production_config_with_registry(&registry);

    validate_production_startup_readiness(&config).unwrap();

    let _ = fs::remove_file(registry);
}

fn production_config_with_registry(path: &std::path::Path) -> GatewayRuntimeConfig {
    GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        path.to_str().unwrap(),
        "local_static",
    )
    .unwrap()
}

fn temp_path(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("secs-magik-{name}-{nanos}"))
}
