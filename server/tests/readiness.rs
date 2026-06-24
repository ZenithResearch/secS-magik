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
        "/tmp/caller-registry.json",
        "/tmp/permission-policy.json",
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
    fs::write(
        &registry,
        br#"{"trusted_verifiers":[{"key_id":"verifier:operator"}]}"#,
    )
    .unwrap();
    let caller_registry = write_caller_registry_fixture("caller-registry-valid", false);
    let permission_policy = write_permission_policy_fixture("permission-policy-valid");
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry.to_str().unwrap(),
        caller_registry.to_str().unwrap(),
        permission_policy.to_str().unwrap(),
        "wallet_presentation",
    )
    .unwrap();

    validate_production_startup_readiness(&config).unwrap();

    let _ = fs::remove_file(registry);
    let _ = fs::remove_file(caller_registry);
    let _ = fs::remove_file(permission_policy);
}

#[test]
fn production_startup_validation_rejects_fixture_only_caller_registry_without_smoke() {
    let registry = temp_path("trust-registry-for-caller-check.json");
    fs::write(
        &registry,
        br#"{"trusted_verifiers":[{"key_id":"verifier:operator"}]}"#,
    )
    .unwrap();

    // Fixture-only caller registry must be refused without the explicit
    // SECS_FIXTURE_ONLY_SMOKE allowance.
    let fixture_caller_registry = write_caller_registry_fixture("caller-registry-fixture", true);
    let permission_policy = write_permission_policy_fixture("permission-policy-caller-check");
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry.to_str().unwrap(),
        fixture_caller_registry.to_str().unwrap(),
        permission_policy.to_str().unwrap(),
        "wallet_presentation",
    )
    .unwrap();
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::CallerRegistryNotReady { .. })
    ));

    // Missing and empty caller registries also fail closed.
    let missing = temp_path("missing-caller-registry.json");
    config.caller_registry_path = Some(missing);
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::CallerRegistryNotReady { .. })
    ));

    let empty = temp_path("empty-caller-registry.json");
    fs::write(&empty, br#"{"callers": []}"#).unwrap();
    config.caller_registry_path = Some(empty.clone());
    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::CallerRegistryNotReady { .. })
    ));

    let _ = fs::remove_file(registry);
    let _ = fs::remove_file(fixture_caller_registry);
    let _ = fs::remove_file(permission_policy);
    let _ = fs::remove_file(empty);
}

fn write_caller_registry_fixture(name: &str, fixture_only: bool) -> std::path::PathBuf {
    let public_key_hex = {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        key.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let path = temp_path(name);
    fs::write(
        &path,
        format!(
            r#"{{"fixture_only": {fixture_only}, "callers": [{{"key_id": "caller:test", "subject_id": "did:example:test", "algorithm": "ed25519", "public_key_hex": "{public_key_hex}"}}]}}"#
        ),
    )
    .unwrap();
    path
}

fn write_permission_policy_fixture(name: &str) -> std::path::PathBuf {
    let path = temp_path(name);
    fs::write(
        &path,
        br#"[
          {
            "caller_id": "did:example:test",
            "opcode": 16,
            "operation": "file.write",
            "resource": { "kind": "prefix", "prefix": "urn:secs:demo:" },
            "effect": "allow",
            "status": "active",
            "authority_source": "receiver_local",
            "not_before": 0,
            "not_after": 4102444800
          }
        ]"#,
    )
    .unwrap();
    path
}

#[test]
fn production_startup_validation_rejects_empty_fixture_registry_without_smoke_override() {
    let registry = temp_path("fixture-empty-trust-registry.json");
    fs::write(
        &registry,
        br#"{"fixture_only":true,"trusted_verifiers":[]}"#,
    )
    .unwrap();
    let config = production_config_with_registry(&registry);

    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::TrustRegistryNotReady { .. })
    ));

    let _ = fs::remove_file(registry);
}

#[test]
fn production_startup_validation_rejects_local_static_adapter_without_smoke_override() {
    let registry = temp_path("operator-trust-registry.json");
    fs::write(
        &registry,
        br#"{"trusted_verifiers":[{"key_id":"verifier:operator"}]}"#,
    )
    .unwrap();
    let config = production_config_with_registry(&registry);

    assert!(matches!(
        validate_production_startup_readiness(&config),
        Err(StartupReadinessError::TrustRegistryNotReady { .. })
    ));

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
        "/tmp/caller-registry.json",
        "/tmp/permission-policy.json",
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
