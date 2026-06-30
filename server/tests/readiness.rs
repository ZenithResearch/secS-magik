use server::config::{
    validate_production_startup_readiness, DreggLiveSourceConfig, GatewayRuntimeConfig,
    ReadinessStatus, StartupReadinessError,
};
use server::gateway::init_telemetry_schema;
use sqlx::sqlite::SqlitePoolOptions;
use std::fs;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn write_valid_dregg_authority_snapshot_fixture(name: &str) -> std::path::PathBuf {
    let path = temp_path(name);
    fs::write(
        &path,
        br#"{
          "schema_version": "secs-dregg-authority-snapshot-v1",
          "snapshot_id": "dregg-snapshot:readiness:001",
          "source_node_id": "dregg-node:readiness",
          "federation_id": "castalia-demo",
          "entity_id": "did:example:david-lab",
          "namespace_id": "castalia-demo:david-lab",
          "entity_display_name": "David Lab Demo Entity",
          "observed_at": 0,
          "expires_at": 4102444800,
          "authority_mode": "fixture_snapshot",
          "issuers": [{
            "issuer_id": "did:example:david-lab#issuer-1",
            "issuer_key_id": "pubkey:sha256:david-lab-issuer-1",
            "trust_root_ref": "trust-root:david-lab-demo",
            "authority_root_ref": "dregg-root:local-demo",
            "accepted_evidence": ["provisioning_credential"],
            "accepted_audiences": ["secS://operator-receiver"],
            "accepted_operations": ["resource.provision"],
            "accepted_resources": ["resource://david-lab/*"],
            "status": "active",
            "not_before": 0,
            "not_after": 4102444800,
            "status_ref": "dregg-status:david-lab-issuer-active"
          }],
          "resources": [{
            "resource_id": "resource://david-lab/demo-agent",
            "resource_kind": "agent",
            "controller_entity_id": "did:example:david-lab",
            "allowed_operations": ["resource.provision"],
            "required_evidence": ["provisioning_credential"],
            "status": "active",
            "status_ref": "dregg-status:david-lab-resource-active"
          }]
        }"#,
    )
    .unwrap();
    path
}

#[tokio::test]
async fn readiness_reports_snapshot_source_status_when_snapshot_adapter_is_enabled() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let registry = temp_path("readiness-trust-registry-snapshot.json");
    fs::write(
        &registry,
        br#"{"trusted_verifiers":[{"key_id":"verifier:operator"}]}"#,
    )
    .unwrap();
    let caller_registry =
        write_caller_registry_fixture("readiness-caller-registry-snapshot", false);
    let permission_policy = write_permission_policy_fixture("readiness-permission-policy-snapshot");
    let snapshot = write_valid_dregg_authority_snapshot_fixture("readiness-dregg-snapshot-valid");
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry.to_str().unwrap(),
        caller_registry.to_str().unwrap(),
        permission_policy.to_str().unwrap(),
        "dregg_authority_snapshot",
    )
    .unwrap();
    config.dregg_authority_snapshot_path = Some(snapshot.clone());

    let readiness = config.readiness(&pool).await.unwrap();

    let _ = fs::remove_file(registry);
    let _ = fs::remove_file(caller_registry);
    let _ = fs::remove_file(permission_policy);
    let _ = fs::remove_file(snapshot);
    assert_eq!(
        readiness.dregg_authority_snapshot_ready,
        ReadinessStatus::Ready
    );
    assert!(readiness.is_ready_for_local_smoke());
}

#[tokio::test]
async fn readiness_reports_live_source_status_without_network_calls() {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    let registry = temp_path("readiness-trust-registry-live-source.json");
    fs::write(
        &registry,
        br#"{"trusted_verifiers":[{"key_id":"verifier:operator"}]}"#,
    )
    .unwrap();
    let caller_registry = write_caller_registry_fixture("readiness-caller-registry-live", false);
    let permission_policy = write_permission_policy_fixture("readiness-permission-policy-live");
    let token = temp_path("readiness-dregg-live-source-token");
    fs::write(&token, "owner-private-token\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:0",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry.to_str().unwrap(),
        caller_registry.to_str().unwrap(),
        permission_policy.to_str().unwrap(),
        "dregg_live_source",
    )
    .unwrap();
    config.dregg_live_source = Some(DreggLiveSourceConfig {
        url: "https://dregg.example.test/authority".to_string(),
        auth_token_path: token.clone(),
        timeout: Duration::from_secs(5),
        retry_max: 2,
        cache_ttl: Duration::from_secs(30),
        stale_max: Duration::from_secs(300),
    });

    let readiness = config.readiness(&pool).await.unwrap();

    let _ = fs::remove_file(registry);
    let _ = fs::remove_file(caller_registry);
    let _ = fs::remove_file(permission_policy);
    let _ = fs::remove_file(token);
    assert_eq!(readiness.dregg_live_source_ready, ReadinessStatus::Ready);
    assert!(readiness.is_ready_for_local_smoke());
}
