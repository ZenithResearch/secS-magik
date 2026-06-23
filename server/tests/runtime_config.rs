use serial_test::serial;
use server::config::{GatewayRuntimeConfig, RuntimeConfigError};
use server::runtime_mode::RuntimeMode;
use std::time::Duration;

fn clear_env() {
    for key in [
        "SECS_RECEIVER_AUDIENCE",
        "SECS_BIND_ADDR",
        "SECS_DB_URL",
        "SECS_LEDGER_PATH",
        "SECS_VERIFIER_KEY_PATH",
        "SECS_VERIFIER_KEY_ID",
        "SECS_TRUST_REGISTRY_PATH",
        "SECS_CALLER_REGISTRY_PATH",
        "SECS_PERMISSION_POLICY_PATH",
        "SECS_MAX_WIRE_BYTES",
        "SECS_MAX_PAYLOAD_BYTES",
        "SECS_MAX_OUTPUT_BYTES",
        "SECS_HANDLER_TIMEOUT_MS",
        "SECS_INGRESS_READ_TIMEOUT_MS",
        "SECS_MAX_IN_FLIGHT_CONNECTIONS",
        "SECS_ALLOWED_EVIDENCE_ADAPTERS",
        "SECS_FIXTURE_ONLY_SMOKE",
        "SECS_RUNTIME_MODE",
        "SECZ_RUNTIME_MODE",
    ] {
        std::env::remove_var(key);
    }
}

fn set_required_production_env() {
    std::env::set_var("SECS_RUNTIME_MODE", "production_verified");
    std::env::set_var("SECS_BIND_ADDR", "127.0.0.1:9009");
    std::env::set_var("SECS_DB_URL", "sqlite:/tmp/prod.db?mode=rwc");
    std::env::set_var("SECS_LEDGER_PATH", "/tmp/prod.db");
    std::env::set_var("SECS_RECEIVER_AUDIENCE", "secS://operator-receiver");
    std::env::set_var("SECS_VERIFIER_KEY_PATH", "/tmp/operator.key");
    std::env::set_var("SECS_TRUST_REGISTRY_PATH", "/tmp/trust-registry.json");
    std::env::set_var("SECS_CALLER_REGISTRY_PATH", "/tmp/caller-registry.json");
    std::env::set_var("SECS_PERMISSION_POLICY_PATH", "/tmp/permission-policy.json");
    std::env::set_var("SECS_MAX_WIRE_BYTES", "2097152");
    std::env::set_var("SECS_MAX_PAYLOAD_BYTES", "1048576");
    std::env::set_var("SECS_MAX_OUTPUT_BYTES", "1048576");
    std::env::set_var("SECS_HANDLER_TIMEOUT_MS", "30000");
    std::env::set_var("SECS_INGRESS_READ_TIMEOUT_MS", "10000");
    std::env::set_var("SECS_MAX_IN_FLIGHT_CONNECTIONS", "64");
}

fn write_valid_caller_registry(name: &str) -> std::path::PathBuf {
    // SigningKey::from_bytes(&[1u8; 32]).verifying_key() — fixed test key.
    let public_key_hex = {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::from_bytes(&[1u8; 32]).verifying_key();
        key.as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        format!(
            r#"{{"callers": [{{"key_id": "caller:test", "subject_id": "did:example:test", "algorithm": "ed25519", "public_key_hex": "{public_key_hex}"}}]}}"#
        ),
    )
    .expect("caller registry fixture should be writable");
    path
}

fn write_valid_trust_registry(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"trusted_verifiers":[{"id":"operator"}]}"#,
    )
    .expect("trust registry fixture should be writable");
    path
}

fn write_valid_permission_policy(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"[
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
    .expect("permission policy fixture should be writable");
    path
}

#[test]
#[serial]
fn local_dev_defaults_bind_loopback_only() {
    clear_env();
    std::env::set_var("SECS_RUNTIME_MODE", "local_dev_plaintext");

    let config = GatewayRuntimeConfig::from_env().unwrap();

    assert_eq!(config.bind_addr, "127.0.0.1:9001");
    assert!(config.fixture_only);
    clear_env();
}

#[test]
fn production_startup_rejects_unknown_evidence_adapter_names() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-adapters");
    let caller_registry_path = write_valid_caller_registry("secs-magik-caller-registry-adapters");
    let permission_policy_path = write_valid_permission_policy("secs-magik-permission-policy-adapters");
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "wallet_presentation,unknown_adapter",
    )
    .unwrap();

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    assert!(
        error.to_string().contains("unknown evidence adapter"),
        "production startup must reject unsupported evidence adapters instead of silently accepting policy typos: {error}"
    );
}

#[test]
fn production_startup_rejects_missing_permission_policy_file() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-policy-missing");
    let caller_registry_path = write_valid_caller_registry("secs-magik-caller-registry-policy-missing");
    let missing_policy_path = std::env::temp_dir().join(format!(
        "missing-permission-policy-{}.json",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing_policy_path);
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        missing_policy_path.to_str().unwrap(),
        "wallet_presentation",
    )
    .unwrap();

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    assert!(
        error.to_string().contains("permission policy"),
        "production startup must reject unreadable/missing permission policy files: {error}"
    );
}

#[test]
fn production_startup_accepts_valid_permission_policy_file() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-policy-valid");
    let caller_registry_path = write_valid_caller_registry("secs-magik-caller-registry-policy-valid");
    let permission_policy_path = write_valid_permission_policy("secs-magik-permission-policy-valid");
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "wallet_presentation",
    )
    .unwrap();

    let result = server::config::validate_production_startup_readiness(&config);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    assert!(
        result.is_ok(),
        "valid production registries and permission policy should be startup-ready: {result:?}"
    );
}


#[test]
#[serial]
fn production_config_requires_explicit_receiver_audience() {
    clear_env();
    set_required_production_env();
    std::env::remove_var("SECS_RECEIVER_AUDIENCE");

    let config = GatewayRuntimeConfig::from_env();

    assert!(matches!(
        config,
        Err(RuntimeConfigError::MissingProductionField(
            "SECS_RECEIVER_AUDIENCE"
        ))
    ));
    clear_env();
}

#[test]
#[serial]
fn secs_runtime_mode_takes_precedence_over_legacy_secz() {
    clear_env();
    set_required_production_env();
    std::env::set_var("SECS_RUNTIME_MODE", "production_verified");
    std::env::set_var("SECZ_RUNTIME_MODE", "local_dev_plaintext");

    let config = GatewayRuntimeConfig::from_env().unwrap();

    assert_eq!(config.runtime_mode, RuntimeMode::ProductionVerified);
    assert!(!config.fixture_only);
    clear_env();
}

#[test]
#[serial]
fn production_config_rejects_missing_explicit_runtime_fields() {
    for field in [
        "SECS_BIND_ADDR",
        "SECS_DB_URL",
        "SECS_LEDGER_PATH",
        "SECS_MAX_WIRE_BYTES",
        "SECS_MAX_PAYLOAD_BYTES",
        "SECS_MAX_OUTPUT_BYTES",
        "SECS_HANDLER_TIMEOUT_MS",
        "SECS_INGRESS_READ_TIMEOUT_MS",
        "SECS_MAX_IN_FLIGHT_CONNECTIONS",
        "SECS_PERMISSION_POLICY_PATH",
    ] {
        clear_env();
        set_required_production_env();
        std::env::remove_var(field);

        let config = GatewayRuntimeConfig::from_env();

        assert_eq!(
            config,
            Err(RuntimeConfigError::MissingProductionField(field))
        );
    }
    clear_env();
}

#[test]
#[serial]
fn production_config_rejects_unbounded_or_inconsistent_limits() {
    for (field, value) in [
        ("SECS_MAX_WIRE_BYTES", "2097153"),
        ("SECS_MAX_PAYLOAD_BYTES", "1048577"),
        ("SECS_MAX_OUTPUT_BYTES", "1048577"),
        ("SECS_HANDLER_TIMEOUT_MS", "300001"),
        ("SECS_INGRESS_READ_TIMEOUT_MS", "60001"),
        ("SECS_MAX_IN_FLIGHT_CONNECTIONS", "0"),
        ("SECS_MAX_IN_FLIGHT_CONNECTIONS", "4097"),
    ] {
        clear_env();
        set_required_production_env();
        std::env::set_var(field, value);

        assert!(matches!(
            GatewayRuntimeConfig::from_env(),
            Err(RuntimeConfigError::InvalidNumber { field: rejected, .. }) if rejected == field
        ));
    }

    clear_env();
    set_required_production_env();
    std::env::set_var("SECS_MAX_WIRE_BYTES", "1024");
    std::env::set_var("SECS_MAX_PAYLOAD_BYTES", "1025");
    assert_eq!(
        GatewayRuntimeConfig::from_env(),
        Err(RuntimeConfigError::PayloadExceedsWireBudget)
    );
    clear_env();
}

#[test]
#[serial]
fn production_config_rejects_db_and_ledger_path_mismatch() {
    clear_env();
    set_required_production_env();
    std::env::set_var("SECS_LEDGER_PATH", "/tmp/other-ledger.db");

    assert_eq!(
        GatewayRuntimeConfig::from_env(),
        Err(RuntimeConfigError::LedgerPathDoesNotMatchDbUrl)
    );
    clear_env();
}

#[test]
fn fixture_config_is_clearly_local_and_can_use_prototype_receiver() {
    let config = GatewayRuntimeConfig::local_fixture();

    assert_eq!(config.runtime_mode, RuntimeMode::LocalDevPlaintext);
    assert_eq!(config.receiver_audience, "secS://receiver-a");
    assert!(config.fixture_only);
}

#[test]
fn production_config_accepts_explicit_operator_runtime_fields() {
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        "/tmp/trust-registry.json",
        "/tmp/caller-registry.json",
        "/tmp/permission-policy.json",
        "local_static,wallet_presentation",
    )
    .unwrap();

    assert_eq!(config.receiver_audience, "secS://operator-receiver");
    assert_eq!(config.bind_addr, "127.0.0.1:9009");
    assert_eq!(config.max_wire_bytes, 2 * 1024 * 1024);
    assert_eq!(config.max_payload_bytes, 1024 * 1024);
    assert_eq!(config.max_output_bytes, 1024 * 1024);
    assert_eq!(config.handler_timeout, Duration::from_secs(30));
    assert_eq!(config.ingress_read_timeout, Duration::from_secs(10));
    assert_eq!(config.max_in_flight_connections, 64);
    assert_eq!(
        config.allowed_evidence_adapters,
        vec!["local_static", "wallet_presentation"]
    );
    assert_eq!(
        config.permission_policy_path.as_deref(),
        Some(std::path::Path::new("/tmp/permission-policy.json"))
    );
    assert!(!config.fixture_only);
}

#[test]
fn production_config_rejects_prototype_receiver_audience() {
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://receiver-a",
        "/tmp/operator.key",
        None,
        "/tmp/trust-registry.json",
        "/tmp/caller-registry.json",
        "/tmp/permission-policy.json",
        "local_static",
    );

    assert!(matches!(
        config,
        Err(RuntimeConfigError::PrototypeReceiverAudienceInProduction)
    ));
}

