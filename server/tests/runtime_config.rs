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
        "SECS_DREGG_AUTHORITY_REGISTRY_PATH",
        "SECS_DREGG_LIVE_REVOCATION_ROOTS_PATH",
        "SECS_DREGG_BLS_FINALITY_COMMITTEES_PATH",
        "SECS_MAX_WIRE_BYTES",
        "SECS_MAX_PAYLOAD_BYTES",
        "SECS_MAX_OUTPUT_BYTES",
        "SECS_HANDLER_TIMEOUT_MS",
        "SECS_INGRESS_READ_TIMEOUT_MS",
        "SECS_MAX_IN_FLIGHT_CONNECTIONS",
        "SECS_ALLOWED_EVIDENCE_ADAPTERS",
        "SECS_TUNNEL_X25519_SECRET_HEX",
        "SECZ_TUNNEL_X25519_SECRET_HEX",
        "SECS_TUNNEL_NEXT_X25519_SECRET_HEX",
        "SECZ_TUNNEL_NEXT_X25519_SECRET_HEX",
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
    std::env::set_var(
        "SECS_TUNNEL_X25519_SECRET_HEX",
        "0808080808080808080808080808080808080808080808080808080808080808",
    );
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
    std::fs::write(&path, r#"{"trusted_verifiers":[{"id":"operator"}]}"#)
        .expect("trust registry fixture should be writable");
    path
}

fn write_valid_dregg_authority_registry(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"[
          {
            "issuer_id": "did:dregg:fixture:issuer",
            "issuer_key_id": "dregg-issuer-key:fixture-1",
            "issuer_public_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "federation_id": "dregg-federation:fixture",
            "root_ref": "dregg-root:fixture-root-2026q2",
            "root_fingerprint": "root:sha256:fixture-root-2026q2",
            "epoch_id": "epoch:2026q2",
            "epoch_not_before": 1770000000,
            "epoch_not_after": 1777776000,
            "accepted_audiences": ["secS://operator-receiver"],
            "accepted_operations": ["membership.provision"],
            "accepted_resources": ["application/json"],
            "accepted_suites": ["dregg_authority_fixture_v1"],
            "status_policy": {
              "require_status": true,
              "max_status_age_seconds": 300,
              "require_revocation_check": true,
              "require_finality": false
            },
            "root_status": "active",
            "issuer_status": "active"
          }
        ]"#,
    )
    .expect("Dregg authority registry fixture should be writable");
    path
}

fn write_live_required_dregg_authority_registry(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"[
          {
            "issuer_id": "did:dregg:fixture:issuer",
            "issuer_key_id": "dregg-issuer-key:fixture-1",
            "issuer_public_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "federation_id": "dregg-federation:fixture",
            "root_ref": "dregg-root:fixture-root-2026q2",
            "root_fingerprint": "root:sha256:fixture-root-2026q2",
            "epoch_id": "epoch:2026q2",
            "epoch_not_before": 1770000000,
            "epoch_not_after": 1777776000,
            "accepted_audiences": ["secS://operator-receiver"],
            "accepted_operations": ["membership.provision"],
            "accepted_resources": ["application/json"],
            "accepted_suites": ["dregg_authority_fixture_v1"],
            "status_policy": {
              "require_status": true,
              "max_status_age_seconds": 300,
              "require_revocation_check": true,
              "require_finality": false,
              "revocation_verifier_mode": "live_revocation_verifier_required"
            },
            "root_status": "active",
            "issuer_status": "active"
          }
        ]"#,
    )
    .expect("live-required Dregg authority registry fixture should be writable");
    path
}

fn write_bls_required_dregg_authority_registry(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"[
          {
            "issuer_id": "did:dregg:fixture:issuer",
            "issuer_key_id": "dregg-issuer-key:fixture-1",
            "issuer_public_key_hex": "1111111111111111111111111111111111111111111111111111111111111111",
            "federation_id": "dregg-federation:fixture",
            "root_ref": "dregg-root:fixture-root-2026q2",
            "root_fingerprint": "root:sha256:fixture-root-2026q2",
            "epoch_id": "epoch:2026q2",
            "epoch_not_before": 1770000000,
            "epoch_not_after": 1777776000,
            "accepted_audiences": ["secS://operator-receiver"],
            "accepted_operations": ["membership.provision"],
            "accepted_resources": ["application/json"],
            "accepted_suites": ["dregg_authority_fixture_v1"],
            "status_policy": {
              "require_status": true,
              "max_status_age_seconds": 300,
              "require_revocation_check": false,
              "require_finality": true,
              "finality_mode": "bls_threshold_required"
            },
            "root_status": "active",
            "issuer_status": "active"
          }
        ]"#,
    )
    .expect("BLS-required Dregg registry fixture should be writable");
    path
}

fn write_valid_bls_finality_committees(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"committees":[{"federation_id":"dregg-federation:fixture","committee_id":"committee:fixture-2026q2","epoch_id":"epoch:2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","quorum_threshold":3,"member_count":4,"not_before":1770000000,"not_after":1777776000}]}"#,
    )
    .expect("BLS committee fixture should be writable");
    path
}

fn write_valid_live_revocation_roots(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{name}-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"trusted_roots":[{"federation_id":"dregg-federation:fixture","issuer_id":"did:dregg:fixture:issuer","root_ref":"dregg-root:fixture-root-2026q2","root_fingerprint":"root:sha256:fixture-root-2026q2","epoch_id":"epoch:2026q2","not_before":1770000000,"not_after":1777776000}]}"#,
    )
    .expect("live Dregg revocation roots fixture should be writable");
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
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-adapters");
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
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-policy-missing");
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
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-policy-valid");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-valid");
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
fn production_config_requires_valid_tunnel_x25519_secret() {
    clear_env();
    set_required_production_env();
    std::env::remove_var("SECS_TUNNEL_X25519_SECRET_HEX");
    assert_eq!(
        GatewayRuntimeConfig::from_env(),
        Err(RuntimeConfigError::MissingProductionField(
            "SECS_TUNNEL_X25519_SECRET_HEX"
        ))
    );

    set_required_production_env();
    std::env::set_var("SECS_TUNNEL_X25519_SECRET_HEX", "not-hex");
    assert_eq!(
        GatewayRuntimeConfig::from_env(),
        Err(RuntimeConfigError::InvalidTunnelX25519Secret)
    );
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

#[test]
fn production_startup_rejects_dregg_authority_adapter_without_registry_path() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-dregg-missing");
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-dregg-missing");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-dregg-missing");
    let config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "wallet_presentation,dregg_authority",
    )
    .unwrap();

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    assert!(
        error.to_string().contains("production Dregg authority registry")
            && error.to_string().contains("missing Dregg authority registry path"),
        "production startup must reject dregg_authority adapter without SECS_DREGG_AUTHORITY_REGISTRY_PATH: {error}"
    );
}

#[test]
fn production_startup_accepts_dregg_authority_adapter_with_registry_path() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-dregg-valid");
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-dregg-valid");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-dregg-valid");
    let dregg_registry_path =
        write_valid_dregg_authority_registry("secs-magik-dregg-authority-valid");
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "wallet_presentation,dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    let result = server::config::validate_production_startup_readiness(&config);
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    assert!(
        result.is_ok(),
        "valid Dregg authority registry should make dregg_authority adapter startup-ready: {result:?}"
    );
}

#[test]
fn production_startup_rejects_empty_dregg_authority_registry() {
    let registry_path = write_valid_trust_registry("secs-magik-trust-registry-dregg-empty");
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-dregg-empty");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-dregg-empty");
    let dregg_registry_path =
        std::env::temp_dir().join(format!("empty-dregg-authority-{}.json", std::process::id()));
    std::fs::write(&dregg_registry_path, "[]").unwrap();
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();
    let _ = std::fs::remove_file(registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    assert!(
        error
            .to_string()
            .contains("production Dregg authority registry has no issuer/root entries"),
        "production startup must reject empty Dregg authority registries: {error}"
    );
}

#[test]
#[serial]
fn production_config_reports_current_and_next_tunnel_key_id_without_secret() {
    clear_env();
    set_required_production_env();
    std::env::set_var(
        "SECS_TUNNEL_NEXT_X25519_SECRET_HEX",
        "0909090909090909090909090909090909090909090909090909090909090909",
    );

    let config = GatewayRuntimeConfig::from_env().expect("production config should load");
    let summary = config
        .tunnel_key_lifecycle_summary()
        .expect("summary should exist");

    assert!(summary.current_key_id.starts_with("tunnel:x25519:"));
    assert!(summary
        .next_key_id
        .as_ref()
        .unwrap()
        .starts_with("tunnel:x25519:"));
    assert_ne!(
        summary.current_key_id,
        *summary.next_key_id.as_ref().unwrap()
    );
    let debug = format!("{summary:?}");
    assert!(!debug.contains("0808080808080808"));
    assert!(!debug.contains("0909090909090909"));

    clear_env();
}

#[test]
#[serial]
fn production_startup_rejects_live_dregg_required_registry_without_live_verifier_dependency() {
    clear_env();
    let trust_registry_path = write_valid_trust_registry("secs-magik-trust-registry-live-dregg");
    let caller_registry_path = write_valid_caller_registry("secs-magik-caller-registry-live-dregg");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-live-dregg");
    let dregg_registry_path =
        write_live_required_dregg_authority_registry("secs-magik-dregg-live-required");
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        trust_registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();

    let _ = std::fs::remove_file(trust_registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    assert!(
        error.to_string().contains("live Dregg revocation verifier dependency"),
        "production readiness must not report ready when registry requires a live Dregg verifier that is not configured: {error}"
    );
}

#[test]
#[serial]
fn production_startup_accepts_live_dregg_revocation_registry_with_live_root_config() {
    clear_env();
    let trust_registry_path = write_valid_trust_registry("secs-magik-trust-registry-live-dregg-ok");
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-live-dregg-ok");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-live-dregg-ok");
    let dregg_registry_path =
        write_live_required_dregg_authority_registry("secs-magik-dregg-live-required-ok");
    let live_roots_path = write_valid_live_revocation_roots("secs-magik-live-revocation-roots-ok");
    std::env::set_var("SECS_DREGG_LIVE_REVOCATION_ROOTS_PATH", &live_roots_path);
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        trust_registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    server::config::validate_production_startup_readiness(&config).unwrap();

    let _ = std::fs::remove_file(trust_registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    let _ = std::fs::remove_file(live_roots_path);
    clear_env();
}

#[test]
#[serial]
fn production_startup_rejects_bls_required_registry_without_bls_committee_config() {
    clear_env();
    let trust_registry_path = write_valid_trust_registry("secs-magik-trust-registry-bls-dregg");
    let caller_registry_path = write_valid_caller_registry("secs-magik-caller-registry-bls-dregg");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-bls-dregg");
    let dregg_registry_path =
        write_bls_required_dregg_authority_registry("secs-magik-dregg-bls-required");
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        trust_registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    let error = server::config::validate_production_startup_readiness(&config).unwrap_err();

    let _ = std::fs::remove_file(trust_registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    clear_env();
    assert!(
        error.to_string().contains("live Dregg BLS finality verifier dependency"),
        "production readiness must reject BLS-required Dregg registry without committee config: {error}"
    );
}

#[test]
#[serial]
fn production_startup_accepts_bls_required_registry_with_bls_committee_config() {
    clear_env();
    let trust_registry_path = write_valid_trust_registry("secs-magik-trust-registry-bls-dregg-ok");
    let caller_registry_path =
        write_valid_caller_registry("secs-magik-caller-registry-bls-dregg-ok");
    let permission_policy_path =
        write_valid_permission_policy("secs-magik-permission-policy-bls-dregg-ok");
    let dregg_registry_path =
        write_bls_required_dregg_authority_registry("secs-magik-dregg-bls-required-ok");
    let committee_path = write_valid_bls_finality_committees("secs-magik-bls-committees-ok");
    std::env::set_var("SECS_DREGG_BLS_FINALITY_COMMITTEES_PATH", &committee_path);
    let mut config = GatewayRuntimeConfig::production_for_tests(
        "127.0.0.1:9009",
        "sqlite:prod.db?mode=rwc",
        "secS://operator-receiver",
        "/tmp/operator.key",
        Some("verifier:operator"),
        trust_registry_path.to_str().unwrap(),
        caller_registry_path.to_str().unwrap(),
        permission_policy_path.to_str().unwrap(),
        "dregg_authority",
    )
    .unwrap();
    config.dregg_authority_registry_path = Some(dregg_registry_path.clone());

    server::config::validate_production_startup_readiness(&config).unwrap();

    let _ = std::fs::remove_file(trust_registry_path);
    let _ = std::fs::remove_file(caller_registry_path);
    let _ = std::fs::remove_file(permission_policy_path);
    let _ = std::fs::remove_file(dregg_registry_path);
    let _ = std::fs::remove_file(committee_path);
    clear_env();
}
