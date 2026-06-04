use serial_test::serial;
use server::config::{GatewayRuntimeConfig, RuntimeConfigError};
use server::runtime_mode::RuntimeMode;
use std::time::Duration;

fn clear_env() {
    for key in [
        "SECS_RECEIVER_AUDIENCE",
        "SECS_BIND_ADDR",
        "SECS_DB_URL",
        "SECS_VERIFIER_KEY_PATH",
        "SECS_VERIFIER_KEY_ID",
        "SECS_TRUST_REGISTRY_PATH",
        "SECS_MAX_WIRE_BYTES",
        "SECS_MAX_PAYLOAD_BYTES",
        "SECS_HANDLER_TIMEOUT_MS",
        "SECS_INGRESS_READ_TIMEOUT_MS",
        "SECS_ALLOWED_EVIDENCE_ADAPTERS",
        "SECS_RUNTIME_MODE",
        "SECZ_RUNTIME_MODE",
    ] {
        std::env::remove_var(key);
    }
}

#[test]
#[serial]
fn production_config_requires_explicit_receiver_audience() {
    clear_env();
    std::env::set_var("SECS_RUNTIME_MODE", "production_verified");
    std::env::set_var("SECS_VERIFIER_KEY_PATH", "/tmp/fixture.key");
    std::env::set_var("SECS_TRUST_REGISTRY_PATH", "/tmp/trust-registry.json");

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
        "local_static,wallet_presentation",
    )
    .unwrap();

    assert_eq!(config.receiver_audience, "secS://operator-receiver");
    assert_eq!(config.bind_addr, "127.0.0.1:9009");
    assert_eq!(config.max_wire_bytes, 2 * 1024 * 1024);
    assert_eq!(config.max_payload_bytes, 1024 * 1024);
    assert_eq!(config.handler_timeout, Duration::from_secs(30));
    assert_eq!(config.ingress_read_timeout, Duration::from_secs(10));
    assert_eq!(
        config.allowed_evidence_adapters,
        vec!["local_static", "wallet_presentation"]
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
        "local_static",
    );

    assert!(matches!(
        config,
        Err(RuntimeConfigError::PrototypeReceiverAudienceInProduction)
    ));
}
