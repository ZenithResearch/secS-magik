use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serial_test::serial;
use server::identity::{
    explicit_test_fixture_identity, load_node_verifier_identity, IdentityConfigError,
    VerifierIdentityConfig,
};
use server::receipt::{AuthenticatorKind, Decision, Receipt};
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerifiedCallContext, VerifiedSubject};

fn unique_temp_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("secs-magik-{name}-{nanos}.key"))
}

fn write_key_file(bytes: [u8; 32]) -> PathBuf {
    let path = unique_temp_path("identity-key-config");
    fs::write(&path, hex_encode(&bytes)).expect("key fixture should be writable");
    path
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sample_context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 1,
        context_id: "ctx_identity_config".to_string(),
        packet_hash: [3u8; 32],
        session_id: [4u8; 16],
        nonce: [5u8; 12],
        opcode: 0x10,
        operation: "membership.provision".to_string(),
        subject: VerifiedSubject {
            subject_id: "did:example:node-operator".to_string(),
            key_id: "did:example:node-operator#key-1".to_string(),
        },
        audience: "secs://receiver-a".to_string(),
        evidence_summary: vec!["membership.provision.fixture".to_string()],
        capability_result: "allowed".to_string(),
        credential_result: "accepted".to_string(),
        issued_at: 100,
        expires_at: 200,
        replay_scope: "session:opcode:nonce".to_string(),
        handler_id: Some("membership_provision".to_string()),
    }
}

fn clear_identity_env() {
    std::env::remove_var("SECS_RUNTIME_MODE");
    std::env::remove_var("SECZ_RUNTIME_MODE");
    std::env::remove_var("SECS_VERIFIER_KEY_PATH");
    std::env::remove_var("SECS_VERIFIER_KEY_ID");
}

#[test]
#[serial]
fn identity_key_config_from_env_reads_operator_visible_key_path_and_id() {
    clear_identity_env();
    let path = write_key_file([0x21; 32]);
    std::env::set_var("SECS_RUNTIME_MODE", "production_verified");
    std::env::set_var("SECS_VERIFIER_KEY_PATH", &path);
    std::env::set_var("SECS_VERIFIER_KEY_ID", "node-verifier:env-configured");

    let config = VerifierIdentityConfig::from_env();
    let identity =
        load_node_verifier_identity(&config).expect("env-configured identity should load");

    assert_eq!(config.runtime_mode, RuntimeMode::ProductionVerified);
    assert_eq!(config.verifier_key_path.as_ref(), Some(&path));
    assert_eq!(identity.signer_key_id(), "node-verifier:env-configured");
    assert_eq!(identity.secret_key_bytes(), [0x21; 32]);

    clear_identity_env();
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_config_production_verified_requires_explicit_key_path() {
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: None,
        verifier_key_id: Some("node-verifier:test".to_string()),
    };

    let err = load_node_verifier_identity(&config)
        .expect_err("production_verified must fail before signing without explicit key path");

    assert_eq!(err, IdentityConfigError::MissingVerifierKeyPath);
}

#[test]
fn identity_key_config_malformed_key_path_is_typed_config_failure() {
    let path = write_key_file([0x42; 32]);
    fs::write(&path, "not-a-32-byte-ed25519-secret")
        .expect("malformed key fixture should be writable");
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    };

    let err = load_node_verifier_identity(&config)
        .expect_err("malformed verifier key must fail as identity config, not fallback");

    assert_eq!(err, IdentityConfigError::MalformedVerifierKey);
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_config_inaccessible_key_path_is_typed_config_failure() {
    let path = unique_temp_path("missing-identity-key-config");
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path),
        verifier_key_id: None,
    };

    let err = load_node_verifier_identity(&config)
        .expect_err("missing verifier key file must fail closed before signing");

    assert!(matches!(
        err,
        IdentityConfigError::KeyFileInaccessible { .. }
    ));
}

#[test]
fn identity_key_config_loads_operator_key_and_exposes_signer_key_id() {
    let path = write_key_file([0x11; 32]);
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: Some("node-verifier:operator-configured".to_string()),
    };

    let identity = load_node_verifier_identity(&config).expect("valid explicit key should load");

    assert_eq!(
        identity.signer_key_id(),
        "node-verifier:operator-configured"
    );
    assert_eq!(
        identity.authenticator_kind(),
        AuthenticatorKind::Ed25519NodeAndVerifier
    );
    assert_eq!(identity.secret_key_bytes(), [0x11; 32]);
    assert_eq!(identity.public_key().as_bytes().len(), 32);
    let signed_context = identity
        .sign_context(sample_context())
        .expect("loaded operator key should sign verified contexts");
    assert_eq!(
        signed_context.signer_key_id,
        "node-verifier:operator-configured"
    );
    signed_context
        .verify_ed25519(&identity.secret_key_bytes(), "secs://receiver-a", 150)
        .expect("configured public key should verify the signed context");

    let unsigned_receipt = Receipt::execution(
        "receipt-identity-config",
        &signed_context.context,
        Decision::Accepted,
        None,
        151,
    );
    let signed_receipt = identity
        .sign_receipt(unsigned_receipt)
        .expect("loaded operator key should sign receipts");
    assert_eq!(
        signed_receipt.signer_key_id,
        "node-verifier:operator-configured"
    );
    signed_receipt
        .verify_ed25519_with_key(identity.public_key())
        .expect("configured public key should verify the signed receipt");
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_config_local_dev_uses_only_explicit_fixture_helper() {
    let identity = explicit_test_fixture_identity("node-verifier:test-fixture", [0x07; 32]);

    assert_eq!(identity.signer_key_id(), "node-verifier:test-fixture");
    assert_eq!(identity.secret_key_bytes(), [0x07; 32]);
    assert_eq!(
        identity.authenticator_kind(),
        AuthenticatorKind::LocalDevUntrusted
    );
}
