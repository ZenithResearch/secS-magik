use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serial_test::serial;
use server::identity::{
    derive_ed25519_key_id, explicit_test_fixture_identity, load_node_verifier_identity,
    IdentityConfigError, PublicVerifierKey, PublicVerifierKeyRegistry, VerificationKeyStatus,
    VerifierIdentityConfig,
};
use server::receipt::{AuthenticatorKind, Decision, Receipt};
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerificationError, VerifiedCallContext, VerifiedSubject};

const KEY_VALID_NOW: u64 = 150;

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("key fixture should be owner-private");
    }
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
    assert_eq!(identity.public_key().as_bytes().len(), 32);

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
    assert_eq!(identity.public_key().as_bytes().len(), 32);
    let signed_context = identity
        .sign_context(sample_context())
        .expect("loaded operator key should sign verified contexts");
    assert_eq!(
        signed_context.signer_key_id,
        "node-verifier:operator-configured"
    );
    signed_context
        .verify_ed25519_with_key(identity.public_key(), "secs://receiver-a", 150)
        .expect("configured public key should verify the signed context");
    let registry = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
    registry
        .verify_production_signed_context(&signed_context, "secs://receiver-a", 150)
        .expect("configured non-local identity should satisfy production context authority");

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
    registry
        .verify_production_receipt_at(&signed_receipt, 151)
        .expect("configured non-local identity should satisfy production receipt authority");
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_id_rejects_unsafe_explicit_override_that_looks_like_path_or_secret() {
    let path = write_key_file([0x71; 32]);
    for unsafe_key_id in [
        "/tmp/node-verifier.ed25519",
        "relative/path/key",
        "3131313131313131313131313131313131313131313131313131313131313131",
    ] {
        let config = VerifierIdentityConfig {
            runtime_mode: RuntimeMode::ProductionVerified,
            verifier_key_path: Some(path.clone()),
            verifier_key_id: Some(unsafe_key_id.to_string()),
        };

        let err = load_node_verifier_identity(&config)
            .expect_err("unsafe key id overrides must not encode paths or key material");

        assert_eq!(err, IdentityConfigError::UnsafeVerifierKeyId);
    }
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_config_local_dev_uses_only_explicit_fixture_helper() {
    let identity = explicit_test_fixture_identity("node-verifier:test-fixture", [0x07; 32]);

    assert_eq!(identity.signer_key_id(), "node-verifier:test-fixture");
    assert_eq!(identity.public_key().as_bytes().len(), 32);
    assert_eq!(
        identity.authenticator_kind(),
        AuthenticatorKind::LocalDevUntrusted
    );
}

#[test]
fn identity_key_id_is_stable_for_same_key_and_changes_for_different_key() {
    let first = explicit_test_fixture_identity("ignored:first", [0x31; 32]);
    let same = explicit_test_fixture_identity("ignored:same", [0x31; 32]);
    let different = explicit_test_fixture_identity("ignored:different", [0x32; 32]);

    let first_id = derive_ed25519_key_id(first.public_key());
    let same_id = derive_ed25519_key_id(same.public_key());
    let different_id = derive_ed25519_key_id(different.public_key());

    assert_eq!(first_id, same_id);
    assert_ne!(first_id, different_id);
    assert!(first_id.starts_with("ed25519:"));
    assert!(!first_id.contains('/'));
    assert!(!first_id.contains("31".repeat(16).as_str()));
}

#[test]
fn identity_key_id_defaults_to_public_key_fingerprint_for_contexts_and_receipts() {
    let path = write_key_file([0x41; 32]);
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    };

    let identity = load_node_verifier_identity(&config).expect("valid explicit key should load");
    let expected_key_id = derive_ed25519_key_id(identity.public_key());
    let signed_context = identity
        .sign_context(sample_context())
        .expect("identity should sign context with deterministic key id");
    let signed_receipt = identity
        .sign_receipt(Receipt::execution(
            "receipt-key-id",
            &signed_context.context,
            Decision::Accepted,
            None,
            160,
        ))
        .expect("identity should sign receipt with deterministic key id");

    assert_eq!(identity.signer_key_id(), expected_key_id);
    assert_eq!(signed_context.signer_key_id, expected_key_id);
    assert_eq!(signed_receipt.signer_key_id, expected_key_id);
    let _ = fs::remove_file(path);
}

#[test]
fn identity_key_id_registry_rejects_unknown_key_id_and_wrong_key() {
    let trusted = explicit_test_fixture_identity("ignored:trusted", [0x51; 32]);
    let untrusted = explicit_test_fixture_identity("ignored:untrusted", [0x52; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([
        trusted.public_verifier_key(),
        untrusted.public_verifier_key(),
    ]);
    let unknown = explicit_test_fixture_identity("ignored:unknown", [0x53; 32]);

    let trusted_context = trusted
        .sign_context(sample_context())
        .expect("trusted identity should sign context");
    registry
        .verify_signed_context(&trusted_context, "secs://receiver-a", 150)
        .expect("registered key id should verify");

    let unknown_context = unknown
        .sign_context(sample_context())
        .expect("unknown identity should sign context");
    registry
        .verify_signed_context(&unknown_context, "secs://receiver-a", 150)
        .expect_err("unknown key id must fail through registry seam");

    let mut mismatched_context = trusted_context.clone();
    mismatched_context.signer_key_id = derive_ed25519_key_id(untrusted.public_key());
    registry
        .verify_signed_context(&mismatched_context, "secs://receiver-a", 150)
        .expect_err("declared key id must select the verifying key, so wrong key fails");
}

#[test]
fn identity_key_id_registry_verifies_receipts_by_declared_key_id() {
    let trusted = explicit_test_fixture_identity("ignored:trusted-receipt", [0x61; 32]);
    let untrusted = explicit_test_fixture_identity("ignored:untrusted-receipt", [0x62; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([trusted.public_verifier_key()]);
    let signed_context = trusted
        .sign_context(sample_context())
        .expect("trusted identity should sign context");
    let receipt = Receipt::execution(
        "receipt-registry-key-id",
        &signed_context.context,
        Decision::Accepted,
        None,
        170,
    );
    let signed_receipt = trusted
        .sign_receipt(receipt)
        .expect("trusted identity should sign receipt");

    registry
        .verify_receipt_at(&signed_receipt, 170)
        .expect("registered receipt key id should verify");

    let mut mismatched_receipt = signed_receipt.clone();
    mismatched_receipt.signer_key_id = derive_ed25519_key_id(untrusted.public_key());
    registry
        .verify_receipt_at(&mismatched_receipt, 170)
        .expect_err("receipt verification must fail when declared key id selects another key");
}

#[test]
fn identity_key_status_public_verifier_key_active_defaults_to_non_production_authority() {
    let signer = explicit_test_fixture_identity("node-verifier:explicit-non-prod", [0x79; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([PublicVerifierKey::active(
        signer.signer_key_id(),
        "ed25519",
        *signer.public_key(),
    )]);
    let signed_context = sample_context()
        .sign_ed25519(
            signer.signer_key_id(),
            &[0x79; 32],
            AuthenticatorKind::Ed25519NodeAndVerifier,
        )
        .expect("non-local-shaped context should sign");

    registry
        .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
        .expect("normal registry lookup should still verify when the key is active");
    assert_eq!(
        registry
            .verify_production_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UntrustedVerifierKey
    );
}

#[test]
fn identity_key_status_active_configured_key_verifies_contexts_and_receipts() {
    let trusted = explicit_test_fixture_identity("node-verifier:active", [0x81; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([trusted
        .public_verifier_key()
        .with_validity_window(Some(100), Some(200))]);
    let signed_context = trusted
        .sign_context(sample_context())
        .expect("trusted identity should sign context");

    registry
        .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
        .expect("active key inside validity window should verify context");

    let signed_receipt = trusted
        .sign_receipt(Receipt::execution(
            "receipt-active-key-status",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .expect("trusted identity should sign receipt");

    registry
        .verify_receipt_at(&signed_receipt, KEY_VALID_NOW)
        .expect("active key inside validity window should verify receipt");
}

#[test]
fn revoked_key_rejects_contexts_and_receipts_without_trusting_replacement_automatically() {
    let old = explicit_test_fixture_identity("node-verifier:old", [0x82; 32]);
    let replacement = explicit_test_fixture_identity("node-verifier:replacement", [0x83; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([old
        .public_verifier_key()
        .with_status(VerificationKeyStatus::Revoked)
        .with_revoked_at(Some(140))
        .with_replaced_by(Some(replacement.signer_key_id().to_string()))]);
    let signed_context = old
        .sign_context(sample_context())
        .expect("revoked identity can still produce bytes, but registry must reject");

    assert_eq!(
        registry
            .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::RevokedVerifierKey
    );

    let replacement_context = replacement
        .sign_context(sample_context())
        .expect("replacement identity can sign bytes");
    assert_eq!(
        registry
            .verify_signed_context(&replacement_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UnknownVerifierKey
    );

    let signed_receipt = old
        .sign_receipt(Receipt::execution(
            "receipt-revoked-key-status",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .expect("revoked identity can still produce receipt bytes");
    assert_eq!(
        registry
            .verify_receipt_at(&signed_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::RevokedVerifierKey
    );
}

#[test]
fn revoked_key_rejects_active_key_with_effective_revoked_at_metadata() {
    let revoked = explicit_test_fixture_identity("node-verifier:revoked-at-active", [0x89; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([revoked
        .public_verifier_key()
        .with_revoked_at(Some(140))]);
    let signed_context = revoked
        .sign_context(sample_context())
        .expect("active identity can still produce bytes, but revoked_at must reject");
    let signed_receipt = revoked
        .sign_receipt(Receipt::execution(
            "receipt-revoked-at-active-key-status",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .expect("active identity can still produce receipt bytes");

    assert_eq!(
        registry
            .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::RevokedVerifierKey
    );
    assert_eq!(
        registry
            .verify_receipt_at(&signed_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::RevokedVerifierKey
    );
}

#[test]
fn expired_key_rejects_contexts_and_receipts() {
    let expired = explicit_test_fixture_identity("node-verifier:expired", [0x84; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([expired
        .public_verifier_key()
        .with_validity_window(Some(10), Some(120))]);
    let signed_context = expired
        .sign_context(sample_context())
        .expect("expired identity can still produce bytes, but registry must reject");

    assert_eq!(
        registry
            .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::ExpiredVerifierKey
    );

    let signed_receipt = expired
        .sign_receipt(Receipt::execution(
            "receipt-expired-key-status",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .expect("expired identity can still produce receipt bytes");
    assert_eq!(
        registry
            .verify_receipt_at(&signed_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::ExpiredVerifierKey
    );
}

#[test]
fn identity_key_status_rejects_unknown_and_not_yet_valid_keys() {
    let unknown = explicit_test_fixture_identity("node-verifier:unknown-status", [0x85; 32]);
    let not_yet_valid = explicit_test_fixture_identity("node-verifier:not-yet-valid", [0x86; 32]);
    let missing = explicit_test_fixture_identity("node-verifier:missing", [0x87; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([
        unknown
            .public_verifier_key()
            .with_status(VerificationKeyStatus::Unknown),
        not_yet_valid
            .public_verifier_key()
            .with_validity_window(Some(200), Some(300)),
    ]);

    assert_eq!(
        registry
            .verify_signed_context(
                &missing.sign_context(sample_context()).unwrap(),
                "secs://receiver-a",
                KEY_VALID_NOW,
            )
            .unwrap_err(),
        VerificationError::UnknownVerifierKey
    );
    assert_eq!(
        registry
            .verify_signed_context(
                &unknown.sign_context(sample_context()).unwrap(),
                "secs://receiver-a",
                KEY_VALID_NOW,
            )
            .unwrap_err(),
        VerificationError::UnknownVerifierKey
    );
    assert_eq!(
        registry
            .verify_signed_context(
                &not_yet_valid.sign_context(sample_context()).unwrap(),
                "secs://receiver-a",
                KEY_VALID_NOW,
            )
            .unwrap_err(),
        VerificationError::NotYetValidVerifierKey
    );

    let missing_receipt_context = missing.sign_context(sample_context()).unwrap();
    let missing_receipt = missing
        .sign_receipt(Receipt::execution(
            "receipt-missing-status",
            &missing_receipt_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .unwrap();
    assert_eq!(
        registry
            .verify_receipt_at(&missing_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UnknownVerifierKey
    );

    let unknown_receipt_context = unknown.sign_context(sample_context()).unwrap();
    let unknown_receipt = unknown
        .sign_receipt(Receipt::execution(
            "receipt-unknown-status",
            &unknown_receipt_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .unwrap();
    assert_eq!(
        registry
            .verify_receipt_at(&unknown_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UnknownVerifierKey
    );

    let not_yet_valid_receipt_context = not_yet_valid.sign_context(sample_context()).unwrap();
    let not_yet_valid_receipt = not_yet_valid
        .sign_receipt(Receipt::execution(
            "receipt-not-yet-valid-status",
            &not_yet_valid_receipt_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .unwrap();
    assert_eq!(
        registry
            .verify_receipt_at(&not_yet_valid_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::NotYetValidVerifierKey
    );
}

#[test]
fn identity_key_status_local_dev_fixture_cannot_satisfy_production_authority() {
    let fixture = explicit_test_fixture_identity("node-verifier:local-fixture", [0x88; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([fixture.public_verifier_key()]);
    let signed_context = fixture
        .sign_context(sample_context())
        .expect("local fixture should sign bytes for tests");

    registry
        .verify_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
        .expect("local lookup still verifies test signatures");
    assert_eq!(
        registry
            .verify_production_signed_context(&signed_context, "secs://receiver-a", KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UntrustedVerifierKey
    );

    let signed_receipt = fixture
        .sign_receipt(Receipt::execution(
            "receipt-local-fixture-production-rejected",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .expect("local fixture should sign receipt bytes for tests");
    registry
        .verify_receipt_at(&signed_receipt, KEY_VALID_NOW)
        .expect("local lookup still verifies test receipt signatures");
    assert_eq!(
        registry
            .verify_production_receipt_at(&signed_receipt, KEY_VALID_NOW)
            .unwrap_err(),
        VerificationError::UntrustedVerifierKey
    );
}

#[test]
fn production_verification_rejects_every_non_allowlisted_authenticator_kind() {
    let signer = explicit_test_fixture_identity("node-verifier:allowlist", [0x91; 32]);
    let registry =
        PublicVerifierKeyRegistry::from_keys([PublicVerifierKey::configured_production_authority(
            signer.signer_key_id(),
            "ed25519",
            *signer.public_key(),
        )]);

    for kind in [
        AuthenticatorKind::LocalDevUntrusted,
        AuthenticatorKind::LocalMac,
        AuthenticatorKind::Ed25519Node,
        AuthenticatorKind::Ed25519Verifier,
        AuthenticatorKind::ExternalAnchor,
    ] {
        let signed_context = sample_context()
            .sign_ed25519(signer.signer_key_id(), &[0x91; 32], kind)
            .expect("test context should sign for authenticator allowlist check");
        assert_eq!(
            registry
                .verify_production_signed_context(
                    &signed_context,
                    "secs://receiver-a",
                    KEY_VALID_NOW
                )
                .unwrap_err(),
            VerificationError::UntrustedVerifierKey,
            "production context verification must reject {kind:?} even with a valid signature"
        );

        let signed_receipt = signer
            .sign_receipt(Receipt::execution(
                format!("receipt-auth-kind-{kind:?}"),
                &signed_context.context,
                Decision::Accepted,
                None,
                KEY_VALID_NOW,
            ))
            .expect("test receipt should sign for authenticator allowlist check");
        assert_eq!(
            registry
                .verify_production_receipt_at(&signed_receipt, KEY_VALID_NOW)
                .unwrap_err(),
            VerificationError::UntrustedVerifierKey,
            "production receipt verification must reject {kind:?} even with a valid signature"
        );
    }
}

#[test]
fn production_verification_rejects_algorithm_metadata_that_does_not_match_ed25519() {
    let signer = explicit_test_fixture_identity("node-verifier:algorithm", [0x92; 32]);
    let signed_context = sample_context()
        .sign_ed25519(
            signer.signer_key_id(),
            &[0x92; 32],
            AuthenticatorKind::Ed25519NodeAndVerifier,
        )
        .unwrap();
    let signed_receipt = signer
        .sign_receipt(Receipt::execution(
            "receipt-wrong-algorithm",
            &signed_context.context,
            Decision::Accepted,
            None,
            KEY_VALID_NOW,
        ))
        .unwrap();

    for algorithm in ["", "rsa", "external_anchor", "ED25519"] {
        let registry = PublicVerifierKeyRegistry::from_keys([
            PublicVerifierKey::configured_production_authority(
                signer.signer_key_id(),
                algorithm,
                *signer.public_key(),
            ),
        ]);
        assert_eq!(
            registry
                .verify_production_signed_context(
                    &signed_context,
                    "secs://receiver-a",
                    KEY_VALID_NOW
                )
                .unwrap_err(),
            VerificationError::UntrustedVerifierKey,
            "non-ed25519 algorithm metadata {algorithm:?} must fail closed for contexts"
        );
        assert_eq!(
            registry
                .verify_production_receipt_at(&signed_receipt, KEY_VALID_NOW)
                .unwrap_err(),
            VerificationError::UntrustedVerifierKey,
            "non-ed25519 algorithm metadata {algorithm:?} must fail closed for receipts"
        );
    }
}

#[cfg(unix)]
#[test]
fn production_key_loader_rejects_world_readable_key_files() {
    use std::os::unix::fs::PermissionsExt;

    let path = write_key_file([0x93; 32]);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
        .expect("test should be able to set unsafe key permissions");
    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(path.clone()),
        verifier_key_id: None,
    };

    let err = load_node_verifier_identity(&config)
        .expect_err("production key loader must reject group/world-readable key files");
    assert!(
        format!("{err:?}").contains("UnsafeVerifierKeyFile"),
        "expected unsafe key-file permission error, got {err:?}"
    );
    let _ = fs::remove_file(path);
}

#[test]
fn production_key_loader_rejects_symlink_key_paths_before_reading_secret_material() {
    let target = write_key_file([0x94; 32]);
    let link = unique_temp_path("identity-key-symlink");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &link).expect("test symlink should be creatable");
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &link).expect("test symlink should be creatable");

    let config = VerifierIdentityConfig {
        runtime_mode: RuntimeMode::ProductionVerified,
        verifier_key_path: Some(link.clone()),
        verifier_key_id: None,
    };
    let err = load_node_verifier_identity(&config)
        .expect_err("production key loader must reject symlink key paths");
    assert!(
        format!("{err:?}").contains("UnsafeVerifierKeyFile"),
        "expected unsafe key-file type error, got {err:?}"
    );
    let _ = fs::remove_file(link);
    let _ = fs::remove_file(target);
}

#[test]
fn identity_source_does_not_expose_public_secret_key_byte_accessor_in_normal_builds() {
    let source = include_str!("../src/identity.rs");
    assert!(
        !source.contains("pub fn secret_key_bytes"),
        "normal builds must not expose raw verifier secret bytes through a public accessor"
    );
}

#[test]
fn receipt_verification_uses_receipt_signing_time_for_key_validity() {
    let signer = explicit_test_fixture_identity("node-verifier:historical-receipt", [0x95; 32]);
    let registry = PublicVerifierKeyRegistry::from_keys([signer
        .public_verifier_key()
        .with_validity_window(Some(100), Some(200))]);
    let signed_context = signer.sign_context(sample_context()).unwrap();
    let receipt_signed_while_valid = signer
        .sign_receipt(Receipt::execution(
            "receipt-before-expiry",
            &signed_context.context,
            Decision::Accepted,
            None,
            150,
        ))
        .unwrap();

    registry
        .verify_receipt_at(&receipt_signed_while_valid, 250)
        .expect("historical receipt signed while key was valid should verify after key expiry");

    let receipt_signed_after_expiry = signer
        .sign_receipt(Receipt::execution(
            "receipt-after-expiry",
            &signed_context.context,
            Decision::Accepted,
            None,
            250,
        ))
        .unwrap();
    assert_eq!(
        registry
            .verify_receipt_at(&receipt_signed_after_expiry, 150)
            .unwrap_err(),
        VerificationError::ExpiredVerifierKey,
        "receipt timestamp after key expiry must fail even if caller supplies an in-window now"
    );
}

#[test]
fn duplicate_key_ids_do_not_silently_depend_on_registry_input_order() {
    let first = explicit_test_fixture_identity("node-verifier:duplicate", [0x96; 32]);
    let second = explicit_test_fixture_identity("node-verifier:duplicate", [0x97; 32]);
    let signed_by_first = first.sign_context(sample_context()).unwrap();

    let first_then_second = PublicVerifierKeyRegistry::from_keys([
        first.public_verifier_key(),
        second.public_verifier_key(),
    ]);
    let second_then_first = PublicVerifierKeyRegistry::from_keys([
        second.public_verifier_key(),
        first.public_verifier_key(),
    ]);

    let first_result = first_then_second
        .verify_signed_context(&signed_by_first, "secs://receiver-a", KEY_VALID_NOW)
        .map(|_| ());
    let second_result = second_then_first
        .verify_signed_context(&signed_by_first, "secs://receiver-a", KEY_VALID_NOW)
        .map(|_| ());

    assert_eq!(
        first_result, second_result,
        "duplicate key ids must be rejected or modeled explicitly; registry input order must not change verification outcome"
    );
}
