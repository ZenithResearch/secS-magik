use server::dregg_authority::{
    DreggAuthorityFinalityStatus, DreggAuthorityLookup, DreggAuthorityRegistry,
    DreggAuthorityRegistryError, DreggAuthorityRevocationStatus,
};
use server::verifier::VerificationError;

fn registry_json() -> String {
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
          "revocation_verifier_mode": "expected_root_binding",
          "finality_mode": "not_required",
          "expected_revocation_root_ref": "dregg-revocation-root:fixture-2026q2"
        },
        "root_status": "active",
        "issuer_status": "active"
      }
    ]"#
    .to_string()
}

fn valid_lookup() -> DreggAuthorityLookup {
    DreggAuthorityLookup {
        issuer_id: "did:dregg:fixture:issuer".to_string(),
        issuer_key_id: "dregg-issuer-key:fixture-1".to_string(),
        root_ref: "dregg-root:fixture-root-2026q2".to_string(),
        root_fingerprint: "root:sha256:fixture-root-2026q2".to_string(),
        epoch_id: "epoch:2026q2".to_string(),
        audience: "secS://operator-receiver".to_string(),
        operation: "membership.provision".to_string(),
        resource: "application/json".to_string(),
        suite: "dregg_authority_fixture_v1".to_string(),
        validation_time: 1770000300,
        status_checked_at: Some(1770000200),
        revocation_status: Some(DreggAuthorityRevocationStatus::Active),
        finality_status: Some(DreggAuthorityFinalityStatus::Final),
        attested_revocation_root_ref: Some("dregg-revocation-root:fixture-2026q2".to_string()),
    }
}

#[test]
fn dregg_authority_registry_loads_receiver_held_epoch_policy() {
    let registry = DreggAuthorityRegistry::from_json_str(&registry_json()).unwrap();

    let entry = registry.lookup_active_policy(&valid_lookup()).unwrap();

    assert_eq!(entry.issuer_id, "did:dregg:fixture:issuer");
    assert_eq!(entry.root_ref, "dregg-root:fixture-root-2026q2");
    assert_eq!(entry.epoch_id, "epoch:2026q2");
    assert_eq!(entry.status_policy.max_status_age_seconds, 300);
}

#[test]
fn dregg_authority_registry_rejects_missing_empty_malformed_and_duplicates() {
    assert_eq!(
        DreggAuthorityRegistry::from_json_str("").unwrap_err(),
        DreggAuthorityRegistryError::Empty
    );
    assert!(matches!(
        DreggAuthorityRegistry::from_json_str("not json").unwrap_err(),
        DreggAuthorityRegistryError::Malformed(_)
    ));
    assert_eq!(
        DreggAuthorityRegistry::from_json_str("[]").unwrap_err(),
        DreggAuthorityRegistryError::Empty
    );

    assert!(matches!(
        DreggAuthorityRegistry::from_json_str(&registry_json().replace(
            "1111111111111111111111111111111111111111111111111111111111111111",
            "ABCDEF1111111111111111111111111111111111111111111111111111111111"
        ))
        .unwrap_err(),
        DreggAuthorityRegistryError::InvalidEntry(error)
        if error.contains("issuer_public_key_hex")
    ));

    let duplicate = format!(
        "[{},{}]",
        registry_json()
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']'),
        registry_json()
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
    );
    assert_eq!(
        DreggAuthorityRegistry::from_json_str(&duplicate).unwrap_err(),
        DreggAuthorityRegistryError::DuplicateIssuer("did:dregg:fixture:issuer".to_string())
    );
}

#[test]
fn dregg_authority_registry_rejects_root_epoch_status_and_binding_failures() {
    let registry = DreggAuthorityRegistry::from_json_str(&registry_json()).unwrap();

    let mut lookup = valid_lookup();
    lookup.root_ref = "dregg-root:wrong".to_string();
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongRoot
    );
    assert_eq!(VerificationError::WrongRoot.reason_code(), "wrong_root");

    let mut lookup = valid_lookup();
    lookup.attested_revocation_root_ref = None;
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::MissingRevocationRoot
    );
    assert_eq!(
        VerificationError::MissingRevocationRoot.reason_code(),
        "missing_revocation_root"
    );

    let mut lookup = valid_lookup();
    lookup.attested_revocation_root_ref = Some("dregg-revocation-root:wrong".to_string());
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongRevocationRoot
    );
    assert_eq!(
        VerificationError::WrongRevocationRoot.reason_code(),
        "wrong_revocation_root"
    );

    let mut lookup = valid_lookup();
    lookup.epoch_id = "epoch:wrong".to_string();
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongEpoch
    );
    assert_eq!(VerificationError::WrongEpoch.reason_code(), "wrong_epoch");

    let mut lookup = valid_lookup();
    lookup.validation_time = 1777776001;
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongEpoch
    );

    let mut lookup = valid_lookup();
    lookup.status_checked_at = None;
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::MissingStatus
    );
    assert_eq!(
        VerificationError::MissingStatus.reason_code(),
        "missing_status"
    );

    let mut lookup = valid_lookup();
    lookup.status_checked_at = Some(1769990000);
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::Stale
    );
    assert_eq!(VerificationError::Stale.reason_code(), "stale");

    let mut lookup = valid_lookup();
    lookup.suite = "unsupported".to_string();
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::UnsupportedSuite
    );
    assert_eq!(
        VerificationError::UnsupportedSuite.reason_code(),
        "unsupported_suite"
    );

    let mut lookup = valid_lookup();
    lookup.resource = "other/resource".to_string();
    assert_eq!(
        registry.lookup_active_policy(&lookup).unwrap_err(),
        VerificationError::WrongResource
    );
}
