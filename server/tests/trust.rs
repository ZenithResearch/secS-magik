#[path = "support/trust_fixtures.rs"]
mod trust_fixtures;

use ed25519_dalek::SigningKey;
use server::evidence::{
    public_key_ref_for_bytes, EvidenceKind, TrustedIssuerEntry, TrustedIssuerRegistry,
    TrustedIssuerStatus,
};
use server::verifier::VerificationError;
use trust_fixtures::{
    ISSUER_FIXTURE_ED25519_SEED, MEMBERSHIP_OPERATION, REGISTRY_ROOT_REF, TRUSTED_AUDIENCE,
    TRUSTED_ISSUER_ID, TRUSTED_NOT_AFTER, TRUSTED_NOT_BEFORE, TRUSTED_RESOURCE, TRUST_ROOT_REF,
    WRONG_REGISTRY_ROOT_REF, WRONG_TRUST_ROOT_REF,
};

fn issuer_entry() -> TrustedIssuerEntry {
    let signing_key = SigningKey::from_bytes(&ISSUER_FIXTURE_ED25519_SEED);
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    TrustedIssuerEntry {
        issuer_id: TRUSTED_ISSUER_ID.to_string(),
        issuer_key_id: public_key_ref_for_bytes(&public_key_bytes),
        public_key_bytes,
        trust_root_ref: TRUST_ROOT_REF.to_string(),
        registry_root_ref: REGISTRY_ROOT_REF.to_string(),
        accepted_evidence: vec![EvidenceKind::MembershipCredential],
        accepted_audiences: vec![TRUSTED_AUDIENCE.to_string()],
        accepted_operations: vec![MEMBERSHIP_OPERATION.to_string()],
        accepted_resources: vec![TRUSTED_RESOURCE.to_string()],
        status: TrustedIssuerStatus::Active,
        not_before: TRUSTED_NOT_BEFORE,
        not_after: TRUSTED_NOT_AFTER,
        registry_status_ref: "registry-status:active-fixture".to_string(),
    }
}

#[test]
fn trusted_issuer_registry_returns_receiver_held_active_entry() {
    let entry = issuer_entry();
    let registry = TrustedIssuerRegistry::new([entry.clone()]).expect("unique issuer registry");
    let found = registry
        .lookup_active(
            &entry.issuer_id,
            &entry.issuer_key_id,
            TRUST_ROOT_REF,
            REGISTRY_ROOT_REF,
            EvidenceKind::MembershipCredential,
            TRUSTED_AUDIENCE,
            MEMBERSHIP_OPERATION,
            TRUSTED_RESOURCE,
            TRUSTED_NOT_BEFORE + 1,
        )
        .expect("trusted issuer should resolve");

    assert_eq!(found.issuer_id, TRUSTED_ISSUER_ID);
    assert_eq!(found.trust_root_ref, TRUST_ROOT_REF);
    assert_eq!(found.registry_root_ref, REGISTRY_ROOT_REF);
}

#[test]
fn trusted_issuer_registry_rejects_unknown_wrong_root_and_status() {
    let mut entry = issuer_entry();
    let registry = TrustedIssuerRegistry::new([entry.clone()]).expect("unique issuer registry");
    assert_eq!(
        registry
            .lookup_active(
                "did:example:missing",
                &entry.issuer_key_id,
                TRUST_ROOT_REF,
                REGISTRY_ROOT_REF,
                EvidenceKind::MembershipCredential,
                TRUSTED_AUDIENCE,
                MEMBERSHIP_OPERATION,
                TRUSTED_RESOURCE,
                TRUSTED_NOT_BEFORE + 1,
            )
            .expect_err("unknown issuer should reject"),
        VerificationError::UnknownIssuer
    );
    assert_eq!(
        registry
            .lookup_active(
                &entry.issuer_id,
                &entry.issuer_key_id,
                WRONG_TRUST_ROOT_REF,
                REGISTRY_ROOT_REF,
                EvidenceKind::MembershipCredential,
                TRUSTED_AUDIENCE,
                MEMBERSHIP_OPERATION,
                TRUSTED_RESOURCE,
                TRUSTED_NOT_BEFORE + 1,
            )
            .expect_err("wrong trust root should reject"),
        VerificationError::WrongTrustRoot
    );
    assert_eq!(
        registry
            .lookup_active(
                &entry.issuer_id,
                &entry.issuer_key_id,
                TRUST_ROOT_REF,
                WRONG_REGISTRY_ROOT_REF,
                EvidenceKind::MembershipCredential,
                TRUSTED_AUDIENCE,
                MEMBERSHIP_OPERATION,
                TRUSTED_RESOURCE,
                TRUSTED_NOT_BEFORE + 1,
            )
            .expect_err("wrong registry root should reject"),
        VerificationError::WrongRegistryRoot
    );

    entry.status = TrustedIssuerStatus::Revoked;
    let registry = TrustedIssuerRegistry::new([entry.clone()]).expect("unique issuer registry");
    assert_eq!(
        registry
            .lookup_active(
                &entry.issuer_id,
                &entry.issuer_key_id,
                TRUST_ROOT_REF,
                REGISTRY_ROOT_REF,
                EvidenceKind::MembershipCredential,
                TRUSTED_AUDIENCE,
                MEMBERSHIP_OPERATION,
                TRUSTED_RESOURCE,
                TRUSTED_NOT_BEFORE + 1,
            )
            .expect_err("revoked issuer should reject"),
        VerificationError::RevokedIssuer
    );
}
