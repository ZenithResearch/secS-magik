#![allow(dead_code)]

//! Shared no-real-secret fixtures for Track D wallet, Track E trusted issuer,
//! and Track I membership-provisioning E2E tests.
//!
//! All keys and references in this module are deterministic local test material.
//! They are deliberately synthetic and must never be treated as production
//! Castalia/Dregg/Midnight/Cardano authority.

use ed25519_dalek::{Signer, SigningKey};
use server::evidence::{
    public_key_ref_for_bytes, EvidenceKind, FederatedCredentialFixture, FederatedCredentialStatus,
    SecsFederatedCredential, TrustedIssuerEntry, TrustedIssuerRegistry, TrustedIssuerStatus,
};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};

pub const MEMBERSHIP_OPCODE: u8 = 0x42;
pub const PROVISIONING_OPCODE: u8 = 0x43;
pub const WALLET_AND_MEMBERSHIP_OPCODE: u8 = 0x44;

pub const MEMBERSHIP_OPERATION: &str = "membership.provision";
pub const PROVISIONING_OPERATION: &str = "membership.provision.delegated";
pub const TRUSTED_RESOURCE: &str = "application/json";

pub const TRUSTED_SUBJECT: &str = "did:example:alice#key-1";
pub const TRUSTED_AUDIENCE: &str = "secS://local-test";
pub const TRUSTED_ORIGIN: &str = "https://gallery.localhost";
pub const WRONG_ORIGIN: &str = "https://evil.example";

pub const TRUSTED_ISSUER_ID: &str = "did:example:gallery-issuer";
pub const UNKNOWN_ISSUER_ID: &str = "did:example:unknown-issuer";
pub const TRUST_ROOT_REF: &str = "trust-root:fixture-castalia-gallery";
pub const WRONG_TRUST_ROOT_REF: &str = "trust-root:wrong";
pub const REGISTRY_ROOT_REF: &str = "registry-root:fixture-castalia";
pub const WRONG_REGISTRY_ROOT_REF: &str = "registry-root:wrong";
pub const REGISTRY_STATUS_REF: &str = "registry-status:active-fixture";
pub const STALE_REGISTRY_STATUS_REF: &str = "registry-status:stale-fixture";
pub const CREDENTIAL_STATUS_REF: &str = "credential-status:active-fixture";
pub const REVOKED_CREDENTIAL_STATUS_REF: &str = "credential-status:revoked-fixture";

pub const MEMBERSHIP_CREDENTIAL_REF: &str = "membership-credential:alice-active";
pub const PROVISIONING_CREDENTIAL_REF: &str = "provisioning-credential:alice-active";
pub const MALFORMED_CREDENTIAL_REF: &str = "membership-credential:malformed";

pub const TRUSTED_ISSUED_AT: u64 = 1_717_000_000;
pub const TRUSTED_EXPIRES_AT: u64 = 1_717_000_300;
pub const TRUSTED_VALIDATION_TIME: u64 = TRUSTED_ISSUED_AT + 60;
pub const TRUSTED_NOT_BEFORE: u64 = 1_716_999_900;
pub const TRUSTED_NOT_AFTER: u64 = 1_717_000_600;
pub const EXPIRED_VALIDATION_TIME: u64 = TRUSTED_EXPIRES_AT + 1;
pub const NOT_YET_VALID_TIME: u64 = TRUSTED_ISSUED_AT - 1;

pub const ISSUER_FIXTURE_ED25519_SEED: [u8; 32] = [0xE3; 32];
pub const WRONG_ISSUER_FIXTURE_ED25519_SEED: [u8; 32] = [0xE4; 32];

pub fn issuer_entry() -> TrustedIssuerEntry {
    let signing_key = SigningKey::from_bytes(&ISSUER_FIXTURE_ED25519_SEED);
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    TrustedIssuerEntry {
        issuer_id: TRUSTED_ISSUER_ID.to_string(),
        issuer_key_id: public_key_ref_for_bytes(&public_key_bytes),
        public_key_bytes,
        trust_root_ref: TRUST_ROOT_REF.to_string(),
        registry_root_ref: REGISTRY_ROOT_REF.to_string(),
        accepted_evidence: vec![
            EvidenceKind::MembershipCredential,
            EvidenceKind::ProvisioningCredential,
        ],
        accepted_audiences: vec![TRUSTED_AUDIENCE.to_string()],
        accepted_operations: vec![
            MEMBERSHIP_OPERATION.to_string(),
            PROVISIONING_OPERATION.to_string(),
        ],
        accepted_resources: vec![TRUSTED_RESOURCE.to_string()],
        status: TrustedIssuerStatus::Active,
        not_before: TRUSTED_NOT_BEFORE,
        not_after: TRUSTED_NOT_AFTER,
        registry_status_ref: REGISTRY_STATUS_REF.to_string(),
    }
}

pub fn trusted_registry() -> TrustedIssuerRegistry {
    TrustedIssuerRegistry::new([issuer_entry()]).expect("fixture registry should be valid")
}

pub fn membership_credential_fixture() -> FederatedCredentialFixture {
    credential_fixture(
        MEMBERSHIP_CREDENTIAL_REF,
        EvidenceKind::MembershipCredential,
        MEMBERSHIP_OPERATION,
    )
}

pub fn provisioning_credential_fixture() -> FederatedCredentialFixture {
    credential_fixture(
        PROVISIONING_CREDENTIAL_REF,
        EvidenceKind::ProvisioningCredential,
        PROVISIONING_OPERATION,
    )
}

pub fn credential_fixture(
    evidence_ref: &str,
    kind: EvidenceKind,
    operation: &str,
) -> FederatedCredentialFixture {
    let signing_key = SigningKey::from_bytes(&ISSUER_FIXTURE_ED25519_SEED);
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    let credential = SecsFederatedCredential {
        credential_id: evidence_ref.to_string(),
        kind,
        subject: TRUSTED_SUBJECT.to_string(),
        audience: TRUSTED_AUDIENCE.to_string(),
        origin: Some(TRUSTED_ORIGIN.to_string()),
        operation: operation.to_string(),
        resource: TRUSTED_RESOURCE.to_string(),
        issuer_id: TRUSTED_ISSUER_ID.to_string(),
        issuer_key_id: public_key_ref_for_bytes(&public_key_bytes),
        trust_root_ref: TRUST_ROOT_REF.to_string(),
        registry_root_ref: REGISTRY_ROOT_REF.to_string(),
        issued_at: TRUSTED_ISSUED_AT,
        expires_at: TRUSTED_EXPIRES_AT,
        status: FederatedCredentialStatus::Active,
        status_ref: CREDENTIAL_STATUS_REF.to_string(),
        signature_suite: SecsFederatedCredential::ED25519_SIGNATURE_SUITE.to_string(),
    };
    let signature = signing_key.sign(&credential.canonical_bytes());
    FederatedCredentialFixture {
        evidence_ref: evidence_ref.to_string(),
        credential: Some(credential),
        embedded_issuer_public_key_bytes: public_key_bytes,
        signature_bytes: signature.to_bytes().to_vec(),
    }
}

pub fn malformed_credential_fixture() -> FederatedCredentialFixture {
    FederatedCredentialFixture {
        evidence_ref: MALFORMED_CREDENTIAL_REF.to_string(),
        credential: None,
        embedded_issuer_public_key_bytes: Vec::new(),
        signature_bytes: Vec::new(),
    }
}

pub fn resign_credential(fixture: &mut FederatedCredentialFixture) {
    let signing_key = SigningKey::from_bytes(&ISSUER_FIXTURE_ED25519_SEED);
    if let Some(credential) = &fixture.credential {
        fixture.signature_bytes = signing_key
            .sign(&credential.canonical_bytes())
            .to_bytes()
            .to_vec();
        fixture.embedded_issuer_public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    }
}

pub fn membership_descriptor(opcode: u8) -> OperationDescriptor {
    trusted_descriptor(
        opcode,
        MEMBERSHIP_OPERATION,
        vec![EvidenceKind::MembershipCredential.as_str().to_string()],
    )
}

pub fn provisioning_descriptor(opcode: u8) -> OperationDescriptor {
    trusted_descriptor(
        opcode,
        PROVISIONING_OPERATION,
        vec![EvidenceKind::ProvisioningCredential.as_str().to_string()],
    )
}

/// Track I fixture for the canonical `0x44 membership.provision`
/// descriptor. Delegates to the production constructor (#80) so the fixture
/// IS the active contract; only the opcode may be rebased for tests that
/// deliberately probe non-canonical opcodes.
pub fn wallet_and_membership_descriptor(opcode: u8) -> OperationDescriptor {
    let mut descriptor = server::manifest::membership_provision_descriptor();
    if descriptor.opcode != opcode {
        descriptor.opcode = opcode;
        descriptor.range = OpcodeRange::classify(opcode);
    }
    descriptor
}

pub fn membership_or_provisioning_descriptor(opcode: u8) -> OperationDescriptor {
    trusted_descriptor(
        opcode,
        MEMBERSHIP_OPERATION,
        vec![
            EvidenceKind::MembershipCredential.as_str().to_string(),
            EvidenceKind::ProvisioningCredential.as_str().to_string(),
        ],
    )
}

fn trusted_descriptor(
    opcode: u8,
    operation: &str,
    accepted_evidence: Vec<String>,
) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new(operation),
        payload_schema: Some(TRUSTED_RESOURCE.to_string()),
        // #82: this fixture models production-shaped membership/provisioning
        // authority, so it uses the production receiver target kind — not
        // LocalDevProcess — matching the canonical 0x44 descriptor.
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec!["trusted.membership".to_string()],
        required_capabilities: vec!["membership.provision".to_string()],
        accepted_evidence,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "membership/provision-fixture".to_string(),
        dev_binding: false,
        range: OpcodeRange::classify(opcode),
    }
}
