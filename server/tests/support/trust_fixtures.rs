#![allow(dead_code)]

//! Shared no-real-secret fixtures for Track D wallet, Track E trusted issuer,
//! and Track I membership-provisioning E2E tests.
//!
//! All keys and references in this module are deterministic local test material.
//! They are deliberately synthetic and must never be treated as production
//! Castalia/Dregg/Midnight/Cardano authority.

use server::evidence::EvidenceKind;
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

pub fn wallet_and_membership_descriptor(opcode: u8) -> OperationDescriptor {
    trusted_descriptor(
        opcode,
        MEMBERSHIP_OPERATION,
        vec![
            EvidenceKind::WalletPresentation.as_str().to_string(),
            EvidenceKind::MembershipCredential.as_str().to_string(),
        ],
    )
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
        target_kind: TargetKind::LocalDevProcess,
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
