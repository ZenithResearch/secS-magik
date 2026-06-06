#![allow(dead_code)]

use ed25519_dalek::{Signer, SigningKey};
use server::evidence::{
    public_key_ref_for_bytes, EvidenceRequest, SecsWalletChallenge, WalletPresentationFixture,
};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};

pub const WALLET_OPCODE: u8 = 0x41;
pub const WALLET_OPERATION: &str = "candidate.wallet.present";
pub const WALLET_RESOURCE: &str = "application/json";
pub const WALLET_SUBJECT: &str = "did:example:alice#key-1";
pub const WALLET_AUDIENCE: &str = "secS://local-test";
pub const WALLET_OTHER_AUDIENCE: &str = "secS://other-target";
pub const WALLET_ORIGIN: &str = "https://gallery.localhost";
pub const WALLET_WRONG_ORIGIN: &str = "https://evil.example";
pub const WALLET_EVIDENCE_REF: &str = "wallet-presentation:alice-local";
pub const WALLET_INCOMPLETE_EVIDENCE_REF: &str = "wallet-presentation:missing-shape";
pub const WALLET_CHALLENGE_REF: &str = "challenge:phase4-test";
pub const WALLET_SIGNATURE_REF: &str = "signature:fixture-only";
pub const WALLET_REPLAY_NONCE_REF: &str = "nonce:wallet-present-0001";
pub const WALLET_SESSION_REF: &str = "session:wallet-present-local";
pub const WALLET_ISSUED_AT: u64 = 1_717_000_000;
pub const WALLET_EXPIRES_AT: u64 = 1_717_000_300;

// Deterministic fixture-only Ed25519 seed for tests. This is intentionally
// synthetic, local test material and must never be used as a real wallet key.
const WALLET_FIXTURE_ED25519_SEED: [u8; 32] = [0xD2; 32];

pub fn wallet_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new(WALLET_OPERATION),
        payload_schema: Some(WALLET_RESOURCE.to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["wallet.presentation".to_string()],
        required_capabilities: vec!["wallet.present".to_string()],
        accepted_evidence: vec![server::evidence::EvidenceKind::WalletPresentation
            .as_str()
            .to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/wallet-presentation".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

pub fn wallet_request_with_ref(evidence_ref: Option<&str>) -> EvidenceRequest {
    EvidenceRequest::from_descriptor(
        &wallet_descriptor(WALLET_OPCODE),
        WALLET_SUBJECT,
        WALLET_AUDIENCE,
        evidence_ref,
    )
}

pub fn wallet_request_with_origin(evidence_ref: Option<&str>) -> EvidenceRequest {
    let mut request = wallet_request_with_ref(evidence_ref);
    request
        .public_inputs
        .push(format!("session_ref:{WALLET_SESSION_REF}"));
    request.public_inputs.push(origin_input(WALLET_ORIGIN));
    request
}

pub fn wallet_fixture() -> WalletPresentationFixture {
    let signing_key = SigningKey::from_bytes(&WALLET_FIXTURE_ED25519_SEED);
    let public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    let challenge = wallet_challenge();
    let signature = signing_key.sign(&challenge.canonical_bytes());

    WalletPresentationFixture {
        evidence_ref: WALLET_EVIDENCE_REF.to_string(),
        subject: WALLET_SUBJECT.to_string(),
        audience: WALLET_AUDIENCE.to_string(),
        origin: WALLET_ORIGIN.to_string(),
        operation: WALLET_OPERATION.to_string(),
        resource: WALLET_RESOURCE.to_string(),
        challenge_ref: WALLET_CHALLENGE_REF.to_string(),
        signature_ref: WALLET_SIGNATURE_REF.to_string(),
        public_key_ref: wallet_public_key_ref(),
        replay_nonce_ref: WALLET_REPLAY_NONCE_REF.to_string(),
        issued_at: WALLET_ISSUED_AT,
        expires_at: WALLET_EXPIRES_AT,
        signature_suite: SecsWalletChallenge::ED25519_SIGNATURE_SUITE.to_string(),
        public_key_bytes,
        signature_bytes: signature.to_bytes().to_vec(),
    }
}

pub fn wallet_challenge() -> SecsWalletChallenge {
    SecsWalletChallenge {
        subject: WALLET_SUBJECT.to_string(),
        audience: WALLET_AUDIENCE.to_string(),
        origin: WALLET_ORIGIN.to_string(),
        operation: WALLET_OPERATION.to_string(),
        resource: WALLET_RESOURCE.to_string(),
        nonce: WALLET_REPLAY_NONCE_REF.to_string(),
        issued_at: WALLET_ISSUED_AT,
        expires_at: WALLET_EXPIRES_AT,
        signature_suite: SecsWalletChallenge::ED25519_SIGNATURE_SUITE.to_string(),
        public_key_ref: wallet_public_key_ref(),
    }
}

pub fn sign_wallet_fixture(fixture: &mut WalletPresentationFixture) {
    let signing_key = SigningKey::from_bytes(&WALLET_FIXTURE_ED25519_SEED);
    fixture.public_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    fixture.signature_bytes = signing_key
        .sign(&wallet_challenge_for_fixture(fixture).canonical_bytes())
        .to_bytes()
        .to_vec();
}

pub fn wallet_public_key_ref() -> String {
    let signing_key = SigningKey::from_bytes(&WALLET_FIXTURE_ED25519_SEED);
    public_key_ref_for_bytes(&signing_key.verifying_key().to_bytes())
}

fn wallet_challenge_for_fixture(fixture: &WalletPresentationFixture) -> SecsWalletChallenge {
    SecsWalletChallenge {
        subject: fixture.subject.clone(),
        audience: fixture.audience.clone(),
        origin: fixture.origin.clone(),
        operation: fixture.operation.clone(),
        resource: fixture.resource.clone(),
        nonce: fixture.replay_nonce_ref.clone(),
        issued_at: fixture.issued_at,
        expires_at: fixture.expires_at,
        signature_suite: fixture.signature_suite.clone(),
        public_key_ref: fixture.public_key_ref.clone(),
    }
}

pub fn incomplete_wallet_fixture() -> WalletPresentationFixture {
    WalletPresentationFixture {
        evidence_ref: WALLET_INCOMPLETE_EVIDENCE_REF.to_string(),
        challenge_ref: String::new(),
        ..wallet_fixture()
    }
}

pub fn origin_input(origin: &str) -> String {
    format!("origin:{origin}")
}

pub fn replay_nonce_summary_field() -> String {
    format!("replay_nonce_ref:{WALLET_REPLAY_NONCE_REF}")
}

pub fn issued_at_summary_field() -> String {
    format!("issued_at:{WALLET_ISSUED_AT}")
}

pub fn expires_at_summary_field() -> String {
    format!("expires_at:{WALLET_EXPIRES_AT}")
}

pub fn origin_summary_field() -> String {
    origin_input(WALLET_ORIGIN)
}
