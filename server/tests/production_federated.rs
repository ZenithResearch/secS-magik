#[path = "support/trust_fixtures.rs"]
mod trust_fixtures;
#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use async_trait::async_trait;
use libsec_core::ZenithPacket;
use server::evidence::{
    CompositeEvidenceAdapter, EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult,
    FederatedCredentialAdapter, FederatedCredentialStatus, LocalStaticEvidenceAdapter,
    LocalStaticGrant, TrustedIssuerRegistry, TrustedIssuerStatus, WalletPresentationAdapter,
};
use server::gateway::{
    init_telemetry_schema, ConfigurableRouter, ExecutionLimits, HandlerOutcome, MachineProgram,
};
use server::identity::explicit_test_fixture_identity;
use server::ledger::Ledger;
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, ReceiverManifest, ReplayScope, TargetKind,
};
use server::receipt::Receipt;
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerificationError, VerifiedCallContext, Verifier};
use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use trust_fixtures::{
    credential_fixture, issuer_entry, malformed_credential_fixture, membership_credential_fixture,
    membership_descriptor, provisioning_credential_fixture, provisioning_descriptor,
    resign_credential, trusted_registry, wallet_and_membership_descriptor, CREDENTIAL_STATUS_REF,
    ISSUER_FIXTURE_ED25519_SEED, MEMBERSHIP_CREDENTIAL_REF, MEMBERSHIP_OPCODE,
    MEMBERSHIP_OPERATION, PROVISIONING_CREDENTIAL_REF, PROVISIONING_OPCODE, REGISTRY_ROOT_REF,
    TRUSTED_AUDIENCE, TRUSTED_EXPIRES_AT, TRUSTED_ISSUED_AT, TRUSTED_ISSUER_ID, TRUSTED_ORIGIN,
    TRUSTED_RESOURCE, TRUSTED_SUBJECT, TRUSTED_VALIDATION_TIME, TRUST_ROOT_REF,
    WALLET_AND_MEMBERSHIP_OPCODE, WRONG_ORIGIN, WRONG_REGISTRY_ROOT_REF, WRONG_TRUST_ROOT_REF,
};
use wallet_fixtures::{
    origin_input, sign_wallet_fixture, wallet_fixture, WALLET_EVIDENCE_REF, WALLET_ISSUED_AT,
    WALLET_OPCODE, WALLET_OPERATION, WALLET_OTHER_AUDIENCE,
};

struct MembershipProvisionProgram {
    calls: Arc<AtomicUsize>,
}

#[async_trait]
impl MachineProgram for MembershipProvisionProgram {
    async fn execute(
        &self,
        _context: &VerifiedCallContext,
        _payload: &[u8],
        _limits: ExecutionLimits,
    ) -> HandlerOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        HandlerOutcome::succeeded()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PolicyMatrixStatus {
    Executable,
    Deferred,
}

#[derive(Debug)]
struct PolicyMatrixRow {
    row_name: &'static str,
    input_condition: &'static str,
    expected_accept_reject_reason: &'static str,
    test_name: &'static str,
    status: PolicyMatrixStatus,
    first_path: bool,
}

// E9 executable/docs-contract matrix for the A6 production policy rows.
// Row names mirror the A6 table and add explicit deferred rows for Midnight and
// Cardano so future labels cannot silently become production authority.
const A6_POLICY_MATRIX: &[PolicyMatrixRow] = &[
    PolicyMatrixRow {
        row_name: "local_dev_descriptor_accepts_local_static_fixture",
        input_condition: "local_dev_plaintext/local_dev_tunnel + dev descriptor + local_static fixture",
        expected_accept_reject_reason: "accept only with local_dev_test_only evidence summary",
        test_name: "production_federated_policy_matrix_local_dev_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "local_dev_runtime_rejects_production_descriptor",
        input_condition: "local_dev runtime label + production descriptor + local_static fixture",
        expected_accept_reject_reason: "reject insufficient_evidence; local/dev evidence is not production authority",
        test_name: "production_federated_policy_matrix_local_dev_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_verified_missing_evidence_rejects_before_handler",
        input_condition: "production_verified + production descriptor + no evidence refs",
        expected_accept_reject_reason: "reject insufficient_evidence before handler authority",
        test_name: "production_federated_policy_matrix_local_dev_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_wallet_descriptor_rejects_local_static",
        input_condition: "production_verified + wallet descriptor + local_static fixture",
        expected_accept_reject_reason: "reject insufficient_evidence; wallet proof-of-possession is distinct from local_static",
        test_name: "production_wallet_policy_matrix_rows_are_executable_or_track_d_boundaries",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_wallet_shape_only_shell_fails_closed",
        input_condition: "production_verified + wallet descriptor + shape-only wallet_presentation",
        expected_accept_reject_reason: "reject invalid_presentation; shape-only/unsupported crypto cannot satisfy wallet authority",
        test_name: "production_wallet_policy_matrix_rows_are_executable_or_track_d_boundaries",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_wallet_core_presentation_accepts_when_policy_matches",
        input_condition: "production_verified + wallet descriptor + temporary secS challenge with valid signature/bindings",
        expected_accept_reject_reason: "accept as cryptographic wallet_presentation without claiming full wallet-core parity",
        test_name: "production_wallet_policy_matrix_rows_are_executable_or_track_d_boundaries",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_wallet_presentation_reject_matrix",
        input_condition: "production_verified + wallet descriptor + wrong signature/key/subject/audience/origin/operation/replay/expiry",
        expected_accept_reject_reason: "reject with typed wallet binding/signature/validity reason",
        test_name: "production_wallet_policy_matrix_rows_are_executable_or_track_d_boundaries",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_federated_untrusted_issuer_rejects",
        input_condition: "production_verified + federated descriptor + untrusted issuer or caller-supplied key/root",
        expected_accept_reject_reason: "reject unknown_issuer/wrong_issuer_key/wrong_trust_root/wrong_registry_root",
        test_name: "production_federated_policy_matrix_first_path_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_federated_status_reject_matrix",
        input_condition: "production_verified + federated descriptor + revoked/expired/not-yet-valid issuer or credential",
        expected_accept_reject_reason: "reject revoked_issuer/expired_verifier_key/not_yet_valid_verifier_key/revoked_credential/expired_claim/not_yet_valid_claim",
        test_name: "production_federated_policy_matrix_first_path_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_federated_binding_reject_matrix",
        input_condition: "production_verified + federated descriptor + wrong subject/audience/origin/operation/resource or unsupported descriptor evidence kind",
        expected_accept_reject_reason: "reject wrong_subject/wrong_audience/wrong_origin/wrong_operation/wrong_resource/insufficient_evidence",
        test_name: "production_federated_policy_matrix_first_path_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_federated_valid_evidence_local_policy_rejects",
        input_condition: "production_verified + valid credential + receiver-local manifest policy mismatch",
        expected_accept_reject_reason: "reject wrong_operation/wrong_resource/wrong_audience; foreign evidence never bypasses local policy",
        test_name: "production_federated_policy_matrix_first_path_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_federated_membership_credential_accepts_when_policy_matches",
        input_condition: "production_verified + trusted active membership/provisioning credential + descriptor permits it",
        expected_accept_reject_reason: "accept with redacted public proof summary",
        test_name: "production_federated_policy_matrix_first_path_rows_are_executable",
        status: PolicyMatrixStatus::Executable,
        first_path: true,
    },
    PolicyMatrixRow {
        row_name: "production_membership_root_ref_without_inclusion_proof_rejects",
        input_condition: "production_verified + membership proof descriptor + membership_root_ref label only",
        expected_accept_reject_reason: "deferred marker: reject insufficient_evidence; root refs alone are not authorization evidence",
        test_name: "production_federated_policy_matrix_future_root_and_rail_refs_are_inert",
        status: PolicyMatrixStatus::Deferred,
        first_path: false,
    },
    PolicyMatrixRow {
        row_name: "production_dregg_ref_without_promotion_is_not_live_validation",
        input_condition: "production_verified + Dregg-shaped root/ref while A9 has not promoted live Dregg",
        expected_accept_reject_reason: "deferred marker: reject insufficient_evidence; label is inert metadata only",
        test_name: "production_federated_policy_matrix_future_root_and_rail_refs_are_inert",
        status: PolicyMatrixStatus::Deferred,
        first_path: false,
    },
    PolicyMatrixRow {
        row_name: "production_midnight_ref_without_promotion_is_not_authority",
        input_condition: "production_verified + midnight_proof-shaped evidence ref/credential kind",
        expected_accept_reject_reason: "deferred marker: reject insufficient_evidence; no Midnight proof adapter is promoted",
        test_name: "production_federated_policy_matrix_future_root_and_rail_refs_are_inert",
        status: PolicyMatrixStatus::Deferred,
        first_path: false,
    },
    PolicyMatrixRow {
        row_name: "production_cardano_ref_without_promotion_is_not_authority",
        input_condition: "production_verified + cardano_settlement-shaped evidence ref/credential kind",
        expected_accept_reject_reason: "deferred marker: reject insufficient_evidence; no Cardano settlement adapter is promoted",
        test_name: "production_federated_policy_matrix_future_root_and_rail_refs_are_inert",
        status: PolicyMatrixStatus::Deferred,
        first_path: false,
    },
];

fn production_request(evidence_ref: Option<&str>) -> EvidenceRequest {
    request_for(&membership_descriptor(MEMBERSHIP_OPCODE), evidence_ref)
}

fn request_for(
    descriptor: &server::manifest::OperationDescriptor,
    evidence_ref: Option<&str>,
) -> EvidenceRequest {
    request_with_refs(descriptor, evidence_ref)
}

fn request_with_refs<'a>(
    descriptor: &server::manifest::OperationDescriptor,
    evidence_refs: impl IntoIterator<Item = &'a str>,
) -> EvidenceRequest {
    let mut request = EvidenceRequest::from_descriptor_with_refs(
        descriptor,
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        evidence_refs,
    );
    request.public_inputs.push(origin_input(TRUSTED_ORIGIN));
    request
}

fn production_packet(opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: b"prototype-proof-envelope".to_vec(),
        claim_ttl: 60,
        encrypted_payload: br#"{"membership":"requested"}"#.to_vec(),
        mac: [3u8; 16],
    }
}

async fn memory_pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    init_telemetry_schema(&pool).await.unwrap();
    pool
}

fn current_test_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_secs()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn evidence_kind_names_include_first_path_federated_credentials() {
    assert_eq!(
        EvidenceKind::MembershipCredential.as_str(),
        "membership_credential"
    );
    assert_eq!(
        EvidenceKind::ProvisioningCredential.as_str(),
        "provisioning_credential"
    );
}

#[test]
fn production_policy_rejects_local_static() {
    let adapter = LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: TRUSTED_SUBJECT.to_string(),
        audience: TRUSTED_AUDIENCE.to_string(),
        operation: MEMBERSHIP_OPERATION.to_string(),
        resource: Some(TRUSTED_RESOURCE.to_string()),
        evidence_ref: "local-static:test-grant".to_string(),
    }]);

    assert_eq!(
        adapter.verify(&production_request(Some("local-static:test-grant"))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

#[test]
fn production_policy_rejects_wallet_only_authority() {
    let adapter =
        WalletPresentationAdapter::with_validation_time([wallet_fixture()], WALLET_ISSUED_AT + 60);

    assert_eq!(
        adapter.verify(&production_request(Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

#[test]
fn prototype_proof_envelope_is_not_a_federated_production_evidence_kind() {
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::PrototypeProofEnvelope.as_str()));
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::LocalStatic.as_str()));
    assert!(!membership_descriptor(MEMBERSHIP_OPCODE)
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::WalletPresentation.as_str()));
    assert!(wallet_fixtures::wallet_descriptor(WALLET_OPCODE).dev_binding);
}

#[test]
fn track_e_fixture_constants_share_track_d_subject_audience_origin_and_resource() {
    assert_eq!(TRUSTED_SUBJECT, wallet_fixtures::WALLET_SUBJECT);
    assert_eq!(TRUSTED_AUDIENCE, wallet_fixtures::WALLET_AUDIENCE);
    assert_eq!(TRUSTED_ORIGIN, wallet_fixtures::WALLET_ORIGIN);
    assert_eq!(TRUSTED_RESOURCE, wallet_fixtures::WALLET_RESOURCE);
    assert!(MEMBERSHIP_CREDENTIAL_REF.starts_with("membership-credential:"));
}

#[test]
fn valid_membership_credential_verifies() {
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    match adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::MembershipCredential);
            assert_eq!(summary.subject, TRUSTED_SUBJECT);
            assert!(summary.public_proof);
            assert!(!summary.local_dev_test_only);
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:membership_credential"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "proof:redacted_ed25519_signature"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected valid membership credential, got {error:?}")
        }
    }
}

#[test]
fn evidence_summary_redacts_private_material() {
    let sensitive_evidence_ref =
        "/Users/bananawalnut/.secrets/registry.json?Authorization=Bearer raw-registry-secret-token";
    let mut fixture = membership_credential_fixture();
    fixture.evidence_ref = sensitive_evidence_ref.to_string();
    let credential = fixture.credential.clone().expect("credential fixture");
    let raw_signature_hex = hex_lower(&fixture.signature_bytes);
    let raw_signature_debug = format!("{:?}", fixture.signature_bytes);
    let raw_private_seed_hex = hex_lower(&ISSUER_FIXTURE_ED25519_SEED);
    let raw_private_seed_debug = format!("{:?}", ISSUER_FIXTURE_ED25519_SEED);
    let raw_credential_body = String::from_utf8(credential.canonical_bytes()).unwrap();

    let adapter =
        FederatedCredentialAdapter::new([fixture], trusted_registry(), TRUSTED_VALIDATION_TIME);
    let manifest = ReceiverManifest::new([membership_descriptor(MEMBERSHIP_OPCODE)]);
    let signed = Verifier::verify_manifest_operation_with_evidence_inputs_and_sign(
        &production_packet(MEMBERSHIP_OPCODE),
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        Some(sensitive_evidence_ref),
        [origin_input(TRUSTED_ORIGIN)],
        &adapter,
        TRUSTED_VALIDATION_TIME,
        "verifier:e10-fixture",
        &[7u8; 32],
    )
    .expect("accepted federated evidence should produce a signed context");
    signed
        .verify_ed25519(&[7u8; 32], TRUSTED_AUDIENCE, TRUSTED_VALIDATION_TIME)
        .expect("signed context remains verifiable");

    let summary = &signed.context.evidence_summary;
    for expected in [
        "evidence_kind:membership_credential",
        "credential_kind:membership_credential",
        &format!("credential_id:{MEMBERSHIP_CREDENTIAL_REF}"),
        &format!("issuer_id:{TRUSTED_ISSUER_ID}"),
        &format!("trust_root_ref:{TRUST_ROOT_REF}"),
        &format!("registry_root_ref:{REGISTRY_ROOT_REF}"),
        &format!("status_ref:{CREDENTIAL_STATUS_REF}"),
        "status:active",
        &format!("issued_at:{TRUSTED_ISSUED_AT}"),
        &format!("expires_at:{TRUSTED_EXPIRES_AT}"),
        "public_proof:true",
        "proof:redacted_ed25519_signature",
    ] {
        assert!(
            summary.iter().any(|field| field == expected),
            "missing safe summary field {expected}"
        );
    }
    assert!(summary
        .iter()
        .any(|field| field.starts_with("issuer_key_id:pubkey:sha256:")));
    assert!(summary
        .iter()
        .any(|field| field.starts_with("evidence_ref_sha256:")));

    let joined_summary = summary.join("\n");
    for forbidden in [
        sensitive_evidence_ref,
        "Bearer raw-registry-secret-token",
        "raw-registry-secret-token",
        "/Users/bananawalnut/.secrets/registry.json",
        &raw_signature_hex,
        &raw_signature_debug,
        &raw_private_seed_hex,
        &raw_private_seed_debug,
        raw_credential_body.as_str(),
        server::evidence::SecsFederatedCredential::VERSION,
    ] {
        assert!(
            !joined_summary.contains(forbidden),
            "summary leaked forbidden material: {forbidden}"
        );
    }

    let receipt = Receipt::verify_from_signed_context(
        "receipt-e10-federated",
        &signed,
        TRUSTED_VALIDATION_TIME,
    )
    .sign_ed25519(
        "verifier:e10-fixture",
        &[7u8; 32],
        server::receipt::AuthenticatorKind::Ed25519Verifier,
    )
    .expect("receipt signs");
    assert_eq!(
        receipt.context_id.as_deref(),
        Some(signed.context.context_id.as_str())
    );
    assert_eq!(receipt.operation.as_deref(), Some(MEMBERSHIP_OPERATION));
    let receipt_debug = format!("{receipt:?}");
    assert!(!receipt_debug.contains("raw-registry-secret-token"));
    assert!(!receipt_debug.contains("/Users/bananawalnut/.secrets"));
    assert!(!receipt_debug.contains(server::evidence::SecsFederatedCredential::VERSION));
}

#[test]
fn valid_provisioning_credential_verifies_when_descriptor_permits_it() {
    let adapter = FederatedCredentialAdapter::new(
        [provisioning_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    match adapter.verify(&request_for(
        &provisioning_descriptor(PROVISIONING_OPCODE),
        Some(PROVISIONING_CREDENTIAL_REF),
    )) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::ProvisioningCredential);
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:provisioning_credential"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected valid provisioning credential, got {error:?}")
        }
    }
}

fn assert_credential_rejected(
    fixture: server::evidence::FederatedCredentialFixture,
    request: EvidenceRequest,
    expected: VerificationError,
) {
    let adapter =
        FederatedCredentialAdapter::new([fixture], trusted_registry(), TRUSTED_VALIDATION_TIME);
    assert_eq!(adapter.verify(&request), EvidenceResult::Rejected(expected));
}

#[test]
fn reject_matrix_missing_unknown_malformed_suite_signature_and_embedded_key() {
    assert_eq!(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(None)),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(Some("membership-credential:missing"))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_credential_rejected(
        malformed_credential_fixture(),
        production_request(Some(trust_fixtures::MALFORMED_CREDENTIAL_REF)),
        VerificationError::InvalidPresentation,
    );

    let mut unsupported_suite = membership_credential_fixture();
    unsupported_suite
        .credential
        .as_mut()
        .expect("credential")
        .signature_suite = "FixtureSuite-v0".to_string();
    resign_credential(&mut unsupported_suite);
    assert_credential_rejected(
        unsupported_suite,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::UnsupportedSignatureSuite,
    );

    let mut wrong_signature = membership_credential_fixture();
    wrong_signature.signature_bytes[0] ^= 0x01;
    assert_credential_rejected(
        wrong_signature,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::InvalidSignature,
    );

    let mut wrong_embedded_key = membership_credential_fixture();
    wrong_embedded_key.embedded_issuer_public_key_bytes = vec![0x99; 32];
    assert_credential_rejected(
        wrong_embedded_key,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::WrongIssuerKey,
    );
}

#[test]
fn reject_matrix_issuer_roots_status_and_validity_fail_closed() {
    for (fixture, expected) in [
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").issuer_id =
                    "did:example:missing".to_string();
                fixture
            },
            VerificationError::UnknownIssuer,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture
                    .credential
                    .as_mut()
                    .expect("credential")
                    .trust_root_ref = WRONG_TRUST_ROOT_REF.to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongTrustRoot,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture
                    .credential
                    .as_mut()
                    .expect("credential")
                    .registry_root_ref = WRONG_REGISTRY_ROOT_REF.to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongRegistryRoot,
        ),
    ] {
        assert_credential_rejected(
            fixture,
            production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
            expected,
        );
    }

    let mut revoked = issuer_entry();
    revoked.status = TrustedIssuerStatus::Revoked;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([revoked]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::RevokedIssuer)
    );

    let mut expired = issuer_entry();
    expired.not_after = TRUSTED_VALIDATION_TIME - 1;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([expired]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::ExpiredVerifierKey)
    );

    let mut future = issuer_entry();
    future.not_before = TRUSTED_VALIDATION_TIME + 1;
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        TrustedIssuerRegistry::new([future]).expect("registry"),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::NotYetValidVerifierKey)
    );
}

#[test]
fn reject_matrix_credential_claim_and_descriptor_policy_fields_fail_closed() {
    for (fixture, expected) in [
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").status =
                    FederatedCredentialStatus::Revoked;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::RevokedCredential,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").expires_at =
                    TRUSTED_VALIDATION_TIME;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::ExpiredClaim,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").issued_at =
                    TRUSTED_VALIDATION_TIME + 1;
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::NotYetValidClaim,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").subject =
                    "did:example:bob#key-1".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongSubject,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").audience =
                    "secS://other".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongAudience,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").origin =
                    Some("https://evil.example".to_string());
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongOrigin,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").operation =
                    "membership.other".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongOperation,
        ),
        (
            {
                let mut fixture = membership_credential_fixture();
                fixture.credential.as_mut().expect("credential").resource =
                    "application/not-json".to_string();
                resign_credential(&mut fixture);
                fixture
            },
            VerificationError::WrongResource,
        ),
    ] {
        assert_credential_rejected(
            fixture,
            production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
            expected,
        );
    }

    assert_eq!(
        FederatedCredentialAdapter::new(
            [provisioning_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(Some(PROVISIONING_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
}

fn composite_adapter<'a>(
    wallet: &'a WalletPresentationAdapter,
    credential: &'a FederatedCredentialAdapter,
) -> CompositeEvidenceAdapter<'a> {
    CompositeEvidenceAdapter::new([
        wallet as &dyn EvidenceAdapter,
        credential as &dyn EvidenceAdapter,
    ])
}

fn membership_wallet_adapter() -> WalletPresentationAdapter {
    let mut fixture = wallet_fixture();
    fixture.operation = MEMBERSHIP_OPERATION.to_string();
    sign_wallet_fixture(&mut fixture);
    WalletPresentationAdapter::with_validation_time([fixture], WALLET_ISSUED_AT + 60)
}

fn local_static_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.dev.local_static"),
        payload_schema: Some(TRUSTED_RESOURCE.to_string()),
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["local_static.subject".to_string()],
        required_capabilities: vec!["dev.execute".to_string()],
        accepted_evidence: vec![EvidenceKind::LocalStatic.as_str().to_string()],
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 300,
        handler_id: "dev/local-static".to_string(),
        dev_binding: true,
        range: OpcodeRange::classify(opcode),
    }
}

fn local_static_adapter_for(
    descriptor: &OperationDescriptor,
    subject: &str,
    audience: &str,
    evidence_ref: &str,
) -> LocalStaticEvidenceAdapter {
    LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: subject.to_string(),
        audience: audience.to_string(),
        operation: descriptor.name.as_str().to_string(),
        resource: descriptor.payload_schema.clone(),
        evidence_ref: evidence_ref.to_string(),
    }])
}

fn assert_rejected(result: EvidenceResult, expected: VerificationError) {
    assert_eq!(result, EvidenceResult::Rejected(expected));
}

fn assert_matrix_row(row_name: &str, expected_status: PolicyMatrixStatus) {
    let row = A6_POLICY_MATRIX
        .iter()
        .find(|row| row.row_name == row_name)
        .unwrap_or_else(|| panic!("missing A6 policy matrix row {row_name}"));
    assert_eq!(row.status, expected_status);
    assert!(!row.input_condition.is_empty());
    assert!(!row.expected_accept_reject_reason.is_empty());
    assert!(row.test_name.contains("policy_matrix"));
}

#[test]
fn production_federated_policy_matrix_table_accounts_for_a6_rows() {
    let required_rows = [
        "local_dev_descriptor_accepts_local_static_fixture",
        "local_dev_runtime_rejects_production_descriptor",
        "production_verified_missing_evidence_rejects_before_handler",
        "production_wallet_descriptor_rejects_local_static",
        "production_wallet_shape_only_shell_fails_closed",
        "production_wallet_core_presentation_accepts_when_policy_matches",
        "production_wallet_presentation_reject_matrix",
        "production_federated_untrusted_issuer_rejects",
        "production_federated_status_reject_matrix",
        "production_federated_binding_reject_matrix",
        "production_federated_valid_evidence_local_policy_rejects",
        "production_federated_membership_credential_accepts_when_policy_matches",
        "production_membership_root_ref_without_inclusion_proof_rejects",
        "production_dregg_ref_without_promotion_is_not_live_validation",
        "production_midnight_ref_without_promotion_is_not_authority",
        "production_cardano_ref_without_promotion_is_not_authority",
    ];

    assert_eq!(A6_POLICY_MATRIX.len(), required_rows.len());
    for row_name in required_rows {
        assert!(
            A6_POLICY_MATRIX.iter().any(|row| row.row_name == row_name),
            "missing A6 row {row_name}"
        );
    }
    assert!(A6_POLICY_MATRIX
        .iter()
        .filter(|row| row.first_path)
        .all(|row| row.status == PolicyMatrixStatus::Executable));
}

#[test]
fn production_federated_policy_matrix_local_dev_rows_are_executable() {
    assert_matrix_row(
        "local_dev_descriptor_accepts_local_static_fixture",
        PolicyMatrixStatus::Executable,
    );
    assert_matrix_row(
        "local_dev_runtime_rejects_production_descriptor",
        PolicyMatrixStatus::Executable,
    );
    assert_matrix_row(
        "production_verified_missing_evidence_rejects_before_handler",
        PolicyMatrixStatus::Executable,
    );
    assert_eq!(
        RuntimeMode::parse("local_dev_plaintext"),
        Some(RuntimeMode::LocalDevPlaintext)
    );
    assert_eq!(
        RuntimeMode::parse("local_dev_tunnel"),
        Some(RuntimeMode::LocalDevTunnel)
    );
    assert_eq!(
        RuntimeMode::parse("production_verified"),
        Some(RuntimeMode::ProductionVerified)
    );

    let dev_descriptor = local_static_descriptor(0x45);
    let local_static = local_static_adapter_for(
        &dev_descriptor,
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        "local-static:policy-matrix",
    );
    match local_static.verify(&request_for(
        &dev_descriptor,
        Some("local-static:policy-matrix"),
    )) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::LocalStatic);
            assert!(summary.local_dev_test_only);
            assert!(!summary.public_proof);
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected dev local_static accept, got {error:?}")
        }
    }

    let production_descriptor = membership_descriptor(MEMBERSHIP_OPCODE);
    assert_rejected(
        local_static.verify(&request_for(
            &production_descriptor,
            Some("local-static:policy-matrix"),
        )),
        VerificationError::InsufficientEvidence,
    );
    assert_rejected(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&request_for(&production_descriptor, None)),
        VerificationError::InsufficientEvidence,
    );
}

#[test]
fn production_wallet_policy_matrix_rows_are_executable_or_track_d_boundaries() {
    for row_name in [
        "production_wallet_descriptor_rejects_local_static",
        "production_wallet_shape_only_shell_fails_closed",
        "production_wallet_core_presentation_accepts_when_policy_matches",
        "production_wallet_presentation_reject_matrix",
    ] {
        assert_matrix_row(row_name, PolicyMatrixStatus::Executable);
    }

    let wallet_descriptor = wallet_fixtures::wallet_descriptor(WALLET_OPCODE);
    let local_static = local_static_adapter_for(
        &wallet_descriptor,
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        "local-static:wallet-policy-matrix",
    );
    assert_rejected(
        local_static.verify(&request_for(
            &wallet_descriptor,
            Some("local-static:wallet-policy-matrix"),
        )),
        VerificationError::InsufficientEvidence,
    );

    let mut shape_only = wallet_fixture();
    shape_only.signature_bytes.clear();
    let wallet_adapter =
        WalletPresentationAdapter::with_validation_time([shape_only], WALLET_ISSUED_AT + 60);
    assert_rejected(
        wallet_adapter.verify(&request_for(&wallet_descriptor, Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidPresentation,
    );

    let wallet_adapter =
        WalletPresentationAdapter::with_validation_time([wallet_fixture()], WALLET_ISSUED_AT + 60);
    match wallet_adapter.verify(&request_for(&wallet_descriptor, Some(WALLET_EVIDENCE_REF))) {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::WalletPresentation);
            assert_eq!(summary.operation, WALLET_OPERATION);
            assert!(summary.public_proof);
            assert!(!summary.local_dev_test_only);
        }
        EvidenceResult::Rejected(error) => panic!("expected valid wallet accept, got {error:?}"),
    }

    let mut wrong_signature = wallet_fixture();
    wrong_signature.signature_bytes[0] ^= 0x01;
    assert_rejected(
        WalletPresentationAdapter::with_validation_time([wrong_signature], WALLET_ISSUED_AT + 60)
            .verify(&request_for(&wallet_descriptor, Some(WALLET_EVIDENCE_REF))),
        VerificationError::InvalidSignature,
    );
}

#[test]
fn production_federated_policy_matrix_first_path_rows_are_executable() {
    for row_name in [
        "production_federated_untrusted_issuer_rejects",
        "production_federated_status_reject_matrix",
        "production_federated_binding_reject_matrix",
        "production_federated_valid_evidence_local_policy_rejects",
        "production_federated_membership_credential_accepts_when_policy_matches",
    ] {
        assert_matrix_row(row_name, PolicyMatrixStatus::Executable);
    }

    let mut untrusted = membership_credential_fixture();
    untrusted.credential.as_mut().expect("credential").issuer_id =
        "did:example:untrusted-policy-matrix".to_string();
    resign_credential(&mut untrusted);
    assert_credential_rejected(
        untrusted,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::UnknownIssuer,
    );

    let mut revoked_issuer = issuer_entry();
    revoked_issuer.status = TrustedIssuerStatus::Revoked;
    assert_rejected(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            TrustedIssuerRegistry::new([revoked_issuer]).expect("registry"),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        VerificationError::RevokedIssuer,
    );

    let mut wrong_subject = membership_credential_fixture();
    wrong_subject
        .credential
        .as_mut()
        .expect("credential")
        .subject = "did:example:bob#key-1".to_string();
    resign_credential(&mut wrong_subject);
    assert_credential_rejected(
        wrong_subject,
        production_request(Some(MEMBERSHIP_CREDENTIAL_REF)),
        VerificationError::WrongSubject,
    );

    let mut wrong_policy = membership_descriptor(MEMBERSHIP_OPCODE);
    wrong_policy.name = OperationName::new("membership.other");
    assert_rejected(
        FederatedCredentialAdapter::new(
            [membership_credential_fixture()],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        )
        .verify(&request_for(&wrong_policy, Some(MEMBERSHIP_CREDENTIAL_REF))),
        VerificationError::WrongOperation,
    );

    let accepted = FederatedCredentialAdapter::new(
        [
            membership_credential_fixture(),
            provisioning_credential_fixture(),
        ],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert!(matches!(
        accepted.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Satisfied(_)
    ));
    assert!(matches!(
        accepted.verify(&request_for(
            &provisioning_descriptor(PROVISIONING_OPCODE),
            Some(PROVISIONING_CREDENTIAL_REF),
        )),
        EvidenceResult::Satisfied(_)
    ));
}

fn future_rail_descriptor(kind: EvidenceKind) -> OperationDescriptor {
    OperationDescriptor {
        accepted_evidence: vec![kind.as_str().to_string()],
        ..membership_descriptor(MEMBERSHIP_OPCODE)
    }
}

#[test]
fn production_federated_policy_matrix_future_root_and_rail_refs_are_inert() {
    for row_name in [
        "production_membership_root_ref_without_inclusion_proof_rejects",
        "production_dregg_ref_without_promotion_is_not_live_validation",
        "production_midnight_ref_without_promotion_is_not_authority",
        "production_cardano_ref_without_promotion_is_not_authority",
    ] {
        assert_matrix_row(row_name, PolicyMatrixStatus::Deferred);
    }

    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let mut root_ref_only = request_for(&membership_descriptor(MEMBERSHIP_OPCODE), None);
    root_ref_only
        .evidence_refs
        .push("membership_root_ref:fixture-root-without-inclusion-proof".to_string());
    assert_rejected(
        adapter.verify(&root_ref_only),
        VerificationError::InsufficientEvidence,
    );

    for (kind, evidence_ref) in [
        (EvidenceKind::DreggReceipt, "dregg_anchor_ref:fixture-only"),
        (EvidenceKind::MidnightProof, "midnight_proof:fixture-only"),
        (
            EvidenceKind::CardanoSettlement,
            "cardano_settlement:fixture-only",
        ),
    ] {
        let credential = credential_fixture(evidence_ref, kind, MEMBERSHIP_OPERATION);
        let adapter = FederatedCredentialAdapter::new(
            [credential],
            trusted_registry(),
            TRUSTED_VALIDATION_TIME,
        );
        assert_rejected(
            adapter.verify(&request_for(
                &future_rail_descriptor(kind),
                Some(evidence_ref),
            )),
            VerificationError::InsufficientEvidence,
        );
    }
}

#[test]
fn membership_provision_default_manifest_exposes_canonical_descriptor_contract() {
    let manifest = ReceiverManifest::default_v0();
    let descriptor = manifest
        .lookup(WALLET_AND_MEMBERSHIP_OPCODE)
        .expect("default receiver manifest must expose canonical membership.provision descriptor");

    assert_eq!(descriptor.name.as_str(), MEMBERSHIP_OPERATION);
    assert_eq!(descriptor.handler_id, "membership/provision");
    assert!(!descriptor.dev_binding);
    assert!(descriptor
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::WalletPresentation.as_str()));
    assert!(descriptor
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::MembershipCredential.as_str()));
    assert!(!descriptor
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::LocalStatic.as_str()));
    assert!(!descriptor
        .accepted_evidence
        .iter()
        .any(|kind| kind == EvidenceKind::PrototypeProofEnvelope.as_str()));
}

#[test]
fn membership_provision_runtime_rejects_descriptor_only_without_wallet_and_issuer_evidence() {
    let manifest = ReceiverManifest::default_v0();
    let descriptor = manifest
        .lookup(WALLET_AND_MEMBERSHIP_OPCODE)
        .expect("default receiver manifest must expose canonical membership.provision descriptor");
    assert_eq!(WALLET_AND_MEMBERSHIP_OPCODE, 0x44);
    assert_eq!(descriptor.name.as_str(), MEMBERSHIP_OPERATION);

    let packet = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    let unsigned_result = Verifier::verify_manifest_operation_for_runtime(
        &packet,
        &manifest,
        TRUSTED_AUDIENCE,
        current_test_time(),
        RuntimeMode::ProductionVerified,
    );
    assert!(
        matches!(unsigned_result, Err(VerificationError::InsufficientEvidence)),
        "descriptor-only production runtime verification for opcode 0x44 membership.provision must fail before signed context creation; got {unsigned_result:?}"
    );

    let identity = explicit_test_fixture_identity("verifier:runtime-red", [7u8; 32]);
    let result = Verifier::verify_manifest_operation_and_sign_for_runtime_with_identity(
        &packet,
        &manifest,
        TRUSTED_AUDIENCE,
        current_test_time(),
        &identity,
        RuntimeMode::ProductionVerified,
    );

    assert!(
        matches!(result, Err(VerificationError::InsufficientEvidence)),
        "descriptor-only production runtime verification for opcode 0x44 membership.provision must reject without wallet proof-of-possession and trusted issuer evidence; got {result:?}"
    );
}

#[test]
fn membership_provision_descriptor_only_guard_is_production_runtime_only() {
    let manifest = ReceiverManifest::default_v0();
    let packet = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);

    for runtime_mode in [RuntimeMode::LocalDevPlaintext, RuntimeMode::LocalDevTunnel] {
        let signed = Verifier::verify_manifest_operation_and_sign_for_runtime_with_identity(
            &packet,
            &manifest,
            TRUSTED_AUDIENCE,
            current_test_time(),
            &explicit_test_fixture_identity("verifier:runtime-local", [9u8; 32]),
            runtime_mode,
        )
        .expect("local/dev descriptor-only runtime compatibility should not be changed by the production-only membership.provision evidence guard");

        assert_eq!(signed.context.opcode, WALLET_AND_MEMBERSHIP_OPCODE);
        assert_eq!(signed.context.operation, MEMBERSHIP_OPERATION);
        assert!(
            signed
                .context
                .evidence_summary
                .iter()
                .any(|field| field == EvidenceKind::WalletPresentation.as_str()),
            "local/dev descriptor summaries should preserve the manifest evidence contract"
        );
        assert!(
            signed
                .context
                .evidence_summary
                .iter()
                .any(|field| field == EvidenceKind::MembershipCredential.as_str()),
            "local/dev descriptor summaries should preserve the manifest evidence contract"
        );
    }
}

#[tokio::test]
async fn membership_provision_e2e_contract_reaches_verify_execute_and_ledger_inspection() {
    // #80: the happy path exercises the ACTIVE default manifest descriptor,
    // not an independent fixture copy.
    let manifest = ReceiverManifest::default_v0();
    let descriptor = manifest
        .lookup(WALLET_AND_MEMBERSHIP_OPCODE)
        .expect("default manifest exposes canonical membership.provision")
        .clone();
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);
    let packet = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    let payload = packet.encrypted_payload.clone();
    let payload_size = payload.len() as i64;

    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(        &packet,        &manifest,        TRUSTED_AUDIENCE,        TRUSTED_SUBJECT,        &server::evidence::EvidenceInputs::new(            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],            [origin_input(TRUSTED_ORIGIN)],        ),        &composite,        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .expect("canonical membership.provision packet should verify with wallet PoP and trusted issuer evidence");
    assert_eq!(signed.context.operation, MEMBERSHIP_OPERATION);
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:wallet_presentation"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:membership_credential"));
    assert!(!signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "authority:local_dev_test_only"));

    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let identity = bootstrap.identity().clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    router.register_handler(
        descriptor.handler_id.clone(),
        Box::new(MembershipProvisionProgram {
            calls: Arc::clone(&calls),
        }),
    );

    router.route_verified(&signed, payload).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "membership.provision success must execute the production-bound handler, not stop at packet echo or verifier-only acceptance"
    );
    let telemetry: (i64, String) = sqlx::query_as(
        "SELECT payload_size, operation FROM node_telemetry WHERE opcode = ? ORDER BY id DESC LIMIT 1",
    )
    .bind(i64::from(WALLET_AND_MEMBERSHIP_OPCODE))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(telemetry.0, payload_size);
    assert_eq!(telemetry.1, MEMBERSHIP_OPERATION);

    let ledger = Ledger::new(pool.clone());
    let chain = ledger
        .inspect_receipt_chain_by_context_id(&signed.context.context_id)
        .await
        .unwrap();
    let decisions: Vec<_> = chain
        .iter()
        .map(|receipt| {
            (
                receipt.kind.as_str(),
                receipt.decision.as_str(),
                receipt.reason.as_deref(),
                receipt.operation.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        decisions,
        vec![
            ("verify", "accepted", None, Some(MEMBERSHIP_OPERATION)),
            ("execute", "accepted", None, Some(MEMBERSHIP_OPERATION)),
        ],
        "success requires inspectable verify + execute receipts; descriptor mismatch, handler_unavailable, fixture smoke output, or local_static fallback is not success"
    );
}

#[tokio::test]
async fn membership_provision_verifier_acceptance_without_execute_receipt_is_not_success() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);
    let packet = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    let payload = packet.encrypted_payload.clone();

    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(        &packet,        &manifest,        TRUSTED_AUDIENCE,        TRUSTED_SUBJECT,        &server::evidence::EvidenceInputs::new(            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],            [origin_input(TRUSTED_ORIGIN)],        ),        &composite,        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .expect("fixture smoke/log output must show real membership.provision verifier acceptance with wallet PoP and trusted issuer evidence before proving verifier-only acceptance is not success");
    assert_eq!(
        signed.context.operation, MEMBERSHIP_OPERATION,
        "fixture smoke/log output must verify the membership.provision operation before proving verifier-only acceptance is not success"
    );
    assert!(
        signed
            .context
            .evidence_summary
            .iter()
            .any(|field| field == "evidence_kind:wallet_presentation"),
        "fixture smoke/log output must include wallet_presentation evidence; verifier-only acceptance is not success"
    );
    assert!(
        signed
            .context
            .evidence_summary
            .iter()
            .any(|field| field == "evidence_kind:membership_credential"),
        "fixture smoke/log output must include membership_credential evidence; verifier-only acceptance is not success"
    );
    assert!(
        !signed
            .context
            .evidence_summary
            .iter()
            .any(|field| field == "authority:local_dev_test_only"),
        "fixture smoke/log output must not rely on local_dev_test_only authority; verifier-only acceptance is not success"
    );

    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let identity = bootstrap.identity().clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    // Intentionally do not register descriptor.handler_id (membership/provision):
    // this proves verifier acceptance alone is not a successful provision.

    router.route_verified(&signed, payload).await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "fixture smoke/log output with verifier-only acceptance is not success; no membership.provision handler should run when membership/provision is unregistered"
    );

    let ledger = Ledger::new(pool.clone());
    let chain = ledger
        .inspect_receipt_chain_by_context_id(&signed.context.context_id)
        .await
        .unwrap();
    let decisions: Vec<_> = chain
        .iter()
        .map(|receipt| {
            (
                receipt.kind.as_str(),
                receipt.decision.as_str(),
                receipt.reason.as_deref(),
                receipt.operation.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        decisions,
        vec![
            ("verify", "accepted", None, Some(MEMBERSHIP_OPERATION)),
            (
                "execute",
                "rejected",
                Some("handler_unavailable"),
                Some(MEMBERSHIP_OPERATION),
            ),
        ],
        "fixture smoke/log output must record verify accepted plus execute rejected handler_unavailable; verifier-only acceptance is not success"
    );
    assert!(
        !decisions.iter().any(|(kind, decision, _, operation)| {
            *kind == "execute"
                && *decision == "accepted"
                && *operation == Some(MEMBERSHIP_OPERATION)
        }),
        "fixture smoke/log output must not contain execute accepted for membership.provision; verifier-only acceptance is not success"
    );
}

#[test]
fn membership_provision_contract_rejects_single_layer_and_local_static_success_substitutes() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence),
        "wallet proof-of-possession alone is not membership.provision success"
    );
    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence),
        "trusted issuer credential alone is not membership.provision success"
    );

    let local_static = local_static_adapter_for(
        &descriptor,
        TRUSTED_SUBJECT,
        TRUSTED_AUDIENCE,
        "local-static:membership-provision-fallback",
    );
    assert_eq!(
        local_static.verify(&request_for(
            &descriptor,
            Some("local-static:membership-provision-fallback"),
        )),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence),
        "local_static fixture fallback must not satisfy membership.provision"
    );
}

#[test]
fn membership_provision_negative_matrix_rejects_at_focused_layers() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    for (case, refs, expected) in [
        (
            "missing wallet evidence",
            vec![MEMBERSHIP_CREDENTIAL_REF],
            VerificationError::InsufficientEvidence,
        ),
        (
            "missing issuer credential evidence",
            vec![WALLET_EVIDENCE_REF],
            VerificationError::InsufficientEvidence,
        ),
    ] {
        assert_eq!(
            composite.verify(&request_with_refs(&descriptor, refs)),
            EvidenceResult::Rejected(expected),
            "{case} must reject before membership.provision success"
        );
    }

    let mut mismatched_wallet = wallet_fixture();
    mismatched_wallet.operation = MEMBERSHIP_OPERATION.to_string();
    mismatched_wallet.subject = "did:example:bob#key-1".to_string();
    sign_wallet_fixture(&mut mismatched_wallet);
    let wallet_subject_mismatch =
        WalletPresentationAdapter::with_validation_time([mismatched_wallet], WALLET_ISSUED_AT + 60);
    assert_eq!(
        composite_adapter(&wallet_subject_mismatch, &credential).verify(&request_with_refs(
            &descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongSubject),
        "wallet subject mismatch must reject at the wallet layer"
    );

    let mut mismatched_credential = membership_credential_fixture();
    mismatched_credential
        .credential
        .as_mut()
        .expect("credential")
        .subject = "did:example:bob#key-1".to_string();
    resign_credential(&mut mismatched_credential);
    let credential_subject_mismatch = FederatedCredentialAdapter::new(
        [mismatched_credential],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        composite_adapter(&wallet, &credential_subject_mismatch).verify(&request_with_refs(
            &descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongSubject),
        "credential subject mismatch must reject at the issuer/root-authority layer"
    );

    let mut wrong_origin = request_with_refs(
        &descriptor,
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    );
    wrong_origin
        .public_inputs
        .retain(|input| !input.starts_with("origin:"));
    wrong_origin
        .public_inputs
        .push(origin_input("https://evil.example"));
    assert_eq!(
        composite.verify(&wrong_origin),
        EvidenceResult::Rejected(VerificationError::WrongOrigin),
        "wrong origin must be caught by wallet challenge binding before success"
    );

    let mut wrong_audience_wallet = wallet_fixture();
    wrong_audience_wallet.operation = MEMBERSHIP_OPERATION.to_string();
    wrong_audience_wallet.audience = "secS://other-target".to_string();
    sign_wallet_fixture(&mut wrong_audience_wallet);
    let wrong_audience_wallet = WalletPresentationAdapter::with_validation_time(
        [wrong_audience_wallet],
        WALLET_ISSUED_AT + 60,
    );
    let mut wrong_audience_request = EvidenceRequest::from_descriptor_with_refs(
        &descriptor,
        TRUSTED_SUBJECT,
        "secS://other-target",
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    );
    wrong_audience_request
        .public_inputs
        .push(origin_input(TRUSTED_ORIGIN));
    assert_eq!(
        composite_adapter(&wrong_audience_wallet, &credential).verify(&wrong_audience_request),
        EvidenceResult::Rejected(VerificationError::WrongAudience),
        "wallet-matched wrong audience must still reject at issuer/root-authority binding"
    );

    let mut wrong_operation_descriptor = descriptor.clone();
    wrong_operation_descriptor.name = OperationName::new("membership.not-permitted");
    let mut wrong_operation_wallet = wallet_fixture();
    wrong_operation_wallet.operation = wrong_operation_descriptor.name.as_str().to_string();
    sign_wallet_fixture(&mut wrong_operation_wallet);
    let wrong_operation_wallet = WalletPresentationAdapter::with_validation_time(
        [wrong_operation_wallet],
        WALLET_ISSUED_AT + 60,
    );
    assert_eq!(
        composite_adapter(&wrong_operation_wallet, &credential).verify(&request_with_refs(
            &wrong_operation_descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongOperation),
        "wallet-matched wrong operation must still reject at issuer/root-authority binding"
    );

    let mut wrong_resource_descriptor = descriptor.clone();
    wrong_resource_descriptor.payload_schema = Some("application/not-json".to_string());
    let mut wrong_resource_wallet = wallet_fixture();
    wrong_resource_wallet.operation = MEMBERSHIP_OPERATION.to_string();
    wrong_resource_wallet.resource = "application/not-json".to_string();
    sign_wallet_fixture(&mut wrong_resource_wallet);
    let wrong_resource_wallet = WalletPresentationAdapter::with_validation_time(
        [wrong_resource_wallet],
        WALLET_ISSUED_AT + 60,
    );
    assert_eq!(
        composite_adapter(&wrong_resource_wallet, &credential).verify(&request_with_refs(
            &wrong_resource_descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongResource),
        "wallet-matched wrong resource must still reject at issuer/root-authority binding"
    );

    let mut provisioning_only_policy = descriptor.clone();
    provisioning_only_policy.accepted_evidence = vec![
        EvidenceKind::WalletPresentation.as_str().to_string(),
        EvidenceKind::ProvisioningCredential.as_str().to_string(),
    ];
    assert_eq!(
        composite.verify(&request_with_refs(
            &provisioning_only_policy,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence),
        "descriptor-local evidence policy must reject an otherwise valid membership credential when provisioning authority is required"
    );
}

#[tokio::test]
async fn membership_provision_rejects_remain_inspectable_and_redacted() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let sensitive_wallet_ref =
        "/Users/bananawalnut/.secrets/wallet.jwt?Authorization=Bearer raw-wallet-token";
    let sensitive_credential_ref =
        "/Users/bananawalnut/.secrets/membership.json?Authorization=Bearer raw-credential-token";

    let mut wallet_fixture = wallet_fixture();
    wallet_fixture.evidence_ref = sensitive_wallet_ref.to_string();
    wallet_fixture.operation = MEMBERSHIP_OPERATION.to_string();
    sign_wallet_fixture(&mut wallet_fixture);
    let raw_wallet_signature_hex = hex_lower(&wallet_fixture.signature_bytes);
    let raw_wallet_signature_debug = format!("{:?}", wallet_fixture.signature_bytes);
    let wallet =
        WalletPresentationAdapter::with_validation_time([wallet_fixture], WALLET_ISSUED_AT + 60);

    let mut credential_fixture = membership_credential_fixture();
    credential_fixture.evidence_ref = sensitive_credential_ref.to_string();
    let credential = credential_fixture.credential.clone().expect("credential");
    let raw_credential_body = String::from_utf8(credential.canonical_bytes()).unwrap();
    let raw_credential_signature_hex = hex_lower(&credential_fixture.signature_bytes);
    let raw_credential_signature_debug = format!("{:?}", credential_fixture.signature_bytes);
    let raw_private_seed_hex = hex_lower(&ISSUER_FIXTURE_ED25519_SEED);
    let raw_private_seed_debug = format!("{:?}", ISSUER_FIXTURE_ED25519_SEED);
    let credential = FederatedCredentialAdapter::new(
        [credential_fixture],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        &server::evidence::EvidenceInputs::new(
            [sensitive_wallet_ref, sensitive_credential_ref],
            [origin_input(TRUSTED_ORIGIN)],
        ),
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .expect("membership.provision with sensitive local refs should verify without leaking them");

    for expected in [
        "evidence_kind:wallet_presentation",
        "evidence_kind:membership_credential",
        "credential_kind:membership_credential",
        &format!("issuer_id:{TRUSTED_ISSUER_ID}"),
        &format!("trust_root_ref:{TRUST_ROOT_REF}"),
        &format!("registry_root_ref:{REGISTRY_ROOT_REF}"),
        "public_proof:true",
        "proof:redacted_ed25519_signature",
    ] {
        assert!(
            signed
                .context
                .evidence_summary
                .iter()
                .any(|field| field == expected),
            "missing wallet/issuer authority summary field {expected}"
        );
    }
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field.starts_with("evidence_ref_sha256:")));

    let joined_summary = signed.context.evidence_summary.join("\n");
    for forbidden in [
        sensitive_wallet_ref,
        sensitive_credential_ref,
        "Bearer raw-wallet-token",
        "Bearer raw-credential-token",
        "raw-wallet-token",
        "raw-credential-token",
        "/Users/bananawalnut/.secrets/wallet.jwt",
        "/Users/bananawalnut/.secrets/membership.json",
        &raw_wallet_signature_hex,
        &raw_wallet_signature_debug,
        &raw_credential_signature_hex,
        &raw_credential_signature_debug,
        &raw_private_seed_hex,
        &raw_private_seed_debug,
        raw_credential_body.as_str(),
        server::evidence::SecsFederatedCredential::VERSION,
    ] {
        assert!(
            !joined_summary.contains(forbidden),
            "membership.provision summary leaked forbidden material: {forbidden}"
        );
    }

    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let identity = bootstrap.identity().clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    router.register_handler(
        descriptor.handler_id.clone(),
        Box::new(MembershipProvisionProgram {
            calls: Arc::clone(&calls),
        }),
    );

    router
        .route_verified(&signed, br#"{"membership":"requested"}"#.to_vec())
        .await;
    router
        .route_verified(&signed, br#"{"membership":"requested"}"#.to_vec())
        .await;

    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "replayed membership.provision context must not execute handler twice"
    );
    let ledger = Ledger::new(pool);
    let chain = ledger
        .inspect_receipt_chain_by_context_id(&signed.context.context_id)
        .await
        .expect("replay reject remains inspectable by context id");
    assert!(chain.iter().any(|receipt| {
        receipt.kind == "verify" && receipt.decision == "accepted" && receipt.reason.is_none()
    }));
    assert!(chain.iter().any(|receipt| {
        receipt.kind == "reject"
            && receipt.decision == "rejected"
            && receipt.reason.as_deref() == Some("replay_detected")
    }));
    let receipt_debug = format!("{chain:?}");
    for forbidden in [
        sensitive_wallet_ref,
        sensitive_credential_ref,
        "raw-wallet-token",
        "raw-credential-token",
        "/Users/bananawalnut/.secrets",
        &raw_wallet_signature_hex,
        &raw_credential_signature_hex,
        raw_credential_body.as_str(),
    ] {
        assert!(
            !receipt_debug.contains(forbidden),
            "inspectable reject receipt leaked forbidden material: {forbidden}"
        );
    }
}

#[test]
fn membership_provision_session_and_packet_guards_still_apply_after_evidence() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let manifest = ReceiverManifest::new([descriptor]);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    let mut invalid_session = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    invalid_session.session_id = [0u8; 16];
    assert_eq!(
        Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
            &invalid_session,
            &manifest,
            TRUSTED_AUDIENCE,
            TRUSTED_SUBJECT,
            &server::evidence::EvidenceInputs::new(
                [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
                [origin_input(TRUSTED_ORIGIN)],
            ),
            &composite,
            current_test_time(),
            "verifier:local-prototype",
            &[7u8; 32],
        ),
        Err(VerificationError::InvalidSession),
        "membership.provision must retain session guard after evidence checks"
    );

    let mut excessive_ttl = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    excessive_ttl.claim_ttl = 301;
    assert_eq!(
        Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
            &excessive_ttl,
            &manifest,
            TRUSTED_AUDIENCE,
            TRUSTED_SUBJECT,
            &server::evidence::EvidenceInputs::new(
                [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
                [origin_input(TRUSTED_ORIGIN)],
            ),
            &composite,
            current_test_time(),
            "verifier:local-prototype",
            &[7u8; 32],
        ),
        Err(VerificationError::ClaimTtlExceedsDescriptorMax),
        "membership.provision must retain descriptor TTL/nonce replay-scope guardrails"
    );
}

#[test]
fn wallet_and_issuer_composition_requires_both_layers() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(WALLET_EVIDENCE_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        composite.verify(&request_for(&descriptor, Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );

    match composite.verify(&request_with_refs(
        &descriptor,
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    )) {
        EvidenceResult::Satisfied(summary) => {
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "evidence_kind:wallet_presentation"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "evidence_kind:membership_credential"));
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "credential_kind:membership_credential"));
        }
        EvidenceResult::Rejected(error) => {
            panic!("expected both evidence layers to satisfy, got {error:?}")
        }
    }
}

#[test]
fn wallet_and_issuer_composition_preserves_layer_specific_failures() {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let wallet = membership_wallet_adapter();
    let mut wrong_root = membership_credential_fixture();
    wrong_root
        .credential
        .as_mut()
        .expect("credential")
        .trust_root_ref = WRONG_TRUST_ROOT_REF.to_string();
    resign_credential(&mut wrong_root);
    let credential =
        FederatedCredentialAdapter::new([wrong_root], trusted_registry(), TRUSTED_VALIDATION_TIME);
    let composite = composite_adapter(&wallet, &credential);

    assert_eq!(
        composite.verify(&request_with_refs(
            &descriptor,
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
        )),
        EvidenceResult::Rejected(VerificationError::WrongTrustRoot)
    );

    let valid_credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &valid_credential);
    let mut wrong_origin = request_with_refs(
        &descriptor,
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    );
    wrong_origin
        .public_inputs
        .retain(|input| !input.starts_with("origin:"));
    wrong_origin
        .public_inputs
        .push(origin_input("https://evil.example"));
    assert_eq!(
        composite.verify(&wrong_origin),
        EvidenceResult::Rejected(VerificationError::WrongOrigin)
    );
}

#[test]
fn valid_evidence_policy_accepts_only_when_descriptor_allows_it() {
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );

    assert!(matches!(
        adapter.verify(&production_request(Some(MEMBERSHIP_CREDENTIAL_REF))),
        EvidenceResult::Satisfied(_)
    ));
}

#[test]
fn valid_evidence_local_policy_rejects_disallowed_descriptor_operation_scope_and_audience() {
    let mut wrong_operation_descriptor = membership_descriptor(MEMBERSHIP_OPCODE);
    wrong_operation_descriptor.name =
        server::manifest::OperationName::new("membership.not-permitted");
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&request_for(
            &wrong_operation_descriptor,
            Some(MEMBERSHIP_CREDENTIAL_REF),
        )),
        EvidenceResult::Rejected(VerificationError::WrongOperation)
    );

    let mut wrong_resource_descriptor = membership_descriptor(MEMBERSHIP_OPCODE);
    wrong_resource_descriptor.payload_schema = Some("application/not-json".to_string());
    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    assert_eq!(
        adapter.verify(&request_for(
            &wrong_resource_descriptor,
            Some(MEMBERSHIP_CREDENTIAL_REF),
        )),
        EvidenceResult::Rejected(VerificationError::WrongResource)
    );

    let adapter = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let mut wrong_audience = EvidenceRequest::from_descriptor(
        &membership_descriptor(MEMBERSHIP_OPCODE),
        TRUSTED_SUBJECT,
        "secS://other-target",
        Some(MEMBERSHIP_CREDENTIAL_REF),
    );
    wrong_audience
        .public_inputs
        .push(origin_input(TRUSTED_ORIGIN));
    assert_eq!(
        adapter.verify(&wrong_audience),
        EvidenceResult::Rejected(VerificationError::WrongAudience)
    );
}

// --- M12.3.4: wallet + issuer + Dregg-shaped composition ---

fn dregg_membership_fixture() -> server::evidence::DreggReceiptFixture {
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[0xD7; 32]);
    let public_key_bytes = key.verifying_key().as_bytes().to_vec();
    let mut fixture = server::evidence::DreggReceiptFixture {
        evidence_ref: "dregg-receipt:alice-membership".to_string(),
        subject: TRUSTED_SUBJECT.to_string(),
        audience: TRUSTED_AUDIENCE.to_string(),
        origin: TRUSTED_ORIGIN.to_string(),
        operation: MEMBERSHIP_OPERATION.to_string(),
        resource: TRUSTED_RESOURCE.to_string(),
        receipt_kind: server::evidence::DreggReceiptFixture::RECEIPT_KIND.to_string(),
        strand_ref: "strand:gallery-author:7".to_string(),
        sequence: 7,
        issued_at: TRUSTED_ISSUED_AT,
        expires_at: TRUSTED_EXPIRES_AT,
        signature_suite: "Ed25519".to_string(),
        public_key_ref: server::evidence::public_key_ref_for_bytes(&public_key_bytes),
        author_public_key_bytes: public_key_bytes,
        signature_bytes: Vec::new(),
    };
    fixture.signature_bytes = key.sign(&fixture.canonical_bytes()).to_bytes().to_vec();
    fixture
}

fn tri_evidence_descriptor(opcode: u8) -> server::manifest::OperationDescriptor {
    let mut descriptor = wallet_and_membership_descriptor(opcode);
    descriptor
        .accepted_evidence
        .push(EvidenceKind::DreggReceipt.as_str().to_string());
    descriptor
}

#[test]
fn wallet_issuer_and_dregg_shaped_evidence_compose_through_composite_adapter() {
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let dregg = server::evidence::DreggShapedEvidenceAdapter::with_validation_time(
        [dregg_membership_fixture()],
        TRUSTED_VALIDATION_TIME,
    );
    let composite = CompositeEvidenceAdapter::new([
        &wallet as &dyn EvidenceAdapter,
        &credential as &dyn EvidenceAdapter,
        &dregg as &dyn EvidenceAdapter,
    ]);

    let request = request_with_refs(
        &tri_evidence_descriptor(WALLET_AND_MEMBERSHIP_OPCODE),
        [
            WALLET_EVIDENCE_REF,
            MEMBERSHIP_CREDENTIAL_REF,
            "dregg-receipt:alice-membership",
        ],
    );

    match composite.verify(&request) {
        EvidenceResult::Satisfied(summary) => {
            let joined = summary.to_context_fields().join("|");
            assert!(joined.contains("evidence_kind:wallet_presentation"));
            assert!(joined.contains("evidence_kind:membership_credential"));
            assert!(joined.contains("evidence_kind:dregg_receipt"));
            assert!(
                !summary.public_proof,
                "composition including shape-only Dregg evidence must not claim public proof"
            );
        }
        EvidenceResult::Rejected(error) => {
            panic!("wallet + issuer + dregg composition must satisfy, got {error:?}")
        }
    }
}

#[test]
fn missing_dregg_evidence_fails_tri_evidence_descriptor_as_insufficient() {
    // All of a descriptor's accepted kinds remain required: wallet + issuer
    // alone cannot satisfy a descriptor that also requires dregg_receipt.
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = CompositeEvidenceAdapter::new([
        &wallet as &dyn EvidenceAdapter,
        &credential as &dyn EvidenceAdapter,
    ]);

    let request = request_with_refs(
        &tri_evidence_descriptor(WALLET_AND_MEMBERSHIP_OPCODE),
        [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
    );

    assert_rejected(
        composite.verify(&request),
        VerificationError::InsufficientEvidence,
    );
}

#[test]
fn standalone_dregg_shaped_evidence_cannot_satisfy_tri_evidence_descriptor() {
    // Necessary-where-required, never sufficient: Dregg-shaped evidence alone
    // does not grant a descriptor that requires wallet + issuer evidence too.
    let dregg = server::evidence::DreggShapedEvidenceAdapter::with_validation_time(
        [dregg_membership_fixture()],
        TRUSTED_VALIDATION_TIME,
    );
    let composite = CompositeEvidenceAdapter::new([&dregg as &dyn EvidenceAdapter]);

    let request = request_with_refs(
        &tri_evidence_descriptor(WALLET_AND_MEMBERSHIP_OPCODE),
        ["dregg-receipt:alice-membership"],
    );

    assert_rejected(
        composite.verify(&request),
        VerificationError::InsufficientEvidence,
    );
}

// --- #79: canonical multi-evidence-ref verification API ---

fn canonical_inputs(refs: &[&str]) -> server::evidence::EvidenceInputs {
    server::evidence::EvidenceInputs::new(refs.iter().copied(), [origin_input(TRUSTED_ORIGIN)])
}

fn canonical_multi_ref_signed(
    refs: &[&str],
) -> Result<server::verifier::SignedVerifiedCallContext, VerificationError> {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let manifest = ReceiverManifest::new([descriptor]);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        &canonical_inputs(refs),
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
}

#[test]
fn canonical_multi_ref_api_accepts_wallet_plus_credential_refs_directly() {
    let signed = canonical_multi_ref_signed(&[WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF])
        .expect("wallet + membership credential refs via the canonical API must verify");

    let summary = signed.context.evidence_summary.join("|");
    assert!(summary.contains("evidence_kind:wallet_presentation"));
    assert!(summary.contains("evidence_kind:membership_credential"));
}

#[test]
fn canonical_multi_ref_api_rejects_missing_either_layer() {
    assert_eq!(
        canonical_multi_ref_signed(&[WALLET_EVIDENCE_REF]).unwrap_err(),
        VerificationError::InsufficientEvidence,
        "wallet ref alone must remain insufficient"
    );
    assert_eq!(
        canonical_multi_ref_signed(&[MEMBERSHIP_CREDENTIAL_REF]).unwrap_err(),
        VerificationError::InsufficientEvidence,
        "membership credential ref alone must remain insufficient"
    );
    assert_eq!(
        canonical_multi_ref_signed(&[]).unwrap_err(),
        VerificationError::InsufficientEvidence,
        "empty refs are an explicit fail-closed input, not a fallback"
    );
}

#[test]
fn canonical_multi_ref_api_deduplicates_refs_without_escalation() {
    // Duplicate refs are deduplicated at construction (first occurrence
    // wins); duplicates never escalate one evidence layer into two.
    let inputs = server::evidence::EvidenceInputs::new(
        [
            WALLET_EVIDENCE_REF,
            WALLET_EVIDENCE_REF,
            WALLET_EVIDENCE_REF,
        ],
        Vec::<String>::new(),
    );
    assert_eq!(inputs.evidence_refs(), [WALLET_EVIDENCE_REF]);

    assert_eq!(
        canonical_multi_ref_signed(&[WALLET_EVIDENCE_REF, WALLET_EVIDENCE_REF]).unwrap_err(),
        VerificationError::InsufficientEvidence
    );
}

fn canonical_signed_with(
    subject: &str,
    audience: &str,
    inputs: server::evidence::EvidenceInputs,
) -> Result<server::verifier::SignedVerifiedCallContext, VerificationError> {
    let descriptor = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    let manifest = ReceiverManifest::new([descriptor]);
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &manifest,
        audience,
        subject,
        &inputs,
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
}

#[test]
fn canonical_path_rejects_binding_mismatches_with_typed_reasons() {
    let both_refs = || [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF];

    // Wrong origin public input rejects at the wallet binding layer.
    assert_eq!(
        canonical_signed_with(
            TRUSTED_SUBJECT,
            TRUSTED_AUDIENCE,
            server::evidence::EvidenceInputs::new(both_refs(), [origin_input(WRONG_ORIGIN)]),
        )
        .unwrap_err(),
        VerificationError::WrongOrigin
    );

    // Missing origin public input fails closed: the wallet layer rejects the
    // presentation, and the composite's skip-and-require semantics surface
    // that as unsatisfied required evidence.
    assert_eq!(
        canonical_signed_with(
            TRUSTED_SUBJECT,
            TRUSTED_AUDIENCE,
            server::evidence::EvidenceInputs::new(both_refs(), Vec::<String>::new()),
        )
        .unwrap_err(),
        VerificationError::InsufficientEvidence
    );

    // Wrong subject rejects when evidence subjects do not match the request.
    assert_eq!(
        canonical_signed_with(
            "did:example:mallory#key-1",
            TRUSTED_AUDIENCE,
            server::evidence::EvidenceInputs::new(both_refs(), [origin_input(TRUSTED_ORIGIN)]),
        )
        .unwrap_err(),
        VerificationError::WrongSubject
    );

    // Wrong audience rejects when evidence audiences do not match the request.
    assert_eq!(
        canonical_signed_with(
            TRUSTED_SUBJECT,
            WALLET_OTHER_AUDIENCE,
            server::evidence::EvidenceInputs::new(both_refs(), [origin_input(TRUSTED_ORIGIN)]),
        )
        .unwrap_err(),
        VerificationError::WrongAudience
    );

    // Unknown refs at either layer leave required evidence unsatisfied.
    assert_eq!(
        canonical_signed_with(
            TRUSTED_SUBJECT,
            TRUSTED_AUDIENCE,
            server::evidence::EvidenceInputs::new(
                ["wallet-presentation:unknown", MEMBERSHIP_CREDENTIAL_REF],
                [origin_input(TRUSTED_ORIGIN)],
            ),
        )
        .unwrap_err(),
        VerificationError::InsufficientEvidence
    );
    assert_eq!(
        canonical_signed_with(
            TRUSTED_SUBJECT,
            TRUSTED_AUDIENCE,
            server::evidence::EvidenceInputs::new(
                [WALLET_EVIDENCE_REF, "membership-credential:unknown"],
                [origin_input(TRUSTED_ORIGIN)],
            ),
        )
        .unwrap_err(),
        VerificationError::InsufficientEvidence
    );
}

#[test]
fn canonical_path_rejects_wrong_operation_and_resource_descriptors() {
    // A descriptor whose operation/resource differ from the evidence
    // bindings must reject through the canonical path.
    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);

    let mut wrong_operation = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    wrong_operation.name = server::manifest::OperationName::new("membership.provision.other");
    let manifest = ReceiverManifest::new([wrong_operation]);
    let result = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        &server::evidence::EvidenceInputs::new(
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
            [origin_input(TRUSTED_ORIGIN)],
        ),
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    );
    assert_eq!(result.unwrap_err(), VerificationError::WrongOperation);

    let mut wrong_resource = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    wrong_resource.payload_schema = Some("text/plain".to_string());
    let manifest = ReceiverManifest::new([wrong_resource]);
    let result = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        &server::evidence::EvidenceInputs::new(
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
            [origin_input(TRUSTED_ORIGIN)],
        ),
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    );
    assert_eq!(result.unwrap_err(), VerificationError::WrongResource);
}

// --- #78: membership.provision default runtime binding posture ---

fn evidence_backed_signed_for_default_manifest(
) -> (server::verifier::SignedVerifiedCallContext, Vec<u8>) {
    // Sign an evidence-backed context for the ACTIVE default manifest
    // descriptor with the router's own identity, mirroring the Track I E2E.
    let manifest = ReceiverManifest::default_v0();
    let descriptor = manifest
        .lookup(WALLET_AND_MEMBERSHIP_OPCODE)
        .expect("default manifest exposes 0x44");
    assert_eq!(descriptor.handler_id, "membership/provision");

    let wallet = membership_wallet_adapter();
    let credential = FederatedCredentialAdapter::new(
        [membership_credential_fixture()],
        trusted_registry(),
        TRUSTED_VALIDATION_TIME,
    );
    let composite = composite_adapter(&wallet, &credential);
    let packet = production_packet(WALLET_AND_MEMBERSHIP_OPCODE);
    let payload = packet.encrypted_payload.clone();

    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &packet,
        &manifest,
        TRUSTED_AUDIENCE,
        TRUSTED_SUBJECT,
        &server::evidence::EvidenceInputs::new(
            [WALLET_EVIDENCE_REF, MEMBERSHIP_CREDENTIAL_REF],
            [origin_input(TRUSTED_ORIGIN)],
        ),
        &composite,
        current_test_time(),
        "verifier:local-prototype",
        &[7u8; 32],
    )
    .expect("evidence-backed signing against the default manifest must verify");
    (signed, payload)
}

#[tokio::test]
async fn default_production_bindings_execute_evidence_backed_membership_provision() {
    // #78 contract: the active default manifest advertises
    // handler_id = "membership/provision", so the default runtime bindings
    // must register a bounded production-shaped handler for it — an
    // evidence-backed signed context routed through default bindings must
    // produce verify accepted + execute accepted, with no manual test-only
    // handler registration.
    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let identity = bootstrap.identity().clone();
    let (signed, payload) = evidence_backed_signed_for_default_manifest();

    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    server::gateway::register_runtime_bindings(&mut router, RuntimeMode::ProductionVerified);

    router.route_verified(&signed, payload).await;

    let execute_rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT decision, handler_id, reason FROM receipts WHERE kind = 'execute' AND context_id = ?",
    )
    .bind(&signed.context.context_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        execute_rows.len(),
        1,
        "exactly one handler execution for the verified context"
    );
    assert_eq!(
        execute_rows[0],
        (
            "accepted".to_string(),
            "membership/provision".to_string(),
            None
        ),
        "default production bindings must execute membership/provision for an evidence-backed context; the default manifest/runtime-binding contract mismatch (descriptor advertised, handler unregistered) must be resolved"
    );
}

#[tokio::test]
async fn descriptor_only_guard_and_missing_binding_remain_distinct_failures() {
    // #77's descriptor-only guard fires BEFORE signed-context creation with
    // insufficient_evidence; a missing handler binding fires AFTER
    // verification as an execute reject with handler_unavailable. These are
    // different boundaries and must stay distinguishable.
    let descriptor_only = Verifier::verify_manifest_operation_for_runtime(
        &production_packet(WALLET_AND_MEMBERSHIP_OPCODE),
        &ReceiverManifest::default_v0(),
        TRUSTED_AUDIENCE,
        current_test_time(),
        RuntimeMode::ProductionVerified,
    );
    assert_eq!(
        descriptor_only.unwrap_err(),
        VerificationError::InsufficientEvidence,
        "#77 fail-closed descriptor-only guard must remain in force"
    );

    // Evidence-backed context routed on a router with NO bindings at all:
    // verify accepted, execute rejected handler_unavailable.
    let pool = memory_pool().await;
    let bare = ConfigurableRouter::new(pool.clone());
    let identity = bare.identity().clone();
    let (signed, payload) = evidence_backed_signed_for_default_manifest();
    let router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    router.route_verified(&signed, payload).await;

    let execute_row: (String, Option<String>) = sqlx::query_as(
        "SELECT decision, reason FROM receipts WHERE kind = 'execute' AND context_id = ?",
    )
    .bind(&signed.context.context_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        execute_row,
        (
            "rejected".to_string(),
            Some("handler_unavailable".to_string())
        )
    );
}

#[tokio::test]
async fn default_bindings_replay_of_membership_provision_rejects_without_second_execution() {
    // 78.4: replay through the default production bindings — the second
    // route of the same verified context must reject as replay_detected
    // with exactly one execute-accepted receipt.
    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let identity = bootstrap.identity().clone();
    let (signed, payload) = evidence_backed_signed_for_default_manifest();

    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        identity,
        TRUSTED_AUDIENCE,
    );
    server::gateway::register_runtime_bindings(&mut router, RuntimeMode::ProductionVerified);

    router.route_verified(&signed, payload.clone()).await;
    router.route_verified(&signed, payload).await;

    let executes: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'execute' AND decision = 'accepted' AND context_id = ?",
    )
    .bind(&signed.context.context_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(executes.0, 1, "replay must not execute the handler twice");

    let replay_rejects: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'reject' AND reason = 'replay_detected' AND context_id = ?",
    )
    .bind(&signed.context.context_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(replay_rejects.0, 1);
}

#[tokio::test]
async fn default_bindings_wrong_audience_rejects_before_membership_execution() {
    // 78.4: a context signed for a different audience must reject before
    // the handler runs, even with the default binding registered.
    let pool = memory_pool().await;
    let bootstrap = ConfigurableRouter::new(pool.clone());
    let (signed, payload) = evidence_backed_signed_for_default_manifest();

    let mut router = ConfigurableRouter::with_limits_identity_and_audience(
        pool.clone(),
        ExecutionLimits::default(),
        bootstrap.identity().clone(),
        "secS://other-receiver",
    );
    server::gateway::register_runtime_bindings(&mut router, RuntimeMode::ProductionVerified);
    router.route_verified(&signed, payload).await;

    let accepted_executes: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM receipts WHERE kind = 'execute' AND decision = 'accepted' AND context_id = ?",
    )
    .bind(&signed.context.context_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(accepted_executes.0, 0, "wrong audience must not execute");
}

#[test]
fn membership_handler_is_native_and_subprocess_free() {
    // 78.5: the production-shaped handler must never become a subprocess
    // surface. Source-level pin, mirroring the legacy-entrypoint checks.
    let source = include_str!("../src/membership.rs");
    for forbidden in ["SubprocessForwarder", "Command::new", "std::process"] {
        assert!(
            !source.contains(forbidden),
            "membership.rs must stay a bounded native handler (found {forbidden:?})"
        );
    }
}

// --- #80: active default manifest descriptor parity / drift gate ---

#[test]
fn active_membership_provision_descriptor_contract_is_pinned_field_by_field() {
    // 80.1/80.5: the exhaustive drift gate. The ACTIVE default-manifest
    // descriptor is asserted against expected literals, and the Track I
    // fixture constructor must be identical to it. Any drift in a
    // routing/authorization-relevant field fails here, not in some
    // partially-asserted downstream test.
    let manifest = ReceiverManifest::default_v0();
    let active = manifest
        .lookup(WALLET_AND_MEMBERSHIP_OPCODE)
        .expect("default manifest must expose 0x44");

    assert_eq!(active.opcode, 0x44);
    assert_eq!(active.name.as_str(), "membership.provision");
    assert_eq!(active.payload_schema.as_deref(), Some("application/json"));
    assert_eq!(
        active.target_kind,
        server::manifest::TargetKind::ReceiverProductionHandler,
        "#82: membership.provision is a production-shaped receiver handler, not a local-dev process target"
    );
    assert_eq!(
        active.required_credentials,
        vec!["trusted.membership", "wallet.presentation"]
    );
    assert_eq!(active.required_capabilities, vec!["membership.provision"]);
    assert_eq!(
        active.accepted_evidence,
        vec!["wallet_presentation", "membership_credential"]
    );
    assert_eq!(
        active.replay_scope,
        server::manifest::ReplayScope::SessionOpcodeNonce
    );
    assert_eq!(active.max_ttl_seconds, 300);
    assert_eq!(active.handler_id, "membership/provision");
    assert!(!active.dev_binding);
    assert_eq!(
        active.range,
        server::manifest::OpcodeRange::classify(0x44),
        "opcode range derives from classification"
    );

    // Fixture parity: the Track I fixture must BE the canonical descriptor.
    let fixture = wallet_and_membership_descriptor(WALLET_AND_MEMBERSHIP_OPCODE);
    assert_eq!(
        &fixture, active,
        "Track I fixture descriptor must not drift from the active default-manifest descriptor"
    );
}
