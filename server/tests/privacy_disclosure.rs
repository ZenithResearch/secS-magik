use libsec_core::ZenithPacket;
use server::evidence::{
    EvidenceAdapter, EvidenceInputs, EvidenceKind, EvidenceRequest, EvidenceResult, EvidenceSummary,
};
use server::manifest::{membership_provision_descriptor, ReceiverManifest, TargetKind};
use server::privacy::{
    scan_json_value, DisclosurePermission, DisclosurePolicy, DisclosureRepresentation,
    ForbiddenFieldClass, PrivacySurface,
};
use server::receipt::{Decision, Receipt};
use server::runtime_mode::RuntimeMode;
use server::verifier::{VerificationError, Verifier};

const NOW: u64 = 1_717_000_000;
const SIGNER: &str = "verifier:i02";
const SECRET: [u8; 32] = [9u8; 32];

fn packet(opcode: u8, payload: serde_json::Value) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: vec![1],
        claim_ttl: 60,
        encrypted_payload: serde_json::to_vec(&payload).unwrap(),
        mac: [0u8; 16],
    }
}

fn sentinel_payload() -> serde_json::Value {
    serde_json::json!({
        "wallet_id": "I02_SENTINEL_WALLET",
        "holderId": "I02_SENTINEL_HOLDER",
        "subject_handle": "I02_SENTINEL_SUBJECT",
        "credential_id": "I02_SENTINEL_CREDENTIAL",
        "attributes": { "name": "I02_SENTINEL_ATTRIBUTE" },
        "raw_proof": "I02_SENTINEL_PROOF",
        "witness": "I02_SENTINEL_WITNESS",
        "debug_trace": "I02_SENTINEL_TRACE",
        "token": "I02_SENTINEL_TOKEN",
        "sourceAuthToken": "I02_SENTINEL_SOURCE_AUTH",
        "issuer_private_key": "I02_SENTINEL_ISSUER_KEY",
        "stable_nullifier": "I02_SENTINEL_NULLIFIER",
        "ip_address": "203.0.113.9"
    })
}

#[test]
fn privacy_policy_forbids_default_identity_leakage_in_verify_receipt() {
    let descriptor = membership_provision_descriptor();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let accepted_packet = packet(
        0x44,
        serde_json::json!({ "requested_resource": "urn:secs:i02" }),
    );
    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &accepted_packet,
        &manifest,
        "secS://receiver-a",
        "did:example:i02-holder",
        &EvidenceInputs::new(["membership-ref"], ["resource:urn:secs:i02".to_string()]),
        &RedactedMembershipAdapter,
        NOW,
        SIGNER,
        &SECRET,
    )
    .unwrap();

    let receipt = Receipt::verify_from_signed_context("receipt-i02-verify", &signed, NOW);
    let receipt_json = serde_json::to_value(&receipt).unwrap();
    scan_json_value(
        PrivacySurface::VerifyReceipt,
        &receipt_json,
        &descriptor.disclosure_policy,
    )
    .expect("verify receipt must be privacy-safe");
    assert_no_forbidden_names_or_sentinels(&receipt_json);
}

#[test]
fn privacy_policy_forbids_default_identity_leakage_in_reject_receipt() {
    let descriptor = membership_provision_descriptor();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let rejected_packet = packet(0x44, sentinel_payload());

    let error = Verifier::verify_manifest_operation_for_runtime(
        &rejected_packet,
        &manifest,
        "secS://receiver-a",
        NOW,
        RuntimeMode::LocalDevPlaintext,
    )
    .unwrap_err();
    assert_eq!(error, VerificationError::OverDisclosedPresentation);

    let receipt = Receipt::reject_from_packet("receipt-i02-reject", &rejected_packet, error, NOW);
    let receipt_json = serde_json::to_value(&receipt).unwrap();
    scan_json_value(
        PrivacySurface::RejectReceipt,
        &receipt_json,
        &descriptor.disclosure_policy,
    )
    .expect("reject receipt must not echo forbidden fields");
    assert_eq!(
        receipt.reason.as_deref(),
        Some("over_disclosed_presentation")
    );
    assert_no_forbidden_names_or_sentinels(&receipt_json);
}

#[test]
fn over_disclosed_packet_or_presentation_rejects_before_handler_execution() {
    let descriptor = membership_provision_descriptor();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let rejected_packet = packet(0x44, sentinel_payload());

    let error = Verifier::verify_manifest_operation_for_runtime(
        &rejected_packet,
        &manifest,
        "secS://receiver-a",
        NOW,
        RuntimeMode::LocalDevPlaintext,
    )
    .unwrap_err();

    assert_eq!(error.reason_code(), "over_disclosed_presentation");
    assert!(!error.handler_ran());
}

#[test]
fn privacy_policy_forbids_default_identity_leakage_in_execute_receipt_and_handler_context() {
    let descriptor = membership_provision_descriptor();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let accepted_packet = packet(
        0x44,
        serde_json::json!({ "requested_resource": "urn:secs:i02" }),
    );
    let signed = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &accepted_packet,
        &manifest,
        "secS://receiver-a",
        "did:example:i02-holder",
        &EvidenceInputs::new(["membership-ref"], ["resource:urn:secs:i02".to_string()]),
        &RedactedMembershipAdapter,
        NOW,
        SIGNER,
        &SECRET,
    )
    .unwrap();

    let handler_projection = signed
        .context
        .privacy_safe_handler_context(&descriptor.disclosure_policy);
    scan_json_value(
        PrivacySurface::HandlerContext,
        &serde_json::to_value(&handler_projection).unwrap(),
        &descriptor.disclosure_policy,
    )
    .unwrap();
    assert!(!serde_json::to_string(&handler_projection)
        .unwrap()
        .contains("did:example:i02-holder"));

    let execute = Receipt::execution(
        "receipt-i02-execute",
        &signed.context,
        Decision::Accepted,
        None,
        NOW,
    );
    let execute_json = serde_json::to_value(&execute).unwrap();
    scan_json_value(
        PrivacySurface::ExecuteReceipt,
        &execute_json,
        &descriptor.disclosure_policy,
    )
    .unwrap();
    assert_no_forbidden_names_or_sentinels(&execute_json);
}

#[test]
fn stable_subject_handle_is_not_allowed_in_anonymous_membership_path() {
    let descriptor = membership_provision_descriptor();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let packet = packet(
        0x44,
        serde_json::json!({ "requested_resource": "urn:secs:i02" }),
    );

    let error = Verifier::verify_manifest_operation_with_evidence_refs_and_inputs_and_sign(
        &packet,
        &manifest,
        "secS://receiver-a",
        "did:example:stable-subject",
        &EvidenceInputs::new(
            ["membership-ref"],
            ["subject_id:did:example:stable-subject".to_string()],
        ),
        &OverDisclosedMembershipAdapter,
        NOW,
        SIGNER,
        &SECRET,
    )
    .unwrap_err();

    assert_eq!(error, VerificationError::ForbiddenFieldPresent);
}

#[test]
fn explicit_identity_opt_in_is_field_and_surface_scoped() {
    let mut descriptor = membership_provision_descriptor();
    descriptor.disclosure_policy = DisclosurePolicy::deny_by_default("i02-opt-in", 1)
        .with_permission(DisclosurePermission::new(
            ForbiddenFieldClass::SubjectIdentity,
            PrivacySurface::VerifyReceipt,
            DisclosureRepresentation::RedactedDigest,
        ));

    let allowed = serde_json::json!({
        "status": "accepted",
        "subject_id_sha256": "abc123"
    });
    scan_json_value(
        PrivacySurface::VerifyReceipt,
        &allowed,
        &descriptor.disclosure_policy,
    )
    .unwrap();

    let same_field_wrong_surface = scan_json_value(
        PrivacySurface::PublicAudit,
        &allowed,
        &descriptor.disclosure_policy,
    )
    .unwrap_err();
    assert_eq!(
        same_field_wrong_surface.class,
        ForbiddenFieldClass::SubjectIdentity
    );

    let raw = serde_json::json!({ "subject_id": "did:example:raw" });
    let raw_error = scan_json_value(
        PrivacySurface::VerifyReceipt,
        &raw,
        &descriptor.disclosure_policy,
    )
    .unwrap_err();
    assert_eq!(raw_error.class, ForbiddenFieldClass::SubjectIdentity);
}

#[test]
fn non_membership_descriptor_uses_same_privacy_guard() {
    let mut descriptor = membership_provision_descriptor();
    descriptor.opcode = 0x55;
    descriptor.name =
        server::manifest::OperationName::new("i14.boundary.node_registration_fixture");
    descriptor.target_kind = TargetKind::ReceiverProductionHandler;
    descriptor.handler_id = "i14-boundary/privacy-fixture".to_string();
    let manifest = ReceiverManifest::new([descriptor.clone()]);
    let rejected_packet = packet(0x55, sentinel_payload());

    let error = Verifier::verify_manifest_operation_for_runtime(
        &rejected_packet,
        &manifest,
        "secS://receiver-a",
        NOW,
        RuntimeMode::LocalDevPlaintext,
    )
    .unwrap_err();

    assert_eq!(error, VerificationError::OverDisclosedPresentation);
}

struct RedactedMembershipAdapter;

impl EvidenceAdapter for RedactedMembershipAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::WalletPresentation
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        EvidenceResult::Satisfied(EvidenceSummary {
            kind: EvidenceKind::WalletPresentation,
            subject: "identity_hidden_by_policy".to_string(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.trusted_requested_resource.clone(),
            local_dev_test_only: false,
            public_proof: false,
            summary_fields: vec![
                "evidence_tier:local_fixture".to_string(),
                "policy_id:i02-default".to_string(),
                "policy_version:1".to_string(),
                "evidence_ref_sha256:abc123".to_string(),
            ],
        })
    }
}

struct OverDisclosedMembershipAdapter;

impl EvidenceAdapter for OverDisclosedMembershipAdapter {
    fn kind(&self) -> EvidenceKind {
        EvidenceKind::WalletPresentation
    }

    fn verify(&self, request: &EvidenceRequest) -> EvidenceResult {
        EvidenceResult::Satisfied(EvidenceSummary {
            kind: EvidenceKind::WalletPresentation,
            subject: request.subject.clone(),
            audience: request.audience.clone(),
            operation: request.operation.clone(),
            resource: request.trusted_requested_resource.clone(),
            local_dev_test_only: false,
            public_proof: false,
            summary_fields: vec!["subject_id:did:example:stable-subject".to_string()],
        })
    }
}

fn assert_no_forbidden_names_or_sentinels(value: &serde_json::Value) {
    let text = serde_json::to_string(value).unwrap();
    for forbidden in [
        "wallet_id",
        "walletId",
        "holder_id",
        "holderId",
        "subject_id",
        "subject_handle",
        "credential_id",
        "attributes",
        "raw_proof",
        "witness",
        "debug_trace",
        "token",
        "sourceAuthToken",
        "issuer_private_key",
        "stable_nullifier",
        "ip_address",
        "I02_SENTINEL_",
    ] {
        assert!(!text.contains(forbidden), "leaked {forbidden} in {text}");
    }
}
