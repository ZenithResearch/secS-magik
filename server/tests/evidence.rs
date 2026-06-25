#[path = "support/wallet_fixtures.rs"]
mod wallet_fixtures;

use libsec_core::ZenithPacket;
use server::evidence::{
    EvidenceAdapter, EvidenceKind, EvidenceRequest, EvidenceResult, LocalStaticEvidenceAdapter,
    LocalStaticGrant, WalletPresentationAdapter,
};
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, ReceiverManifest, ReplayScope, TargetKind,
};
use server::receipt::Receipt;
use server::verifier::{VerificationError, Verifier};
use wallet_fixtures::{
    origin_input, wallet_descriptor, wallet_fixture, WALLET_AUDIENCE, WALLET_EVIDENCE_REF,
    WALLET_ISSUED_AT, WALLET_OPCODE, WALLET_ORIGIN, WALLET_SUBJECT,
};

fn evidence_descriptor(opcode: u8) -> OperationDescriptor {
    OperationDescriptor {
        opcode,
        name: OperationName::new("candidate.dev.local_static"),
        payload_schema: Some("application/json".to_string()),
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

fn packet(opcode: u8) -> ZenithPacket {
    ZenithPacket {
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode,
        proof: b"prototype-proof-envelope".to_vec(),
        claim_ttl: 60,
        encrypted_payload: br#"{"hello":"world"}"#.to_vec(),
        mac: [3u8; 16],
    }
}

fn request_for(descriptor: &OperationDescriptor) -> EvidenceRequest {
    EvidenceRequest::from_descriptor(
        descriptor,
        "prototype.local-dev.subject",
        "secS://local-test",
        Some("local-static:test-grant"),
    )
}

fn adapter() -> LocalStaticEvidenceAdapter {
    LocalStaticEvidenceAdapter::new([LocalStaticGrant {
        subject: "prototype.local-dev.subject".to_string(),
        audience: "secS://local-test".to_string(),
        operation: "candidate.dev.local_static".to_string(),
        resource: Some("application/json".to_string()),
        evidence_ref: "local-static:test-grant".to_string(),
    }])
}

#[test]
fn local_static_adapter_satisfies_matching_descriptor_requirement() {
    let descriptor = evidence_descriptor(0x40);
    let result = adapter().verify(&request_for(&descriptor));

    match result {
        EvidenceResult::Satisfied(summary) => {
            assert_eq!(summary.kind, EvidenceKind::LocalStatic);
            assert!(summary.local_dev_test_only);
            assert!(!summary.public_proof);
            assert_eq!(summary.subject, "prototype.local-dev.subject");
            assert_eq!(summary.audience, "secS://local-test");
            assert_eq!(summary.operation, "candidate.dev.local_static");
            assert!(summary
                .summary_fields
                .iter()
                .any(|field| field == "authority:local_dev_test_only"));
        }
        EvidenceResult::Rejected(error) => panic!("expected satisfied evidence, got {error:?}"),
    }
}

#[test]
fn local_static_missing_required_evidence_fails_closed() {
    let descriptor = evidence_descriptor(0x40);
    let request = EvidenceRequest::from_descriptor(
        &descriptor,
        "prototype.local-dev.subject",
        "secS://local-test",
        None,
    );

    assert_eq!(
        adapter().verify(&request),
        EvidenceResult::Rejected(VerificationError::InsufficientEvidence)
    );
    assert_eq!(
        VerificationError::InsufficientEvidence.reason_code(),
        "insufficient_evidence"
    );
}

#[test]
fn local_static_wrong_subject_and_wrong_audience_are_typed_failures() {
    let descriptor = evidence_descriptor(0x40);
    let wrong_subject = EvidenceRequest::from_descriptor(
        &descriptor,
        "other.subject",
        "secS://local-test",
        Some("local-static:test-grant"),
    );
    let wrong_audience = EvidenceRequest::from_descriptor(
        &descriptor,
        "prototype.local-dev.subject",
        "secS://other-target",
        Some("local-static:test-grant"),
    );

    assert_eq!(
        adapter().verify(&wrong_subject),
        EvidenceResult::Rejected(VerificationError::WrongSubject)
    );
    assert_eq!(
        adapter().verify(&wrong_audience),
        EvidenceResult::Rejected(VerificationError::WrongAudience)
    );
}

#[test]
fn verifier_signed_context_includes_local_static_summary_without_public_proof_claim() {
    let manifest = ReceiverManifest::new([evidence_descriptor(0x40)]);
    let packet = packet(0x40);
    let signed = Verifier::verify_manifest_operation_with_evidence_and_sign(
        &packet,
        &manifest,
        "secS://local-test",
        "prototype.local-dev.subject",
        Some("local-static:test-grant"),
        &adapter(),
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect("local_static evidence should produce signed context");

    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:local_static"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "authority:local_dev_test_only"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:false"));
    assert!(!signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:true"));

    let receipt =
        Receipt::verify_from_signed_context("verify-local-static", &signed, 1_700_000_001);
    assert_eq!(
        receipt.operation.as_deref(),
        Some("candidate.dev.local_static")
    );
    assert_eq!(receipt.signer_key_id, "secs-verifier-test-key");
}

#[test]
fn verifier_rejects_missing_local_static_evidence_before_signing_context() {
    let manifest = ReceiverManifest::new([evidence_descriptor(0x40)]);
    let packet = packet(0x40);

    let error = Verifier::verify_manifest_operation_with_evidence_and_sign(
        &packet,
        &manifest,
        "secS://local-test",
        "prototype.local-dev.subject",
        None,
        &adapter(),
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect_err("missing local_static evidence should fail closed");

    assert_eq!(error, VerificationError::InsufficientEvidence);
}

#[test]
fn verifier_signed_context_can_pass_wallet_public_inputs_for_origin_bound_evidence() {
    let manifest = ReceiverManifest::new([wallet_descriptor(WALLET_OPCODE)]);
    let packet = packet(WALLET_OPCODE);
    let adapter =
        WalletPresentationAdapter::with_validation_time([wallet_fixture()], WALLET_ISSUED_AT + 60);

    assert_eq!(
        Verifier::verify_manifest_operation_with_evidence_and_sign(
            &packet,
            &manifest,
            WALLET_AUDIENCE,
            WALLET_SUBJECT,
            Some(WALLET_EVIDENCE_REF),
            &adapter,
            1_700_000_000,
            "secs-verifier-test-key",
            &[7u8; 32],
        )
        .expect_err("legacy evidence API does not supply wallet origin"),
        VerificationError::InvalidPresentation
    );

    let signed = Verifier::verify_manifest_operation_with_evidence_inputs_and_sign(
        &packet,
        &manifest,
        WALLET_AUDIENCE,
        WALLET_SUBJECT,
        Some(WALLET_EVIDENCE_REF),
        [origin_input(WALLET_ORIGIN)],
        &adapter,
        1_700_000_000,
        "secs-verifier-test-key",
        &[7u8; 32],
    )
    .expect("wallet evidence with explicit origin public input should produce signed context");

    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "evidence_kind:wallet_presentation"));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == &origin_input(WALLET_ORIGIN)));
    assert!(signed
        .context
        .evidence_summary
        .iter()
        .any(|field| field == "public_proof:true"));
}

mod dregg_shaped {
    use ed25519_dalek::{Signer, SigningKey};
    use server::evidence::{
        public_key_ref_for_bytes, DreggReceiptFixture, DreggShapedEvidenceAdapter, EvidenceAdapter,
        EvidenceKind, EvidenceRequest, EvidenceResult,
    };
    use server::verifier::VerificationError;

    const NOW: u64 = 1_000;
    const SUBJECT: &str = "did:example:alice";
    const AUDIENCE: &str = "secS://receiver-a";
    const ORIGIN: &str = "https://castalia.example";
    const OPERATION: &str = "queue.enqueue";
    const RESOURCE: &str = "application/json";

    fn author_key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn signed_fixture() -> DreggReceiptFixture {
        let key = author_key();
        let public_key_bytes = key.verifying_key().as_bytes().to_vec();
        let mut fixture = DreggReceiptFixture {
            evidence_ref: "dregg:evidence:alpha".to_string(),
            subject: SUBJECT.to_string(),
            audience: AUDIENCE.to_string(),
            origin: ORIGIN.to_string(),
            operation: OPERATION.to_string(),
            resource: RESOURCE.to_string(),
            receipt_kind: DreggReceiptFixture::RECEIPT_KIND.to_string(),
            strand_ref: "strand:author:42".to_string(),
            sequence: 42,
            issued_at: 100,
            expires_at: 2_000,
            signature_suite: "Ed25519".to_string(),
            public_key_ref: public_key_ref_for_bytes(&public_key_bytes),
            author_public_key_bytes: public_key_bytes,
            signature_bytes: Vec::new(),
        };
        fixture.signature_bytes = key.sign(&fixture.canonical_bytes()).to_bytes().to_vec();
        fixture
    }

    fn request_for(fixture: &DreggReceiptFixture) -> EvidenceRequest {
        EvidenceRequest {
            accepted_evidence: vec![EvidenceKind::DreggReceipt.as_str().to_string()],
            subject: SUBJECT.to_string(),
            audience: AUDIENCE.to_string(),
            operation: OPERATION.to_string(),
            resource: Some(RESOURCE.to_string()),
            evidence_refs: vec![fixture.evidence_ref.clone()],
            public_inputs: vec![format!("origin:{ORIGIN}")],
            trusted_requested_resource: None,
        }
    }

    fn adapter_with(fixture: DreggReceiptFixture) -> DreggShapedEvidenceAdapter {
        DreggShapedEvidenceAdapter::with_validation_time([fixture], NOW)
    }

    fn expect_reject(result: EvidenceResult, expected: VerificationError) {
        match result {
            EvidenceResult::Rejected(error) => assert_eq!(error, expected),
            EvidenceResult::Satisfied(summary) => {
                panic!("expected {expected:?} reject, got satisfied: {summary:?}")
            }
        }
    }

    #[test]
    fn valid_dregg_shaped_receipt_with_author_signature_satisfies_adapter() {
        let fixture = signed_fixture();
        let request = request_for(&fixture);

        match adapter_with(fixture).verify(&request) {
            EvidenceResult::Satisfied(summary) => {
                assert_eq!(summary.kind, EvidenceKind::DreggReceipt);
                assert_eq!(summary.subject, SUBJECT);
                assert!(
                    !summary.public_proof,
                    "shape+signature evidence must not claim public/consensus proof"
                );
            }
            EvidenceResult::Rejected(error) => {
                panic!("valid Dregg-shaped fixture must satisfy the adapter, got {error:?}")
            }
        }
    }

    #[test]
    fn capability_ref_kind_also_satisfies_the_shape_contract() {
        let key = author_key();
        let mut fixture = signed_fixture();
        fixture.receipt_kind = DreggReceiptFixture::CAPABILITY_REF_KIND.to_string();
        fixture.signature_bytes = key.sign(&fixture.canonical_bytes()).to_bytes().to_vec();
        let request = request_for(&fixture);

        assert!(matches!(
            adapter_with(fixture).verify(&request),
            EvidenceResult::Satisfied(_)
        ));
    }

    #[test]
    fn wrong_author_signature_rejects_with_invalid_signature() {
        let mut fixture = signed_fixture();
        let impostor = SigningKey::from_bytes(&[6u8; 32]);
        fixture.signature_bytes = impostor
            .sign(&fixture.canonical_bytes())
            .to_bytes()
            .to_vec();
        let request = request_for(&fixture);

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::InvalidSignature,
        );
    }

    #[test]
    fn tampered_canonical_field_rejects_with_invalid_signature() {
        // Signature was made over sequence 42; presenting sequence 43 changes
        // the canonical bytes.
        let mut fixture = signed_fixture();
        fixture.sequence = 43;
        let request = request_for(&fixture);

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::InvalidSignature,
        );
    }

    #[test]
    fn mismatched_public_key_ref_rejects_as_invalid_presentation() {
        let mut fixture = signed_fixture();
        fixture.public_key_ref = "pubkey:sha256:0000".to_string();
        let request = request_for(&fixture);

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::InvalidPresentation,
        );
    }

    #[test]
    fn missing_required_fields_reject_as_invalid_presentation() {
        for breaker in [
            |fixture: &mut DreggReceiptFixture| fixture.strand_ref = String::new(),
            |fixture: &mut DreggReceiptFixture| fixture.receipt_kind = "unknown_kind".to_string(),
            |fixture: &mut DreggReceiptFixture| fixture.author_public_key_bytes = vec![1, 2, 3],
            |fixture: &mut DreggReceiptFixture| fixture.signature_bytes = vec![0u8; 10],
            |fixture: &mut DreggReceiptFixture| {
                fixture.issued_at = 500;
                fixture.expires_at = 400;
            },
        ] {
            let mut fixture = signed_fixture();
            breaker(&mut fixture);
            let request = request_for(&fixture);
            expect_reject(
                adapter_with(fixture).verify(&request),
                VerificationError::InvalidPresentation,
            );
        }
    }

    #[test]
    fn unsupported_signature_suite_rejects() {
        let key = author_key();
        let mut fixture = signed_fixture();
        fixture.signature_suite = "secp256k1".to_string();
        fixture.signature_bytes = key.sign(&fixture.canonical_bytes()).to_bytes().to_vec();
        let request = request_for(&fixture);

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::UnsupportedSignatureSuite,
        );
    }

    #[test]
    fn expired_and_future_receipts_reject_with_typed_time_reasons() {
        let key = author_key();

        let mut expired = signed_fixture();
        expired.issued_at = 100;
        expired.expires_at = NOW;
        expired.signature_bytes = key.sign(&expired.canonical_bytes()).to_bytes().to_vec();
        let request = request_for(&expired);
        expect_reject(
            adapter_with(expired).verify(&request),
            VerificationError::ExpiredClaim,
        );

        let mut future = signed_fixture();
        future.issued_at = NOW + 10;
        future.expires_at = NOW + 100;
        future.signature_bytes = key.sign(&future.canonical_bytes()).to_bytes().to_vec();
        let request = request_for(&future);
        expect_reject(
            adapter_with(future).verify(&request),
            VerificationError::NotYetValidClaim,
        );
    }

    #[test]
    fn binding_mismatches_reject_with_typed_reasons() {
        type FixtureBreaker = fn(&mut DreggReceiptFixture);
        let key = author_key();
        let cases: [(FixtureBreaker, VerificationError); 5] = [
            (
                |fixture| fixture.subject = "did:example:mallory".to_string(),
                VerificationError::WrongSubject,
            ),
            (
                |fixture| fixture.audience = "secS://receiver-b".to_string(),
                VerificationError::WrongAudience,
            ),
            (
                |fixture| fixture.operation = "agent.chat".to_string(),
                VerificationError::WrongOperation,
            ),
            (
                |fixture| fixture.resource = "text/plain".to_string(),
                VerificationError::WrongResource,
            ),
            (
                |fixture| fixture.origin = "https://evil.example".to_string(),
                VerificationError::WrongOrigin,
            ),
        ];
        for (breaker, expected) in cases {
            let mut fixture = signed_fixture();
            breaker(&mut fixture);
            fixture.signature_bytes = key.sign(&fixture.canonical_bytes()).to_bytes().to_vec();
            let request = request_for(&fixture);
            expect_reject(adapter_with(fixture).verify(&request), expected);
        }
    }

    #[test]
    fn unknown_evidence_ref_rejects_as_invalid_presentation() {
        let fixture = signed_fixture();
        let mut request = request_for(&fixture);
        request.evidence_refs = vec!["dregg:evidence:unknown".to_string()];

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::InvalidPresentation,
        );
    }

    #[test]
    fn descriptor_not_accepting_dregg_receipt_rejects_as_insufficient() {
        let fixture = signed_fixture();
        let mut request = request_for(&fixture);
        request.accepted_evidence = vec!["wallet_presentation".to_string()];

        expect_reject(
            adapter_with(fixture).verify(&request),
            VerificationError::InsufficientEvidence,
        );
    }

    #[test]
    fn satisfied_summary_is_redaction_safe() {
        let fixture = signed_fixture();
        let raw_key_hex: String = fixture
            .author_public_key_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let raw_evidence_ref = fixture.evidence_ref.clone();
        let raw_strand_ref = fixture.strand_ref.clone();
        let request = request_for(&fixture);

        let EvidenceResult::Satisfied(summary) = adapter_with(fixture).verify(&request) else {
            panic!("expected satisfied summary");
        };

        let joined = summary.to_context_fields().join("|");
        assert!(
            !joined.contains(&raw_key_hex),
            "summary must not leak raw author key bytes"
        );
        assert!(
            !joined.contains(&raw_evidence_ref),
            "summary must not leak the raw evidence ref"
        );
        assert!(
            !joined.contains(&raw_strand_ref),
            "summary must not leak the raw strand ref"
        );
        assert!(joined.contains("evidence_kind:dregg_receipt"));
        assert!(joined.contains(&format!("shape_contract:{}", DreggReceiptFixture::VERSION)));
    }
}
