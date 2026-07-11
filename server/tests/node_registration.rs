use server::manifest::{node_registration_descriptor, ReceiverManifest};
use server::node_registration::{
    process_node_registration, registration_rejection_projection, registration_surface_projection,
    verify_node_registration, NodeRegistrationHandler, NodeRegistrationPolicy,
    NodeRegistrationReason, NodeRegistrationRequestV0, NODE_REGISTRATION_DISCLOSURE_POLICY_ID,
    NODE_REGISTRATION_HANDLER_ID, NODE_REGISTRATION_OPCODE, NODE_REGISTRATION_OPERATION,
    NODE_REGISTRATION_PAYLOAD_SCHEMA,
};
use server::privacy::PrivacySurface;

const M15_DEMO_README: &str = include_str!("../../examples/m15-dregg-authority-demo/README.md");

#[test]
fn node_registration_descriptor_has_first_class_identity() {
    let descriptor = node_registration_descriptor();
    assert_eq!(descriptor.opcode, NODE_REGISTRATION_OPCODE);
    assert_eq!(descriptor.name.as_str(), NODE_REGISTRATION_OPERATION);
    assert_eq!(descriptor.handler_id, NODE_REGISTRATION_HANDLER_ID);

    let manifest = ReceiverManifest::default_v0();
    let active = manifest
        .lookup(NODE_REGISTRATION_OPCODE)
        .expect("registration descriptor must be active");
    assert_eq!(active.name.as_str(), NODE_REGISTRATION_OPERATION);
    assert_eq!(
        active.authorization_fingerprint(),
        descriptor.authorization_fingerprint()
    );
}

#[test]
fn node_registration_identity_is_not_an_operation_alias() {
    let descriptor = node_registration_descriptor();
    for alias in [
        "membership.provision",
        "node.list",
        "node.federate",
        "dregg.authority.finalize",
        "authority.execute",
    ] {
        assert_ne!(descriptor.name.as_str(), alias);
    }
    assert_ne!(
        descriptor.opcode, 0x44,
        "membership opcode is not registration"
    );
}

#[test]
fn node_registration_descriptor_pins_schema_policy_and_local_fixture_tier() {
    let descriptor = node_registration_descriptor();
    assert_eq!(
        descriptor.payload_schema.as_deref(),
        Some(NODE_REGISTRATION_PAYLOAD_SCHEMA)
    );
    assert_eq!(
        descriptor.disclosure_policy.policy_id,
        NODE_REGISTRATION_DISCLOSURE_POLICY_ID
    );
    assert_eq!(
        descriptor.required_authority_mode.map(|mode| mode.as_str()),
        Some("local_fixture")
    );
    assert_eq!(descriptor.accepted_evidence, ["dregg_authority"]);
    assert_eq!(
        descriptor.required_capabilities,
        [NODE_REGISTRATION_OPERATION]
    );
}

#[test]
fn node_registration_payload_schema_rejects_private_or_unknown_fields() {
    let valid = serde_json::json!({
        "schema_version": 0,
        "operation": NODE_REGISTRATION_OPERATION,
        "opcode": NODE_REGISTRATION_OPCODE,
        "request_id": "req-1",
        "audience": "secs://receiver.example",
        "resource": "node:castalia:node-public-1:keyfp:endpoint-hash:v0",
        "node_public_key_fingerprint": "keyfp",
        "endpoint_hash": "endpoint-hash",
        "authority_source_id": "receiver-held-fixture",
        "evidence_ref": "fixture:registration-1",
        "evidence_tier": "local_verified",
        "descriptor_fingerprint": node_registration_descriptor().authorization_fingerprint(),
        "disclosure_policy_id": NODE_REGISTRATION_DISCLOSURE_POLICY_ID,
        "issued_at": 100,
        "expires_at": 200,
        "requested_disclosure": ["public_node_id", "endpoint_hash"]
    });
    let request: NodeRegistrationRequestV0 = serde_json::from_value(valid).unwrap();
    assert_eq!(request.operation, NODE_REGISTRATION_OPERATION);

    for forbidden in [
        "wallet_id",
        "holder_id",
        "subject_id",
        "credential_id",
        "source_auth_token",
        "raw_proof",
    ] {
        let mut invalid = serde_json::to_value(&request).unwrap();
        invalid[forbidden] = serde_json::json!("private-value");
        assert!(serde_json::from_value::<NodeRegistrationRequestV0>(invalid).is_err());
    }
}

fn bound_request() -> NodeRegistrationRequestV0 {
    serde_json::from_value(serde_json::json!({
        "schema_version": 0,
        "operation": NODE_REGISTRATION_OPERATION,
        "opcode": NODE_REGISTRATION_OPCODE,
        "request_id": "req-bound",
        "audience": "secs://receiver.example",
        "resource": "node:castalia:node-public-1:keyfp:endpoint-hash:v0",
        "node_public_key_fingerprint": "keyfp",
        "endpoint_hash": "endpoint-hash",
        "authority_source_id": "receiver-held-fixture",
        "evidence_ref": "fixture:registration-1",
        "evidence_tier": "local_verified",
        "descriptor_fingerprint": node_registration_descriptor().authorization_fingerprint(),
        "disclosure_policy_id": NODE_REGISTRATION_DISCLOSURE_POLICY_ID,
        "issued_at": 100,
        "expires_at": 200,
        "requested_disclosure": ["public_node_id", "endpoint_hash"]
    }))
    .unwrap()
}

fn bound_policy() -> NodeRegistrationPolicy {
    NodeRegistrationPolicy::from_descriptor(
        &node_registration_descriptor(),
        "secs://receiver.example",
        "node:castalia:node-public-1:keyfp:endpoint-hash:v0",
        150,
    )
}

#[test]
fn node_registration_verifies_every_descriptor_binding() {
    assert!(verify_node_registration(&bound_request(), &bound_policy()).is_ok());
}

#[test]
fn node_registration_rejects_mismatched_or_stale_bindings_with_bounded_reasons() {
    type Mutation = Box<dyn Fn(&mut NodeRegistrationRequestV0)>;
    let cases: Vec<(&str, Mutation, NodeRegistrationReason)> = vec![
        (
            "operation",
            Box::new(|r| r.operation = "membership.provision".into()),
            NodeRegistrationReason::WrongOperation,
        ),
        (
            "opcode",
            Box::new(|r| r.opcode = 0x44),
            NodeRegistrationReason::WrongOperation,
        ),
        (
            "audience",
            Box::new(|r| r.audience = "secs://wrong".into()),
            NodeRegistrationReason::WrongAudience,
        ),
        (
            "resource",
            Box::new(|r| r.resource = "node:wrong".into()),
            NodeRegistrationReason::WrongResource,
        ),
        (
            "descriptor",
            Box::new(|r| r.descriptor_fingerprint = "descriptor:sha256:wrong".into()),
            NodeRegistrationReason::ManifestMismatch,
        ),
        (
            "privacy",
            Box::new(|r| r.disclosure_policy_id = "wrong-policy".into()),
            NodeRegistrationReason::PrivacyPolicyViolation,
        ),
        (
            "tier",
            Box::new(|r| r.evidence_tier = "shape_only".into()),
            NodeRegistrationReason::InsufficientEvidence,
        ),
        (
            "source",
            Box::new(|r| r.authority_source_id = "caller-source".into()),
            NodeRegistrationReason::UnauthorizedSource,
        ),
        (
            "missing authority",
            Box::new(|r| r.evidence_ref.clear()),
            NodeRegistrationReason::MissingAuthority,
        ),
        (
            "stale",
            Box::new(|r| r.expires_at = 149),
            NodeRegistrationReason::StaleEvidence,
        ),
        (
            "expired before issue",
            Box::new(|r| r.expires_at = r.issued_at.saturating_sub(1)),
            NodeRegistrationReason::StaleEvidence,
        ),
        (
            "excessive lifetime",
            Box::new(|r| r.expires_at = r.issued_at + 301),
            NodeRegistrationReason::StaleEvidence,
        ),
        (
            "over-disclosure",
            Box::new(|r| r.requested_disclosure.push("wallet_id".into())),
            NodeRegistrationReason::PrivacyPolicyViolation,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut request = bound_request();
        mutate(&mut request);
        assert_eq!(
            verify_node_registration(&request, &bound_policy()),
            Err(expected),
            "{name}"
        );
    }
}

#[test]
fn node_registration_accepts_bound_authority_and_runs_handler_once() {
    let mut handler = NodeRegistrationHandler::default();
    let receipt = process_node_registration(&bound_request(), &bound_policy(), &mut handler)
        .expect("bound local-fixture registration must execute");

    assert_eq!(handler.execution_count(), 1);
    assert!(receipt.handler_ran);
    assert_eq!(receipt.operation, NODE_REGISTRATION_OPERATION);
    assert_eq!(receipt.opcode, NODE_REGISTRATION_OPCODE);
    assert_eq!(receipt.handler_id, NODE_REGISTRATION_HANDLER_ID);
    assert_eq!(receipt.evidence_tier, "local_verified");
}

#[test]
fn node_registration_rejections_never_run_handler() {
    type Mutation = Box<dyn Fn(&mut NodeRegistrationRequestV0)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "membership alias",
            Box::new(|r| r.operation = "membership.provision".into()),
        ),
        (
            "wrong resource",
            Box::new(|r| r.resource = "node:wrong".into()),
        ),
        (
            "unauthorized source",
            Box::new(|r| r.authority_source_id = "caller-source".into()),
        ),
        ("missing authority", Box::new(|r| r.evidence_ref.clear())),
        (
            "weak tier",
            Box::new(|r| r.evidence_tier = "shape_only".into()),
        ),
        (
            "missing descriptor",
            Box::new(|r| r.descriptor_fingerprint.clear()),
        ),
        ("stale", Box::new(|r| r.expires_at = 149)),
        (
            "private holder",
            Box::new(|r| r.requested_disclosure.push("holder_id".into())),
        ),
    ];

    for (name, mutate) in cases {
        let mut handler = NodeRegistrationHandler::default();
        let mut request = bound_request();
        mutate(&mut request);
        let rejection =
            process_node_registration(&request, &bound_policy(), &mut handler).expect_err(name);
        assert!(!rejection.handler_ran, "{name}");
        assert_eq!(handler.execution_count(), 0, "{name}");
    }
}

#[test]
fn node_registration_replay_is_request_local_and_does_not_run_twice() {
    let mut handler = NodeRegistrationHandler::default();
    process_node_registration(&bound_request(), &bound_policy(), &mut handler).unwrap();
    let rejection = process_node_registration(&bound_request(), &bound_policy(), &mut handler)
        .expect_err("duplicate request id must reject");

    assert_eq!(rejection.reason, NodeRegistrationReason::ReplayDetected);
    assert!(!rejection.handler_ran);
    assert_eq!(handler.execution_count(), 1);
}

#[test]
fn node_registration_receipt_and_operator_surfaces_redact_private_material() {
    let mut request = bound_request();
    request.evidence_ref = "raw-evidence:wallet-holder-secret-token".into();
    request.request_id = "private-request-id".into();
    let mut handler = NodeRegistrationHandler::default();
    let receipt = process_node_registration(&request, &bound_policy(), &mut handler).unwrap();

    for surface in [
        PrivacySurface::VerifyReceipt,
        PrivacySurface::Log,
        PrivacySurface::ReadinessStatus,
        PrivacySurface::DemoProjection,
        PrivacySurface::OperatorCli,
    ] {
        let projection = registration_surface_projection(&receipt, surface);
        let text = serde_json::to_string(&projection).unwrap();
        for forbidden in [
            "raw-evidence",
            "wallet",
            "holder",
            "secret-token",
            "private-request-id",
            "subject_id",
            "credential_id",
            "authority_source_id",
            "endpoint_hash",
        ] {
            assert!(!text.contains(forbidden), "{surface:?}: {forbidden}");
        }
        assert_eq!(projection["operation"], NODE_REGISTRATION_OPERATION);
        assert_eq!(projection["evidence_tier"], "local_verified");
        assert_eq!(projection["handler_ran"], true);
        assert_eq!(projection["scope"], "local_registration_only");
    }
}

#[test]
fn node_registration_rejection_projection_is_bounded_and_redacted() {
    let mut request = bound_request();
    request.authority_source_id = "unauthorized-secret-source-token".into();
    let mut handler = NodeRegistrationHandler::default();
    let rejection = process_node_registration(&request, &bound_policy(), &mut handler).unwrap_err();
    let projection = registration_rejection_projection(&rejection);
    let text = serde_json::to_string(&projection).unwrap();

    assert_eq!(projection["reason"], "unauthorized_source");
    assert_eq!(projection["handler_ran"], false);
    assert!(!text.contains("secret-source-token"));
    assert!(!text.contains("evidence_ref"));
    assert!(!text.contains("payload"));
}

#[test]
fn node_registration_listing_output_does_not_claim_federation_finality() {
    for required in [
        "Node registration is not membership provisioning",
        "A local registration projection is not a node listing product",
        "A registered or listed node is not automatically federated or finality-backed",
        "local_fixture",
        "I16",
        "I17",
        "node_registration_accepts_bound_authority_and_runs_handler_once",
        "node_registration_rejections_never_run_handler",
    ] {
        assert!(M15_DEMO_README.contains(required), "missing: {required}");
    }

    for forbidden in [
        "node listing proves federation membership",
        "registered nodes are federated nodes",
        "production authority registration is implemented",
    ] {
        assert!(
            !M15_DEMO_README.contains(forbidden),
            "forbidden: {forbidden}"
        );
    }
}
