use server::manifest::{node_registration_descriptor, ReceiverManifest};
use server::node_registration::{
    verify_node_registration, NodeRegistrationPolicy, NodeRegistrationReason,
    NodeRegistrationRequestV0, NODE_REGISTRATION_DISCLOSURE_POLICY_ID,
    NODE_REGISTRATION_HANDLER_ID, NODE_REGISTRATION_OPCODE, NODE_REGISTRATION_OPERATION,
    NODE_REGISTRATION_PAYLOAD_SCHEMA,
};

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
