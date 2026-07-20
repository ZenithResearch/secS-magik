use libsec_core::execution_response::{
    EXECUTION_RESPONSE_TOO_LARGE, HANDLER_OUTPUT_MISSING, HANDLER_OUTPUT_UNEXPECTED,
    OUTPUT_TOO_LARGE,
};
use server::gateway::{ExecutionLimits, HandlerOutcome};
use server::manifest::{
    OpcodeRange, OperationDescriptor, OperationName, OutputProfile, ReplayScope, TargetKind,
};
use server::privacy::DisclosurePolicy;
use std::time::Duration;

fn descriptor(output_profile: Option<OutputProfile>) -> OperationDescriptor {
    OperationDescriptor {
        opcode: 0x52,
        name: OperationName::new("fixture.output.v1"),
        payload_schema: Some("fixture.request.v1".into()),
        output_profile,
        target_kind: TargetKind::LocalDevProcess,
        required_credentials: vec!["fixture".into()],
        required_capabilities: vec!["fixture.execute".into()],
        accepted_evidence: vec!["prototype-proof-envelope".into()],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 30,
        handler_id: "fixture/output".into(),
        dev_binding: true,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::default_i02(),
    }
}

#[test]
fn output_profile_is_receiver_owned_fingerprinted_and_effectively_bounded() {
    let profile = OutputProfile {
        schema_id: "fixture.response.v1".into(),
        max_output_bytes: 8,
        max_execution_response_bytes: 512,
    };
    let with_output = descriptor(Some(profile.clone()));
    let without_output = descriptor(None);
    assert_ne!(
        with_output.authorization_fingerprint(),
        without_output.authorization_fingerprint()
    );

    for mutated in [
        OutputProfile {
            schema_id: "fixture.response.v2".into(),
            ..profile.clone()
        },
        OutputProfile {
            max_output_bytes: 7,
            ..profile.clone()
        },
        OutputProfile {
            max_execution_response_bytes: 511,
            ..profile.clone()
        },
    ] {
        assert_ne!(
            with_output.authorization_fingerprint(),
            descriptor(Some(mutated)).authorization_fingerprint()
        );
    }

    let limits = ExecutionLimits {
        max_payload_bytes: 1024,
        max_output_bytes: 6,
        handler_timeout: Duration::from_secs(1),
    };
    let effective = limits.for_output_profile(&profile).unwrap();
    assert_eq!(effective.max_output_bytes, 6);
    assert_eq!(effective.max_execution_response_bytes, 512);
}

#[test]
fn handler_outcome_owns_bytes_and_reason_vocabulary_is_exact() {
    assert_eq!(HandlerOutcome::succeeded().output, None);
    assert_eq!(
        HandlerOutcome::succeeded_with_output(Vec::new()).output,
        Some(Vec::new())
    );
    assert_eq!(HandlerOutcome::rejected("handler_timeout").output, None);
    assert_eq!(
        [
            HANDLER_OUTPUT_MISSING,
            HANDLER_OUTPUT_UNEXPECTED,
            OUTPUT_TOO_LARGE,
            EXECUTION_RESPONSE_TOO_LARGE,
        ],
        [
            "handler_output_missing",
            "handler_output_unexpected",
            "output_too_large",
            "execution_response_too_large",
        ]
    );
}

#[test]
fn invalid_output_profiles_fail_closed_without_clamping() {
    for profile in [
        OutputProfile {
            schema_id: String::new(),
            max_output_bytes: 1,
            max_execution_response_bytes: 128,
        },
        OutputProfile {
            schema_id: "fixture.response.v1".into(),
            max_output_bytes: 0,
            max_execution_response_bytes: 128,
        },
        OutputProfile {
            schema_id: "fixture.response.v1".into(),
            max_output_bytes: 1,
            max_execution_response_bytes: 0,
        },
    ] {
        assert!(descriptor(Some(profile)).validate().is_err());
    }
}
