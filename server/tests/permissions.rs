//! M13.1 — receiver-local permission model and policy store.

use server::permissions::{
    AuthoritySource, DenyReason, PermissionDecision, PermissionEffect, PermissionPolicy,
    PermissionRecord, PermissionStatus, PolicyError, ResourceScope,
};

const CALLER: &str = "secS://caller-a";
const OPCODE: u8 = 0x50;
const OPERATION: &str = "demo.file.write";
const RESOURCE: &str = "file:///tmp/secs-demo/allowed.txt";
const NOW: u64 = 1_000;

fn allow_exact() -> PermissionRecord {
    PermissionRecord {
        caller_id: CALLER.to_string(),
        opcode: OPCODE,
        operation: OPERATION.to_string(),
        resource: ResourceScope::Exact {
            value: RESOURCE.to_string(),
        },
        effect: PermissionEffect::Allow,
        not_before: 0,
        not_after: 10_000,
        status: PermissionStatus::Active,
        authority_source: AuthoritySource::ReceiverLocal,
    }
}

fn policy(records: Vec<PermissionRecord>) -> PermissionPolicy {
    PermissionPolicy::new(records).expect("valid policy")
}

#[test]
fn allowed_caller_opcode_operation_exact_resource_allows() {
    let policy = policy(vec![allow_exact()]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Ok(PermissionDecision::Allow)
    );
}

#[test]
fn resource_under_allowed_prefix_allows() {
    let mut record = allow_exact();
    record.resource = ResourceScope::Prefix {
        prefix: "file:///tmp/secs-demo/".to_string(),
    };
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(
            CALLER,
            OPCODE,
            OPERATION,
            "file:///tmp/secs-demo/nested/other.txt",
            NOW
        ),
        Ok(PermissionDecision::Allow)
    );
}

#[test]
fn resource_outside_prefix_denies() {
    let mut record = allow_exact();
    record.resource = ResourceScope::Prefix {
        prefix: "file:///tmp/secs-demo/".to_string(),
    };
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, "file:///tmp/other/x.txt", NOW),
        Err(DenyReason::NoMatchingGrant)
    );
}

#[test]
fn wrong_caller_opcode_operation_resource_each_denies() {
    let policy = policy(vec![allow_exact()]);
    assert_eq!(
        policy.evaluate("secS://other", OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::NoMatchingGrant)
    );
    assert_eq!(
        policy.evaluate(CALLER, 0x51, OPERATION, RESOURCE, NOW),
        Err(DenyReason::NoMatchingGrant)
    );
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, "demo.file.read", RESOURCE, NOW),
        Err(DenyReason::NoMatchingGrant)
    );
    assert_eq!(
        policy.evaluate(
            CALLER,
            OPCODE,
            OPERATION,
            "file:///tmp/secs-demo/denied.txt",
            NOW
        ),
        Err(DenyReason::NoMatchingGrant)
    );
}

#[test]
fn empty_policy_fails_closed() {
    let policy = policy(vec![]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::NoMatchingGrant)
    );
}

#[test]
fn explicit_deny_wins_over_allow() {
    let mut deny = allow_exact();
    deny.effect = PermissionEffect::Deny;
    // Allow and Deny both match; deny must win regardless of order.
    let policy = policy(vec![allow_exact(), deny]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::ExplicitDeny)
    );
}

#[test]
fn revoked_grant_denies() {
    let mut record = allow_exact();
    record.status = PermissionStatus::Revoked;
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::Revoked)
    );
}

#[test]
fn expired_grant_denies() {
    let mut record = allow_exact();
    record.not_before = 0;
    record.not_after = 500;
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::Expired)
    );
}

#[test]
fn not_yet_valid_grant_denies() {
    let mut record = allow_exact();
    record.not_before = 2_000;
    record.not_after = 5_000;
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::NotYetValid)
    );
}

#[test]
fn validity_window_boundaries_are_inclusive_lower_exclusive_upper() {
    let mut record = allow_exact();
    record.not_before = 1_000;
    record.not_after = 2_000;
    let policy = policy(vec![record]);
    // exactly not_before -> valid
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, 1_000),
        Ok(PermissionDecision::Allow)
    );
    // exactly not_after -> expired
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, 2_000),
        Err(DenyReason::Expired)
    );
}

#[test]
fn non_receiver_local_authority_source_is_unsupported_in_m13() {
    let mut record = allow_exact();
    record.authority_source = AuthoritySource::DreggBacked;
    let policy = policy(vec![record]);
    assert_eq!(
        policy.evaluate(CALLER, OPCODE, OPERATION, RESOURCE, NOW),
        Err(DenyReason::AuthoritySourceUnsupported)
    );
}

#[test]
fn deny_reason_codes_are_stable() {
    assert_eq!(
        DenyReason::NoMatchingGrant.code(),
        "permission_no_matching_grant"
    );
    assert_eq!(DenyReason::ExplicitDeny.code(), "permission_explicit_deny");
    assert_eq!(DenyReason::Revoked.code(), "permission_revoked");
    assert_eq!(DenyReason::Expired.code(), "permission_expired");
    assert_eq!(DenyReason::NotYetValid.code(), "permission_not_yet_valid");
    assert_eq!(
        DenyReason::AuthoritySourceUnsupported.code(),
        "permission_authority_source_unsupported"
    );
}

#[test]
fn record_round_trips_through_json_with_defaults() {
    // effect and authority_source default; status/validity explicit.
    let json = r#"[
        {
            "caller_id": "secS://caller-a",
            "opcode": 80,
            "operation": "demo.file.write",
            "resource": { "kind": "prefix", "prefix": "file:///tmp/secs-demo/" },
            "not_before": 0,
            "not_after": 10000,
            "status": "active"
        }
    ]"#;
    let policy = PermissionPolicy::from_json_str(json).expect("valid policy json");
    assert_eq!(policy.len(), 1);
    assert_eq!(
        policy.evaluate(
            CALLER,
            OPCODE,
            OPERATION,
            "file:///tmp/secs-demo/allowed.txt",
            NOW
        ),
        Ok(PermissionDecision::Allow)
    );
}

#[test]
fn serde_round_trip_preserves_record() {
    let record = allow_exact();
    let json = serde_json::to_string(&record).expect("serialize");
    let back: PermissionRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, back);
}

#[test]
fn empty_json_fails_closed() {
    assert_eq!(
        PermissionPolicy::from_json_str("   "),
        Err(PolicyError::Empty)
    );
}

#[test]
fn malformed_json_fails_closed() {
    assert_eq!(
        PermissionPolicy::from_json_str("{ not an array"),
        Err(PolicyError::Malformed)
    );
}

#[test]
fn invalid_record_fails_closed() {
    // not_before >= not_after
    let mut bad = allow_exact();
    bad.not_before = 5_000;
    bad.not_after = 1_000;
    assert_eq!(
        PermissionPolicy::new(vec![bad]),
        Err(PolicyError::InvalidRecord)
    );

    // empty caller
    let mut empty_caller = allow_exact();
    empty_caller.caller_id = String::new();
    assert_eq!(
        PermissionPolicy::new(vec![empty_caller]),
        Err(PolicyError::InvalidRecord)
    );

    // empty resource value
    let mut empty_resource = allow_exact();
    empty_resource.resource = ResourceScope::Exact {
        value: String::new(),
    };
    assert_eq!(
        PermissionPolicy::new(vec![empty_resource]),
        Err(PolicyError::InvalidRecord)
    );
}

#[test]
fn from_json_file_missing_path_fails_closed() {
    assert_eq!(
        PermissionPolicy::from_json_file("/nonexistent/secs-permissions.json"),
        Err(PolicyError::Unreadable)
    );
}
