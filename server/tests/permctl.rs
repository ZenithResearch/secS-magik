//! M13.4a — secs-permctl operator CLI logic.

use server::permctl::{
    build_record, evaluate, grant, list_lines, load_records, revoke, save_records, PermctlError,
};
use server::permissions::DenyReason;
use std::time::{SystemTime, UNIX_EPOCH};

const CALLER: &str = "secS://caller-a";
const OPCODE: u8 = 0x50;
const OP: &str = "demo.file.write";
const RESOURCE: &str = "file:///tmp/secs-demo/allowed.txt";

fn temp_policy_path(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("secs-permctl-{label}-{nanos}.json"))
}

#[test]
fn grant_then_evaluate_allows() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    assert_eq!(
        evaluate(records, CALLER, OPCODE, OP, RESOURCE, 1_000),
        Ok(())
    );
}

#[test]
fn evaluate_unknown_request_denies() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    assert_eq!(
        evaluate(
            records,
            CALLER,
            OPCODE,
            OP,
            "file:///tmp/secs-demo/other.txt",
            1_000
        ),
        Err(DenyReason::NoMatchingGrant)
    );
}

#[test]
fn prefix_grant_allows_under_prefix() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        "file:///tmp/secs-demo/".to_string(),
        true,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    assert_eq!(
        evaluate(
            records,
            CALLER,
            OPCODE,
            OP,
            "file:///tmp/secs-demo/nested/x.txt",
            1_000
        ),
        Ok(())
    );
}

#[test]
fn deny_record_wins() {
    let allow = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let deny = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        true,
        0,
        u64::MAX,
    );
    let records = grant(grant(Vec::new(), allow), deny);
    assert_eq!(
        evaluate(records, CALLER, OPCODE, OP, RESOURCE, 1_000),
        Err(DenyReason::ExplicitDeny)
    );
}

#[test]
fn revoke_sets_status_and_denies() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    let (records, n) = revoke(records, CALLER, OPCODE, OP, RESOURCE);
    assert_eq!(n, 1);
    assert_eq!(
        evaluate(records, CALLER, OPCODE, OP, RESOURCE, 1_000),
        Err(DenyReason::Revoked)
    );
}

#[test]
fn revoke_no_match_reports_zero() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    let (_records, n) = revoke(records, "secS://other", OPCODE, OP, RESOURCE);
    assert_eq!(n, 0);
}

#[test]
fn list_lines_describe_records() {
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let lines = list_lines(&grant(Vec::new(), record));
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("allow active"));
    assert!(lines[0].contains("caller=secS://caller-a"));
    assert!(lines[0].contains("opcode=0x50"));
    assert!(lines[0].contains("source=receiver_local"));
}

#[test]
fn save_and_load_round_trip() {
    let path = temp_policy_path("roundtrip");
    let record = build_record(
        CALLER.to_string(),
        OPCODE,
        OP.to_string(),
        RESOURCE.to_string(),
        false,
        false,
        0,
        u64::MAX,
    );
    let records = grant(Vec::new(), record);
    save_records(&path, &records).expect("save");
    let loaded = load_records(&path).expect("load");
    assert_eq!(loaded, records);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn missing_file_is_empty_policy() {
    let path = temp_policy_path("missing");
    assert_eq!(load_records(&path), Ok(Vec::new()));
}

#[test]
fn malformed_file_fails_closed() {
    let path = temp_policy_path("malformed");
    std::fs::write(&path, "{ not an array").unwrap();
    assert_eq!(load_records(&path), Err(PermctlError::Malformed));
    let _ = std::fs::remove_file(&path);
}
