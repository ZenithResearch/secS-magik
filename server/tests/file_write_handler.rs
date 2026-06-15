//! M13.2/M13.3 — sandboxed `demo.file.write` handler.
//!
//! The write target is the `resource` bound into the verified context; the
//! payload is the raw content. These tests exercise the sandbox guard.

use server::file_write::{reject_reason, DemoFileWriteProgram};
use server::gateway::{ExecutionLimits, HandlerOutcome, MachineProgram};
use server::receipt::Decision;
use server::verifier::{
    VerifiedCallContext, VerifiedSubject, VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh, created sandbox directory under the system temp dir.
fn fresh_sandbox(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secs-demo-file-write-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create sandbox dir");
    dir
}

/// A verified context carrying `resource` as the write target.
fn context_for(resource: Option<&str>) -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: "ctx-demo-file-write".to_string(),
        packet_hash: [0u8; 32],
        session_id: [0u8; 16],
        nonce: [0u8; 12],
        opcode: 0x50,
        operation: "demo.file.write".to_string(),
        resource: resource.map(ToString::to_string),
        subject: VerifiedSubject {
            subject_id: "secS://caller-a".to_string(),
            key_id: "key-a".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec![],
        capability_result: "ok".to_string(),
        credential_result: "ok".to_string(),
        issued_at: 1_000,
        expires_at: 2_000,
        descriptor_fingerprint: String::new(),
        replay_scope: "session_opcode_nonce".to_string(),
        handler_id: Some("demo/file-write".to_string()),
    }
}

fn file_uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

async fn write(
    program: &DemoFileWriteProgram,
    resource: Option<&str>,
    content: &[u8],
) -> HandlerOutcome {
    program
        .execute(&context_for(resource), content, ExecutionLimits::default())
        .await
}

#[tokio::test]
async fn missing_sandbox_directory_fails_closed_at_construction() {
    assert!(DemoFileWriteProgram::new("/nonexistent/secs-demo-sandbox-xyz").is_none());
}

#[tokio::test]
async fn missing_resource_rejects() {
    let sandbox = fresh_sandbox("no-resource");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");

    let outcome = write(&program, None, b"content").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::MISSING_RESOURCE)
    );
}

#[tokio::test]
async fn allowed_target_under_sandbox_writes_expected_content() {
    let sandbox = fresh_sandbox("allow");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let target = sandbox.join("allowed.txt");

    let outcome = write(&program, Some(&file_uri(&target)), b"hello sandbox").await;

    assert_eq!(outcome.decision, Decision::Accepted);
    assert_eq!(outcome.output_bytes, "hello sandbox".len());
    assert_eq!(
        std::fs::read_to_string(&target).expect("file written"),
        "hello sandbox"
    );
}

#[tokio::test]
async fn nested_target_under_existing_subdir_writes() {
    let sandbox = fresh_sandbox("nested");
    std::fs::create_dir_all(sandbox.join("sub")).expect("subdir");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let target = sandbox.join("sub").join("note.txt");

    let outcome = write(&program, Some(&file_uri(&target)), b"nested").await;

    assert_eq!(outcome.decision, Decision::Accepted);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "nested");
}

#[tokio::test]
async fn target_outside_sandbox_rejects_before_write() {
    let sandbox = fresh_sandbox("outside");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let outside = std::env::temp_dir().join("secs-demo-outside-target.txt");
    let _ = std::fs::remove_file(&outside);

    let outcome = write(&program, Some(&file_uri(&outside)), b"escape").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::PATH_OUTSIDE_SANDBOX)
    );
    assert!(!outside.exists(), "no write outside the sandbox");
}

#[tokio::test]
async fn traversal_path_rejects() {
    let sandbox = fresh_sandbox("traversal");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let resource = format!("file://{}/../escape.txt", sandbox.display());

    let outcome = write(&program, Some(&resource), b"x").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::PATH_TRAVERSAL)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_rejects() {
    let sandbox = fresh_sandbox("symlink");
    let outside_dir = fresh_sandbox("symlink-outside");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let link = sandbox.join("escape-link");
    std::os::unix::fs::symlink(&outside_dir, &link).expect("create symlink");

    let target = link.join("pwned.txt");
    let outcome = write(&program, Some(&file_uri(&target)), b"x").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::PATH_OUTSIDE_SANDBOX)
    );
    assert!(
        !outside_dir.join("pwned.txt").exists(),
        "symlink escape must not write outside the sandbox"
    );
}

#[tokio::test]
async fn non_file_uri_rejects() {
    let sandbox = fresh_sandbox("scheme");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");

    let outcome = write(&program, Some("https://example.com/x"), b"x").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::NOT_A_FILE_URI)
    );
}

#[tokio::test]
async fn oversized_payload_rejects_before_write() {
    let sandbox = fresh_sandbox("oversized");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let target = sandbox.join("big.txt");
    let limits = ExecutionLimits {
        max_payload_bytes: 16,
        max_output_bytes: 16,
        ..ExecutionLimits::default()
    };

    let outcome = program
        .execute(
            &context_for(Some(&file_uri(&target))),
            b"this content is definitely longer than sixteen bytes",
            limits,
        )
        .await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::PAYLOAD_TOO_LARGE)
    );
    assert!(!target.exists(), "no write when payload exceeds limits");
}
