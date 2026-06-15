//! M13.2 — sandboxed `demo.file.write` handler.

use server::file_write::{reject_reason, DemoFileWriteProgram};
use server::gateway::{ExecutionLimits, MachineProgram};
use server::receipt::Decision;
use server::verifier::{
    VerifiedCallContext, VerifiedSubject, VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A fresh, created sandbox directory under the system temp dir. The handler
/// ignores the context entirely; these tests exercise the sandbox guard.
fn fresh_sandbox(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("secs-demo-file-write-{label}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create sandbox dir");
    dir
}

fn dummy_context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: "ctx-demo-file-write".to_string(),
        packet_hash: [0u8; 32],
        session_id: [0u8; 16],
        nonce: [0u8; 12],
        opcode: 0x50,
        operation: "demo.file.write".to_string(),
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

fn payload(resource: &str, content: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "resource": resource, "content": content }))
        .expect("serialize payload")
}

fn file_uri(path: &Path) -> String {
    format!("file://{}", path.display())
}

async fn run(program: &DemoFileWriteProgram, payload: &[u8]) -> server::gateway::HandlerOutcome {
    program
        .execute(&dummy_context(), payload, ExecutionLimits::default())
        .await
}

#[tokio::test]
async fn missing_sandbox_directory_fails_closed_at_construction() {
    assert!(DemoFileWriteProgram::new("/nonexistent/secs-demo-sandbox-xyz").is_none());
}

#[tokio::test]
async fn allowed_target_under_sandbox_writes_expected_content() {
    let sandbox = fresh_sandbox("allow");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let target = sandbox.join("allowed.txt");

    let outcome = run(&program, &payload(&file_uri(&target), "hello sandbox")).await;

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

    let outcome = run(&program, &payload(&file_uri(&target), "nested")).await;

    assert_eq!(outcome.decision, Decision::Accepted);
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "nested");
}

#[tokio::test]
async fn target_outside_sandbox_rejects_before_write() {
    let sandbox = fresh_sandbox("outside");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");
    let outside = std::env::temp_dir().join("secs-demo-outside-target.txt");
    let _ = std::fs::remove_file(&outside);

    let outcome = run(&program, &payload(&file_uri(&outside), "escape")).await;

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
    // file:///<sandbox>/../escape.txt
    let resource = format!("file://{}/../escape.txt", sandbox.display());

    let outcome = run(&program, &payload(&resource, "x")).await;

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
    // A symlinked subdir inside the sandbox that points outside it.
    let link = sandbox.join("escape-link");
    std::os::unix::fs::symlink(&outside_dir, &link).expect("create symlink");

    let target = link.join("pwned.txt");
    let outcome = run(&program, &payload(&file_uri(&target), "x")).await;

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

    let outcome = run(&program, &payload("https://example.com/x", "x")).await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::NOT_A_FILE_URI)
    );
}

#[tokio::test]
async fn malformed_payload_rejects() {
    let sandbox = fresh_sandbox("malformed");
    let program = DemoFileWriteProgram::new(&sandbox).expect("sandbox exists");

    let outcome = run(&program, b"{ not json").await;

    assert_eq!(outcome.decision, Decision::Rejected);
    assert_eq!(
        outcome.reason.as_deref(),
        Some(reject_reason::MALFORMED_PAYLOAD)
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
            &dummy_context(),
            &payload(
                &file_uri(&target),
                "this content is definitely longer than sixteen bytes",
            ),
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
