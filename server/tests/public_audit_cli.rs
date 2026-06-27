use ed25519_dalek::SigningKey;
use server::ledger::Ledger;
use server::public_audit::{PublicAuditBundle, PublicAuditVerificationError};
use server::public_audit_cli::{verify_public_audit_bundle_file, PublicAuditCliVerification};
use server::receipt::{AuthenticatorKind, Decision, Receipt};
use server::verifier::{VerifiedCallContext, VerifiedSubject};
use sqlx::sqlite::SqlitePoolOptions;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

async fn memory_ledger() -> Ledger {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    ledger
}

fn context(context_id: &str) -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: 2,
        descriptor_fingerprint: "descriptor:public-audit-cli-fixture".to_string(),
        context_id: context_id.to_string(),
        packet_hash: [9u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x50,
        operation: "candidate.dev.local_static".to_string(),
        resource: Some("application/json".to_string()),
        subject: VerifiedSubject {
            subject_id: "prototype.local-dev.subject".to_string(),
            key_id: "subject-key:test".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec![
            "evidence_kind:local_static".to_string(),
            "public_key_ref_sha256:abcdef".to_string(),
        ],
        capability_result: "accepted".to_string(),
        credential_result: "accepted".to_string(),
        issued_at: 1_770_000_000,
        expires_at: 1_770_000_300,
        replay_scope: "SessionOpcodeNonce".to_string(),
        handler_id: Some("candidate/local-static".to_string()),
    }
}

fn signer_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn signed_receipt(receipt_id: &str, context: &VerifiedCallContext, timestamp: u64) -> Receipt {
    Receipt::execution(receipt_id, context, Decision::Accepted, None, timestamp)
        .sign_ed25519(
            "verifier:public-audit-cli-test",
            &[7u8; 32],
            AuthenticatorKind::Ed25519NodeAndVerifier,
        )
        .unwrap()
}

async fn fixture_bundle(context_id: &str) -> PublicAuditBundle {
    let ledger = memory_ledger().await;
    let context = context(context_id);
    ledger
        .record_receipt(&signed_receipt("r-cli-1", &context, 1_770_000_010))
        .await
        .unwrap();
    ledger
        .record_receipt(&signed_receipt("r-cli-2", &context, 1_770_000_011))
        .await
        .unwrap();
    ledger
        .export_public_audit_bundle_for_context(
            context_id,
            [(
                "verifier:public-audit-cli-test",
                signer_key().verifying_key().as_bytes(),
            )],
            1_770_000_100,
        )
        .await
        .unwrap()
}

fn temp_bundle_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("secs-public-audit-{label}-{nanos}.json"))
}

fn write_bundle(label: &str, bundle: &PublicAuditBundle) -> PathBuf {
    let path = temp_bundle_path(label);
    fs::write(&path, serde_json::to_vec_pretty(bundle).unwrap()).unwrap();
    path
}

#[tokio::test]
async fn verifier_cli_engine_accepts_valid_bundle_without_database_access() {
    let bundle = fixture_bundle("ctx-public-audit-cli-valid").await;
    let path = write_bundle("valid", &bundle);

    let report = verify_public_audit_bundle_file(&path).unwrap();

    assert_eq!(
        report,
        PublicAuditCliVerification {
            valid: true,
            bundle_version: "secs-public-audit-bundle-v1".to_string(),
            chain_algorithm_version: "secs-public-audit-chain-v1".to_string(),
            chain_scope: "context:ctx-public-audit-cli-valid".to_string(),
            root_hash_hex: bundle.chain.root_hash_hex,
            receipt_count: 2,
            error: None,
        }
    );
}

#[tokio::test]
async fn verifier_cli_engine_reports_stable_error_names_without_raw_material() {
    let mut bundle = fixture_bundle("ctx-public-audit-cli-tamper").await;
    bundle.receipts[0].decision = "rejected".to_string();
    let path = write_bundle("tamper", &bundle);

    let error = verify_public_audit_bundle_file(&path).unwrap_err();

    assert_eq!(
        error.verification_error,
        Some(PublicAuditVerificationError::ReceiptEntryHashMismatch)
    );
    let rendered = error.to_string();
    assert!(rendered.contains("ReceiptEntryHashMismatch"));
    assert!(!rendered.contains("raw_payload"));
    assert!(!rendered.contains("raw_private_evidence"));
    assert!(!rendered.contains("target-ref"));
}

#[tokio::test]
async fn secz_audit_verify_exits_zero_for_valid_and_nonzero_for_invalid_bundle() {
    let valid = fixture_bundle("ctx-public-audit-cli-process").await;
    let valid_path = write_bundle("process-valid", &valid);
    let valid_output = Command::new(env!("CARGO_BIN_EXE_secz"))
        .args(["audit", "verify", valid_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        valid_output.status.success(),
        "{}",
        String::from_utf8_lossy(&valid_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&valid_output.stdout);
    assert!(stdout.contains("valid=true"));
    assert!(stdout.contains("receipt_count=2"));
    assert!(!stdout.contains("raw_payload"));
    assert!(!stdout.contains("raw_private_evidence"));

    let mut invalid = valid;
    invalid.version = "future-public-audit-bundle".to_string();
    let invalid_path = write_bundle("process-invalid", &invalid);
    let invalid_output = Command::new(env!("CARGO_BIN_EXE_secz"))
        .args(["audit", "verify", invalid_path.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!invalid_output.status.success());
    let stderr = String::from_utf8_lossy(&invalid_output.stderr);
    assert!(stderr.contains("UnsupportedBundleVersion"));
    assert!(!stderr.contains("raw_payload"));
    assert!(!stderr.contains("raw_private_evidence"));
}
