use ed25519_dalek::SigningKey;
use server::ledger::Ledger;
use server::public_audit::{
    verify_external_audit_anchor_record, ExternalAuditAnchorRecord, GitHubGistAuditPublisher,
    PublicAuditPublicationStatus,
};
use server::receipt::{AuthenticatorKind, Decision, Receipt};
use server::verifier::{VerifiedCallContext, VerifiedSubject};
use sqlx::sqlite::SqlitePoolOptions;

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
        descriptor_fingerprint: "descriptor:external-anchor-fixture".to_string(),
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
            "verifier:external-anchor-test",
            &[7u8; 32],
            AuthenticatorKind::Ed25519NodeAndVerifier,
        )
        .unwrap()
}

#[tokio::test]
async fn github_gist_anchor_publisher_records_external_redacted_status_and_anchor_record() {
    let ledger = memory_ledger().await;
    let context = context("ctx-public-audit-gist-anchor");
    ledger
        .record_receipt(&signed_receipt("r-anchor-1", &context, 1_770_000_010))
        .await
        .unwrap();
    ledger
        .record_receipt(&signed_receipt("r-anchor-2", &context, 1_770_000_011))
        .await
        .unwrap();
    let bundle = ledger
        .export_public_audit_bundle_for_context(
            "ctx-public-audit-gist-anchor",
            [(
                "verifier:external-anchor-test",
                signer_key().verifying_key().as_bytes(),
            )],
            1_770_000_100,
        )
        .await
        .unwrap();

    let publisher =
        GitHubGistAuditPublisher::dry_run("https://gist.github.com/ZenithResearch/example-anchor");
    let status = ledger
        .publish_public_audit_bundle(&bundle, &publisher, 1_770_000_200)
        .await
        .unwrap();
    let anchor = publisher.anchor_record(&bundle, 1_770_000_200).unwrap();

    assert_eq!(status.status, PublicAuditPublicationStatus::Published);
    assert_eq!(status.target_kind, "github-gist");
    assert_ne!(
        status.target_ref_digest_hex.as_deref(),
        Some("https://gist.github.com/ZenithResearch/example-anchor")
    );
    assert_eq!(anchor.target_kind, "github-gist");
    assert_eq!(anchor.bundle_version, "secs-public-audit-bundle-v1");
    assert_eq!(anchor.chain_algorithm_version, "secs-public-audit-chain-v1");
    assert_eq!(anchor.chain_scope, "context:ctx-public-audit-gist-anchor");
    assert_eq!(anchor.root_hash_hex, bundle.chain.root_hash_hex);
    assert_eq!(anchor.receipt_count, 2);
    assert_eq!(anchor.verifier_command, "secz audit verify <bundle.json>");
    assert!(verify_external_audit_anchor_record(&bundle, &anchor).is_ok());

    let json = serde_json::to_string(&anchor).unwrap();
    assert!(!json.contains("raw_payload"));
    assert!(!json.contains("raw_private_evidence"));
    assert!(!json.contains("sqlite"));
}

#[tokio::test]
async fn external_anchor_verifier_rejects_tampered_anchor_metadata() {
    let ledger = memory_ledger().await;
    let context = context("ctx-public-audit-gist-anchor-tamper");
    ledger
        .record_receipt(&signed_receipt(
            "r-anchor-tamper-1",
            &context,
            1_770_000_010,
        ))
        .await
        .unwrap();
    let bundle = ledger
        .export_public_audit_bundle_for_context(
            "ctx-public-audit-gist-anchor-tamper",
            [(
                "verifier:external-anchor-test",
                signer_key().verifying_key().as_bytes(),
            )],
            1_770_000_100,
        )
        .await
        .unwrap();
    let publisher =
        GitHubGistAuditPublisher::dry_run("https://gist.github.com/ZenithResearch/example-anchor");
    let mut anchor = publisher.anchor_record(&bundle, 1_770_000_200).unwrap();

    anchor.root_hash_hex = "00".repeat(32);

    assert_eq!(
        verify_external_audit_anchor_record(&bundle, &anchor)
            .unwrap_err()
            .to_string(),
        "external_anchor_mismatch=root_hash_hex"
    );
}

#[test]
fn external_anchor_record_is_versioned_and_public_safe_json() {
    let record = ExternalAuditAnchorRecord {
        anchor_schema_version: "secs-public-audit-github-gist-anchor-v1".to_string(),
        target_kind: "github-gist".to_string(),
        target_ref: "https://gist.github.com/ZenithResearch/example-anchor".to_string(),
        bundle_version: "secs-public-audit-bundle-v1".to_string(),
        chain_algorithm_version: "secs-public-audit-chain-v1".to_string(),
        chain_scope: "context:ctx".to_string(),
        root_hash_hex: "ab".repeat(32),
        receipt_count: 2,
        published_at: 1_770_000_200,
        verifier_command: "secz audit verify <bundle.json>".to_string(),
    };

    let json = serde_json::to_string(&record).unwrap();
    assert!(json.contains("secs-public-audit-github-gist-anchor-v1"));
    assert!(json.contains("github-gist"));
    assert!(!json.contains("raw_payload"));
    assert!(!json.contains("raw_private_evidence"));
}
