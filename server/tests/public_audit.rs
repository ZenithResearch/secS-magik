use server::public_audit::{
    PublicAuditBundle, PublicAuditBundleStatus, PublicAuditChainMetadata, PublicAuditReceiptEntry,
    PublicAuditRedactionPolicy, PublicAuditSignerKey,
};

#[test]
fn public_audit_bundle_schema_is_versioned_redacted_and_serializable() {
    let bundle = PublicAuditBundle {
        version: PublicAuditBundle::VERSION.to_string(),
        redaction_policy: PublicAuditRedactionPolicy::DefaultNoPayloadOrPrivateEvidence,
        status: PublicAuditBundleStatus::Complete,
        exported_at: 1_770_000_000,
        chain: PublicAuditChainMetadata {
            root_hash_hex: "root-hash".to_string(),
            first_receipt_id: "r-1".to_string(),
            last_receipt_id: "r-2".to_string(),
            receipt_count: 2,
            complete: true,
        },
        signer_keys: vec![PublicAuditSignerKey {
            signer_key_id: "verifier:test".to_string(),
            public_key_hex: "11".repeat(32),
        }],
        receipts: vec![PublicAuditReceiptEntry {
            receipt_id: "r-1".to_string(),
            schema_version: 2,
            context_id: Some("ctx-1".to_string()),
            timestamp: 1_770_000_001,
            kind: "verify".to_string(),
            decision: "accepted".to_string(),
            reason: None,
            operation: Some("candidate.dev.local_static".to_string()),
            handler_id: Some("handler:file_write".to_string()),
            opcode: 0x50,
            packet_hash_hex: "aa".repeat(32),
            session_id_hex: "bb".repeat(16),
            nonce_hex: "cc".repeat(12),
            authenticator_kind: "ed25519_node_and_verifier".to_string(),
            signer_key_id: "verifier:test".to_string(),
            signature_hex: "dd".repeat(64),
            evidence_summary: vec!["evidence_kind:local_static".to_string()],
            entry_hash_hex: "ee".repeat(32),
        }],
    };

    let json = serde_json::to_string(&bundle).expect("public audit bundle should serialize");
    assert!(json.contains("secs-public-audit-bundle-v1"));
    assert!(json.contains("default_no_payload_or_private_evidence"));
    assert!(!json.contains("raw_payload"));
    assert!(!json.contains("raw_private_evidence"));

    let decoded: PublicAuditBundle = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.version, PublicAuditBundle::VERSION);
    assert_eq!(decoded.chain.receipt_count, 2);
}

use ed25519_dalek::SigningKey;
use server::ledger::{Ledger, PublicAuditExportError};
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
        descriptor_fingerprint: "descriptor:public-audit-fixture".to_string(),
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
            "verifier:public-audit-test",
            &[7u8; 32],
            AuthenticatorKind::Ed25519NodeAndVerifier,
        )
        .unwrap()
}

#[tokio::test]
async fn exports_complete_redacted_public_audit_bundle_for_context_chain() {
    let ledger = memory_ledger().await;
    let context = context("ctx-public-audit-export");
    ledger
        .record_receipt(&signed_receipt("r-public-1", &context, 1_770_000_010))
        .await
        .unwrap();
    ledger
        .record_receipt(&signed_receipt("r-public-2", &context, 1_770_000_011))
        .await
        .unwrap();

    let bundle = ledger
        .export_public_audit_bundle_for_context(
            "ctx-public-audit-export",
            [(
                "verifier:public-audit-test",
                signer_key().verifying_key().as_bytes(),
            )],
            1_770_000_100,
        )
        .await
        .unwrap();

    assert_eq!(bundle.version, PublicAuditBundle::VERSION);
    assert_eq!(bundle.status, PublicAuditBundleStatus::Complete);
    assert!(bundle.chain.complete);
    assert_eq!(bundle.chain.receipt_count, 2);
    assert_eq!(bundle.chain.first_receipt_id, "r-public-1");
    assert_eq!(bundle.chain.last_receipt_id, "r-public-2");
    assert_eq!(
        bundle.signer_keys[0].signer_key_id,
        "verifier:public-audit-test"
    );
    assert_eq!(bundle.receipts.len(), 2);
    assert!(bundle.receipts[0].signature_hex.len() >= 128);
    assert!(bundle.receipts[0]
        .evidence_summary
        .iter()
        .all(|field| !field.contains("raw_payload") && !field.contains("raw_private_evidence")));

    let json = serde_json::to_string(&bundle).unwrap();
    assert!(!json.contains("secret payload"));
    assert!(!json.contains("raw_private_evidence"));
}

#[tokio::test]
async fn public_audit_export_rejects_incomplete_or_unsigned_context_chains() {
    let ledger = memory_ledger().await;
    let context = context("ctx-public-audit-incomplete");
    ledger
        .record_receipt(&Receipt::execution(
            "r-unsigned",
            &context,
            Decision::Accepted,
            None,
            1_770_000_010,
        ))
        .await
        .unwrap();

    let error = ledger
        .export_public_audit_bundle_for_context(
            "ctx-public-audit-incomplete",
            [(
                "verifier:public-audit-test",
                signer_key().verifying_key().as_bytes(),
            )],
            1_770_000_100,
        )
        .await
        .unwrap_err();

    assert_eq!(error, PublicAuditExportError::IncompleteReceiptChain);
}
