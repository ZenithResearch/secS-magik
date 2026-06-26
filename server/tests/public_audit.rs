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
