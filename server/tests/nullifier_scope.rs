//! I04-C01 owner discovery: scoped nullifier/use-state belongs in a new
//! `server::nullifier` module plus receiver-local `server::ledger` storage.
//! The routing hook is `ConfigurableRouter::route_verified`, before file/directory
//! handlers run and before execute-success side effects are recorded.

use server::ledger::{Ledger, ScopedNullifierUseOutcome};
use server::nullifier::{
    canonical_resource_id, NullifierCommitment, NullifierDomainV1, NullifierDomainV1Inputs,
    NullifierOutcome, NullifierReason, ResourceKind, ScopedNullifierEvidence,
};
use server::verifier::{VerifiedCallContext, VerifiedSubject};

fn context() -> VerifiedCallContext {
    VerifiedCallContext {
        schema_version: server::verifier::VERIFIED_CALL_CONTEXT_SCHEMA_VERSION,
        context_id: "ctx-i04".to_string(),
        packet_hash: [9u8; 32],
        session_id: [1u8; 16],
        nonce: [2u8; 12],
        opcode: 0x50,
        operation: "demo.file.write".to_string(),
        resource: Some("file:///tmp/secS/../secS/allowed.txt".to_string()),
        subject: VerifiedSubject {
            subject_id: "prototype.local-dev.subject".to_string(),
            key_id: "fixture-key".to_string(),
        },
        audience: "secS://receiver-a".to_string(),
        evidence_summary: vec![
            "scoped_use_required".to_string(),
            "nullifier_epoch:epoch-1".to_string(),
            "nullifier_issuer:issuer-a".to_string(),
            "nullifier_root:root-a".to_string(),
            "subject_commitment:subject-commitment-a".to_string(),
            "nullifier_commitment:commitment-a".to_string(),
        ],
        capability_result: "ok".to_string(),
        credential_result: "ok".to_string(),
        issued_at: 10,
        expires_at: 310,
        descriptor_fingerprint: "descriptor:fixture".to_string(),
        replay_scope: "session_opcode_nonce".to_string(),
        handler_id: Some("demo/file-write".to_string()),
    }
}

fn domain_from(ctx: &VerifiedCallContext, kind: ResourceKind) -> NullifierDomainV1 {
    NullifierDomainV1::from_verified_context(
        ctx,
        NullifierDomainV1Inputs {
            resource_kind: kind,
            epoch_or_window: "epoch-1".to_string(),
            issuer_or_authority_source_id: "issuer-a".to_string(),
            root_or_checkpoint_id: "root-a".to_string(),
            subject_commitment: "subject-commitment-a".to_string(),
            allowance_id: None,
        },
    )
    .unwrap()
}

#[test]
fn nullifier_domain_changes_when_audience_changes() {
    let base = domain_from(&context(), ResourceKind::File);
    let mut changed = context();
    changed.audience = "secS://receiver-b".to_string();
    assert_ne!(base.fingerprint(), domain_from(&changed, ResourceKind::File).fingerprint());
}

#[test]
fn nullifier_domain_changes_when_operation_changes() {
    let base = domain_from(&context(), ResourceKind::File);
    let mut changed = context();
    changed.operation = "demo.directory.list".to_string();
    assert_ne!(base.fingerprint(), domain_from(&changed, ResourceKind::File).fingerprint());
}

#[test]
fn nullifier_domain_changes_when_resource_changes() {
    let base = domain_from(&context(), ResourceKind::File);
    let mut changed = context();
    changed.resource = Some("file:///tmp/secS/other.txt".to_string());
    assert_ne!(base.fingerprint(), domain_from(&changed, ResourceKind::File).fingerprint());
}

#[test]
fn nullifier_domain_changes_when_epoch_window_changes() {
    let ctx = context();
    let base = domain_from(&ctx, ResourceKind::File);
    let changed = NullifierDomainV1::from_verified_context(
        &ctx,
        NullifierDomainV1Inputs {
            resource_kind: ResourceKind::File,
            epoch_or_window: "epoch-2".to_string(),
            issuer_or_authority_source_id: "issuer-a".to_string(),
            root_or_checkpoint_id: "root-a".to_string(),
            subject_commitment: "subject-commitment-a".to_string(),
            allowance_id: None,
        },
    )
    .unwrap();
    assert_ne!(base.fingerprint(), changed.fingerprint());
}

#[test]
fn nullifier_domain_changes_when_issuer_or_root_changes() {
    let ctx = context();
    let base = domain_from(&ctx, ResourceKind::File);
    let issuer = NullifierDomainV1::from_verified_context(
        &ctx,
        NullifierDomainV1Inputs {
            resource_kind: ResourceKind::File,
            epoch_or_window: "epoch-1".to_string(),
            issuer_or_authority_source_id: "issuer-b".to_string(),
            root_or_checkpoint_id: "root-a".to_string(),
            subject_commitment: "subject-commitment-a".to_string(),
            allowance_id: None,
        },
    )
    .unwrap();
    let root = NullifierDomainV1::from_verified_context(
        &ctx,
        NullifierDomainV1Inputs {
            resource_kind: ResourceKind::File,
            epoch_or_window: "epoch-1".to_string(),
            issuer_or_authority_source_id: "issuer-a".to_string(),
            root_or_checkpoint_id: "root-b".to_string(),
            subject_commitment: "subject-commitment-a".to_string(),
            allowance_id: None,
        },
    )
    .unwrap();
    assert_ne!(base.fingerprint(), issuer.fingerprint());
    assert_ne!(base.fingerprint(), root.fingerprint());
}

#[test]
fn missing_required_tuple_field_rejects_without_global_fallback() {
    let mut ctx = context();
    ctx.resource = None;
    let err = NullifierDomainV1::from_verified_context(
        &ctx,
        NullifierDomainV1Inputs {
            resource_kind: ResourceKind::File,
            epoch_or_window: "epoch-1".to_string(),
            issuer_or_authority_source_id: "issuer-a".to_string(),
            root_or_checkpoint_id: "root-a".to_string(),
            subject_commitment: "subject-commitment-a".to_string(),
            allowance_id: None,
        },
    )
    .unwrap_err();
    assert_eq!(err, NullifierReason::MissingScopedNullifier);
}

#[test]
fn canonical_resource_id_normalizes_file_paths() {
    assert_eq!(
        canonical_resource_id("file:///tmp/secS/../secS/allowed.txt").unwrap(),
        "file:///tmp/secS/allowed.txt"
    );
}

#[test]
fn global_or_domainless_nullifier_rejected_for_scoped_operation() {
    let mut ctx = context();
    ctx.evidence_summary.retain(|field| !field.starts_with("nullifier_commitment:"));
    let evidence = ScopedNullifierEvidence::from_context(&ctx).unwrap_err();
    assert_eq!(evidence, NullifierReason::MissingScopedNullifier);
}

#[test]
fn allowed_distinct_domain_uses_non_equal_commitments() {
    let ctx = context();
    let file = domain_from(&ctx, ResourceKind::File);
    let mut dir_ctx = ctx.clone();
    dir_ctx.operation = "demo.directory.list".to_string();
    dir_ctx.resource = Some("file:///tmp/secS".to_string());
    let directory = domain_from(&dir_ctx, ResourceKind::Directory);
    let file_commitment = NullifierCommitment::new("commitment-file").unwrap();
    let directory_commitment = NullifierCommitment::new("commitment-directory").unwrap();
    assert_ne!(file.fingerprint(), directory.fingerprint());
    assert_ne!(file_commitment.fingerprint(), directory_commitment.fingerprint());
}

#[test]
fn mismatch_reason_labels_are_stable() {
    assert_eq!(NullifierReason::DuplicateNullifier.as_str(), "duplicate_nullifier");
    assert_eq!(NullifierReason::DomainMismatch.as_str(), "nullifier_domain_mismatch");
    assert_eq!(NullifierReason::MissingScopedNullifier.as_str(), "missing_scoped_nullifier");
    assert_eq!(NullifierReason::UnsupportedScope.as_str(), "unsupported_nullifier_scope");
    assert_eq!(NullifierOutcome::ScopedUseRecorded.as_str(), "scoped_use_recorded");
}

async fn memory_ledger() -> Ledger {
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    ledger
}

#[tokio::test]
async fn duplicate_nullifier_same_domain_rejected_before_handler() {
    let ctx = context();
    let domain = domain_from(&ctx, ResourceKind::File);
    let commitment = NullifierCommitment::new("commitment-a").unwrap();
    let ledger = memory_ledger().await;
    assert_eq!(
        ledger
            .record_scoped_nullifier_use(&domain, &commitment, &ctx, 10)
            .await
            .unwrap(),
        ScopedNullifierUseOutcome::Recorded
    );
    assert_eq!(
        ledger
            .record_scoped_nullifier_use(&domain, &commitment, &ctx, 11)
            .await
            .unwrap(),
        ScopedNullifierUseOutcome::Duplicate
    );
    assert_eq!(ledger.scoped_nullifier_use_count(&domain, &commitment).await.unwrap(), 1);
    assert_eq!(Ledger::duplicate_nullifier_reason(), "duplicate_nullifier");
}

#[tokio::test]
async fn concurrent_duplicate_insert_accepts_once() {
    let ctx = context();
    let domain = domain_from(&ctx, ResourceKind::File);
    let commitment = NullifierCommitment::new("commitment-concurrent").unwrap();
    let ledger = memory_ledger().await;
    let (left, right) = tokio::join!(
        ledger.record_scoped_nullifier_use(&domain, &commitment, &ctx, 10),
        ledger.record_scoped_nullifier_use(&domain, &commitment, &ctx, 10)
    );
    let outcomes = vec![left.unwrap(), right.unwrap()];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ScopedNullifierUseOutcome::Recorded)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == ScopedNullifierUseOutcome::Duplicate)
            .count(),
        1
    );
}

#[tokio::test]
async fn durable_scoped_use_survives_ledger_reopen() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("secs-nullifier-{nanos}.sqlite"));
    std::fs::File::create(&path).expect("create durable sqlite file");
    let url = format!("sqlite://{}", path.display());
    let ctx = context();
    let domain = domain_from(&ctx, ResourceKind::File);
    let commitment = NullifierCommitment::new("commitment-durable").unwrap();

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    assert_eq!(
        ledger
            .record_scoped_nullifier_use(&domain, &commitment, &ctx, 10)
            .await
            .unwrap(),
        ScopedNullifierUseOutcome::Recorded
    );
    drop(ledger);

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .unwrap();
    let ledger = Ledger::new(pool);
    ledger.init_schema().await.unwrap();
    assert_eq!(
        ledger
            .record_scoped_nullifier_use(&domain, &commitment, &ctx, 11)
            .await
            .unwrap(),
        ScopedNullifierUseOutcome::Duplicate
    );
    let _ = std::fs::remove_file(path);
}
