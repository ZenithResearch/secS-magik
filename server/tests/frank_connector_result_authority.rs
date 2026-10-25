//! Disposable Frank-journal -> native result authority controls. No provider call.
use serde::Serialize;
use serde_json::{json, Value};
use server::manifest::{OpcodeRange, OperationDescriptor, OperationName, ReplayScope, TargetKind};
use server::privacy::DisclosurePolicy;
use server::{FrankConnectorResultAuthority, FrankResultMode};
use sha2::{Digest, Sha256};
use sqlx::{sqlite::SqliteConnectOptions, Connection, SqliteConnection};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::Duration,
};

fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    fn emit(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|left, right| left.0.cmp(right.0));
                for (index, (key, value)) in entries.into_iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).unwrap());
                    out.push(b':');
                    emit(value, out);
                }
                out.push(b'}');
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        out.push(b',');
                    }
                    emit(value, out);
                }
                out.push(b']');
            }
            _ => out.extend(serde_json::to_vec(value).unwrap()),
        }
    }
    let mut bytes = Vec::new();
    emit(&serde_json::to_value(value).unwrap(), &mut bytes);
    bytes
}
fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn directory(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn descriptor() -> OperationDescriptor {
    OperationDescriptor {
        opcode: 232,
        name: OperationName::new("frank.result.attest.v1"),
        payload_schema: Some("frank.native-result-payload.v1".into()),
        output_profile: None,
        target_kind: TargetKind::ReceiverProductionHandler,
        required_credentials: vec!["frank.connector.result-party-assignment.v1".into()],
        required_capabilities: vec!["frank.result.attest.v1".into()],
        accepted_evidence: vec!["frank.connector.capture.v1".into()],
        required_authority_mode: None,
        replay_scope: ReplayScope::SessionOpcodeNonce,
        max_ttl_seconds: 60,
        handler_id: "fixture-connector-result-receiver".into(),
        dev_binding: false,
        range: OpcodeRange::OperatorDefined,
        disclosure_policy: DisclosurePolicy::deny_by_default("frank.result-receipt.v1", 1),
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
    outer: PathBuf,
    pin: [u8; 32],
    database: PathBuf,
    selector: Vec<u8>,
    payload: Vec<u8>,
}

impl Fixture {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in [
            "issuer",
            "assignment",
            "captures",
            "result-journal",
            "frank",
        ] {
            directory(&root.join(name));
        }
        for name in [
            "assignment/assignment.lock",
            "captures/capture.lock",
            "result-journal/journal.lock",
        ] {
            write(&root.join(name), b"");
        }
        let public =
            FrankConnectorResultAuthority::create_issuer_key(&root.join("issuer")).unwrap();
        let model_configuration = canonical(&json!({
            "max_iterations":4,
            "model":"openai-codex/gpt-5.6-sol",
            "routes":["local"],
            "toolsets":[]
        }));
        let configuration_hash = sha(&model_configuration);
        let artifact_hash = sha(b"fixture hermes 0.20.0 artifact");
        let normalization_hash = sha(b"frank hermes normalization v1");
        let source_hash = sha(b"fixture source manifest");
        let policy = canonical(&json!({
            "actor_id":"frank-hermes-pilot",
            "artifact_sha256":artifact_hash,
            "configuration_sha256":configuration_hash,
            "integration_id":"hermes-sophia-pilot",
            "kind":"hermes",
            "normalization_sha256":normalization_hash,
            "route":"local"
        }));
        let policy_hash = sha(&policy);
        let t = now();
        let assignment = canonical(&json!({
            "active":true,
            "actor_id":"frank-hermes-pilot",
            "assignment_id":"fixture-hermes-result-assignment",
            "configuration_sha256":configuration_hash,
            "generation":1,
            "integration_id":"hermes-sophia-pilot",
            "issuer_public_key_hex":public.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
            "key_id":"fixture-hermes-result-key",
            "normalizer_sha256":normalization_hash,
            "not_after":t+600,
            "not_before":t-1,
            "operations":["compute"],
            "producer_artifact_sha256":artifact_hash,
            "route":"local",
            "run_ids":["run-1"],
            "schema":"frank.connector.result-party-assignment.v1",
            "source_manifest_sha256":source_hash,
            "subject_id":"fixture-hermes-result-party"
        }));
        write(&root.join("assignment/assignment.json"), &assignment);
        let authority = root.join("authority.json");
        let authority_raw = canonical(&json!({
            "assignment_root":root.join("assignment"),
            "assignment_sha256":sha(&assignment),
            "capture_root":root.join("captures"),
            "descriptor":{
                "fingerprint":descriptor().authorization_fingerprint().strip_prefix("descriptor:sha256:").unwrap(),
                "handler_id":"fixture-connector-result-receiver",
                "opcode":232
            },
            "issuer_key_id":"fixture-hermes-result-key",
            "issuer_public_key_hex":public.iter().map(|byte|format!("{byte:02x}")).collect::<String>(),
            "issuer_root":root.join("issuer"),
            "issuer_subject_id":"fixture-hermes-result-party",
            "journal_root":root.join("result-journal"),
            "maximum_ttl":60,
            "schema":"frank.result-authority-configuration.v1"
        }));
        write(&authority, &authority_raw);

        let binding =
            json!({"attempt_id":"attempt-1","fence":1,"run_id":"run-1","step_id":"step-1"});
        let work = canonical(&json!({
            "actor_id":"frank-hermes-pilot",
            "binding":binding,
            "effect_id":"effect-1",
            "inputs":{"number":7},
            "integration_id":"hermes-sophia-pilot",
            "operation":"compute",
            "output_types":{"answer":{"kind":"integer"}},
            "route":"local",
            "schema":"frank.work.v1",
            "scope":"answer"
        }));
        let outputs = canonical(&json!({"answer":14}));
        let result = canonical(&json!({
            "actor_id":"frank-hermes-pilot",
            "binding":binding,
            "effect_id":"effect-1",
            "event_id":"hermes-event-1",
            "integration_id":"hermes-sophia-pilot",
            "outcome":"succeeded",
            "outputs":{"answer":14},
            "provider_reference":"effect-1",
            "route":"local",
            "schema":"frank.result.v1"
        }));
        let body_hash = sha(&result);
        let work_hash = sha(&work);
        let payload = canonical(&json!({
            "result":serde_json::from_slice::<Value>(&result).unwrap(),
            "schema":"frank.native-result-payload.v1",
            "work_sha256":work_hash
        }));
        let final_response = "{\"answer\":14}";
        let prompt_hash = sha(b"fixture exact prompt");
        let provenance = canonical(&json!({
            "final_response_sha256":sha(final_response.as_bytes()),
            "interruption":"returned-final-response",
            "kind":"hermes",
            "outputs_sha256":sha(&outputs),
            "prompt_sha256":prompt_hash,
            "session_id":"effect-1",
            "task_id":"effect-1"
        }));
        let original = canonical(&json!({"final_response":final_response}));
        let effect_key = "delivery-0123456789abcdef0123456789abcdef0123456789abcdef";
        let resource = "runs/run-1/steps/step-1/attempts/attempt-1/effects/effect-1";
        let selector = canonical(&json!({
            "body_sha256":body_hash,
            "effect_key":effect_key,
            "event_id":"hermes-event-1",
            "integration_id":"hermes-sophia-pilot",
            "original_sha256":sha(&original),
            "payload_sha256":sha(&payload),
            "policy_sha256":policy_hash,
            "provenance_sha256":sha(&provenance),
            "renewal_of":null,
            "resource":resource,
            "schema":"frank.connector-result-selector.v1",
            "work_sha256":work_hash
        }));
        let database = root.join("frank/frank.sqlite3");
        let options = SqliteConnectOptions::new()
            .filename(&database)
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(2));
        let mut db = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("PRAGMA application_id=1179799115")
            .execute(&mut db)
            .await
            .unwrap();
        for ddl in [
            "CREATE TABLE deliveries(effect_key TEXT PRIMARY KEY,work TEXT NOT NULL,digest TEXT NOT NULL,state TEXT NOT NULL,result TEXT)",
            "CREATE TABLE connector_dispatch(effect_key TEXT PRIMARY KEY,work_sha256 TEXT NOT NULL,policy TEXT NOT NULL,prompt_sha256 TEXT NOT NULL)",
            "CREATE TABLE connector_captures(effect_key TEXT PRIMARY KEY,work_sha256 TEXT NOT NULL,policy TEXT NOT NULL,body TEXT NOT NULL,body_sha256 TEXT NOT NULL,payload_sha256 TEXT NOT NULL,resource TEXT NOT NULL,provenance TEXT NOT NULL,provenance_sha256 TEXT NOT NULL,original TEXT NOT NULL,original_sha256 TEXT NOT NULL,integration_id TEXT NOT NULL,event_id TEXT NOT NULL,UNIQUE(integration_id,event_id))",
            "CREATE TABLE connector_result_exchange(id INTEGER PRIMARY KEY AUTOINCREMENT,effect_key TEXT NOT NULL,selector_sha256 TEXT NOT NULL,selector BLOB NOT NULL,mode TEXT NOT NULL,renewal_of TEXT,envelope BLOB,UNIQUE(effect_key,selector_sha256))",
        ] {
            sqlx::query(ddl).execute(&mut db).await.unwrap();
        }
        sqlx::query("INSERT INTO deliveries VALUES(?,?,?,'unknown',NULL)")
            .bind(effect_key)
            .bind(String::from_utf8(work.clone()).unwrap())
            .bind(&work_hash)
            .execute(&mut db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO connector_dispatch VALUES(?,?,?,?)")
            .bind(effect_key)
            .bind(&work_hash)
            .bind(String::from_utf8(policy.clone()).unwrap())
            .bind(&prompt_hash)
            .execute(&mut db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO connector_captures VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(effect_key)
            .bind(&work_hash)
            .bind(String::from_utf8(policy).unwrap())
            .bind(String::from_utf8(result).unwrap())
            .bind(&body_hash)
            .bind(sha(&payload))
            .bind(resource)
            .bind(String::from_utf8(provenance.clone()).unwrap())
            .bind(sha(&provenance))
            .bind(String::from_utf8(original.clone()).unwrap())
            .bind(sha(&original))
            .bind("hermes-sophia-pilot")
            .bind("hermes-event-1")
            .execute(&mut db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO connector_result_exchange(effect_key,selector_sha256,selector,mode,renewal_of,envelope) VALUES(?,?,?,'attest',NULL,NULL)")
            .bind(effect_key)
            .bind(sha(&selector))
            .bind(&selector)
            .execute(&mut db)
            .await
            .unwrap();
        db.close().await.unwrap();
        fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();

        let outer = root.join("connector-authority.json");
        let outer_raw = canonical(&json!({
            "authority_configuration":authority,
            "authority_configuration_sha256":sha(&authority_raw),
            "connector_policy_sha256":policy_hash,
            "journal":database,
            "schema":"frank.connector-result-producer.v1"
        }));
        write(&outer, &outer_raw);
        Self {
            _temp: temp,
            root,
            outer,
            pin: hash(&outer_raw),
            database,
            selector,
            payload,
        }
    }

    async fn authority(&self) -> FrankConnectorResultAuthority {
        FrankConnectorResultAuthority::open_pinned_owner_configuration(&self.outer, self.pin)
            .await
            .unwrap()
    }

    async fn save_envelope(&self, selector: &[u8], envelope: &[u8]) {
        let options = SqliteConnectOptions::new()
            .filename(&self.database)
            .create_if_missing(false);
        let mut db = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("UPDATE connector_result_exchange SET envelope=? WHERE selector_sha256=?")
            .bind(envelope)
            .bind(sha(selector))
            .execute(&mut db)
            .await
            .unwrap();
        db.close().await.unwrap();
    }

    async fn add_renewal(&self, envelope: &[u8]) -> Vec<u8> {
        let mut selector: Value = serde_json::from_slice(&self.selector).unwrap();
        selector["renewal_of"] = Value::String(sha(envelope));
        let selector = canonical(&selector);
        let effect_key = selector_value(&selector, "effect_key");
        let options = SqliteConnectOptions::new()
            .filename(&self.database)
            .create_if_missing(false);
        let mut db = SqliteConnection::connect_with(&options).await.unwrap();
        sqlx::query("INSERT INTO connector_result_exchange(effect_key,selector_sha256,selector,mode,renewal_of,envelope) VALUES(?,?,?,'renew',?,NULL)")
            .bind(effect_key)
            .bind(sha(&selector))
            .bind(&selector)
            .bind(sha(envelope))
            .execute(&mut db)
            .await
            .unwrap();
        db.close().await.unwrap();
        selector
    }
}

fn selector_value(raw: &[u8], field: &str) -> String {
    serde_json::from_slice::<Value>(raw).unwrap()[field]
        .as_str()
        .unwrap()
        .to_owned()
}

fn decode(
    raw: &[u8],
) -> (
    libsec_core::ZenithPacket,
    server::verifier::SignedVerifiedCallContext,
) {
    let value: Value = serde_json::from_slice(raw).unwrap();
    let unhex = |text: &str| {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    (
        bincode::deserialize(&unhex(value["packet_hex"].as_str().unwrap())).unwrap(),
        bincode::deserialize(&unhex(value["signed_context_hex"].as_str().unwrap())).unwrap(),
    )
}

#[tokio::test]
async fn connector_attest_resume_and_exact_native_context() {
    let fixture = Fixture::new().await;
    let authority = fixture.authority().await;
    assert!(authority
        .execute(FrankResultMode::Resume, &fixture.selector)
        .await
        .is_err());
    let first = authority
        .execute(FrankResultMode::Attest, &fixture.selector)
        .await
        .unwrap();
    let (packet, context) = decode(&first);
    assert_eq!(packet.encrypted_payload, fixture.payload);
    assert_eq!(context.context.operation, "frank.result.attest.v1");
    assert_eq!(
        context.context.resource.as_deref(),
        Some("runs/run-1/steps/step-1/attempts/attempt-1/effects/effect-1")
    );
    assert!(context
        .context
        .evidence_summary
        .iter()
        .any(|item| item == "connector-kind:hermes"));
    assert!(context
        .context
        .credential_result
        .ends_with("role:connector-result-party"));
    fixture.save_envelope(&fixture.selector, &first).await;
    assert_eq!(
        fixture
            .authority()
            .await
            .execute(FrankResultMode::Resume, &fixture.selector)
            .await
            .unwrap(),
        first
    );
}

#[tokio::test]
async fn connector_renewal_chains_from_the_persisted_envelope() {
    let fixture = Fixture::new().await;
    let first = fixture
        .authority()
        .await
        .execute(FrankResultMode::Attest, &fixture.selector)
        .await
        .unwrap();
    fixture.save_envelope(&fixture.selector, &first).await;
    let renewal = fixture.add_renewal(&first).await;
    let second = fixture
        .authority()
        .await
        .execute(FrankResultMode::Renew, &renewal)
        .await
        .unwrap();
    assert_ne!(first, second);
    fixture.save_envelope(&renewal, &second).await;
    assert_eq!(
        fixture
            .authority()
            .await
            .execute(FrankResultMode::Resume, &renewal)
            .await
            .unwrap(),
        second
    );
}

#[tokio::test]
async fn changed_capture_and_wrong_mode_deny_without_a_result() {
    let fixture = Fixture::new().await;
    let authority = fixture.authority().await;
    assert!(authority
        .execute(FrankResultMode::Renew, &fixture.selector)
        .await
        .is_err());
    let options = SqliteConnectOptions::new()
        .filename(&fixture.database)
        .create_if_missing(false);
    let mut db = SqliteConnection::connect_with(&options).await.unwrap();
    sqlx::query("UPDATE connector_captures SET original='{}' WHERE effect_key LIKE 'delivery-%'")
        .execute(&mut db)
        .await
        .unwrap();
    db.close().await.unwrap();
    assert!(fixture
        .authority()
        .await
        .execute(FrankResultMode::Attest, &fixture.selector)
        .await
        .is_err());
    assert!(!fixture.root.join("result-journal/results.sqlite3").exists());
}
