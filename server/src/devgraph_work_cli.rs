//! Fixed owner-local adapter for the separate named Work authority contract.
use crate::devgraph_issue_create_cli::{
    canonical_data_root, parse_idempotency_file, parse_public_key_registry,
    validate_owned_directory,
};
use crate::devgraph_work_authority::{
    digest, issue_work_authority, WorkAuthorityInput, WorkPolicy,
};
use crate::devgraph_work_request::{strict_json, Result, WorkRequest};
use crate::identity::load_devgraph_authority_identity_v1;
use crate::ledger::Ledger;
use crate::work_private_files as private;
use clap::Parser;
use serde::Deserialize;
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "secs-devgraph-work-v1",
    about = "Authorize a closed named Work v1 request"
)]
pub struct WorkCli {
    #[arg(long)]
    pub request_file: PathBuf,
    #[arg(long)]
    pub idempotency_key_file: PathBuf,
    #[arg(long)]
    pub signed_projection_output: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    request: Value,
    wallet_presentation: Value,
    schema: String,
    schema_version: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    audience: String,
    receiver_policy_digest_sha256: String,
    replay_schema: String,
    schema: String,
    schema_version: u64,
    secs_public_key_registry_sha256: String,
    secs_verifier_key_id: String,
}

pub async fn run(cli: WorkCli) -> Result<()> {
    let data_root = canonical_data_root().map_err(|_| "unsafe_data_root")?;
    run_at(cli, &data_root, crate::clock::failclosed_unix_seconds).await
}

async fn run_at(cli: WorkCli, data_root: &Path, clock: impl Fn() -> u64) -> Result<()> {
    let _authority_lock = crate::devgraph_work_admin::authority_lock(data_root, false)?;
    let authority = data_root.join("authority/devgraph.work.v1");
    for directory in [
        data_root.to_path_buf(),
        data_root.join("authority"),
        authority.clone(),
    ] {
        validate_owned_directory(&directory, true).map_err(|_| "unsafe_work_authority")?;
    }
    if cli.signed_projection_output.starts_with(data_root) {
        return Err("unsafe_output");
    }
    let output =
        private::Output::prepare(&cli.signed_projection_output).map_err(|_| "unsafe_output")?;
    let input: Input = serde_json::from_value(strict_json(
        &private::read(&cli.request_file, 160 * 1024).map_err(|_| "unsafe_input")?,
        160 * 1024,
    )?)
    .map_err(|_| "invalid_work_input")?;
    if input.schema != "secs-devgraph-work-producer-input.v1" || input.schema_version != 1 {
        return Err("invalid_work_input");
    }
    let request =
        WorkRequest::parse(&serde_json::to_vec(&input.request).map_err(|_| "invalid_work_input")?)?;
    let presentation =
        serde_json::to_vec(&input.wallet_presentation).map_err(|_| "invalid_work_input")?;
    let key_bytes =
        private::read(&cli.idempotency_key_file, 130).map_err(|_| "unsafe_idempotency_file")?;
    let idempotency = parse_idempotency_file(&key_bytes).map_err(|_| "invalid_idempotency_file")?;
    let manifest: Manifest = serde_json::from_value(strict_json(
        &private::read(&authority.join("producer-manifest.json"), 65_536)
            .map_err(|_| "unsafe_work_authority")?,
        65_536,
    )?)
    .map_err(|_| "invalid_work_manifest")?;
    if manifest.schema != "secs-devgraph-work-producer-manifest.v1"
        || manifest.schema_version != 1
        || manifest.replay_schema != "secs-devgraph-work-replay.v1"
        || manifest.audience != "devgraph://receiver-local"
    {
        return Err("invalid_work_manifest");
    }
    let policy = WorkPolicy::parse(
        &private::read(&authority.join("receiver-policy.json"), 262_144)
            .map_err(|_| "unsafe_work_authority")?,
    )?;
    let registry_bytes = private::read(&authority.join("secs-public-key-registry.json"), 262_144)
        .map_err(|_| "unsafe_work_authority")?;
    strict_json(&registry_bytes, 262_144)?;
    if policy.audience != manifest.audience
        || policy.digest()? != manifest.receiver_policy_digest_sha256
        || digest(b"", &registry_bytes) != manifest.secs_public_key_registry_sha256
    {
        return Err("work_manifest_binding_mismatch");
    }
    let registry =
        parse_public_key_registry(&registry_bytes).map_err(|_| "invalid_secs_registry")?;
    let raw_seed = Zeroizing::new(
        private::read(&authority.join("verifier.key"), 256).map_err(|_| "unsafe_verifier_key")?,
    );
    let identity = load_devgraph_authority_identity_v1(&raw_seed, &manifest.secs_verifier_key_id)
        .map_err(|_| "invalid_secs_identity")?;
    drop(raw_seed);
    let replay_path = authority.join("replay.sqlite3");
    let replay_guard =
        private::open(&replay_path, 256 * 1024 * 1024).map_err(|_| "unsafe_replay_database")?;
    let before = replay_guard
        .metadata()
        .map_err(|_| "unsafe_replay_database")?;
    let options = SqliteConnectOptions::new()
        .filename(&replay_path)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| "replay_storage_failed")?;
    let after = fs::symlink_metadata(&replay_path).map_err(|_| "unsafe_replay_database")?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("unsafe_replay_database");
    }
    let ledger = Ledger::new(pool);
    let initialized = ledger.init_schema().await;
    if initialized.is_err() {
        ledger.pool().close().await;
        return Err("replay_storage_failed");
    }
    let projection = issue_work_authority(
        &ledger,
        &identity,
        &registry,
        &policy,
        WorkAuthorityInput {
            request_json: &request.canonical,
            wallet_presentation_json: &presentation,
            idempotency_key: idempotency,
            now: clock(),
        },
    )
    .await;
    ledger.pool().close().await;
    let projection = projection?;
    if clock() >= projection.expires_at {
        return Err("work_authority_expired_before_output");
    }
    let bytes = projection.canonical()?;
    if bytes.len() > 16_384 {
        return Err("projection_too_large");
    }
    output.write(&bytes).map_err(|_| "output_failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devgraph_authority::encode_base64url;
    use crate::devgraph_work_authority::{WorkRule, POLICY_SCHEMA};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;

    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    async fn fixture_roundtrip(requests: Vec<Value>, wallet_binary: Option<PathBuf>) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        directory(&root);
        let data = root.join("secS");
        let authority = data.join("authority/devgraph.work.v1");
        for dir in [&data, &data.join("authority"), &authority] {
            directory(dir);
        }
        let mut all = Vec::new();
        let vectors: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/named-work-v1/signed-vectors.json"
        ))
        .unwrap();
        let key = "named-work-native-test-0001";
        let key_path = root.join("idempotency.txt");
        write(&key_path, format!("{key}\n").as_bytes());
        let wallet_key = root.join("synthetic-wallet.key");
        write(&wallet_key, &[37; 32]);
        let public = SigningKey::from_bytes(&[37; 32]).verifying_key();
        let pin = public
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        for (index, request_json) in requests.into_iter().enumerate() {
            let selected_key = if wallet_binary.is_some() {
                format!("named-work-native-workflow-{index:04}")
            } else {
                key.into()
            };
            write(&key_path, format!("{selected_key}\n").as_bytes());
            let request = WorkRequest::parse(&serde_json::to_vec(&request_json).unwrap()).unwrap();
            let input_path = root.join(format!("input-{index}.json"));
            if let Some(binary) = &wallet_binary {
                let request_path = root.join("request.json");
                write(&request_path, &request.canonical);
                let output = std::process::Command::new(binary)
                    .env_clear()
                    .env("DEVGRAPH_SIGNING_KEY_FILE", &wallet_key)
                    .env("DEVGRAPH_SIGNING_PUBLIC_KEY", &pin)
                    .arg("--request-file")
                    .arg(&request_path)
                    .arg("--idempotency-key-file")
                    .arg(&key_path)
                    .arg("--producer-input-output")
                    .arg(&input_path)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            } else {
                let input = json!({"schema":"secs-devgraph-work-producer-input.v1","schema_version":1,
                    "request":request_json,"wallet_presentation":vectors[index]["wallet_presentation"]});
                write(&input_path, &serde_json::to_vec(&input).unwrap());
            }
            let input: Value = serde_json::from_slice(&fs::read(&input_path).unwrap()).unwrap();
            let now = input["wallet_presentation"]["issued_at"].as_u64().unwrap();
            let policy = WorkPolicy {
                schema: POLICY_SCHEMA.into(),
                schema_version: 1,
                audience: "devgraph://receiver-local".into(),
                policy_id: format!("named-file-test-{index}"),
                policy_version: 1,
                rules: request
                    .resources
                    .iter()
                    .map(|resource| WorkRule {
                        actor_id: crate::devgraph_authority::actor_id_for_public_key(
                            public.as_bytes(),
                        ),
                        operation: request.operation.clone(),
                        resource: resource.clone(),
                        resource_match: "exact".into(),
                        effect: "allow".into(),
                        status: "active".into(),
                        not_before: now - 1,
                        not_after: now + 600,
                    })
                    .collect(),
            };
            let secs_public = SigningKey::from_bytes(&[43; 32]).verifying_key();
            let registry = json!({"schema":"secs-public-verifier-key-registry.v1","schema_version":1,"keys":[{
                "algorithm":"ed25519","key_id":"named-test-secs","public_key_base64url":encode_base64url(secs_public.as_bytes()),
                "production_authority":true,"status":"active"}]});
            let registry_bytes = serde_json::to_vec(&registry).unwrap();
            write(
                &authority.join("receiver-policy.json"),
                &serde_json::to_vec(&policy).unwrap(),
            );
            write(
                &authority.join("secs-public-key-registry.json"),
                &registry_bytes,
            );
            write(&authority.join("verifier.key"), "2b".repeat(32).as_bytes());
            if index == 0 {
                write(&authority.join("replay.sqlite3"), b"");
            }
            let manifest = json!({"schema":"secs-devgraph-work-producer-manifest.v1","schema_version":1,
                "audience":"devgraph://receiver-local","receiver_policy_digest_sha256":policy.digest().unwrap(),
                "replay_schema":"secs-devgraph-work-replay.v1","secs_public_key_registry_sha256":digest(b"",&registry_bytes),
                "secs_verifier_key_id":"named-test-secs"});
            write(
                &authority.join("producer-manifest.json"),
                &serde_json::to_vec(&manifest).unwrap(),
            );
            let output_path = root.join(format!("projection-{index}.json"));
            run_at(
                WorkCli {
                    request_file: input_path.clone(),
                    idempotency_key_file: key_path.clone(),
                    signed_projection_output: output_path.clone(),
                },
                &data,
                || now,
            )
            .await
            .unwrap();
            let projection: Value =
                serde_json::from_slice(&fs::read(&output_path).unwrap()).unwrap();
            // No overwrite, including aliases to the caller request.
            let before = fs::read(&input_path).unwrap();
            assert!(run_at(
                WorkCli {
                    request_file: input_path.clone(),
                    idempotency_key_file: key_path.clone(),
                    signed_projection_output: input_path.clone()
                },
                &data,
                || now
            )
            .await
            .is_err());
            assert_eq!(before, fs::read(&input_path).unwrap());
            all.push(json!({"request":request_json,"projection":projection,"public_key":encode_base64url(secs_public.as_bytes()),
                "policy":policy,"key":selected_key,"now":now,"native_wallet_binary":wallet_binary.is_some()}));
        }
        if let Ok(path) = std::env::var("DEVGRAPH_TEST_NATIVE_WORK_OUTPUT") {
            fs::write(path, serde_json::to_vec_pretty(&all).unwrap()).unwrap();
        }
    }

    #[tokio::test]
    async fn native_file_contracts_and_aliases() {
        let vectors: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/named-work-v1/signed-vectors.json"
        ))
        .unwrap();
        fixture_roundtrip(vectors.iter().map(|v| v["request"].clone()).collect(), None).await;
    }

    #[tokio::test]
    #[ignore = "requires explicitly selected built Wallet binary and isolated workflow fixtures"]
    async fn native_wallet_to_secs_workflow() {
        let binary = PathBuf::from(std::env::var("DEVGRAPH_TEST_WALLET_BINARY").unwrap());
        let path = std::env::var("DEVGRAPH_TEST_WORKFLOW").unwrap();
        let requests = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        fixture_roundtrip(requests, Some(binary)).await;
    }
}
