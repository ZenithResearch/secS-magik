//! Explicit opt-in v2 file ceremony; no live service activation or caller-selected authority root.
use crate::credential_presentation::{
    canonical, strict_value, Caller, Credential, Disclosure, Presentation, MAX_ENVELOPE,
};
use crate::devgraph_issue_create_cli::{
    canonical_data_root, parse_idempotency_file, parse_public_key_registry,
    validate_owned_directory,
};
use crate::devgraph_work_authority::{digest, WorkPolicy};
use crate::devgraph_work_request::{strict_json, Result};
use crate::devgraph_work_v2::{
    issue_credential, issue_work_authority_v2, CredentialConfig, CredentialInput,
    WorkAuthorityInputV2,
};
use crate::identity::{
    load_devgraph_authority_identity_v1, NodeVerifierIdentity, PublicVerifierKeyRegistry,
};
use crate::ledger::Ledger;
use crate::work_private_files as private;
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::Deserialize;
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "secs-devgraph-work-v2",
    about = "Explicit credential-bound Work/Arena approval; never executes mutations"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    IssueCredential {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long)]
        idempotency_key_file: PathBuf,
        #[arg(long)]
        presentation_request_output: PathBuf,
    },
    Authorize {
        #[arg(long)]
        request_file: PathBuf,
        #[arg(long)]
        idempotency_key_file: PathBuf,
        #[arg(long)]
        signed_projection_output: PathBuf,
    },
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreflightInput {
    schema: String,
    schema_version: u64,
    request: Value,
    holder_public_key: String,
    caller: Caller,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizationInput {
    schema: String,
    schema_version: u64,
    request: Value,
    credential: Credential,
    disclosure: Disclosure,
    presentation: Presentation,
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
struct Authority {
    policy: WorkPolicy,
    registry: PublicVerifierKeyRegistry,
    identity: NodeVerifierIdentity,
    config: CredentialConfig,
    directory: PathBuf,
}
impl Authority {
    fn load(root: &Path) -> Result<Self> {
        let directory = root.join("authority/devgraph.work.v1");
        for path in [
            root.to_path_buf(),
            root.join("authority"),
            directory.clone(),
        ] {
            validate_owned_directory(&path, true).map_err(|_| "unsafe_work_authority")?;
        }
        let read = |name: &str, max: u64| {
            private::read(&directory.join(name), max).map_err(|_| "unsafe_work_authority")
        };
        let manifest: Manifest =
            serde_json::from_value(strict_json(&read("producer-manifest.json", 65536)?, 65536)?)
                .map_err(|_| "invalid_work_manifest")?;
        if manifest.schema != "secs-devgraph-work-producer-manifest.v1"
            || manifest.schema_version != 1
            || manifest.replay_schema != "secs-devgraph-work-replay.v1"
            || manifest.audience != "devgraph://receiver-local"
        {
            return Err("invalid_work_manifest");
        }
        let policy = WorkPolicy::parse(&read("receiver-policy.json", 262144)?)?;
        let registry_raw = read("secs-public-key-registry.json", 262144)?;
        strict_json(&registry_raw, 262144)?;
        if policy.audience != manifest.audience
            || policy.digest()? != manifest.receiver_policy_digest_sha256
            || digest(b"", &registry_raw) != manifest.secs_public_key_registry_sha256
        {
            return Err("work_manifest_binding_mismatch");
        }
        let registry =
            parse_public_key_registry(&registry_raw).map_err(|_| "invalid_secs_registry")?;
        let key = Zeroizing::new(read("verifier.key", 256)?);
        let identity = load_devgraph_authority_identity_v1(&key, &manifest.secs_verifier_key_id)
            .map_err(|_| "invalid_secs_identity")?;
        drop(key);
        // Separate opt-in config is not silently installed by v1 provisioning or renewal.
        let config = CredentialConfig::parse(
            &private::read(
                &root.join("authority/credential-presentation-v2.json"),
                65536,
            )
            .map_err(|_| "credential_v2_not_configured")?,
        )?;
        Ok(Self {
            policy,
            registry,
            identity,
            config,
            directory,
        })
    }
}
pub async fn run(cli: Cli) -> Result<()> {
    let root = canonical_data_root().map_err(|_| "unsafe_data_root")?;
    run_at(cli, &root, crate::clock::failclosed_unix_seconds).await
}
async fn run_at(cli: Cli, root: &Path, clock: impl Fn() -> u64) -> Result<()> {
    let _lock = crate::devgraph_work_admin::authority_lock(root, false)?;
    let authority = Authority::load(root)?;
    let (input_path, key_path, output_path) = match &cli.command {
        Command::IssueCredential {
            request_file,
            idempotency_key_file,
            presentation_request_output,
        } => (
            request_file,
            idempotency_key_file,
            presentation_request_output,
        ),
        Command::Authorize {
            request_file,
            idempotency_key_file,
            signed_projection_output,
        } => (request_file, idempotency_key_file, signed_projection_output),
    };
    if output_path.starts_with(root) {
        return Err("unsafe_output");
    }
    let output = private::Output::prepare(output_path).map_err(|_| "unsafe_output")?;
    let raw = private::read(input_path, MAX_ENVELOPE as u64).map_err(|_| "unsafe_input")?;
    let value = strict_value(&raw)?;
    let key_raw = private::read(key_path, 130).map_err(|_| "unsafe_idempotency_file")?;
    let key = parse_idempotency_file(&key_raw).map_err(|_| "invalid_idempotency_file")?;
    let (bytes, expires) = match cli.command {
        Command::IssueCredential { .. } => {
            let input: PreflightInput =
                serde_json::from_value(value).map_err(|_| "invalid_credential_input")?;
            if input.schema != "secs-devgraph-credential-input.v2" || input.schema_version != 2 {
                return Err("invalid_credential_input");
            }
            let mut nonce = [0; 16];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let result = issue_credential(
                &authority.identity,
                &authority.registry,
                &authority.policy,
                &authority.config,
                CredentialInput {
                    request_json: &canonical(&input.request)?,
                    idempotency_key: key,
                    holder_public_key: &input.holder_public_key,
                    caller: &input.caller,
                    nonce,
                    now: clock(),
                },
            )?;
            (canonical(&result)?, result.credential.claims.expires_at)
        }
        Command::Authorize { .. } => {
            let input: AuthorizationInput =
                serde_json::from_value(value).map_err(|_| "invalid_work_input")?;
            if input.schema != "secs-devgraph-work-producer-input.v2" || input.schema_version != 2 {
                return Err("invalid_work_input");
            }
            let path = authority.directory.join("replay.sqlite3");
            let guard =
                private::open(&path, 256 * 1024 * 1024).map_err(|_| "unsafe_replay_database")?;
            let before = guard.metadata().map_err(|_| "unsafe_replay_database")?;
            let pool = SqlitePoolOptions::new()
                .max_connections(1)
                .connect_with(
                    SqliteConnectOptions::new()
                        .filename(&path)
                        .create_if_missing(false),
                )
                .await
                .map_err(|_| "replay_storage_failed")?;
            let after = fs::symlink_metadata(&path).map_err(|_| "unsafe_replay_database")?;
            if before.dev() != after.dev() || before.ino() != after.ino() {
                pool.close().await;
                return Err("unsafe_replay_database");
            }
            let ledger = Ledger::new(pool);
            let result = issue_work_authority_v2(
                &ledger,
                &authority.identity,
                &authority.registry,
                &authority.policy,
                &authority.config,
                WorkAuthorityInputV2 {
                    request_json: &canonical(&input.request)?,
                    credential_json: &canonical(&input.credential)?,
                    disclosure_json: &canonical(&input.disclosure)?,
                    presentation_json: &canonical(&input.presentation)?,
                    idempotency_key: key,
                    now: clock(),
                },
            )
            .await;
            ledger.pool().close().await;
            let result = result?;
            (result.canonical()?, result.expires_at)
        }
    };
    if clock() >= expires {
        return Err("work_authority_expired_before_output");
    }
    if bytes.len() > MAX_ENVELOPE {
        return Err("output_too_large");
    }
    output.write(&bytes).map_err(|_| "output_failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential_presentation::{hex, PresentationRequest};
    use crate::devgraph_authority::{actor_id_for_public_key, encode_base64url};
    use crate::devgraph_work_authority::WorkRule;
    use crate::devgraph_work_request::WorkRequest;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    fn write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    #[tokio::test]
    async fn private_cli_preflight_approval_retry_and_fail_closed() {
        const NOW: u64 = 1_800_000_000;
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        dir(&root);
        let data = root.join("secS");
        let bundle = data.join("authority/devgraph.work.v1");
        for p in [&data, &data.join("authority"), &bundle] {
            dir(p);
        }
        let vectors: Vec<Value> = serde_json::from_slice(include_bytes!(
            "../tests/fixtures/named-work-v1/requests.json"
        ))
        .unwrap();
        let request = WorkRequest::parse(vectors[0]["raw"].as_str().unwrap().as_bytes()).unwrap();
        let holder = SigningKey::from_bytes(&[37; 32]);
        let issuer = SigningKey::from_bytes(&[43; 32]);
        let policy = WorkPolicy {
            audience: "devgraph://receiver-local".into(),
            policy_id: "v2-cli-fixture".into(),
            policy_version: 1,
            schema: "secs-devgraph-work-policy.v1".into(),
            schema_version: 1,
            rules: request
                .resources
                .iter()
                .map(|r| WorkRule {
                    actor_id: actor_id_for_public_key(holder.verifying_key().as_bytes()),
                    effect: "allow".into(),
                    not_before: NOW - 10,
                    not_after: NOW + 600,
                    operation: request.operation.clone(),
                    resource: r.clone(),
                    resource_match: "exact".into(),
                    status: "active".into(),
                })
                .collect(),
        };
        let registry = json!({"schema":"secs-public-verifier-key-registry.v1","schema_version":1,"keys":[{"algorithm":"ed25519","key_id":"v2-cli-secs","public_key_base64url":encode_base64url(issuer.verifying_key().as_bytes()),"production_authority":true,"status":"active"}]});
        let registry_raw = canonical(&registry).unwrap();
        write(
            &bundle.join("receiver-policy.json"),
            &canonical(&policy).unwrap(),
        );
        write(&bundle.join("secs-public-key-registry.json"), &registry_raw);
        write(&bundle.join("verifier.key"), "2b".repeat(32).as_bytes());
        write(&bundle.join("replay.sqlite3"), b"");
        write(&bundle.join("producer-manifest.json"),&canonical(&json!({"schema":"secs-devgraph-work-producer-manifest.v1","schema_version":1,"audience":policy.audience,"receiver_policy_digest_sha256":policy.digest().unwrap(),"replay_schema":"secs-devgraph-work-replay.v1","secs_public_key_registry_sha256":digest(b"",&registry_raw),"secs_verifier_key_id":"v2-cli-secs"})).unwrap());
        let input = root.join("input.json");
        let key = root.join("key.txt");
        let output = root.join("wallet-request.json");
        let caller = Caller {
            kind: "terminal".into(),
            id: "cli-fixture".into(),
        };
        write(&input,&canonical(&json!({"schema":"secs-devgraph-credential-input.v2","schema_version":2,"request":request.value,"holder_public_key":hex(holder.verifying_key().as_bytes()),"caller":caller})).unwrap());
        write(&key, b"named-work-native-test-0001\n");
        let preflight = || Cli {
            command: Command::IssueCredential {
                request_file: input.clone(),
                idempotency_key_file: key.clone(),
                presentation_request_output: output.clone(),
            },
        };
        assert_eq!(
            run_at(preflight(), &data, || NOW).await.unwrap_err(),
            "credential_v2_not_configured"
        );
        let config = data.join("authority/credential-presentation-v2.json");
        write(&config,&canonical(&json!({"schema":"secs-devgraph-credential-config.v2","schema_version":2,"issuer":"secs://devgraph-work","callers":[caller]})).unwrap());
        run_at(preflight(), &data, || NOW).await.unwrap();
        assert_eq!(
            fs::metadata(bundle.join("replay.sqlite3")).unwrap().len(),
            0,
            "preflight must not open or consume replay"
        );
        assert!(
            run_at(preflight(), &data, || NOW).await.is_err(),
            "create-only output"
        );
        let attached: PresentationRequest =
            serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        let c = &attached.credential.claims;
        let mut presentation = Presentation {
            schema: "castalia.credential-presentation.v2".into(),
            holder_public_key: c.holder_public_key.clone(),
            issuer: c.issuer.clone(),
            key_id: c.key_id.clone(),
            audience: c.audience.clone(),
            caller: c.caller.clone(),
            request_digest_sha256: c.request_digest_sha256.clone(),
            credential_digest_sha256: attached.credential.digest().unwrap(),
            disclosure_digest_sha256: c.disclosure_digest_sha256.clone(),
            nonce: hex(&[9; 16]),
            issued_at: NOW + 1,
            expires_at: NOW + 61,
            signature: String::new(),
        };
        presentation.signature = hex(&holder.sign(&presentation.preimage().unwrap()).to_bytes());
        let approved = root.join("approved.json");
        write(&approved,&canonical(&json!({"schema":"secs-devgraph-work-producer-input.v2","schema_version":2,"request":request.value,"credential":attached.credential,"disclosure":attached.disclosure,"presentation":presentation})).unwrap());
        let mut outputs = Vec::new();
        for i in 0..2 {
            let path = root.join(format!("projection-{i}.json"));
            run_at(
                Cli {
                    command: Command::Authorize {
                        request_file: approved.clone(),
                        idempotency_key_file: key.clone(),
                        signed_projection_output: path.clone(),
                    },
                },
                &data,
                || NOW + 1,
            )
            .await
            .unwrap();
            outputs.push(fs::read(path).unwrap());
        }
        assert_eq!(outputs[0], outputs[1]);
        let link = root.join("linked.json");
        std::os::unix::fs::symlink(&approved, &link).unwrap();
        assert!(run_at(
            Cli {
                command: Command::Authorize {
                    request_file: link,
                    idempotency_key_file: key,
                    signed_projection_output: root.join("must-not-exist.json")
                }
            },
            &data,
            || NOW + 1
        )
        .await
        .is_err());
        assert!(!root.join("must-not-exist.json").exists());
    }
}
