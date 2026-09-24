//! Owner-local named Work authority lifecycle. Actor keys never enter this module.
use crate::devgraph_authority::encode_base64url;
use crate::devgraph_issue_create_cli::{canonical_data_root, parse_public_key_registry};
use crate::devgraph_work_authority::{digest, WorkPolicy};
use crate::devgraph_work_request::{strict_json, Result};
use crate::identity::{derive_ed25519_key_id, load_devgraph_authority_identity_v1};
use crate::ledger::Ledger;
use crate::work_private_files as private;
use clap::{Parser, Subcommand};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{
    fs,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const BUNDLE: &str = "devgraph.work.v1";
pub const FILES: [&str; 5] = [
    "producer-manifest.json",
    "receiver-policy.json",
    "secs-public-key-registry.json",
    "verifier.key",
    "replay.sqlite3",
];
#[derive(Parser)]
pub struct AdminCli {
    #[command(subcommand)]
    pub command: Command,
}
#[derive(Subcommand)]
pub enum Command {
    Provision {
        #[arg(long)]
        policy_file: PathBuf,
        #[arg(long)]
        expected_policy_digest: Option<String>,
        #[arg(long)]
        rotate_verifier: bool,
    },
    Status,
    Snapshot {
        #[arg(long)]
        output_directory: PathBuf,
    },
    VerifySnapshot {
        #[arg(long)]
        input_directory: PathBuf,
    },
}
#[derive(Serialize, Deserialize)]
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
struct Bundle {
    manifest: Manifest,
    policy: WorkPolicy,
    registry: Value,
    key: Zeroizing<Vec<u8>>,
    key_current: bool,
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(&serde_json::to_value(value).map_err(|_| "encoding_failed")?)
        .map_err(|_| "encoding_failed")
}
fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    private::read(path, maximum).map_err(|_| "unsafe_work_authority")
}
fn write(path: &Path, bytes: &[u8]) -> Result<()> {
    private::Output::prepare(path)
        .and_then(|out| out.write(bytes))
        .map_err(|_| "authority_output_failed")
}
impl Bundle {
    fn load(path: &Path, now: u64) -> Result<Self> {
        let _directory = private::Directory::open(path).map_err(|_| "unsafe_work_authority")?;
        let manifest: Manifest =
            serde_json::from_value(strict_json(&read(&path.join(FILES[0]), 65536)?, 65536)?)
                .map_err(|_| "invalid_work_manifest")?;
        let policy = WorkPolicy::parse(&read(&path.join(FILES[1]), 262144)?)?;
        let registry_raw = read(&path.join(FILES[2]), 262144)?;
        let registry = strict_json(&registry_raw, 262144)?;
        let parsed_registry =
            parse_public_key_registry(&registry_raw).map_err(|_| "invalid_secs_registry")?;
        if manifest.schema != "secs-devgraph-work-producer-manifest.v1"
            || manifest.schema_version != 1
            || manifest.audience != "devgraph://receiver-local"
            || manifest.replay_schema != "secs-devgraph-work-replay.v1"
            || manifest.receiver_policy_digest_sha256 != policy.digest()?
            || manifest.secs_public_key_registry_sha256 != digest(b"", &registry_raw)
        {
            return Err("work_manifest_binding_mismatch");
        }
        if registry["keys"]
            .as_array()
            .is_none_or(|keys| keys.len() != 1)
        {
            return Err("invalid_secs_registry");
        }
        let key = Zeroizing::new(read(&path.join(FILES[3]), 256)?);
        let identity = load_devgraph_authority_identity_v1(&key, &manifest.secs_verifier_key_id)
            .map_err(|_| "invalid_secs_identity")?;
        let pinned = parsed_registry
            .get(&manifest.secs_verifier_key_id)
            .ok_or("invalid_secs_registry")?;
        if pinned.public_key != *identity.public_key()
            || pinned.algorithm != "ed25519"
            || !pinned.production_authority
        {
            return Err("invalid_secs_identity");
        }
        let key_current = pinned.status == crate::identity::VerificationKeyStatus::Active
            && pinned.not_before.is_none_or(|t| t <= now)
            && pinned.not_after.is_none_or(|t| now < t)
            && pinned.revoked_at.is_none_or(|t| now < t);
        Ok(Self {
            manifest,
            policy,
            registry,
            key,
            key_current,
        })
    }
    fn descriptor(&self, action: &str, now: u64) -> Result<Value> {
        Ok(
            json!({"schema":"secs-devgraph-work-admin.v1", "action":action,
            "ready":self.key_current && self.policy.rules.iter().any(|r| r.effect == "allow" && r.status == "active" && r.not_before <= now && now < r.not_after),
            "key_current": self.key_current, "policy_id":self.policy.policy_id,
            "policy_version":self.policy.policy_version, "policy_digest_sha256":self.policy.digest()?,
            "secs_verifier_key_id":self.manifest.secs_verifier_key_id,
            "registry_sha256":self.manifest.secs_public_key_registry_sha256,
            "policy":self.policy, "registry":self.registry, "files":FILES}),
        )
    }
}
async fn snapshot_descriptor(
    bundle: &Bundle,
    path: &Path,
    action: &str,
    now: u64,
) -> Result<Value> {
    let mut descriptor = bundle.descriptor(action, now)?;
    let mut hashes = serde_json::Map::new();
    for name in FILES {
        let maximum = if name == "replay.sqlite3" {
            256 * 1024 * 1024
        } else {
            262144
        };
        let raw = Zeroizing::new(read(&path.join(name), maximum)?);
        hashes.insert(
            name.into(),
            json!({"sha256":digest(b"", &raw), "size_bytes":raw.len()}),
        );
    }
    descriptor["file_hashes"] = Value::Object(hashes);
    descriptor["current_authority_valid"] = descriptor["ready"].clone();
    Ok(descriptor)
}
async fn database(path: &Path, read_only: bool) -> Result<sqlx::SqlitePool> {
    open_database(path, read_only, false).await
}
async fn open_database(path: &Path, read_only: bool, immutable: bool) -> Result<sqlx::SqlitePool> {
    let guard = private::open(path, 256 * 1024 * 1024).map_err(|_| "unsafe_replay_database")?;
    let before = guard.metadata().map_err(|_| "unsafe_replay_database")?;
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .read_only(read_only)
        .immutable(immutable);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| "replay_storage_failed")?;
    let after = fs::symlink_metadata(path).map_err(|_| "unsafe_replay_database")?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        pool.close().await;
        return Err("unsafe_replay_database");
    }
    Ok(pool)
}
async fn check_database(path: &Path, immutable: bool) -> Result<()> {
    let pool = open_database(path, true, immutable).await?;
    let result = async {
        let check: String = sqlx::query_scalar("PRAGMA quick_check")
            .fetch_one(&pool)
            .await
            .map_err(|_| "invalid_replay_database")?;
        if check != "ok" {
            return Err("invalid_replay_database");
        }
        let _: i64 =
            sqlx::query_scalar("SELECT count(*) FROM devgraph_authority_replay_reservations")
                .fetch_one(&pool)
                .await
                .map_err(|_| "invalid_replay_database")?;
        Ok(())
    }
    .await;
    pool.close().await;
    result
}
async fn copy_database(source: &Path, output: &Path) -> Result<()> {
    write(output, b"")?;
    let guard = private::open(output, 0).map_err(|_| "unsafe_snapshot")?;
    let before = guard.metadata().map_err(|_| "unsafe_snapshot")?;
    let pool = database(source, true).await?;
    let result = sqlx::query("VACUUM main INTO ?")
        .bind(output.to_str().ok_or("unsafe_snapshot")?)
        .execute(&pool)
        .await
        .map_err(|_| "snapshot_failed");
    pool.close().await;
    result?;
    let after = fs::symlink_metadata(output).map_err(|_| "unsafe_snapshot")?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err("unsafe_snapshot");
    }
    private::open(output, 256 * 1024 * 1024)
        .map_err(|_| "unsafe_snapshot")?
        .sync_all()
        .map_err(|_| "snapshot_failed")?;
    check_database(output, true).await
}
pub fn authority_lock(root: &Path, exclusive: bool) -> Result<fs::File> {
    private::lock(&root.join("authority/.devgraph-work.lock"), exclusive)
        .map_err(|_| "authority_busy_or_unsafe")
}
pub async fn run(cli: AdminCli) -> Result<Value> {
    run_at(
        cli,
        &canonical_data_root().map_err(|_| "unsafe_data_root")?,
        crate::clock::failclosed_unix_seconds(),
    )
    .await
}
async fn run_at(cli: AdminCli, root: &Path, now: u64) -> Result<Value> {
    if let Command::VerifySnapshot { input_directory } = &cli.command {
        let bundle = Bundle::load(input_directory, now)?;
        check_database(&input_directory.join(FILES[4]), true).await?;
        return snapshot_descriptor(&bundle, input_directory, "verify-snapshot", now).await;
    }
    let _root = private::Directory::open(root).map_err(|_| "unsafe_data_root")?;
    let parent_path = root.join("authority");
    if !parent_path.exists() {
        _root
            .create_child("authority")
            .map_err(|_| "unsafe_data_root")?;
    }
    let parent = private::Directory::open(&parent_path).map_err(|_| "unsafe_work_authority")?;
    let _lock = authority_lock(root, !matches!(&cli.command, Command::Status))?;
    let active = parent_path.join(BUNDLE);
    match cli.command {
        Command::Status => {
            if !active.try_exists().map_err(|_| "unsafe_work_authority")? {
                return Ok(
                    json!({"schema":"secs-devgraph-work-admin.v1", "action":"status", "ready":false, "state":"missing"}),
                );
            }
            let bundle = Bundle::load(&active, now)?;
            check_database(&active.join(FILES[4]), false).await?;
            bundle.descriptor("status", now)
        }
        Command::Snapshot { output_directory } => {
            if output_directory.starts_with(root) {
                return Err("unsafe_snapshot");
            }
            let _output =
                private::Directory::open(&output_directory).map_err(|_| "unsafe_snapshot")?;
            if fs::read_dir(&output_directory)
                .map_err(|_| "unsafe_snapshot")?
                .next()
                .is_some()
            {
                return Err("snapshot_output_not_empty");
            }
            let bundle = Bundle::load(&active, now)?;
            for name in &FILES[..4] {
                let raw = Zeroizing::new(read(&active.join(name), 262144)?);
                write(&output_directory.join(name), &raw)?;
            }
            copy_database(&active.join(FILES[4]), &output_directory.join(FILES[4])).await?;
            snapshot_descriptor(&bundle, &output_directory, "snapshot", now).await
        }
        Command::Provision {
            policy_file,
            expected_policy_digest,
            rotate_verifier,
        } => {
            let policy = WorkPolicy::parse(&read(&policy_file, 262144)?)?;
            let previous = if active.try_exists().map_err(|_| "unsafe_work_authority")? {
                Some(Bundle::load(&active, now)?)
            } else {
                None
            };
            match &previous {
                Some(old)
                    if expected_policy_digest.as_deref() == Some(old.policy.digest()?.as_str())
                        && old.policy.policy_id == policy.policy_id
                        && policy.policy_version == old.policy.policy_version + 1 => {}
                None if expected_policy_digest.is_none()
                    && policy.policy_version == 1
                    && !rotate_verifier => {}
                _ => return Err("stale_authority_plan"),
            }
            let mut random = [0; 16];
            rand::rngs::OsRng
                .try_fill_bytes(&mut random)
                .map_err(|_| "random_failed")?;
            let staged_name = format!(".work-generation-{}", encode_base64url(&random));
            parent
                .create_child(&staged_name)
                .map_err(|_| "authority_output_failed")?;
            let staged = parent_path.join(&staged_name);
            let key = match &previous {
                Some(old) if !rotate_verifier => Zeroizing::new(old.key.to_vec()),
                _ => {
                    let mut seed = Zeroizing::new([0u8; 32]);
                    rand::rngs::OsRng
                        .try_fill_bytes(&mut *seed)
                        .map_err(|_| "random_failed")?;
                    let encoded =
                        Zeroizing::new(seed.iter().map(|b| format!("{b:02x}")).collect::<String>());
                    Zeroizing::new(encoded.as_bytes().to_vec())
                }
            };
            let identity = load_devgraph_authority_identity_v1(&key, "provisioning")
                .map_err(|_| "invalid_secs_identity")?;
            let key_id = derive_ed25519_key_id(identity.public_key());
            let until = policy
                .rules
                .iter()
                .map(|r| r.not_after)
                .max()
                .ok_or("invalid_work_policy")?;
            let registry = json!({"schema":"secs-public-verifier-key-registry.v1", "schema_version":1, "keys":[{
                "algorithm":"ed25519", "key_id":key_id, "public_key_base64url":encode_base64url(identity.public_key().as_bytes()),
                "production_authority":true, "status":"active", "not_before":now.saturating_sub(1), "not_after":until}]});
            let registry_raw = encoded(&registry)?;
            let manifest = Manifest {
                audience: policy.audience.clone(),
                receiver_policy_digest_sha256: policy.digest()?,
                replay_schema: "secs-devgraph-work-replay.v1".into(),
                schema: "secs-devgraph-work-producer-manifest.v1".into(),
                schema_version: 1,
                secs_public_key_registry_sha256: digest(b"", &registry_raw),
                secs_verifier_key_id: key_id,
            };
            write(&staged.join(FILES[0]), &encoded(&manifest)?)?;
            write(&staged.join(FILES[1]), &encoded(&policy)?)?;
            write(&staged.join(FILES[2]), &registry_raw)?;
            write(&staged.join(FILES[3]), &key)?;
            if previous.is_some() {
                copy_database(&active.join(FILES[4]), &staged.join(FILES[4])).await?;
            } else {
                write(&staged.join(FILES[4]), b"")?;
                let pool = database(&staged.join(FILES[4]), false).await?;
                let result = Ledger::new(pool.clone())
                    .init_schema()
                    .await
                    .map_err(|_| "replay_storage_failed");
                pool.close().await;
                result?;
            }
            let ready = Bundle::load(&staged, now)?;
            check_database(&staged.join(FILES[4]), true).await?;
            parent
                .publish(&staged_name, BUNDLE, previous.is_some())
                .map_err(|_| "authority_publication_failed")?;
            ready.descriptor("provision", now)
        }
        Command::VerifySnapshot { .. } => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn directory(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn policy_file(root: &Path, version: u64, until: u64, revoked: bool) -> PathBuf {
        let path = root.join(format!("policy-{version}.json"));
        let value = json!({"schema":"secs-devgraph-work-policy.v1", "schema_version":1,
            "audience":"devgraph://receiver-local", "policy_id":"native-admin-test", "policy_version":version,
            "rules":[{"actor_id":format!("pubkey:sha256:{}", "1".repeat(64)), "effect":"allow",
                "status":if revoked {"revoked"} else {"active"}, "not_before":100, "not_after":until,
                "operation":"devgraph.work.create.v1", "resource":"Issue/", "resource_match":"prefix"}]});
        write(&path, &encoded(&value).unwrap()).unwrap();
        path
    }
    async fn provision(
        root: &Path,
        policy_file: PathBuf,
        expected: Option<String>,
        rotate: bool,
    ) -> Result<Value> {
        run_at(
            AdminCli {
                command: Command::Provision {
                    policy_file,
                    expected_policy_digest: expected,
                    rotate_verifier: rotate,
                },
            },
            root,
            200,
        )
        .await
    }
    #[tokio::test]
    async fn provision_renew_rotate_and_snapshots_preserve_replay_and_custody() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        directory(&base);
        let root = base.join("secS");
        directory(&root);
        let first = provision(&root, policy_file(&base, 1, 300, false), None, false)
            .await
            .unwrap();
        assert_eq!(first["ready"], true);
        let active = root.join("authority").join(BUNDLE);
        let initial_key = read(&active.join("verifier.key"), 256).unwrap();
        assert!(!encoded(&first)
            .unwrap()
            .windows(initial_key.len())
            .any(|w| w == initial_key));
        let pool = database(&active.join("replay.sqlite3"), false)
            .await
            .unwrap();
        sqlx::query("INSERT INTO devgraph_authority_replay_reservations (reserved_at,expires_at,replay_scope,session_id,operation,nonce,actor_id,audience,resource,request_digest_sha256,idempotency_key_digest_sha256,receiver_policy_id,receiver_policy_version,receiver_policy_digest_sha256,wallet_presentation_digest_sha256,secs_context_id,secs_verifier_key_id,issued_at) VALUES (200,300,'session:operation:nonce',x'01','devgraph.work.create.v1',x'02','actor','audience','Issue/x','request','idempotency','native-admin-test',1,'policy','wallet','context','key',200)").execute(&pool).await.unwrap();
        pool.close().await;
        let next_file = policy_file(&base, 2, 400, false);
        let second = provision(
            &root,
            next_file.clone(),
            first["policy_digest_sha256"].as_str().map(String::from),
            false,
        )
        .await
        .unwrap();
        assert_eq!(
            second["secs_verifier_key_id"],
            first["secs_verifier_key_id"]
        );
        assert_eq!(
            read(&active.join("verifier.key"), 256).unwrap(),
            initial_key
        );
        assert_eq!(
            provision(
                &root,
                next_file,
                first["policy_digest_sha256"].as_str().map(String::from),
                false
            )
            .await,
            Err("stale_authority_plan")
        );
        let third = provision(
            &root,
            policy_file(&base, 3, 500, false),
            second["policy_digest_sha256"].as_str().map(String::from),
            true,
        )
        .await
        .unwrap();
        assert_ne!(
            third["secs_verifier_key_id"],
            second["secs_verifier_key_id"]
        );
        let pool = database(&active.join("replay.sqlite3"), true)
            .await
            .unwrap();
        let count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM devgraph_authority_replay_reservations")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 1);
        pool.close().await;
        let output = base.join("snapshot");
        directory(&output);
        let snapshot = run_at(
            AdminCli {
                command: Command::Snapshot {
                    output_directory: output.clone(),
                },
            },
            &root,
            600,
        )
        .await
        .unwrap();
        assert_eq!(snapshot["current_authority_valid"], false);
        let restored = run_at(
            AdminCli {
                command: Command::VerifySnapshot {
                    input_directory: output.clone(),
                },
            },
            &root,
            600,
        )
        .await
        .unwrap();
        assert_eq!(snapshot["file_hashes"], restored["file_hashes"]);
        assert_eq!(
            restored["policy_digest_sha256"],
            third["policy_digest_sha256"]
        );
        assert_eq!(
            fs::metadata(output.join("verifier.key")).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(
            run_at(
                AdminCli {
                    command: Command::Snapshot {
                        output_directory: output
                    }
                },
                &root,
                600
            )
            .await,
            Err("snapshot_output_not_empty")
        );
    }
    #[tokio::test]
    async fn busy_unsafe_mismatched_and_revoked_states_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        directory(&base);
        let root = base.join("secS");
        directory(&root);
        let first = provision(&root, policy_file(&base, 1, 300, false), None, false)
            .await
            .unwrap();
        let lock = authority_lock(&root, true).unwrap();
        assert_eq!(
            run_at(
                AdminCli {
                    command: Command::Status
                },
                &root,
                200
            )
            .await,
            Err("authority_busy_or_unsafe")
        );
        drop(lock);
        let reader = authority_lock(&root, false).unwrap();
        let other_reader = authority_lock(&root, false).unwrap();
        drop(other_reader);
        drop(reader);
        let result = provision(
            &root,
            policy_file(&base, 2, 400, true),
            first["policy_digest_sha256"].as_str().map(String::from),
            false,
        )
        .await
        .unwrap();
        assert_eq!(result["ready"], false);
        let path = root.join("authority").join(BUNDLE).join("verifier.key");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            run_at(
                AdminCli {
                    command: Command::Status
                },
                &root,
                200
            )
            .await,
            Err("unsafe_work_authority")
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&path, "00".repeat(32)).unwrap();
        assert_eq!(
            run_at(
                AdminCli {
                    command: Command::Status
                },
                &root,
                200
            )
            .await,
            Err("invalid_secs_identity")
        );
    }
    #[test]
    fn administrative_modes_have_no_issuance_or_root_override() {
        assert!(
            AdminCli::try_parse_from(["admin", "status", "--data-root", "/private/tmp"]).is_err()
        );
        assert!(AdminCli::try_parse_from([
            "admin",
            "provision",
            "--policy-file",
            "/x",
            "--request-file",
            "/y"
        ])
        .is_err());
    }
}
