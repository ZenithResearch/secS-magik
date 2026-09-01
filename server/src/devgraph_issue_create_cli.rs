//! Fixed local adapter for exactly `devgraph.issue.create.v1`.
//!
//! This is deliberately not a generic secS route, handler, operation, audience,
//! policy, signer, database, URL, or transport surface. The binary accepts only
//! three owner-private file paths and loads all receiver authority from the one
//! fixed operator data-root layout documented for this adapter.

use crate::devgraph_authority::{
    issue_devgraph_issue_create_authority_v1, DevgraphAuthorityError,
    DevgraphIssueCreateAuthorityInputV1, DevgraphIssueCreatePolicyV1,
    DEVGRAPH_ISSUE_CREATE_OPERATION_V1, DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1,
};
use crate::identity::{
    load_devgraph_authority_identity_v1, NodeVerifierIdentity, PublicVerifierKey,
    PublicVerifierKeyRegistry, VerificationKeyStatus,
};
use crate::ledger::Ledger;
use clap::Parser;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::ffi::{CStr, OsStr};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PRODUCER_INPUT_SCHEMA_V1: &str = "secs-devgraph-issue-create-producer-input.v1";
pub const PRODUCER_MANIFEST_SCHEMA_V1: &str = "secs-devgraph-issue-create-producer-manifest.v1";
pub const REPLAY_SCHEMA_V1: &str = "secs-devgraph-authority-replay.v1";

const AUTHORITY_SUBDIRECTORY: &str = "authority/devgraph.issue.create.v1";
const VERIFIER_KEY_FILE: &str = "verifier.key";
const RECEIVER_POLICY_FILE: &str = "receiver-policy.json";
const PUBLIC_KEY_REGISTRY_FILE: &str = "secs-public-key-registry.json";
const REPLAY_DATABASE_FILE: &str = "replay.sqlite3";
const PRODUCER_MANIFEST_FILE: &str = "producer-manifest.json";

const MAX_INPUT_ENVELOPE_BYTES: u64 = 160 * 1024;
const MAX_IDEMPOTENCY_FILE_BYTES: u64 = 130;
const MAX_POLICY_BYTES: u64 = 256 * 1024;
const MAX_REGISTRY_BYTES: u64 = 256 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_VERIFIER_KEY_BYTES: u64 = 256;
const MAX_REPLAY_DATABASE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROJECTION_BYTES: usize = 16 * 1024;

/// The complete and intentionally non-extensible command-line surface.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "secs-devgraph-issue-create-v1",
    version,
    about = "Issue one fixed devgraph.issue.create.v1 authority projection"
)]
pub struct DevgraphIssueCreateCli {
    /// Owner-private producer input containing one request and Wallet presentation.
    #[arg(long, value_name = "FILE")]
    pub request_file: PathBuf,

    /// Owner-private single-line idempotency key file.
    #[arg(long, value_name = "FILE")]
    pub idempotency_key_file: PathBuf,

    /// Owner-private atomic output for the signed secS projection.
    #[arg(long, value_name = "FILE")]
    pub signed_projection_output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProducerSuccessSummary {
    exact_retry: bool,
}

impl ProducerSuccessSummary {
    pub fn canonical_json(&self) -> String {
        format!(
            "{{\"exact_retry\":{},\"ok\":true,\"operation\":\"{}\",\"output_written\":true}}",
            self.exact_retry, DEVGRAPH_ISSUE_CREATE_OPERATION_V1
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProducerCliError {
    UnsupportedPlatform,
    DataRootUnavailable,
    UnsafeDataRoot,
    UnsafeInputFile,
    InputTooLarge,
    MalformedInputEnvelope,
    InvalidIdempotencyFile,
    MissingVerifierKey,
    UnsafeVerifierKey,
    InvalidVerifierKey,
    MissingReceiverPolicy,
    InvalidReceiverPolicy,
    MissingPublicKeyRegistry,
    InvalidPublicKeyRegistry,
    MissingReplayDatabase,
    UnsafeReplayDatabase,
    ReplayDatabaseFailed,
    MissingProducerManifest,
    InvalidProducerManifest,
    ManifestBindingMismatch,
    AuthorityDenied(&'static str),
    UnsafeOutput,
    OutputFailed,
    Internal,
}

impl ProducerCliError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::DataRootUnavailable => "data_root_unavailable",
            Self::UnsafeDataRoot => "unsafe_data_root",
            Self::UnsafeInputFile => "unsafe_input_file",
            Self::InputTooLarge => "input_too_large",
            Self::MalformedInputEnvelope => "malformed_input_envelope",
            Self::InvalidIdempotencyFile => "invalid_idempotency_file",
            Self::MissingVerifierKey => "missing_verifier_key",
            Self::UnsafeVerifierKey => "unsafe_verifier_key",
            Self::InvalidVerifierKey => "invalid_verifier_key",
            Self::MissingReceiverPolicy => "missing_receiver_policy",
            Self::InvalidReceiverPolicy => "invalid_receiver_policy",
            Self::MissingPublicKeyRegistry => "missing_public_key_registry",
            Self::InvalidPublicKeyRegistry => "invalid_public_key_registry",
            Self::MissingReplayDatabase => "missing_replay_database",
            Self::UnsafeReplayDatabase => "unsafe_replay_database",
            Self::ReplayDatabaseFailed => "replay_database_failed",
            Self::MissingProducerManifest => "missing_producer_manifest",
            Self::InvalidProducerManifest => "invalid_producer_manifest",
            Self::ManifestBindingMismatch => "manifest_binding_mismatch",
            Self::AuthorityDenied(reason) => reason,
            Self::UnsafeOutput => "unsafe_output",
            Self::OutputFailed => "output_failed",
            Self::Internal => "internal_error",
        }
    }

    pub fn canonical_json(self) -> String {
        format!("{{\"error\":\"{}\",\"ok\":false}}", self.reason_code())
    }
}

impl fmt::Display for ProducerCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ProducerCliError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerInputEnvelopeV1 {
    request: Box<serde_json::value::RawValue>,
    schema: String,
    schema_version: u64,
    wallet_presentation: Box<serde_json::value::RawValue>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProducerManifestV1 {
    audience: String,
    operation: String,
    receiver_policy_digest_sha256: String,
    replay_schema: String,
    schema: String,
    schema_version: u64,
    secs_public_key_registry_sha256: String,
    secs_verifier_key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyRegistryFileV1 {
    keys: Vec<PublicKeyEntryV1>,
    schema: String,
    schema_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicKeyEntryV1 {
    algorithm: String,
    key_id: String,
    #[serde(default)]
    not_after: Option<u64>,
    #[serde(default)]
    not_before: Option<u64>,
    production_authority: bool,
    public_key_base64url: String,
    #[serde(default)]
    replaced_by: Option<String>,
    #[serde(default)]
    revoked_at: Option<u64>,
    status: String,
}

struct LoadedAuthority {
    identity: NodeVerifierIdentity,
    registry: PublicVerifierKeyRegistry,
    policy: DevgraphIssueCreatePolicyV1,
    ledger: Ledger,
    _replay_file_guard: File,
}

pub async fn run(cli: DevgraphIssueCreateCli) -> Result<ProducerSuccessSummary, ProducerCliError> {
    let data_root = canonical_data_root()?;
    run_with_data_root_and_now(cli, &data_root, crate::clock::failclosed_unix_seconds()).await
}

async fn run_with_data_root_and_now(
    cli: DevgraphIssueCreateCli,
    data_root: &Path,
    now: u64,
) -> Result<ProducerSuccessSummary, ProducerCliError> {
    let input_bytes = read_private_regular_file(
        &cli.request_file,
        MAX_INPUT_ENVELOPE_BYTES,
        FileRole::CallerInput,
    )?;
    let input: ProducerInputEnvelopeV1 = serde_json::from_slice(&input_bytes)
        .map_err(|_| ProducerCliError::MalformedInputEnvelope)?;
    if input.schema != PRODUCER_INPUT_SCHEMA_V1
        || input.schema_version != 1
        || input.schema_version > DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1
    {
        return Err(ProducerCliError::MalformedInputEnvelope);
    }

    let idempotency_bytes = read_private_regular_file(
        &cli.idempotency_key_file,
        MAX_IDEMPOTENCY_FILE_BYTES,
        FileRole::CallerInput,
    )?;
    let idempotency_key = parse_idempotency_file(&idempotency_bytes)?;
    let authority = load_authority(data_root).await?;

    let outcome = issue_devgraph_issue_create_authority_v1(
        &authority.ledger,
        &authority.identity,
        &authority.registry,
        &authority.policy,
        DevgraphIssueCreateAuthorityInputV1 {
            request_json: input.request.get().as_bytes(),
            idempotency_key,
            wallet_presentation_json: input.wallet_presentation.get().as_bytes(),
            now,
        },
    )
    .await
    .map_err(map_authority_error)?;

    let mut projection = outcome
        .projection()
        .canonical_json()
        .map_err(map_authority_error)?;
    if projection.len() > MAX_PROJECTION_BYTES {
        return Err(ProducerCliError::Internal);
    }
    projection.push('\n');
    write_private_atomic(&cli.signed_projection_output, projection.as_bytes())?;

    Ok(ProducerSuccessSummary {
        exact_retry: outcome.is_exact_retry(),
    })
}

async fn load_authority(data_root: &Path) -> Result<LoadedAuthority, ProducerCliError> {
    validate_owned_directory(data_root, true).map_err(|_| ProducerCliError::UnsafeDataRoot)?;
    validate_owned_directory(&data_root.join("authority"), true)
        .map_err(|_| ProducerCliError::UnsafeDataRoot)?;
    let authority_root = data_root.join(AUTHORITY_SUBDIRECTORY);
    validate_owned_directory(&authority_root, true)
        .map_err(|_| ProducerCliError::UnsafeDataRoot)?;

    let manifest_bytes = read_private_regular_file(
        &authority_root.join(PRODUCER_MANIFEST_FILE),
        MAX_MANIFEST_BYTES,
        FileRole::Manifest,
    )?;
    let manifest: ProducerManifestV1 = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| ProducerCliError::InvalidProducerManifest)?;
    validate_manifest_shape(&manifest)?;

    let policy_bytes = read_private_regular_file(
        &authority_root.join(RECEIVER_POLICY_FILE),
        MAX_POLICY_BYTES,
        FileRole::ReceiverPolicy,
    )?;
    let policy = DevgraphIssueCreatePolicyV1::from_json(&policy_bytes)
        .map_err(|_| ProducerCliError::InvalidReceiverPolicy)?;
    let policy_binding = policy
        .binding()
        .map_err(|_| ProducerCliError::InvalidReceiverPolicy)?;

    let registry_bytes = read_private_regular_file(
        &authority_root.join(PUBLIC_KEY_REGISTRY_FILE),
        MAX_REGISTRY_BYTES,
        FileRole::PublicKeyRegistry,
    )?;
    let registry = parse_public_key_registry(&registry_bytes)?;

    if manifest.audience != policy.audience
        || manifest.receiver_policy_digest_sha256 != policy_binding.policy_digest_sha256
        || manifest.secs_public_key_registry_sha256 != sha256_hex(&registry_bytes)
    {
        return Err(ProducerCliError::ManifestBindingMismatch);
    }

    let verifier_key_path = authority_root.join(VERIFIER_KEY_FILE);
    let key_bytes = read_private_regular_file(
        &verifier_key_path,
        MAX_VERIFIER_KEY_BYTES,
        FileRole::VerifierKey,
    )?;
    let identity = load_devgraph_authority_identity_v1(&key_bytes, &manifest.secs_verifier_key_id)
        .map_err(|_| ProducerCliError::InvalidVerifierKey)?;

    let replay_path = authority_root.join(REPLAY_DATABASE_FILE);
    let replay_file_guard = open_private_regular_file(
        &replay_path,
        MAX_REPLAY_DATABASE_BYTES,
        FileRole::ReplayDatabase,
    )?;
    let replay_metadata = replay_file_guard
        .metadata()
        .map_err(|_| ProducerCliError::UnsafeReplayDatabase)?;
    let options = SqliteConnectOptions::new()
        .filename(&replay_path)
        .create_if_missing(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .map_err(|_| ProducerCliError::ReplayDatabaseFailed)?;
    let ledger = Ledger::new(pool);
    ledger
        .init_schema()
        .await
        .map_err(|_| ProducerCliError::ReplayDatabaseFailed)?;
    let after =
        fs::symlink_metadata(&replay_path).map_err(|_| ProducerCliError::UnsafeReplayDatabase)?;
    if !same_file(&replay_metadata, &after)
        || after.len() > MAX_REPLAY_DATABASE_BYTES
        || after.mode() & 0o077 != 0
    {
        return Err(ProducerCliError::UnsafeReplayDatabase);
    }

    Ok(LoadedAuthority {
        identity,
        registry,
        policy,
        ledger,
        _replay_file_guard: replay_file_guard,
    })
}

fn validate_manifest_shape(manifest: &ProducerManifestV1) -> Result<(), ProducerCliError> {
    if manifest.schema != PRODUCER_MANIFEST_SCHEMA_V1
        || manifest.schema_version != 1
        || manifest.operation != DEVGRAPH_ISSUE_CREATE_OPERATION_V1
        || manifest.replay_schema != REPLAY_SCHEMA_V1
        || !is_safe_receiver_value(&manifest.audience, 256)
        || !is_safe_label(&manifest.secs_verifier_key_id, 128)
        || !is_lower_hex_digest(&manifest.receiver_policy_digest_sha256)
        || !is_lower_hex_digest(&manifest.secs_public_key_registry_sha256)
    {
        return Err(ProducerCliError::InvalidProducerManifest);
    }
    Ok(())
}

fn parse_public_key_registry(bytes: &[u8]) -> Result<PublicVerifierKeyRegistry, ProducerCliError> {
    let file: PublicKeyRegistryFileV1 =
        serde_json::from_slice(bytes).map_err(|_| ProducerCliError::InvalidPublicKeyRegistry)?;
    if file.schema != "secs-public-verifier-key-registry.v1"
        || file.schema_version != 1
        || file.keys.is_empty()
        || file.keys.len() > 256
    {
        return Err(ProducerCliError::InvalidPublicKeyRegistry);
    }
    let mut keys = Vec::with_capacity(file.keys.len());
    for entry in file.keys {
        if entry.algorithm != "ed25519"
            || !is_safe_label(&entry.key_id, 128)
            || entry
                .not_before
                .into_iter()
                .chain(entry.not_after)
                .chain(entry.revoked_at)
                .any(|value| value > DEVGRAPH_JSON_SAFE_INTEGER_MAX_V1)
            || entry
                .replaced_by
                .as_deref()
                .is_some_and(|value| !is_safe_label(value, 128))
        {
            return Err(ProducerCliError::InvalidPublicKeyRegistry);
        }
        let public_key_bytes = decode_base64url_32(&entry.public_key_base64url)
            .ok_or(ProducerCliError::InvalidPublicKeyRegistry)?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| ProducerCliError::InvalidPublicKeyRegistry)?;
        let status = match entry.status.as_str() {
            "active" => VerificationKeyStatus::Active,
            "revoked" => VerificationKeyStatus::Revoked,
            "expired" => VerificationKeyStatus::Expired,
            "unknown" => VerificationKeyStatus::Unknown,
            "not_yet_valid" => VerificationKeyStatus::NotYetValid,
            _ => return Err(ProducerCliError::InvalidPublicKeyRegistry),
        };
        let key = if entry.production_authority {
            PublicVerifierKey::configured_production_authority(
                entry.key_id,
                entry.algorithm,
                public_key,
            )
        } else {
            PublicVerifierKey::active(entry.key_id, entry.algorithm, public_key)
        }
        .with_status(status)
        .with_validity_window(entry.not_before, entry.not_after)
        .with_revoked_at(entry.revoked_at)
        .with_replaced_by(entry.replaced_by);
        keys.push(key);
    }
    Ok(PublicVerifierKeyRegistry::from_keys(keys))
}

fn parse_idempotency_file(bytes: &[u8]) -> Result<&str, ProducerCliError> {
    if !bytes.ends_with(b"\n")
        || bytes[..bytes.len().saturating_sub(1)]
            .iter()
            .any(|byte| *byte == b'\n' || *byte == b'\r')
    {
        return Err(ProducerCliError::InvalidIdempotencyFile);
    }
    let value = std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map_err(|_| ProducerCliError::InvalidIdempotencyFile)?;
    if !(16..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._~-".contains(&byte))
    {
        return Err(ProducerCliError::InvalidIdempotencyFile);
    }
    Ok(value)
}

#[derive(Clone, Copy)]
enum FileRole {
    CallerInput,
    VerifierKey,
    ReceiverPolicy,
    PublicKeyRegistry,
    ReplayDatabase,
    Manifest,
}

fn role_missing_error(role: FileRole) -> ProducerCliError {
    match role {
        FileRole::CallerInput => ProducerCliError::UnsafeInputFile,
        FileRole::VerifierKey => ProducerCliError::MissingVerifierKey,
        FileRole::ReceiverPolicy => ProducerCliError::MissingReceiverPolicy,
        FileRole::PublicKeyRegistry => ProducerCliError::MissingPublicKeyRegistry,
        FileRole::ReplayDatabase => ProducerCliError::MissingReplayDatabase,
        FileRole::Manifest => ProducerCliError::MissingProducerManifest,
    }
}

fn role_unsafe_error(role: FileRole) -> ProducerCliError {
    match role {
        FileRole::CallerInput => ProducerCliError::UnsafeInputFile,
        FileRole::VerifierKey => ProducerCliError::UnsafeVerifierKey,
        FileRole::ReceiverPolicy => ProducerCliError::InvalidReceiverPolicy,
        FileRole::PublicKeyRegistry => ProducerCliError::InvalidPublicKeyRegistry,
        FileRole::ReplayDatabase => ProducerCliError::UnsafeReplayDatabase,
        FileRole::Manifest => ProducerCliError::InvalidProducerManifest,
    }
}

fn open_private_regular_file(
    path: &Path,
    max_bytes: u64,
    role: FileRole,
) -> Result<File, ProducerCliError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                role_missing_error(role)
            } else {
                role_unsafe_error(role)
            }
        })?;
    let metadata = file.metadata().map_err(|_| role_unsafe_error(role))?;
    if !private_regular_metadata_is_safe(
        metadata.file_type().is_file(),
        metadata.uid(),
        metadata.mode(),
        metadata.len(),
        max_bytes,
    ) {
        return Err(
            if metadata.len() > max_bytes && matches!(role, FileRole::CallerInput) {
                ProducerCliError::InputTooLarge
            } else {
                role_unsafe_error(role)
            },
        );
    }
    Ok(file)
}

fn private_regular_metadata_is_safe(
    is_regular_file: bool,
    owner_uid: u32,
    mode: u32,
    len: u64,
    max_bytes: u64,
) -> bool {
    is_regular_file && owner_uid == effective_uid() && mode & 0o077 == 0 && len <= max_bytes
}

fn read_private_regular_file(
    path: &Path,
    max_bytes: u64,
    role: FileRole,
) -> Result<Vec<u8>, ProducerCliError> {
    let mut file = open_private_regular_file(path, max_bytes, role)?;
    let expected_len = file.metadata().map_err(|_| role_unsafe_error(role))?.len();
    let mut bytes = Vec::with_capacity(expected_len as usize);
    Read::by_ref(&mut file)
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| role_unsafe_error(role))?;
    if bytes.len() as u64 != expected_len || bytes.len() as u64 > max_bytes {
        return Err(if matches!(role, FileRole::CallerInput) {
            ProducerCliError::InputTooLarge
        } else {
            role_unsafe_error(role)
        });
    }
    Ok(bytes)
}

fn validate_owned_directory(path: &Path, owner_private: bool) -> Result<(), ()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ())?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != effective_uid()
        || (owner_private && metadata.mode() & 0o077 != 0)
        || (!owner_private && metadata.mode() & 0o022 != 0)
    {
        return Err(());
    }
    Ok(())
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), ProducerCliError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    validate_owned_directory(parent, false).map_err(|_| ProducerCliError::UnsafeOutput)?;
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(ProducerCliError::UnsafeOutput)?;
    if let Ok(existing) = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        let metadata = existing
            .metadata()
            .map_err(|_| ProducerCliError::UnsafeOutput)?;
        if !metadata.file_type().is_file()
            || metadata.uid() != effective_uid()
            || metadata.mode() & 0o077 != 0
        {
            return Err(ProducerCliError::UnsafeOutput);
        }
    } else if fs::symlink_metadata(path).is_ok() {
        return Err(ProducerCliError::UnsafeOutput);
    }

    let mut temp_path = None;
    let mut temp_file = None;
    for attempt in 0..32u32 {
        let candidate = parent.join(format!(
            ".{}.{}.{}.tmp",
            name.to_string_lossy(),
            std::process::id(),
            attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&candidate)
        {
            Ok(file) => {
                temp_path = Some(candidate);
                temp_file = Some(file);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(ProducerCliError::OutputFailed),
        }
    }
    let temp_path = temp_path.ok_or(ProducerCliError::OutputFailed)?;
    let mut temp_file = temp_file.ok_or(ProducerCliError::OutputFailed)?;
    let result = (|| {
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temp_path, path)?;
        File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(ProducerCliError::OutputFailed);
    }
    Ok(())
}

fn map_authority_error(error: DevgraphAuthorityError) -> ProducerCliError {
    ProducerCliError::AuthorityDenied(error.reason_code())
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_safe_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
}

fn is_safe_receiver_value(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && !value.trim().is_empty()
        && !value.chars().any(char::is_control)
}

fn decode_base64url_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 43 || value.contains('=') {
        return None;
    }
    let mut out = [0u8; 32];
    let mut out_index = 0usize;
    for chunk in value.as_bytes().chunks(4) {
        if chunk.len() == 1 {
            return None;
        }
        let mut sextets = [0u8; 4];
        for (index, byte) in chunk.iter().enumerate() {
            sextets[index] = base64url_value(*byte)?;
        }
        let decoded = [
            (sextets[0] << 2) | (sextets[1] >> 4),
            (sextets[1] << 4) | (sextets[2] >> 2),
            (sextets[2] << 6) | sextets[3],
        ];
        let take = if chunk.len() == 4 { 3 } else { chunk.len() - 1 };
        if (chunk.len() == 2 && sextets[1] & 0x0f != 0)
            || (chunk.len() == 3 && sextets[2] & 0x03 != 0)
            || out_index + take > out.len()
        {
            return None;
        }
        out[out_index..out_index + take].copy_from_slice(&decoded[..take]);
        out_index += take;
    }
    if out_index == 32 {
        Some(out)
    } else {
        None
    }
}

fn base64url_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and returns the current process uid.
    unsafe { libc::geteuid() }
}

/// Resolve the effective user's real passwd-database home, never `$HOME` or an
/// environment-selected XDG/config path.
pub fn canonical_data_root() -> Result<PathBuf, ProducerCliError> {
    let home = passwd_home_for_effective_user()?;
    #[cfg(target_os = "macos")]
    {
        Ok(home.join("Library/Application Support/Zenith/secS"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(home.join(".local/share/Zenith/secS"))
    }
}

fn passwd_home_for_effective_user() -> Result<PathBuf, ProducerCliError> {
    let uid = effective_uid();
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0u8; 16 * 1024];
    // SAFETY: pointers refer to live writable storage for the call, and the
    // returned pw_dir pointer is copied before the backing buffer is dropped.
    let code = unsafe {
        libc::getpwuid_r(
            uid,
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if code != 0 || result.is_null() {
        return Err(ProducerCliError::DataRootUnavailable);
    }
    // SAFETY: successful getpwuid_r initialized the record and a NUL-terminated
    // pw_dir string within `buffer`.
    let record = unsafe { record.assume_init() };
    if record.pw_dir.is_null() {
        return Err(ProducerCliError::DataRootUnavailable);
    }
    let bytes = unsafe { CStr::from_ptr(record.pw_dir) }.to_bytes();
    if bytes.is_empty() {
        return Err(ProducerCliError::DataRootUnavailable);
    }
    Ok(PathBuf::from(OsStr::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devgraph_authority::{
        encode_base64url, DevgraphIssueCreateRequestV1, DevgraphIssueCreateWalletPresentationV1,
    };
    use clap::CommandFactory;
    use ed25519_dalek::{Signer, SigningKey};
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    const NOW: u64 = 1_800_000_000;
    const FIXTURE_ROOT: &str = "tests/fixtures/devgraph_issue_create_v1";
    const SECRET: [u8; 32] = [11; 32];
    const WALLET_SECRET: [u8; 32] = [7; 32];

    fn private_write(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn fixture(path: &str) -> Vec<u8> {
        fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(FIXTURE_ROOT)
                .join(path),
        )
        .unwrap()
    }

    fn configured_root() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let data_root = temp.path().join("data-root");
        let authority = data_root.join(AUTHORITY_SUBDIRECTORY);
        fs::create_dir_all(&authority).unwrap();
        fs::set_permissions(&data_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(
            data_root.join("authority"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::set_permissions(&authority, fs::Permissions::from_mode(0o700)).unwrap();

        let policy = fixture(RECEIVER_POLICY_FILE);
        let registry = fixture(PUBLIC_KEY_REGISTRY_FILE);
        private_write(&authority.join(RECEIVER_POLICY_FILE), &policy);
        private_write(&authority.join(PUBLIC_KEY_REGISTRY_FILE), &registry);
        private_write(
            &authority.join(VERIFIER_KEY_FILE),
            SECRET
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .as_bytes(),
        );
        private_write(&authority.join(REPLAY_DATABASE_FILE), b"");

        let policy_value = DevgraphIssueCreatePolicyV1::from_json(&policy).unwrap();
        let manifest = serde_json::json!({
            "audience": policy_value.audience,
            "operation": DEVGRAPH_ISSUE_CREATE_OPERATION_V1,
            "receiver_policy_digest_sha256": policy_value.binding().unwrap().policy_digest_sha256,
            "replay_schema": REPLAY_SCHEMA_V1,
            "schema": PRODUCER_MANIFEST_SCHEMA_V1,
            "schema_version": 1,
            "secs_public_key_registry_sha256": sha256_hex(&registry),
            "secs_verifier_key_id": "secs-devgraph-authority-v1"
        });
        private_write(
            &authority.join(PRODUCER_MANIFEST_FILE),
            serde_json::to_vec(&manifest).unwrap().as_slice(),
        );
        (temp, data_root)
    }

    fn caller_files(temp: &TempDir) -> DevgraphIssueCreateCli {
        let request_file = temp.path().join("request-envelope.json");
        let idempotency_file = temp.path().join("idempotency-key.txt");
        let output = temp.path().join("signed-projection.json");
        let request: serde_json::Value = serde_json::from_slice(&fixture("request.json")).unwrap();
        let wallet: serde_json::Value =
            serde_json::from_slice(&fixture("wallet-presentation.json")).unwrap();
        private_write(
            &request_file,
            serde_json::to_vec(&serde_json::json!({
                "request": request,
                "schema": PRODUCER_INPUT_SCHEMA_V1,
                "schema_version": 1,
                "wallet_presentation": wallet
            }))
            .unwrap()
            .as_slice(),
        );
        private_write(&idempotency_file, &fixture("idempotency-key.txt"));
        DevgraphIssueCreateCli {
            request_file,
            idempotency_key_file: idempotency_file,
            signed_projection_output: output,
        }
    }

    #[test]
    fn cli_has_exactly_three_file_flags_and_no_generic_surface() {
        let mut command = DevgraphIssueCreateCli::command();
        let long_flags: Vec<_> = command
            .get_arguments()
            .filter_map(|argument| argument.get_long().map(str::to_string))
            .collect();
        assert_eq!(
            long_flags,
            [
                "request-file",
                "idempotency-key-file",
                "signed-projection-output"
            ]
        );
        let help = command.render_long_help().to_string();
        for forbidden in [
            "--operation",
            "--audience",
            "--scope",
            "--policy",
            "--signer",
            "--key",
            "--database",
            "--route",
            "--url",
            "--handler",
        ] {
            assert!(!help.contains(forbidden), "{forbidden}");
        }
    }

    #[tokio::test]
    async fn fixture_parity_retry_and_atomic_owner_private_output() {
        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        let first = run_with_data_root_and_now(cli.clone(), &data_root, NOW)
            .await
            .unwrap();
        assert!(!first.exact_retry);
        assert_eq!(
            fs::read(&cli.signed_projection_output).unwrap(),
            fixture("signed-projection.json")
        );
        assert_eq!(
            fs::metadata(&cli.signed_projection_output).unwrap().mode() & 0o777,
            0o600
        );
        let retry = run_with_data_root_and_now(cli.clone(), &data_root, NOW)
            .await
            .unwrap();
        assert!(retry.exact_retry);
        assert_eq!(
            fs::read(&cli.signed_projection_output).unwrap(),
            fixture("signed-projection.json")
        );
        assert!(!temp.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[tokio::test]
    async fn missing_service_key_is_not_generated_and_no_output_is_written() {
        let (temp, data_root) = configured_root();
        fs::remove_file(
            data_root
                .join(AUTHORITY_SUBDIRECTORY)
                .join(VERIFIER_KEY_FILE),
        )
        .unwrap();
        let cli = caller_files(&temp);
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::MissingVerifierKey)
        );
        assert!(!cli.signed_projection_output.exists());
        assert!(!data_root
            .join(AUTHORITY_SUBDIRECTORY)
            .join(VERIFIER_KEY_FILE)
            .exists());
    }

    #[tokio::test]
    async fn symlink_fifo_mode_and_manifest_binding_fail_closed_without_output() {
        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        let real = temp.path().join("real-request.json");
        fs::rename(&cli.request_file, &real).unwrap();
        symlink(&real, &cli.request_file).unwrap();
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::UnsafeInputFile)
        );
        fs::remove_file(&cli.request_file).unwrap();
        fs::rename(&real, &cli.request_file).unwrap();
        fs::set_permissions(&cli.request_file, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::UnsafeInputFile)
        );
        fs::set_permissions(&cli.request_file, fs::Permissions::from_mode(0o600)).unwrap();

        let manifest_path = data_root
            .join(AUTHORITY_SUBDIRECTORY)
            .join(PRODUCER_MANIFEST_FILE);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        manifest["audience"] = serde_json::Value::String("devgraph://other".to_string());
        private_write(&manifest_path, &serde_json::to_vec(&manifest).unwrap());
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::ManifestBindingMismatch)
        );
        assert!(!cli.signed_projection_output.exists());
    }

    #[test]
    fn file_boundary_rejects_fifo_device_oversize_and_wrong_owner_without_blocking() {
        let temp = tempfile::tempdir().unwrap();
        let fifo = temp.path().join("request.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `fifo_c` is a valid NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        assert_eq!(
            read_private_regular_file(&fifo, 64, FileRole::CallerInput),
            Err(ProducerCliError::UnsafeInputFile)
        );
        assert_eq!(
            read_private_regular_file(Path::new("/dev/null"), 64, FileRole::CallerInput),
            Err(ProducerCliError::UnsafeInputFile)
        );

        let oversized = temp.path().join("oversized.json");
        private_write(&oversized, &[b' '; 65]);
        assert_eq!(
            read_private_regular_file(&oversized, 64, FileRole::CallerInput),
            Err(ProducerCliError::InputTooLarge)
        );

        assert!(!private_regular_metadata_is_safe(
            true,
            effective_uid().wrapping_add(1),
            0o100600,
            1,
            64
        ));
        assert!(!private_regular_metadata_is_safe(
            true,
            effective_uid(),
            0o100644,
            1,
            64
        ));
    }

    #[tokio::test]
    async fn config_key_registry_policy_replay_and_expiry_fail_closed() {
        let cases: &[(&str, ProducerCliError)] = &[
            (
                PRODUCER_MANIFEST_FILE,
                ProducerCliError::MissingProducerManifest,
            ),
            (VERIFIER_KEY_FILE, ProducerCliError::MissingVerifierKey),
            (
                RECEIVER_POLICY_FILE,
                ProducerCliError::MissingReceiverPolicy,
            ),
            (
                PUBLIC_KEY_REGISTRY_FILE,
                ProducerCliError::MissingPublicKeyRegistry,
            ),
            (
                REPLAY_DATABASE_FILE,
                ProducerCliError::MissingReplayDatabase,
            ),
        ];
        for (file, expected) in cases {
            let (temp, data_root) = configured_root();
            fs::remove_file(data_root.join(AUTHORITY_SUBDIRECTORY).join(file)).unwrap();
            let cli = caller_files(&temp);
            assert_eq!(
                run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
                Err(*expected),
                "{file}"
            );
            assert!(!cli.signed_projection_output.exists(), "{file}");
        }

        let (temp, data_root) = configured_root();
        private_write(
            &data_root
                .join(AUTHORITY_SUBDIRECTORY)
                .join(VERIFIER_KEY_FILE),
            b"not-a-key",
        );
        let cli = caller_files(&temp);
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::InvalidVerifierKey)
        );
        assert!(!cli.signed_projection_output.exists());

        let (temp, data_root) = configured_root();
        let replay = data_root
            .join(AUTHORITY_SUBDIRECTORY)
            .join(REPLAY_DATABASE_FILE);
        fs::remove_file(&replay).unwrap();
        symlink("/dev/null", &replay).unwrap();
        let cli = caller_files(&temp);
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::UnsafeReplayDatabase)
        );
        assert!(!cli.signed_projection_output.exists());

        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW + 60).await,
            Err(ProducerCliError::AuthorityDenied(
                "devgraph_authority_expired"
            ))
        );
        assert!(!cli.signed_projection_output.exists());
    }

    #[tokio::test]
    async fn conflicting_retry_preserves_existing_atomic_output() {
        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        run_with_data_root_and_now(cli.clone(), &data_root, NOW)
            .await
            .unwrap();
        let first_output = fs::read(&cli.signed_projection_output).unwrap();

        let mut request_value: serde_json::Value =
            serde_json::from_slice(&fixture("request.json")).unwrap();
        request_value["title"] = serde_json::Value::String("Conflicting retry".to_string());
        let request_bytes = serde_json::to_vec(&request_value).unwrap();
        let request = DevgraphIssueCreateRequestV1::from_json(&request_bytes).unwrap();
        let mut wallet = DevgraphIssueCreateWalletPresentationV1::from_json(&fixture(
            "wallet-presentation.json",
        ))
        .unwrap();
        wallet.request_digest_sha256 = request.request_digest_sha256().unwrap();
        wallet.signature.clear();
        wallet.signature = encode_base64url(
            &SigningKey::from_bytes(&WALLET_SECRET)
                .sign(&wallet.signature_preimage().unwrap())
                .to_bytes(),
        );
        private_write(
            &cli.request_file,
            &serde_json::to_vec(&serde_json::json!({
                "request": request_value,
                "schema": PRODUCER_INPUT_SCHEMA_V1,
                "schema_version": 1,
                "wallet_presentation": wallet
            }))
            .unwrap(),
        );

        assert_eq!(
            run_with_data_root_and_now(cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::AuthorityDenied(
                "devgraph_replay_scope_conflict"
            ))
        );
        assert_eq!(
            fs::read(&cli.signed_projection_output).unwrap(),
            first_output
        );
        assert!(!temp.path().read_dir().unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn errors_and_success_are_bounded_and_redacted() {
        let error = ProducerCliError::AuthorityDenied("expired").canonical_json();
        let success = ProducerSuccessSummary { exact_retry: false }.canonical_json();
        for output in [&error, &success] {
            assert!(output.len() < 256);
            for forbidden in [
                "signature",
                "presentation",
                "projection",
                "private",
                "request-file",
            ] {
                assert!(!output.contains(forbidden));
            }
        }
    }
}
