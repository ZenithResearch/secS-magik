//! Fixed local adapter for exactly `devgraph.issue.create.v1`.
//!
//! This is deliberately not a generic secS route, handler, operation, audience,
//! policy, signer, database, URL, or transport surface. The binary accepts only
//! three owner-private file paths and loads all receiver authority from the one
//! fixed operator data-root layout documented for this adapter.

use crate::devgraph_authority::{
    issue_devgraph_issue_create_authority_v1, DevgraphAuthorityError,
    DevgraphIssueCreateAuthorityInputV1, DevgraphIssueCreatePolicyV1, DevgraphIssueCreateRequestV1,
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
use std::os::fd::{AsRawFd, FromRawFd};
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

struct PreparedOutput {
    parent: File,
    name: std::ffi::CString,
}

/// One preflighted invocation of the exact DG-P producer. This crate-private
/// type is the only seam shared by the file envelope and Wallet ceremony
/// adapters; it cannot select another operation, audience, policy, signer,
/// replay store, or output mode.
pub(crate) struct PreparedExactProducerInvocation {
    idempotency_key: String,
    output: PreparedOutput,
    request_json: Vec<u8>,
}

impl PreparedExactProducerInvocation {
    pub(crate) fn wallet_request_json(&self) -> &[u8] {
        &self.request_json
    }

    pub(crate) fn wallet_idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

pub async fn run(cli: DevgraphIssueCreateCli) -> Result<ProducerSuccessSummary, ProducerCliError> {
    let data_root = canonical_data_root()?;
    run_with_data_root_and_clock(cli, &data_root, crate::clock::failclosed_unix_seconds).await
}

#[cfg(test)]
async fn run_with_data_root_and_now(
    cli: DevgraphIssueCreateCli,
    data_root: &Path,
    now: u64,
) -> Result<ProducerSuccessSummary, ProducerCliError> {
    run_with_data_root_and_clock(cli, data_root, || now).await
}

async fn run_with_data_root_and_clock<F>(
    cli: DevgraphIssueCreateCli,
    data_root: &Path,
    mut clock: F,
) -> Result<ProducerSuccessSummary, ProducerCliError>
where
    F: FnMut() -> u64,
{
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

    let invocation = prepare_exact_producer_invocation(
        input.request.get().as_bytes().to_vec(),
        &cli.request_file,
        &cli.idempotency_key_file,
        &cli.signed_projection_output,
        data_root,
    )?;
    issue_prepared_exact_producer_with_clock(
        invocation,
        input.wallet_presentation.get().as_bytes(),
        data_root,
        &mut clock,
    )
    .await
}

/// Read and validate one raw Issue request, the LF-terminated idempotency key,
/// and the create-only output boundary without opening receiver authority or
/// replay state. The Wallet ceremony uses this before it starts listening.
pub(crate) fn prepare_raw_exact_producer_invocation(
    request_file: &Path,
    idempotency_key_file: &Path,
    signed_projection_output: &Path,
    data_root: &Path,
) -> Result<PreparedExactProducerInvocation, ProducerCliError> {
    let request_json = read_private_regular_file(
        request_file,
        MAX_INPUT_ENVELOPE_BYTES,
        FileRole::CallerInput,
    )?;
    DevgraphIssueCreateRequestV1::from_json(&request_json).map_err(map_authority_error)?;
    prepare_exact_producer_invocation(
        request_json,
        request_file,
        idempotency_key_file,
        signed_projection_output,
        data_root,
    )
}

fn prepare_exact_producer_invocation(
    request_json: Vec<u8>,
    request_file: &Path,
    idempotency_key_file: &Path,
    signed_projection_output: &Path,
    data_root: &Path,
) -> Result<PreparedExactProducerInvocation, ProducerCliError> {
    let idempotency_bytes = read_private_regular_file(
        idempotency_key_file,
        MAX_IDEMPOTENCY_FILE_BYTES,
        FileRole::CallerInput,
    )?;
    let idempotency_key = parse_idempotency_file(&idempotency_bytes)?.to_owned();
    let authority_root = data_root.join(AUTHORITY_SUBDIRECTORY);
    let protected_paths = [
        request_file.to_path_buf(),
        idempotency_key_file.to_path_buf(),
        authority_root.join(PRODUCER_MANIFEST_FILE),
        authority_root.join(VERIFIER_KEY_FILE),
        authority_root.join(RECEIVER_POLICY_FILE),
        authority_root.join(PUBLIC_KEY_REGISTRY_FILE),
        authority_root.join(REPLAY_DATABASE_FILE),
    ];
    let output = preflight_create_only_output(
        signed_projection_output,
        &protected_paths,
        std::slice::from_ref(&authority_root),
    )?;
    Ok(PreparedExactProducerInvocation {
        idempotency_key,
        output,
        request_json,
    })
}

pub(crate) async fn issue_prepared_exact_producer(
    invocation: PreparedExactProducerInvocation,
    wallet_presentation_json: &[u8],
    data_root: &Path,
) -> Result<ProducerSuccessSummary, ProducerCliError> {
    issue_prepared_exact_producer_with_clock(
        invocation,
        wallet_presentation_json,
        data_root,
        &mut crate::clock::failclosed_unix_seconds,
    )
    .await
}

async fn issue_prepared_exact_producer_with_clock<F>(
    invocation: PreparedExactProducerInvocation,
    wallet_presentation_json: &[u8],
    data_root: &Path,
    clock: &mut F,
) -> Result<ProducerSuccessSummary, ProducerCliError>
where
    F: FnMut() -> u64,
{
    let authority = load_authority(data_root).await?;

    let issuance_now = clock();
    let outcome = issue_devgraph_issue_create_authority_v1(
        &authority.ledger,
        &authority.identity,
        &authority.registry,
        &authority.policy,
        DevgraphIssueCreateAuthorityInputV1 {
            request_json: &invocation.request_json,
            idempotency_key: &invocation.idempotency_key,
            wallet_presentation_json,
            now: issuance_now,
        },
    )
    .await
    .map_err(map_authority_error)?;

    let exact_retry = outcome.is_exact_retry();
    let output_now = clock();
    let output_outcome = issue_devgraph_issue_create_authority_v1(
        &authority.ledger,
        &authority.identity,
        &authority.registry,
        &authority.policy,
        DevgraphIssueCreateAuthorityInputV1 {
            request_json: &invocation.request_json,
            idempotency_key: &invocation.idempotency_key,
            wallet_presentation_json,
            now: output_now,
        },
    )
    .await
    .map_err(map_authority_error)?;

    let mut projection = output_outcome
        .projection()
        .canonical_json()
        .map_err(map_authority_error)?;
    if projection.len() > MAX_PROJECTION_BYTES {
        return Err(ProducerCliError::Internal);
    }
    projection.push('\n');
    write_private_atomic_create_new(&invocation.output, projection.as_bytes())?;

    Ok(ProducerSuccessSummary { exact_retry })
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

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn canonical_parent_entry(path: &Path) -> Result<PathBuf, ProducerCliError> {
    let name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(ProducerCliError::UnsafeOutput)?;
    let parent =
        fs::canonicalize(output_parent(path)).map_err(|_| ProducerCliError::UnsafeOutput)?;
    Ok(parent.join(name))
}

fn preflight_create_only_output(
    path: &Path,
    protected_paths: &[PathBuf],
    protected_subtrees: &[PathBuf],
) -> Result<PreparedOutput, ProducerCliError> {
    let parent = output_parent(path);
    let output_parent = fs::canonicalize(parent).map_err(|_| ProducerCliError::UnsafeOutput)?;
    let name = path
        .file_name()
        .filter(|name| !name.is_empty() && name.as_bytes().len() <= 180)
        .ok_or(ProducerCliError::UnsafeOutput)?;
    let name =
        std::ffi::CString::new(name.as_bytes()).map_err(|_| ProducerCliError::UnsafeOutput)?;
    let output_entry = output_parent.join(OsStr::from_bytes(name.to_bytes()));

    let parent_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(&output_parent)
        .map_err(|_| ProducerCliError::UnsafeOutput)?;
    let parent_metadata = parent_file
        .metadata()
        .map_err(|_| ProducerCliError::UnsafeOutput)?;
    let current_parent_metadata =
        fs::metadata(&output_parent).map_err(|_| ProducerCliError::UnsafeOutput)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != effective_uid()
        || parent_metadata.mode() & 0o022 != 0
        || !same_file(&parent_metadata, &current_parent_metadata)
    {
        return Err(ProducerCliError::UnsafeOutput);
    }

    for protected_subtree in protected_subtrees {
        if let Ok(protected_subtree) = fs::canonicalize(protected_subtree) {
            if output_parent.starts_with(protected_subtree) {
                return Err(ProducerCliError::UnsafeOutput);
            }
        }
    }

    let output_metadata = metadata_at(&parent_file, &name)?;
    for protected in protected_paths {
        if let Ok(protected_entry) = canonical_parent_entry(protected) {
            if output_entry == protected_entry {
                return Err(ProducerCliError::UnsafeOutput);
            }
        }
        if let (Some(output_metadata), Ok(protected_metadata)) =
            (output_metadata.as_ref(), fs::metadata(protected))
        {
            if stat_matches_metadata(output_metadata, &protected_metadata) {
                return Err(ProducerCliError::UnsafeOutput);
            }
        }
    }

    if output_metadata.is_some() {
        return Err(ProducerCliError::UnsafeOutput);
    }
    Ok(PreparedOutput {
        parent: parent_file,
        name,
    })
}

fn metadata_at(
    parent: &File,
    name: &std::ffi::CStr,
) -> Result<Option<libc::stat>, ProducerCliError> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: the directory descriptor and NUL-terminated entry name are live,
    // and `metadata` points to writable storage for one `stat` result.
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful fstatat initialized `metadata`.
        return Ok(Some(unsafe { metadata.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.kind() == std::io::ErrorKind::NotFound {
        Ok(None)
    } else {
        Err(ProducerCliError::UnsafeOutput)
    }
}

fn stat_matches_metadata(left: &libc::stat, right: &fs::Metadata) -> bool {
    nonnegative_u128(left.st_dev) == Some(u128::from(right.dev()))
        && nonnegative_u128(left.st_ino) == Some(u128::from(right.ino()))
}

fn nonnegative_u128<T>(value: T) -> Option<u128>
where
    T: TryInto<u128>,
{
    value.try_into().ok()
}

fn unlinkat_entry(parent: &File, name: &std::ffi::CStr) -> std::io::Result<()> {
    // SAFETY: the descriptor and NUL-terminated relative entry name are live.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn write_private_atomic_create_new(
    output: &PreparedOutput,
    bytes: &[u8],
) -> Result<(), ProducerCliError> {
    let name_digest = sha256_hex(output.name.to_bytes());

    let mut temp_name = None;
    let mut temp_file = None;
    for attempt in 0..32u32 {
        let candidate = std::ffi::CString::new(format!(
            ".secs-dg-e1-{}-{}-{}.tmp",
            std::process::id(),
            attempt,
            &name_digest[..16]
        ))
        .map_err(|_| ProducerCliError::OutputFailed)?;
        // SAFETY: `output.parent` is a held validated directory descriptor and
        // `candidate` is a NUL-terminated single entry name.
        let descriptor = unsafe {
            libc::openat(
                output.parent.as_raw_fd(),
                candidate.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if descriptor >= 0 {
            // SAFETY: successful openat returned one owned descriptor.
            temp_file = Some(unsafe { File::from_raw_fd(descriptor) });
            temp_name = Some(candidate);
            break;
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::AlreadyExists => continue,
            _ => return Err(ProducerCliError::OutputFailed),
        }
    }
    let temp_name = temp_name.ok_or(ProducerCliError::OutputFailed)?;
    let mut temp_file = temp_file.ok_or(ProducerCliError::OutputFailed)?;
    let result = (|| {
        temp_file.write_all(bytes)?;
        temp_file.sync_all()?;
        temp_file.set_permissions(fs::Permissions::from_mode(0o600))?;
        // SAFETY: both names are relative to the same held directory and both
        // C strings remain live. linkat is atomic and never replaces `name`.
        if unsafe {
            libc::linkat(
                output.parent.as_raw_fd(),
                temp_name.as_ptr(),
                output.parent.as_raw_fd(),
                output.name.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        unlinkat_entry(&output.parent, &temp_name)?;
        output.parent.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = result {
        let _ = unlinkat_entry(&output.parent, &temp_name);
        return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
            ProducerCliError::UnsafeOutput
        } else {
            ProducerCliError::OutputFailed
        });
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

    fn protected_file_paths(cli: &DevgraphIssueCreateCli, data_root: &Path) -> Vec<PathBuf> {
        let authority = data_root.join(AUTHORITY_SUBDIRECTORY);
        vec![
            cli.request_file.clone(),
            cli.idempotency_key_file.clone(),
            authority.join(PRODUCER_MANIFEST_FILE),
            authority.join(VERIFIER_KEY_FILE),
            authority.join(RECEIVER_POLICY_FILE),
            authority.join(PUBLIC_KEY_REGISTRY_FILE),
            authority.join(REPLAY_DATABASE_FILE),
        ]
    }

    fn assert_no_adapter_temp_files(directory: &Path) {
        assert!(!directory.read_dir().unwrap().any(|entry| {
            let name = entry.unwrap().file_name();
            name.to_string_lossy().ends_with(".tmp")
        }));
    }

    async fn assert_output_preflight_rejects_without_mutation(
        cli: DevgraphIssueCreateCli,
        data_root: &Path,
    ) {
        let protected = protected_file_paths(&cli, data_root);
        let before: Vec<_> = protected
            .iter()
            .map(|path| (path.clone(), fs::read(path).unwrap()))
            .collect();

        assert_eq!(
            run_with_data_root_and_now(cli.clone(), data_root, NOW).await,
            Err(ProducerCliError::UnsafeOutput)
        );
        for (path, bytes) in before {
            assert_eq!(fs::read(&path).unwrap(), bytes, "{}", path.display());
        }
        assert_no_adapter_temp_files(output_parent(&cli.signed_projection_output));
        assert_no_adapter_temp_files(&data_root.join(AUTHORITY_SUBDIRECTORY));
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
        let mut retry_cli = cli.clone();
        retry_cli.signed_projection_output = temp.path().join("signed-projection-retry.json");
        let retry = run_with_data_root_and_now(retry_cli.clone(), &data_root, NOW)
            .await
            .unwrap();
        assert!(retry.exact_retry);
        assert_eq!(
            fs::read(&retry_cli.signed_projection_output).unwrap(),
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
    async fn raw_wallet_invocation_preserves_exact_fixture_projection() {
        let (temp, data_root) = configured_root();
        let request_file = temp.path().join("raw-request.json");
        let idempotency_file = temp.path().join("raw-idempotency.txt");
        let output = temp.path().join("raw-signed-projection.json");
        private_write(&request_file, &fixture("request.json"));
        private_write(&idempotency_file, &fixture("idempotency-key.txt"));

        let invocation = prepare_raw_exact_producer_invocation(
            &request_file,
            &idempotency_file,
            &output,
            &data_root,
        )
        .unwrap();
        let mut clock = || NOW;
        let summary = issue_prepared_exact_producer_with_clock(
            invocation,
            &fixture("wallet-presentation.json"),
            &data_root,
            &mut clock,
        )
        .await
        .unwrap();
        assert!(!summary.exact_retry);
        assert_eq!(
            fs::read(&output).unwrap(),
            fixture("signed-projection.json")
        );
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn output_aliases_caller_inputs_reject_before_replay_or_file_mutation() {
        let (temp, data_root) = configured_root();
        let mut direct = caller_files(&temp);
        direct.signed_projection_output = direct.request_file.clone();
        assert_output_preflight_rejects_without_mutation(direct, &data_root).await;

        let (temp, data_root) = configured_root();
        let mut normalized = caller_files(&temp);
        fs::create_dir(temp.path().join("normalization-component")).unwrap();
        normalized.signed_projection_output = temp
            .path()
            .join("normalization-component")
            .join("..")
            .join("request-envelope.json");
        assert_output_preflight_rejects_without_mutation(normalized, &data_root).await;

        let (temp, data_root) = configured_root();
        let mut symlinked_ancestor = caller_files(&temp);
        fs::create_dir(temp.path().join("ancestor-component")).unwrap();
        symlink(temp.path(), temp.path().join("linked-root")).unwrap();
        symlinked_ancestor.signed_projection_output = temp
            .path()
            .join("linked-root")
            .join("ancestor-component")
            .join("..")
            .join("request-envelope.json");
        assert_output_preflight_rejects_without_mutation(symlinked_ancestor, &data_root).await;

        let (temp, data_root) = configured_root();
        let mut hardlink = caller_files(&temp);
        let hardlink_output = temp.path().join("request-hardlink.json");
        fs::hard_link(&hardlink.request_file, &hardlink_output).unwrap();
        hardlink.signed_projection_output = hardlink_output;
        assert_output_preflight_rejects_without_mutation(hardlink, &data_root).await;

        let (temp, data_root) = configured_root();
        let mut idempotency = caller_files(&temp);
        idempotency.signed_projection_output = idempotency.idempotency_key_file.clone();
        assert_output_preflight_rejects_without_mutation(idempotency, &data_root).await;
    }

    #[tokio::test]
    async fn output_aliases_every_fixed_authority_file_reject_before_any_mutation() {
        for role in [
            PRODUCER_MANIFEST_FILE,
            VERIFIER_KEY_FILE,
            RECEIVER_POLICY_FILE,
            PUBLIC_KEY_REGISTRY_FILE,
            REPLAY_DATABASE_FILE,
        ] {
            let (temp, data_root) = configured_root();
            let mut cli = caller_files(&temp);
            cli.signed_projection_output = data_root.join(AUTHORITY_SUBDIRECTORY).join(role);
            assert_output_preflight_rejects_without_mutation(cli, &data_root).await;
        }

        for fresh_name in [
            "new-projection.json",
            "replay.sqlite3-journal",
            "replay.sqlite3-wal",
            "replay.sqlite3-shm",
        ] {
            let (temp, data_root) = configured_root();
            let mut cli = caller_files(&temp);
            cli.signed_projection_output = data_root.join(AUTHORITY_SUBDIRECTORY).join(fresh_name);
            assert_output_preflight_rejects_without_mutation(cli.clone(), &data_root).await;
            assert!(!cli.signed_projection_output.exists(), "{fresh_name}");
        }
    }

    #[tokio::test]
    async fn unrelated_existing_output_is_create_only_and_preserved_before_issuance() {
        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        private_write(
            &cli.signed_projection_output,
            b"existing unrelated projection\n",
        );
        let before = fs::read(&cli.signed_projection_output).unwrap();
        assert_output_preflight_rejects_without_mutation(cli.clone(), &data_root).await;
        assert_eq!(fs::read(&cli.signed_projection_output).unwrap(), before);
    }

    #[test]
    fn held_parent_directory_prevents_path_swap_during_atomic_publication() {
        let temp = tempfile::tempdir().unwrap();
        let original_parent = temp.path().join("outbox");
        let moved_parent = temp.path().join("held-outbox");
        fs::create_dir(&original_parent).unwrap();
        fs::set_permissions(&original_parent, fs::Permissions::from_mode(0o700)).unwrap();
        let output_path = original_parent.join("projection.json");
        let prepared = preflight_create_only_output(&output_path, &[], &[]).unwrap();

        fs::rename(&original_parent, &moved_parent).unwrap();
        fs::create_dir(&original_parent).unwrap();
        fs::set_permissions(&original_parent, fs::Permissions::from_mode(0o700)).unwrap();
        write_private_atomic_create_new(&prepared, b"complete projection\n").unwrap();

        assert!(!output_path.exists());
        assert_eq!(
            fs::read(moved_parent.join("projection.json")).unwrap(),
            b"complete projection\n"
        );
        assert_no_adapter_temp_files(&moved_parent);
    }

    #[tokio::test]
    async fn advancing_clock_rechecks_exclusive_expiry_before_output() {
        let (temp, data_root) = configured_root();
        let cli = caller_files(&temp);
        let mut reads = [NOW, NOW + 60].into_iter();
        assert_eq!(
            run_with_data_root_and_clock(cli.clone(), &data_root, || reads.next().unwrap()).await,
            Err(ProducerCliError::AuthorityDenied(
                "devgraph_authority_expired"
            ))
        );
        assert!(!cli.signed_projection_output.exists());
        assert_no_adapter_temp_files(temp.path());

        let replay_path = data_root
            .join(AUTHORITY_SUBDIRECTORY)
            .join(REPLAY_DATABASE_FILE);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                SqliteConnectOptions::new()
                    .filename(replay_path)
                    .create_if_missing(false),
            )
            .await
            .unwrap();
        let reservation_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM devgraph_authority_replay_reservations")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(reservation_count, 1);
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

        let mut conflict_cli = cli.clone();
        conflict_cli.signed_projection_output = temp.path().join("conflict-projection.json");

        assert_eq!(
            run_with_data_root_and_now(conflict_cli.clone(), &data_root, NOW).await,
            Err(ProducerCliError::AuthorityDenied(
                "devgraph_replay_scope_conflict"
            ))
        );
        assert_eq!(
            fs::read(&cli.signed_projection_output).unwrap(),
            first_output
        );
        assert!(!conflict_cli.signed_projection_output.exists());
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
