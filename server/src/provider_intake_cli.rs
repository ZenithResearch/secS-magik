//! Fixed native custody and opener for `service.intake-envelope.v1`.
//!
//! The command has no caller-selected key, data-root, algorithm, operation, or
//! output path. It reads the one canonical provider key and accepts an opaque
//! envelope on stdin. Opened bytes are returned through one bounded binary
//! stdout frame for a capturing local Service Management process.

use crate::devgraph_issue_create_cli::canonical_data_root;
use crate::work_private_files::{self as private, Directory, Output};
use clap::{Parser, Subcommand};
use libsec_core::intake_envelope::{
    open_intake_envelope_v1, IntakeEnvelopeError, MAX_INTAKE_ENVELOPE_BYTES,
};
use libsec_core::reference_object_envelope::{
    open_reference_object_envelope_v1, ReferenceObjectEnvelopeError,
    MAX_REFERENCE_OBJECT_ENVELOPE_BYTES,
};
use libsec_core::tunnel::tunnel_public_key_id;
use rand::{rngs::OsRng, RngCore};
use std::fmt;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const AUTHORITY_DIRECTORY: &str = "service.intake-envelope.v1";
const KEY_FILE: &str = "recipient.x25519.key";
const LOCK_FILE: &str = ".service-intake-envelope-v1.lock";
pub const OPENED_FRAME_MAGIC: &[u8; 8] = b"SECSO01\0";
pub const OPENED_REFERENCE_FRAME_MAGIC: &[u8; 8] = b"SECSOR1\0";

#[derive(Debug, Clone, Parser)]
#[command(
    name = "secs-provider-intake-v1",
    version,
    about = "Provision, inspect, or open one fixed provider-intake envelope"
)]
pub struct ProviderIntakeCli {
    #[command(subcommand)]
    pub command: ProviderIntakeCommand,
}

#[derive(Debug, Clone, Subcommand)]
pub enum ProviderIntakeCommand {
    /// Create the canonical provider X25519 key once.
    Provision,
    /// Print only the provider public key and key identifier.
    Status,
    /// Read one envelope from stdin and write one opened binary frame to stdout.
    Open,
    /// Read one reference-object envelope and write one opened binary frame.
    OpenReferenceObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderIntakeCliError {
    UnsupportedPlatform,
    UnsafeDataRoot,
    AlreadyProvisioned,
    ProvisionFailed,
    MissingRecipientKey,
    UnsafeRecipientKey,
    InvalidRecipientKey,
    ClockUnavailable,
    EnvelopeTooLarge,
    EnvelopeRejected,
    InputFailed,
    OutputFailed,
}

impl ProviderIntakeCliError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::UnsafeDataRoot => "unsafe_data_root",
            Self::AlreadyProvisioned => "already_provisioned",
            Self::ProvisionFailed => "provision_failed",
            Self::MissingRecipientKey => "missing_recipient_key",
            Self::UnsafeRecipientKey => "unsafe_recipient_key",
            Self::InvalidRecipientKey => "invalid_recipient_key",
            Self::ClockUnavailable => "clock_unavailable",
            Self::EnvelopeTooLarge => "envelope_too_large",
            Self::EnvelopeRejected => "envelope_rejected",
            Self::InputFailed => "input_failed",
            Self::OutputFailed => "output_failed",
        }
    }

    pub fn canonical_json(self) -> String {
        format!("{{\"error\":\"{}\",\"ok\":false}}", self.reason_code())
    }
}

impl fmt::Display for ProviderIntakeCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ProviderIntakeCliError {}

pub fn run(
    cli: ProviderIntakeCli,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<(), ProviderIntakeCliError> {
    let data_root = canonical_data_root().map_err(|_| ProviderIntakeCliError::UnsafeDataRoot)?;
    run_at(cli, &data_root, input, output, system_time_ms)
}

fn system_time_ms() -> Result<u64, ProviderIntakeCliError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ProviderIntakeCliError::ClockUnavailable)?
        .as_millis();
    u64::try_from(millis).map_err(|_| ProviderIntakeCliError::ClockUnavailable)
}

fn run_at<R: Read, W: Write, F: FnOnce() -> Result<u64, ProviderIntakeCliError>>(
    cli: ProviderIntakeCli,
    data_root: &Path,
    input: &mut R,
    output: &mut W,
    clock: F,
) -> Result<(), ProviderIntakeCliError> {
    match cli.command {
        ProviderIntakeCommand::Provision => {
            let status = provision_at(data_root)?;
            output
                .write_all(status.as_bytes())
                .and_then(|_| output.write_all(b"\n"))
                .map_err(|_| ProviderIntakeCliError::OutputFailed)
        }
        ProviderIntakeCommand::Status => {
            let status = status_at(data_root)?;
            output
                .write_all(status.as_bytes())
                .and_then(|_| output.write_all(b"\n"))
                .map_err(|_| ProviderIntakeCliError::OutputFailed)
        }
        ProviderIntakeCommand::Open => open_at(data_root, input, output, clock()?),
        ProviderIntakeCommand::OpenReferenceObject => {
            open_reference_at(data_root, input, output, clock()?)
        }
    }
}

fn authority_paths(data_root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let authority = data_root.join("authority");
    let intake = authority.join(AUTHORITY_DIRECTORY);
    let key = intake.join(KEY_FILE);
    (authority, intake, key)
}

fn validate_roots(data_root: &Path) -> Result<(Directory, Directory), ProviderIntakeCliError> {
    let (authority, intake, _) = authority_paths(data_root);
    let authority =
        Directory::open(&authority).map_err(|_| ProviderIntakeCliError::UnsafeDataRoot)?;
    let intake = Directory::open(&intake).map_err(|_| ProviderIntakeCliError::UnsafeDataRoot)?;
    Ok((authority, intake))
}

fn provision_at(data_root: &Path) -> Result<String, ProviderIntakeCliError> {
    let (authority_path, intake_path, key_path) = authority_paths(data_root);
    let authority =
        Directory::open(&authority_path).map_err(|_| ProviderIntakeCliError::UnsafeDataRoot)?;
    let _lock = private::lock(&authority_path.join(LOCK_FILE), true)
        .map_err(|_| ProviderIntakeCliError::ProvisionFailed)?;
    match fs::symlink_metadata(&intake_path) {
        Ok(_) => {
            Directory::open(&intake_path).map_err(|_| ProviderIntakeCliError::UnsafeDataRoot)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => authority
            .create_child(AUTHORITY_DIRECTORY)
            .map_err(|_| ProviderIntakeCliError::ProvisionFailed)?,
        Err(_) => return Err(ProviderIntakeCliError::ProvisionFailed),
    }
    let output = Output::prepare(&key_path).map_err(|_| match private::read(&key_path, 32) {
        Ok(existing) if existing.len() == 32 => ProviderIntakeCliError::AlreadyProvisioned,
        _ if fs::symlink_metadata(&key_path).is_ok() => ProviderIntakeCliError::UnsafeRecipientKey,
        _ => ProviderIntakeCliError::ProvisionFailed,
    })?;
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(&mut *secret)
        .map_err(|_| ProviderIntakeCliError::ProvisionFailed)?;
    output
        .write(&secret[..])
        .map_err(|_| ProviderIntakeCliError::ProvisionFailed)?;
    status_at(data_root)
}

fn load_key(data_root: &Path) -> Result<Zeroizing<[u8; 32]>, ProviderIntakeCliError> {
    let (_, _, key_path) = authority_paths(data_root);
    validate_roots(data_root)?;
    let bytes =
        private::read(&key_path, 32).map_err(|_| match fs::symlink_metadata(&key_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ProviderIntakeCliError::MissingRecipientKey
            }
            _ => ProviderIntakeCliError::UnsafeRecipientKey,
        })?;
    let secret: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProviderIntakeCliError::InvalidRecipientKey)?;
    Ok(Zeroizing::new(secret))
}

fn public_binding(data_root: &Path) -> Result<([u8; 32], String), ProviderIntakeCliError> {
    let secret = load_key(data_root)?;
    let public = PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
    if public.iter().all(|byte| *byte == 0) {
        return Err(ProviderIntakeCliError::InvalidRecipientKey);
    }
    let key_id = tunnel_public_key_id(&public);
    Ok((public, key_id))
}

fn status_at(data_root: &Path) -> Result<String, ProviderIntakeCliError> {
    let (public, key_id) = public_binding(data_root)?;
    let public_hex = public
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{{\"configured\":true,\"key_id\":\"{key_id}\",\"ok\":true,\"public_key_hex\":\"{public_hex}\",\"schema\":\"secs.provider-intake-status.v1\"}}"
    ))
}

fn open_at(
    data_root: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
    now_ms: u64,
) -> Result<(), ProviderIntakeCliError> {
    let secret = load_key(data_root)?;
    let public = PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
    let key_id = tunnel_public_key_id(&public);
    let mut envelope = Vec::with_capacity(MAX_INTAKE_ENVELOPE_BYTES + 1);
    input
        .take(MAX_INTAKE_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut envelope)
        .map_err(|_| ProviderIntakeCliError::InputFailed)?;
    if envelope.len() > MAX_INTAKE_ENVELOPE_BYTES {
        return Err(ProviderIntakeCliError::EnvelopeTooLarge);
    }
    let opened =
        open_intake_envelope_v1(&secret, &key_id, &envelope, now_ms).map_err(map_envelope_error)?;
    let mut frame = Zeroizing::new(Vec::with_capacity(
        16 + opened.intake.len() + opened.requester_evidence.len(),
    ));
    frame.extend_from_slice(OPENED_FRAME_MAGIC);
    frame.extend_from_slice(&(opened.intake.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(opened.requester_evidence.len() as u32).to_be_bytes());
    frame.extend_from_slice(&opened.intake);
    frame.extend_from_slice(&opened.requester_evidence);
    output
        .write_all(&frame)
        .map_err(|_| ProviderIntakeCliError::OutputFailed)
}

fn map_envelope_error(_: IntakeEnvelopeError) -> ProviderIntakeCliError {
    // Do not provide a local decryption oracle through detailed error strings.
    ProviderIntakeCliError::EnvelopeRejected
}

fn open_reference_at(
    data_root: &Path,
    input: &mut impl Read,
    output: &mut impl Write,
    now_ms: u64,
) -> Result<(), ProviderIntakeCliError> {
    let secret = load_key(data_root)?;
    let public = PublicKey::from(&StaticSecret::from(*secret)).to_bytes();
    let key_id = tunnel_public_key_id(&public);
    let mut envelope = Vec::with_capacity(MAX_REFERENCE_OBJECT_ENVELOPE_BYTES + 1);
    input
        .take(MAX_REFERENCE_OBJECT_ENVELOPE_BYTES as u64 + 1)
        .read_to_end(&mut envelope)
        .map_err(|_| ProviderIntakeCliError::InputFailed)?;
    if envelope.len() > MAX_REFERENCE_OBJECT_ENVELOPE_BYTES {
        return Err(ProviderIntakeCliError::EnvelopeTooLarge);
    }
    let opened = open_reference_object_envelope_v1(&secret, &key_id, &envelope, now_ms)
        .map_err(map_reference_error)?;
    let request = opened.request_id.as_bytes();
    let idempotency = opened.idempotency_key.as_bytes();
    let artifact = opened.artifact_id.as_bytes();
    let mut frame = Zeroizing::new(Vec::with_capacity(
        8 + 3
            + 32
            + 8
            + request.len()
            + idempotency.len()
            + artifact.len()
            + opened.object.len()
            + opened.requester_evidence.len(),
    ));
    frame.extend_from_slice(OPENED_REFERENCE_FRAME_MAGIC);
    for value in [request, idempotency, artifact] {
        frame.push(value.len() as u8);
    }
    frame.extend_from_slice(&opened.content_hash);
    frame.extend_from_slice(&(opened.object.len() as u32).to_be_bytes());
    frame.extend_from_slice(&(opened.requester_evidence.len() as u32).to_be_bytes());
    frame.extend_from_slice(request);
    frame.extend_from_slice(idempotency);
    frame.extend_from_slice(artifact);
    frame.extend_from_slice(&opened.object);
    frame.extend_from_slice(&opened.requester_evidence);
    output
        .write_all(&frame)
        .map_err(|_| ProviderIntakeCliError::OutputFailed)
}

fn map_reference_error(_: ReferenceObjectEnvelopeError) -> ProviderIntakeCliError {
    ProviderIntakeCliError::EnvelopeRejected
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsec_core::intake_envelope::seal_intake_envelope_v1;
    use libsec_core::reference_object_envelope::seal_reference_object_envelope_v1;
    use sha2::{Digest, Sha256};
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn root() -> (TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("data");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(root.join("authority")).unwrap();
        fs::set_permissions(root.join("authority"), fs::Permissions::from_mode(0o700)).unwrap();
        (temp, root.canonicalize().unwrap())
    }

    fn command(command: ProviderIntakeCommand) -> ProviderIntakeCli {
        ProviderIntakeCli { command }
    }

    fn decode_opened(frame: &[u8]) -> (&[u8], &[u8]) {
        assert_eq!(&frame[..8], OPENED_FRAME_MAGIC);
        let intake = u32::from_be_bytes(frame[8..12].try_into().unwrap()) as usize;
        let evidence = u32::from_be_bytes(frame[12..16].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 16 + intake + evidence);
        (&frame[16..16 + intake], &frame[16 + intake..])
    }

    fn decode_reference(frame: &[u8]) -> (&str, &str, &str, &[u8], &[u8]) {
        assert_eq!(&frame[..8], OPENED_REFERENCE_FRAME_MAGIC);
        let request_len = frame[8] as usize;
        let idempotency_len = frame[9] as usize;
        let artifact_len = frame[10] as usize;
        let object_len = u32::from_be_bytes(frame[43..47].try_into().unwrap()) as usize;
        let evidence_len = u32::from_be_bytes(frame[47..51].try_into().unwrap()) as usize;
        let request_start = 51;
        let idempotency_start = request_start + request_len;
        let artifact_start = idempotency_start + idempotency_len;
        let object_start = artifact_start + artifact_len;
        let evidence_start = object_start + object_len;
        assert_eq!(frame.len(), evidence_start + evidence_len);
        assert_eq!(
            Sha256::digest(&frame[object_start..evidence_start]).as_slice(),
            &frame[11..43]
        );
        (
            std::str::from_utf8(&frame[request_start..idempotency_start]).unwrap(),
            std::str::from_utf8(&frame[idempotency_start..artifact_start]).unwrap(),
            std::str::from_utf8(&frame[artifact_start..object_start]).unwrap(),
            &frame[object_start..evidence_start],
            &frame[evidence_start..],
        )
    }

    #[test]
    fn provision_is_create_only_and_status_exposes_only_public_binding() {
        let (_temp, root) = root();
        let first = provision_at(&root).unwrap();
        assert!(first.contains("secs.provider-intake-status.v1"));
        assert!(!first.contains("recipient.x25519.key"));
        assert_eq!(
            provision_at(&root),
            Err(ProviderIntakeCliError::AlreadyProvisioned)
        );
        let key = root.join("authority/service.intake-envelope.v1/recipient.x25519.key");
        assert_eq!(
            fs::metadata(key).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(status_at(&root).unwrap(), first);
    }

    #[test]
    fn native_opener_round_trips_core_envelope_in_closed_frame() {
        let (_temp, root) = root();
        provision_at(&root).unwrap();
        let (public, _) = public_binding(&root).unwrap();
        let envelope = seal_intake_envelope_v1(
            &public,
            &[8; 32],
            &[9; 12],
            br#"{"schema":"service.intake.v1"}"#,
            b"exact-requester-evidence",
            2_000,
        )
        .unwrap();
        let mut output = Vec::new();
        open_at(&root, &mut Cursor::new(envelope), &mut output, 1_000).unwrap();
        let (intake, evidence) = decode_opened(&output);
        assert_eq!(intake, br#"{"schema":"service.intake.v1"}"#);
        assert_eq!(evidence, b"exact-requester-evidence");
    }

    #[test]
    fn native_opener_round_trips_reference_object_in_distinct_closed_frame() {
        let (_temp, root) = root();
        provision_at(&root).unwrap();
        let (public, _) = public_binding(&root).unwrap();
        let object = b"bounded original reference";
        let content_hash = Sha256::digest(object).into();
        let envelope = seal_reference_object_envelope_v1(
            &public,
            &[8; 32],
            &[9; 12],
            "request-1",
            "submit-1",
            "reference-1",
            &content_hash,
            object,
            b"exact-requester-evidence",
            2_000,
        )
        .unwrap();
        let mut output = Vec::new();
        open_reference_at(&root, &mut Cursor::new(envelope), &mut output, 1_000).unwrap();
        let (request, idempotency, artifact, opened, evidence) = decode_reference(&output);
        assert_eq!(
            (request, idempotency, artifact),
            ("request-1", "submit-1", "reference-1")
        );
        assert_eq!(opened, object);
        assert_eq!(evidence, b"exact-requester-evidence");
    }

    #[test]
    fn opener_collapses_crypto_failures_and_rejects_oversized_input() {
        let (_temp, root) = root();
        provision_at(&root).unwrap();
        let mut output = Vec::new();
        assert_eq!(
            open_at(
                &root,
                &mut Cursor::new(b"not-an-envelope"),
                &mut output,
                1_000
            ),
            Err(ProviderIntakeCliError::EnvelopeRejected)
        );
        let oversized = vec![0u8; MAX_INTAKE_ENVELOPE_BYTES + 1];
        assert_eq!(
            open_at(&root, &mut Cursor::new(oversized), &mut output, 1_000),
            Err(ProviderIntakeCliError::EnvelopeTooLarge)
        );
    }

    #[test]
    fn owner_private_key_permissions_fail_closed() {
        let (_temp, root) = root();
        provision_at(&root).unwrap();
        let key = root.join("authority/service.intake-envelope.v1/recipient.x25519.key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            load_key(&root),
            Err(ProviderIntakeCliError::UnsafeRecipientKey)
        );
        assert_eq!(
            provision_at(&root),
            Err(ProviderIntakeCliError::UnsafeRecipientKey)
        );
    }

    #[test]
    fn cli_open_writes_no_json_or_secret_path_to_binary_success_frame() {
        let (_temp, root) = root();
        provision_at(&root).unwrap();
        let (public, _) = public_binding(&root).unwrap();
        let envelope =
            seal_intake_envelope_v1(&public, &[8; 32], &[9; 12], b"intake", b"evidence", 2_000)
                .unwrap();
        let mut output = Vec::new();
        run_at(
            command(ProviderIntakeCommand::Open),
            &root,
            &mut Cursor::new(envelope),
            &mut output,
            || Ok(1_000),
        )
        .unwrap();
        assert!(output.starts_with(OPENED_FRAME_MAGIC));
        assert!(!output
            .windows(23)
            .any(|bytes| bytes == b"recipient.x25519.key"));
    }
}
