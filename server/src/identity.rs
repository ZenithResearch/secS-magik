use crate::receipt::{AuthenticatorKind, Receipt};
use crate::runtime_mode::RuntimeMode;
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierIdentityConfig {
    pub runtime_mode: RuntimeMode,
    pub verifier_key_path: Option<PathBuf>,
    pub verifier_key_id: Option<String>,
}

impl VerifierIdentityConfig {
    pub fn from_env() -> Self {
        Self {
            runtime_mode: RuntimeMode::from_env(),
            verifier_key_path: std::env::var_os("SECS_VERIFIER_KEY_PATH").map(PathBuf::from),
            verifier_key_id: std::env::var("SECS_VERIFIER_KEY_ID").ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityConfigError {
    MissingVerifierKeyPath,
    KeyFileInaccessible { path: PathBuf },
    MalformedVerifierKey,
    UnsafeVerifierKeyFile { path: PathBuf },
    UnsafeVerifierKeyId,
    LocalDevRequiresExplicitFixture,
}

impl fmt::Display for IdentityConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingVerifierKeyPath => write!(
                f,
                "production_verified requires explicit SECS_VERIFIER_KEY_PATH verifier key config"
            ),
            Self::KeyFileInaccessible { path } => {
                write!(f, "verifier key file is inaccessible: {}", path.display())
            }
            Self::MalformedVerifierKey => write!(
                f,
                "verifier key file must contain a 32-byte hex Ed25519 secret"
            ),
            Self::UnsafeVerifierKeyFile { path } => write!(
                f,
                "verifier key file must be a regular owner-private file: {}",
                path.display()
            ),
            Self::UnsafeVerifierKeyId => write!(
                f,
                "verifier key id override must not contain local paths or secret-shaped material"
            ),
            Self::LocalDevRequiresExplicitFixture => write!(
                f,
                "local/dev verifier keys must be created through explicit fixture helpers"
            ),
        }
    }
}

impl std::error::Error for IdentityConfigError {}

#[derive(Debug, Clone)]
pub struct PublicVerifierKey {
    pub key_id: String,
    pub algorithm: String,
    pub public_key: VerifyingKey,
    pub status: VerificationKeyStatus,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
    pub revoked_at: Option<u64>,
    pub replaced_by: Option<String>,
    pub production_authority: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationKeyStatus {
    Active,
    Revoked,
    Expired,
    Unknown,
    NotYetValid,
}

impl PublicVerifierKey {
    pub fn active(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        public_key: VerifyingKey,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            algorithm: algorithm.into(),
            public_key,
            status: VerificationKeyStatus::Active,
            not_before: None,
            not_after: None,
            revoked_at: None,
            replaced_by: None,
            production_authority: false,
        }
    }

    pub fn configured_production_authority(
        key_id: impl Into<String>,
        algorithm: impl Into<String>,
        public_key: VerifyingKey,
    ) -> Self {
        Self::active(key_id, algorithm, public_key).with_production_authority(true)
    }

    pub fn with_status(mut self, status: VerificationKeyStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_validity_window(mut self, not_before: Option<u64>, not_after: Option<u64>) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    pub fn with_revoked_at(mut self, revoked_at: Option<u64>) -> Self {
        self.revoked_at = revoked_at;
        self
    }

    pub fn with_replaced_by(mut self, replaced_by: Option<String>) -> Self {
        self.replaced_by = replaced_by;
        self
    }

    pub fn with_production_authority(mut self, production_authority: bool) -> Self {
        self.production_authority = production_authority;
        self
    }

    fn ensure_active_at(&self, now: u64) -> Result<(), VerificationError> {
        match self.status {
            VerificationKeyStatus::Active => {}
            VerificationKeyStatus::Revoked => return Err(VerificationError::RevokedVerifierKey),
            VerificationKeyStatus::Expired => return Err(VerificationError::ExpiredVerifierKey),
            VerificationKeyStatus::Unknown => return Err(VerificationError::UnknownVerifierKey),
            VerificationKeyStatus::NotYetValid => {
                return Err(VerificationError::NotYetValidVerifierKey)
            }
        }

        if let Some(not_before) = self.not_before {
            if now < not_before {
                return Err(VerificationError::NotYetValidVerifierKey);
            }
        }
        if let Some(not_after) = self.not_after {
            if now > not_after {
                return Err(VerificationError::ExpiredVerifierKey);
            }
        }
        if let Some(revoked_at) = self.revoked_at {
            if revoked_at <= now {
                return Err(VerificationError::RevokedVerifierKey);
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct PublicVerifierKeyRegistry {
    keys: HashMap<String, PublicVerifierKey>,
    duplicate_key_ids: HashSet<String>,
}

impl PublicVerifierKeyRegistry {
    pub fn from_keys(keys: impl IntoIterator<Item = PublicVerifierKey>) -> Self {
        let mut registry = Self::default();
        for key in keys {
            if registry.keys.contains_key(&key.key_id) {
                registry.duplicate_key_ids.insert(key.key_id.clone());
            }
            registry.keys.insert(key.key_id.clone(), key);
        }
        registry
    }

    pub fn get(&self, key_id: &str) -> Option<&PublicVerifierKey> {
        self.keys.get(key_id)
    }

    pub fn verify_signed_context(
        &self,
        signed: &SignedVerifiedCallContext,
        expected_audience: &str,
        now: u64,
    ) -> Result<(), VerificationError> {
        let key = self
            .get(&signed.signer_key_id)
            .ok_or(VerificationError::UnknownVerifierKey)?;
        if self.duplicate_key_ids.contains(&signed.signer_key_id) {
            return Err(VerificationError::UnknownVerifierKey);
        }
        key.ensure_active_at(now)?;
        signed.verify_ed25519_with_key(&key.public_key, expected_audience, now)
    }

    pub fn verify_production_signed_context(
        &self,
        signed: &SignedVerifiedCallContext,
        expected_audience: &str,
        now: u64,
    ) -> Result<(), VerificationError> {
        let key = self
            .get(&signed.signer_key_id)
            .ok_or(VerificationError::UnknownVerifierKey)?;
        if self.duplicate_key_ids.contains(&signed.signer_key_id) {
            return Err(VerificationError::UnknownVerifierKey);
        }
        key.ensure_active_at(now)?;
        if !key.production_authority
            || key.algorithm != "ed25519"
            || signed.authenticator_kind != AuthenticatorKind::Ed25519NodeAndVerifier
        {
            return Err(VerificationError::UntrustedVerifierKey);
        }
        signed.verify_ed25519_with_key(&key.public_key, expected_audience, now)
    }

    pub fn verify_receipt_at(&self, receipt: &Receipt, now: u64) -> Result<(), VerificationError> {
        let key = self
            .get(&receipt.signer_key_id)
            .ok_or(VerificationError::UnknownVerifierKey)?;
        if self.duplicate_key_ids.contains(&receipt.signer_key_id) {
            return Err(VerificationError::UnknownVerifierKey);
        }
        let _ = now;
        key.ensure_active_at(receipt.timestamp)?;
        receipt.verify_ed25519_with_key(&key.public_key)
    }

    pub fn verify_production_receipt_at(
        &self,
        receipt: &Receipt,
        now: u64,
    ) -> Result<(), VerificationError> {
        let key = self
            .get(&receipt.signer_key_id)
            .ok_or(VerificationError::UnknownVerifierKey)?;
        if self.duplicate_key_ids.contains(&receipt.signer_key_id) {
            return Err(VerificationError::UnknownVerifierKey);
        }
        let _ = now;
        key.ensure_active_at(receipt.timestamp)?;
        if !key.production_authority
            || key.algorithm != "ed25519"
            || receipt.authenticator_kind != AuthenticatorKind::Ed25519NodeAndVerifier
        {
            return Err(VerificationError::UntrustedVerifierKey);
        }
        receipt.verify_ed25519_with_key(&key.public_key)
    }
}

#[derive(Debug, Clone)]
pub struct NodeVerifierIdentity {
    signer_key_id: String,
    signing_key: SigningKey,
    public_key: VerifyingKey,
    authenticator_kind: AuthenticatorKind,
}

impl NodeVerifierIdentity {
    pub fn signer_key_id(&self) -> &str {
        &self.signer_key_id
    }

    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn authenticator_kind(&self) -> AuthenticatorKind {
        self.authenticator_kind
    }

    pub fn public_verifier_key(&self) -> PublicVerifierKey {
        match self.authenticator_kind {
            AuthenticatorKind::LocalDevUntrusted => {
                PublicVerifierKey::active(self.signer_key_id.clone(), "ed25519", self.public_key)
            }
            _ => PublicVerifierKey::configured_production_authority(
                self.signer_key_id.clone(),
                "ed25519",
                self.public_key,
            ),
        }
    }

    pub fn sign_context(
        &self,
        context: VerifiedCallContext,
    ) -> Result<SignedVerifiedCallContext, VerificationError> {
        context.sign_ed25519(
            &self.signer_key_id,
            &self.secret_key_bytes(),
            self.authenticator_kind,
        )
    }

    pub fn sign_receipt(&self, receipt: Receipt) -> Result<Receipt, VerificationError> {
        receipt.sign_ed25519(
            &self.signer_key_id,
            &self.secret_key_bytes(),
            self.authenticator_kind,
        )
    }
}

pub fn load_node_verifier_identity(
    config: &VerifierIdentityConfig,
) -> Result<NodeVerifierIdentity, IdentityConfigError> {
    let path = match &config.verifier_key_path {
        Some(path) => path,
        None => {
            return match config.runtime_mode {
                RuntimeMode::ProductionVerified => Err(IdentityConfigError::MissingVerifierKeyPath),
                RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel => {
                    Err(IdentityConfigError::LocalDevRequiresExplicitFixture)
                }
            };
        }
    };

    validate_key_file_safety(path)?;
    let raw = std::fs::read_to_string(path)
        .map_err(|_| IdentityConfigError::KeyFileInaccessible { path: path.clone() })?;
    let secret_key = parse_hex_secret_key(&raw)?;
    let signing_key = SigningKey::from_bytes(&secret_key);
    let public_key = VerifyingKey::from(&signing_key);
    let signer_key_id = match &config.verifier_key_id {
        Some(key_id) => safe_configured_key_id(key_id)?,
        None => derive_ed25519_key_id(&public_key),
    };

    Ok(NodeVerifierIdentity {
        signer_key_id,
        signing_key,
        public_key,
        authenticator_kind: AuthenticatorKind::Ed25519NodeAndVerifier,
    })
}

pub fn explicit_test_fixture_identity(
    signer_key_id: impl Into<String>,
    secret_key: [u8; 32],
) -> NodeVerifierIdentity {
    let signing_key = SigningKey::from_bytes(&secret_key);
    let public_key = VerifyingKey::from(&signing_key);
    NodeVerifierIdentity {
        signer_key_id: signer_key_id.into(),
        signing_key,
        public_key,
        authenticator_kind: AuthenticatorKind::LocalDevUntrusted,
    }
}

fn validate_key_file_safety(path: &PathBuf) -> Result<(), IdentityConfigError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| IdentityConfigError::KeyFileInaccessible { path: path.clone() })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(IdentityConfigError::UnsafeVerifierKeyFile { path: path.clone() });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IdentityConfigError::UnsafeVerifierKeyFile { path: path.clone() });
        }
    }

    Ok(())
}

fn parse_hex_secret_key(raw: &str) -> Result<[u8; 32], IdentityConfigError> {
    let value: String = raw.chars().filter(|ch| !ch.is_whitespace()).collect();
    if value.len() != 64 {
        return Err(IdentityConfigError::MalformedVerifierKey);
    }

    let mut bytes = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex =
            std::str::from_utf8(chunk).map_err(|_| IdentityConfigError::MalformedVerifierKey)?;
        bytes[index] =
            u8::from_str_radix(hex, 16).map_err(|_| IdentityConfigError::MalformedVerifierKey)?;
    }
    Ok(bytes)
}

fn safe_configured_key_id(value: &str) -> Result<String, IdentityConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || looks_like_secret_hex(trimmed)
    {
        return Err(IdentityConfigError::UnsafeVerifierKeyId);
    }
    Ok(trimmed.to_string())
}

fn looks_like_secret_hex(value: &str) -> bool {
    value.len() >= 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

pub fn derive_ed25519_key_id(public_key: &VerifyingKey) -> String {
    let digest = Sha256::digest(public_key.as_bytes());
    format!("ed25519:{}", lower_hex(&digest[..16]))
}

fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
