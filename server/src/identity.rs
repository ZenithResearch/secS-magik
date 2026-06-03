use crate::receipt::{AuthenticatorKind, Receipt};
use crate::runtime_mode::RuntimeMode;
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
}

#[derive(Debug, Clone, Default)]
pub struct PublicVerifierKeyRegistry {
    keys: HashMap<String, PublicVerifierKey>,
}

impl PublicVerifierKeyRegistry {
    pub fn from_keys(keys: impl IntoIterator<Item = PublicVerifierKey>) -> Self {
        let mut registry = Self::default();
        for key in keys {
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
            .ok_or(VerificationError::InvalidSignature)?;
        signed.verify_ed25519_with_key(&key.public_key, expected_audience, now)
    }

    pub fn verify_receipt(&self, receipt: &Receipt) -> Result<(), VerificationError> {
        let key = self
            .get(&receipt.signer_key_id)
            .ok_or(VerificationError::InvalidSignature)?;
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

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn authenticator_kind(&self) -> AuthenticatorKind {
        self.authenticator_kind
    }

    pub fn public_verifier_key(&self) -> PublicVerifierKey {
        PublicVerifierKey {
            key_id: self.signer_key_id.clone(),
            algorithm: "ed25519".to_string(),
            public_key: self.public_key,
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
