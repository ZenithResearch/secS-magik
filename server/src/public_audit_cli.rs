use crate::public_audit::{PublicAuditBundle, PublicAuditVerificationError};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicAuditCliVerification {
    pub valid: bool,
    pub bundle_version: String,
    pub chain_algorithm_version: String,
    pub chain_scope: String,
    pub root_hash_hex: String,
    pub receipt_count: usize,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct PublicAuditCliError {
    pub verification_error: Option<PublicAuditVerificationError>,
    message: String,
}

impl PublicAuditCliError {
    fn io(path: &Path, error: std::io::Error) -> Self {
        Self {
            verification_error: None,
            message: format!(
                "public_audit_cli_error=ReadBundleFailed path={} error={}",
                path.display(),
                error
            ),
        }
    }

    fn parse(error: serde_json::Error) -> Self {
        Self {
            verification_error: None,
            message: format!("public_audit_cli_error=ParseBundleFailed error={error}"),
        }
    }

    fn verification(error: PublicAuditVerificationError) -> Self {
        Self {
            verification_error: Some(error.clone()),
            message: format!("public_audit_verification_error={error:?}"),
        }
    }
}

impl fmt::Display for PublicAuditCliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for PublicAuditCliError {}

pub fn verify_public_audit_bundle_file(
    path: impl AsRef<Path>,
) -> Result<PublicAuditCliVerification, PublicAuditCliError> {
    let path = path.as_ref();
    let bytes = fs::read(path).map_err(|error| PublicAuditCliError::io(path, error))?;
    let bundle: PublicAuditBundle =
        serde_json::from_slice(&bytes).map_err(PublicAuditCliError::parse)?;
    verify_public_audit_bundle(&bundle)
}

pub fn verify_public_audit_bundle(
    bundle: &PublicAuditBundle,
) -> Result<PublicAuditCliVerification, PublicAuditCliError> {
    bundle
        .verify_local_public_audit()
        .map_err(PublicAuditCliError::verification)?;
    Ok(PublicAuditCliVerification {
        valid: true,
        bundle_version: bundle.version.clone(),
        chain_algorithm_version: bundle.chain.algorithm_version.clone(),
        chain_scope: bundle.chain.chain_scope.clone(),
        root_hash_hex: bundle.chain.root_hash_hex.clone(),
        receipt_count: bundle.chain.receipt_count,
        error: None,
    })
}

impl PublicAuditCliVerification {
    pub fn render_summary(&self) -> String {
        format!(
            "valid={} bundle_version={} chain_algorithm_version={} chain_scope={} root_hash_hex={} receipt_count={}",
            self.valid,
            self.bundle_version,
            self.chain_algorithm_version,
            self.chain_scope,
            self.root_hash_hex,
            self.receipt_count
        )
    }
}
