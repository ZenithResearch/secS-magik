//! Deny-by-default disclosure policy and privacy scanning helpers.
//!
//! I02 boundary: this module only enforces receipt/operator-surface redaction
//! and over-disclosure rejection. It does not implement anonymous membership,
//! selective audit viewing keys, nullifier semantics, or node-registration
//! operation semantics.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySurface {
    VerifyReceipt,
    RejectReceipt,
    ExecuteReceipt,
    ReadinessStatus,
    DemoProjection,
    Log,
    OperatorCli,
    PublicAudit,
    HandlerContext,
}

impl PrivacySurface {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VerifyReceipt => "verify_receipt",
            Self::RejectReceipt => "reject_receipt",
            Self::ExecuteReceipt => "execute_receipt",
            Self::ReadinessStatus => "readiness_status",
            Self::DemoProjection => "demo_projection",
            Self::Log => "log",
            Self::OperatorCli => "operator_cli",
            Self::PublicAudit => "public_audit",
            Self::HandlerContext => "handler_context",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForbiddenFieldClass {
    WalletIdentity,
    HolderIdentity,
    SubjectIdentity,
    CredentialIdentity,
    RawCredentialAttributes,
    RawProofBytes,
    WitnessPrivateInputs,
    TraceDebugMaterial,
    TokenSecret,
    SourceAuthToken,
    IssuerPrivateMaterial,
    StableNullifier,
    NetworkMetadata,
}

impl ForbiddenFieldClass {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::WalletIdentity => "wallet_identity",
            Self::HolderIdentity => "holder_identity",
            Self::SubjectIdentity => "subject_identity",
            Self::CredentialIdentity => "credential_identity",
            Self::RawCredentialAttributes => "raw_credential_attributes",
            Self::RawProofBytes => "raw_proof_bytes",
            Self::WitnessPrivateInputs => "witness_private_inputs",
            Self::TraceDebugMaterial => "trace_debug_material",
            Self::TokenSecret => "token_secret",
            Self::SourceAuthToken => "source_auth_token",
            Self::IssuerPrivateMaterial => "issuer_private_material",
            Self::StableNullifier => "stable_nullifier",
            Self::NetworkMetadata => "network_metadata",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureRepresentation {
    RedactedDigest,
    RedactedPlaceholder,
    DerivedStatus,
}

impl DisclosureRepresentation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RedactedDigest => "redacted_digest",
            Self::RedactedPlaceholder => "redacted_placeholder",
            Self::DerivedStatus => "derived_status",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePermission {
    pub class: ForbiddenFieldClass,
    pub surface: PrivacySurface,
    pub representation: DisclosureRepresentation,
}

impl DisclosurePermission {
    pub fn new(
        class: ForbiddenFieldClass,
        surface: PrivacySurface,
        representation: DisclosureRepresentation,
    ) -> Self {
        Self {
            class,
            surface,
            representation,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosurePolicy {
    pub policy_id: String,
    pub policy_version: u16,
    pub permissions: Vec<DisclosurePermission>,
}

impl DisclosurePolicy {
    pub fn deny_by_default(policy_id: impl Into<String>, policy_version: u16) -> Self {
        Self {
            policy_id: policy_id.into(),
            policy_version,
            permissions: Vec::new(),
        }
    }

    pub fn default_i02() -> Self {
        let mut policy = Self::deny_by_default("secs-i02-deny-by-default", 1);
        for class in [
            ForbiddenFieldClass::WalletIdentity,
            ForbiddenFieldClass::HolderIdentity,
            ForbiddenFieldClass::SubjectIdentity,
            ForbiddenFieldClass::CredentialIdentity,
            ForbiddenFieldClass::RawCredentialAttributes,
            ForbiddenFieldClass::RawProofBytes,
            ForbiddenFieldClass::WitnessPrivateInputs,
            ForbiddenFieldClass::TraceDebugMaterial,
            ForbiddenFieldClass::TokenSecret,
            ForbiddenFieldClass::SourceAuthToken,
            ForbiddenFieldClass::IssuerPrivateMaterial,
            ForbiddenFieldClass::StableNullifier,
            ForbiddenFieldClass::NetworkMetadata,
        ] {
            for surface in [
                PrivacySurface::VerifyReceipt,
                PrivacySurface::RejectReceipt,
                PrivacySurface::ExecuteReceipt,
                PrivacySurface::ReadinessStatus,
                PrivacySurface::DemoProjection,
                PrivacySurface::Log,
                PrivacySurface::OperatorCli,
                PrivacySurface::PublicAudit,
            ] {
                for representation in [
                    DisclosureRepresentation::RedactedDigest,
                    DisclosureRepresentation::RedactedPlaceholder,
                    DisclosureRepresentation::DerivedStatus,
                ] {
                    policy = policy.with_permission(DisclosurePermission::new(
                        class,
                        surface,
                        representation,
                    ));
                }
            }
        }
        policy
    }

    pub fn with_permission(mut self, permission: DisclosurePermission) -> Self {
        if !self.permissions.contains(&permission) {
            self.permissions.push(permission);
        }
        self
    }

    pub fn permits(
        &self,
        class: ForbiddenFieldClass,
        surface: PrivacySurface,
        representation: DisclosureRepresentation,
    ) -> bool {
        self.permissions.iter().any(|permission| {
            permission.class == class
                && permission.surface == surface
                && permission.representation == representation
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyViolation {
    pub surface: PrivacySurface,
    pub class: ForbiddenFieldClass,
    pub field: String,
}

pub fn scan_json_value(
    surface: PrivacySurface,
    value: &serde_json::Value,
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    scan_value(surface, value, policy)
}

pub fn scan_json_bytes(
    surface: PrivacySurface,
    bytes: &[u8],
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    if bytes.is_empty() {
        return Ok(());
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) else {
        return scan_text(surface, &String::from_utf8_lossy(bytes), policy);
    };
    scan_json_value(surface, &value, policy)
}

pub fn scan_string_fields(
    surface: PrivacySurface,
    fields: &[String],
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    for field in fields {
        scan_text(surface, field, policy)?;
    }
    Ok(())
}

fn scan_value(
    surface: PrivacySurface,
    value: &serde_json::Value,
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    match value {
        serde_json::Value::Object(object) => {
            for (key, nested) in object {
                check_field_name(surface, key, policy)?;
                scan_value(surface, nested, policy)?;
            }
        }
        serde_json::Value::Array(values) => {
            for nested in values {
                scan_value(surface, nested, policy)?;
            }
        }
        serde_json::Value::String(text) => scan_text(surface, text, policy)?,
        _ => {}
    }
    Ok(())
}

fn scan_text(
    surface: PrivacySurface,
    text: &str,
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    if text.contains("I02_SENTINEL_") {
        return Err(PrivacyViolation {
            surface,
            class: ForbiddenFieldClass::TraceDebugMaterial,
            field: "sentinel".to_string(),
        });
    }
    if let Some((prefix, rest)) = text.split_once(':') {
        if prefix == "subject" {
            return Ok(());
        }
        if classify_field_name(prefix).is_some() && is_redacted_marker(rest) {
            return Ok(());
        }
        check_field_name(surface, prefix, policy)?;
    }
    Ok(())
}

fn is_redacted_marker(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("[redacted]")
        || value.contains("redacted_")
        || value.starts_with("sha256:")
        || value.starts_with("digest:")
}

fn check_field_name(
    surface: PrivacySurface,
    field: &str,
    policy: &DisclosurePolicy,
) -> Result<(), PrivacyViolation> {
    if field == "signature"
        && matches!(
            surface,
            PrivacySurface::VerifyReceipt
                | PrivacySurface::RejectReceipt
                | PrivacySurface::ExecuteReceipt
                | PrivacySurface::PublicAudit
        )
    {
        return Ok(());
    }
    if let Some((class, representation)) = classify_field_name(field) {
        if representation != DisclosureRepresentation::RedactedDigest
            || !policy.permits(class, surface, representation)
        {
            return Err(PrivacyViolation {
                surface,
                class,
                field: field.to_string(),
            });
        }
    }
    Ok(())
}

pub fn classify_field_name(field: &str) -> Option<(ForbiddenFieldClass, DisclosureRepresentation)> {
    let representation = if field.ends_with("_sha256") {
        DisclosureRepresentation::RedactedDigest
    } else {
        DisclosureRepresentation::DerivedStatus
    };
    let base = field.strip_suffix("_sha256").unwrap_or(field);
    let class = match base {
        "wallet_id" | "walletId" | "wallet" | "wallet_address" | "walletAddress" => {
            ForbiddenFieldClass::WalletIdentity
        }
        "holder_id" | "holderId" | "holder" | "holder_did" | "holderDid" => {
            ForbiddenFieldClass::HolderIdentity
        }
        "subject_id"
        | "subjectId"
        | "subject"
        | "subject_handle"
        | "subjectHandle"
        | "stable_subject_handle" => ForbiddenFieldClass::SubjectIdentity,
        "credential_id" | "credentialId" | "cred_id" | "credential_uuid" => {
            ForbiddenFieldClass::CredentialIdentity
        }
        "credential"
        | "credential_payload"
        | "attributes"
        | "claims"
        | "raw_attributes"
        | "rawCredentialAttributes" => ForbiddenFieldClass::RawCredentialAttributes,
        "proof" | "proof_bytes" | "raw_proof" | "signature" | "sig_bytes"
        | "presentation_proof" => ForbiddenFieldClass::RawProofBytes,
        "witness" | "private_witness" | "secret" | "preimage" | "nullifier_preimage" => {
            ForbiddenFieldClass::WitnessPrivateInputs
        }
        "trace"
        | "debug_trace"
        | "presentation_trace"
        | "span_payload"
        | "backtrace_with_payload" => ForbiddenFieldClass::TraceDebugMaterial,
        "token" | "bearer" | "authorization" | "auth_header" | "api_key" | "session_token" => {
            ForbiddenFieldClass::TokenSecret
        }
        "source_auth_token" | "sourceAuthToken" | "authority_source_token" | "upstream_token" => {
            ForbiddenFieldClass::SourceAuthToken
        }
        "issuer_private_key"
        | "issuer_sk"
        | "issuer_secret"
        | "issuer_private_material"
        | "signing_secret" => ForbiddenFieldClass::IssuerPrivateMaterial,
        "nullifier" | "stable_nullifier" | "global_nullifier" | "link_secret" | "linking_tag" => {
            ForbiddenFieldClass::StableNullifier
        }
        "ip" | "ip_address" | "remote_addr" | "peer_addr" | "x_forwarded_for" | "user_agent"
        | "network_metadata" => ForbiddenFieldClass::NetworkMetadata,
        _ => return None,
    };
    Some((class, representation))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacySafeHandlerContext {
    pub context_id: String,
    pub opcode: u8,
    pub operation: String,
    pub resource: Option<String>,
    pub audience: String,
    pub evidence_summary: Vec<String>,
    pub capability_result: String,
    pub credential_result: String,
    pub descriptor_fingerprint: String,
    pub replay_scope: String,
    pub handler_id: Option<String>,
    pub policy_id: String,
    pub policy_version: u16,
    pub identity_boundary: String,
}
