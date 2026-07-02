//! Canonical secS verification/request/public-input context contract (I03).
//!
//! ADR / ownership note:
//! - I03 owns this vocabulary, required/optional status, canonical serialization,
//!   and fingerprint version. Downstream evidence, source, proof, nullifier, and
//!   receipt work must bind through this context or request an I03 follow-up.
//! - Removing, renaming, weakening, or changing serialization for fields requires
//!   a `CONTEXT_FINGERPRINT_VERSION` bump plus migration tests. Adding optional
//!   fields must fail closed for policies that require them; missing observed
//!   values never silently default to a match.
//! - Public-data rule: this type may carry public identifiers, fingerprints,
//!   commitments, versions, redacted handles, and reason dimensions. It must not
//!   carry raw credentials, raw proof bytes, private witnesses, wallet/holder
//!   private ids, bearer/source tokens, private keys, nullifier preimages, raw
//!   credential attributes, packet payload bytes, or raw signature bytes.
//! - Canonical serialization for fingerprints is `secs-verification-context-json-v1`:
//!   serde JSON over this struct's stable declared field order with explicit
//!   `null` for absent optional fields. The fingerprint is SHA-256 over
//!   `CONTEXT_FINGERPRINT_VERSION || canonical_json`; SHA-256 is already the
//!   repository's descriptor/context fingerprint primitive.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::manifest::OperationDescriptor;

pub const CONTEXT_SCHEMA_ID: &str = "secs-verification-context";
pub const CONTEXT_SCHEMA_VERSION: u16 = 1;
pub const CANONICAL_SERIALIZATION: &str = "secs-verification-context-json-v1";
pub const CONTEXT_FINGERPRINT_VERSION: &str = "secs-vctx-fp-v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextProjectionError {
    MissingRequiredField(&'static str),
}

impl ContextProjectionError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MissingRequiredField(_) => "context_missing_required_field",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationContext {
    pub context_schema_id: String,
    pub context_schema_version: u16,
    pub canonical_serialization: String,
    pub context_fingerprint_version: String,

    pub receiver_id: String,
    pub audience_id: String,
    pub service_id: Option<String>,

    pub operation_id: String,
    pub operation_kind: String,
    pub opcode: u8,
    pub handler_id: String,
    pub action_scope: Option<String>,

    pub resource_type: String,
    pub resource_id: String,
    pub resource_scope: String,
    pub resource_fingerprint: Option<String>,

    pub subject_binding_kind: String,
    pub subject_commitment: Option<String>,

    pub manifest_id: String,
    pub manifest_version: String,
    pub manifest_fingerprint: String,
    pub descriptor_id: String,
    pub descriptor_version: String,
    pub descriptor_fingerprint: String,
    pub required_evidence_tier: String,
    pub required_adapter_kind: String,

    pub privacy_policy_id: String,
    pub privacy_policy_version: String,
    pub privacy_policy_fingerprint: String,
    pub disclosure_scope_id: String,
    pub disclosure_scope_version: String,
    pub disclosure_class: String,

    pub issuer_id: Option<String>,
    pub authority_source_id: Option<String>,
    pub authority_mode: Option<String>,
    pub source_key_id: Option<String>,
    pub source_schema_version: Option<String>,

    pub federation_id: Option<String>,
    pub committee_id: Option<String>,
    pub committee_epoch: Option<String>,

    pub root_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub root_scope: Option<String>,
    pub root_epoch: Option<String>,
    pub finality_mode: Option<String>,
    pub validity_window_id: String,

    pub issued_at: u64,
    pub valid_until: u64,
    pub freshness_window_id: String,
    pub request_id: String,
    pub challenge_id: String,
    pub challenge_nonce_fingerprint: String,
    pub session_replay_scope: String,

    pub proof_adapter_id: Option<String>,
    pub proof_system_id: Option<String>,
    pub proof_kind: Option<String>,
    pub circuit_id: Option<String>,
    pub circuit_version: Option<String>,
    pub vk_id: Option<String>,
    pub vk_fingerprint: Option<String>,
    pub public_input_schema_id: Option<String>,
    pub public_input_schema_version: Option<String>,
    pub public_input_fingerprint: Option<String>,

    pub nullifier_domain_id: Option<String>,
    pub nullifier_domain_version: Option<String>,
    pub nullifier_domain_fingerprint: Option<String>,

    pub evidence_kind: String,
    pub evidence_id: Option<String>,
    pub evidence_schema_version: String,
    pub evidence_tier: String,
    pub adapter_kind: String,
}

impl VerificationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn expected_from_descriptor(
        receiver_id: &str,
        audience_id: &str,
        descriptor: &OperationDescriptor,
        resource_id: Option<&str>,
        request_id: &str,
        challenge_id: &str,
        challenge_nonce_fingerprint: &str,
        issued_at: u64,
    ) -> Result<Self, ContextProjectionError> {
        let resource_id =
            resource_id.ok_or(ContextProjectionError::MissingRequiredField("resource_id"))?;
        let descriptor_fingerprint = descriptor.authorization_fingerprint();
        let manifest_id = "receiver-local-default-v0";
        let manifest_version = "1";
        let manifest_fingerprint = fingerprint_join(
            "manifest:sha256",
            &[manifest_id, manifest_version, &descriptor_fingerprint],
        );
        let accepted_evidence = descriptor.accepted_evidence.join("+");

        Ok(Self {
            context_schema_id: CONTEXT_SCHEMA_ID.to_string(),
            context_schema_version: CONTEXT_SCHEMA_VERSION,
            canonical_serialization: CANONICAL_SERIALIZATION.to_string(),
            context_fingerprint_version: CONTEXT_FINGERPRINT_VERSION.to_string(),
            receiver_id: receiver_id.to_string(),
            audience_id: audience_id.to_string(),
            service_id: Some(receiver_id.to_string()),
            operation_id: descriptor.name.as_str().to_string(),
            operation_kind: "opcode".to_string(),
            opcode: descriptor.opcode,
            handler_id: descriptor.handler_id.clone(),
            action_scope: Some(descriptor.name.as_str().to_string()),
            resource_type: "resource".to_string(),
            resource_id: resource_id.to_string(),
            resource_scope: "exact".to_string(),
            resource_fingerprint: Some(fingerprint_join("resource:sha256", &[resource_id])),
            subject_binding_kind: "policy_dependent".to_string(),
            subject_commitment: None,
            manifest_id: manifest_id.to_string(),
            manifest_version: manifest_version.to_string(),
            manifest_fingerprint,
            descriptor_id: descriptor.name.as_str().to_string(),
            descriptor_version: descriptor.max_ttl_seconds.to_string(),
            descriptor_fingerprint,
            required_evidence_tier: required_evidence_tier(descriptor).to_string(),
            required_adapter_kind: accepted_evidence.clone(),
            privacy_policy_id: "secs-i02-compat-privacy-policy".to_string(),
            privacy_policy_version: "1".to_string(),
            privacy_policy_fingerprint: fingerprint_join(
                "privacy:sha256",
                &["secs-i02-compat-privacy-policy", "1"],
            ),
            disclosure_scope_id: "secs-i02-compat-disclosure-scope".to_string(),
            disclosure_scope_version: "1".to_string(),
            disclosure_class: "redacted_public_ids".to_string(),
            issuer_id: None,
            authority_source_id: None,
            authority_mode: None,
            source_key_id: None,
            source_schema_version: None,
            federation_id: None,
            committee_id: None,
            committee_epoch: None,
            root_id: None,
            checkpoint_id: None,
            root_scope: None,
            root_epoch: None,
            finality_mode: None,
            validity_window_id: format!("ttl:{}", descriptor.max_ttl_seconds),
            issued_at,
            valid_until: issued_at.saturating_add(descriptor.max_ttl_seconds),
            freshness_window_id: format!("max-age:{}", descriptor.max_ttl_seconds),
            request_id: request_id.to_string(),
            challenge_id: challenge_id.to_string(),
            challenge_nonce_fingerprint: challenge_nonce_fingerprint.to_string(),
            session_replay_scope: "session:opcode:nonce".to_string(),
            proof_adapter_id: None,
            proof_system_id: None,
            proof_kind: None,
            circuit_id: None,
            circuit_version: None,
            vk_id: None,
            vk_fingerprint: None,
            public_input_schema_id: None,
            public_input_schema_version: None,
            public_input_fingerprint: None,
            nullifier_domain_id: None,
            nullifier_domain_version: None,
            nullifier_domain_fingerprint: None,
            evidence_kind: accepted_evidence,
            evidence_id: None,
            evidence_schema_version: "descriptor-projection-v1".to_string(),
            evidence_tier: required_evidence_tier(descriptor).to_string(),
            adapter_kind: descriptor.accepted_evidence.join("+"),
        })
    }

    pub fn fixture() -> Self {
        Self {
            context_schema_id: CONTEXT_SCHEMA_ID.to_string(),
            context_schema_version: CONTEXT_SCHEMA_VERSION,
            canonical_serialization: CANONICAL_SERIALIZATION.to_string(),
            context_fingerprint_version: CONTEXT_FINGERPRINT_VERSION.to_string(),
            receiver_id: "receiver.alpha".to_string(),
            audience_id: "audience.alpha".to_string(),
            service_id: Some("service.secS".to_string()),
            operation_id: "membership.provision".to_string(),
            operation_kind: "opcode".to_string(),
            opcode: 0x44,
            handler_id: "membership/provision".to_string(),
            action_scope: Some("provision".to_string()),
            resource_type: "resource".to_string(),
            resource_id: "resource://demo/membership".to_string(),
            resource_scope: "exact".to_string(),
            resource_fingerprint: Some("resource:sha256:fixture".to_string()),
            subject_binding_kind: "anonymous_or_blinded".to_string(),
            subject_commitment: Some("subject:commitment:fixture".to_string()),
            manifest_id: "manifest.default".to_string(),
            manifest_version: "1".to_string(),
            manifest_fingerprint: "manifest:sha256:fixture".to_string(),
            descriptor_id: "descriptor.membership.provision".to_string(),
            descriptor_version: "1".to_string(),
            descriptor_fingerprint: "descriptor:sha256:fixture".to_string(),
            required_evidence_tier: "production_shaped".to_string(),
            required_adapter_kind: "dregg_authority".to_string(),
            privacy_policy_id: "privacy.default".to_string(),
            privacy_policy_version: "1".to_string(),
            privacy_policy_fingerprint: "privacy:sha256:fixture".to_string(),
            disclosure_scope_id: "disclosure.minimum".to_string(),
            disclosure_scope_version: "1".to_string(),
            disclosure_class: "redacted_public_ids".to_string(),
            issuer_id: Some("issuer.castalia.fixture".to_string()),
            authority_source_id: Some("source.dregg.fixture".to_string()),
            authority_mode: Some("receiver_held_static".to_string()),
            source_key_id: Some("source-key:fixture".to_string()),
            source_schema_version: Some("source-schema-v1".to_string()),
            federation_id: Some("federation.fixture".to_string()),
            committee_id: Some("committee.fixture".to_string()),
            committee_epoch: Some("committee-epoch-7".to_string()),
            root_id: Some("root.fixture".to_string()),
            checkpoint_id: Some("checkpoint.fixture".to_string()),
            root_scope: Some("membership".to_string()),
            root_epoch: Some("epoch-7".to_string()),
            finality_mode: Some("metadata_only".to_string()),
            validity_window_id: "window.fixture".to_string(),
            issued_at: 1_700_000_000,
            valid_until: 1_700_003_600,
            freshness_window_id: "freshness.5m".to_string(),
            request_id: "request.fixture".to_string(),
            challenge_id: "challenge.fixture".to_string(),
            challenge_nonce_fingerprint: "nonce:sha256:fixture".to_string(),
            session_replay_scope: "session:opcode:nonce".to_string(),
            proof_adapter_id: Some("proof.adapter.fixture".to_string()),
            proof_system_id: Some("proof.system.fixture".to_string()),
            proof_kind: Some("metadata_only".to_string()),
            circuit_id: Some("circuit.fixture".to_string()),
            circuit_version: Some("1".to_string()),
            vk_id: Some("vk.fixture".to_string()),
            vk_fingerprint: Some("vk:sha256:fixture".to_string()),
            public_input_schema_id: Some("public-input.schema.fixture".to_string()),
            public_input_schema_version: Some("1".to_string()),
            public_input_fingerprint: Some("public-input:sha256:fixture".to_string()),
            nullifier_domain_id: Some("nullifier.domain.fixture".to_string()),
            nullifier_domain_version: Some("1".to_string()),
            nullifier_domain_fingerprint: Some("nullifier-domain:sha256:fixture".to_string()),
            evidence_kind: "dregg_authority".to_string(),
            evidence_id: Some("evidence:sha256:fixture".to_string()),
            evidence_schema_version: "evidence-schema-v1".to_string(),
            evidence_tier: "production_shaped".to_string(),
            adapter_kind: "dregg_authority".to_string(),
        }
    }

    pub fn canonical_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn context_fingerprint(&self) -> Result<String, serde_json::Error> {
        let canonical = self.canonical_json()?;
        let mut hasher = Sha256::new();
        hasher.update(CONTEXT_FINGERPRINT_VERSION.as_bytes());
        hasher.update(canonical.as_bytes());
        Ok(format!(
            "{}:sha256:{}",
            CONTEXT_FINGERPRINT_VERSION,
            hex_digest(hasher.finalize().as_slice())
        ))
    }

    pub fn with_audience_id(&self, audience_id: impl Into<String>) -> Self {
        let mut changed = self.clone();
        changed.audience_id = audience_id.into();
        changed
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fingerprint_join(prefix: &str, fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(field.as_bytes());
        hasher.update(b"\n");
    }
    format!("{}:{}", prefix, hex_digest(hasher.finalize().as_slice()))
}

fn required_evidence_tier(descriptor: &OperationDescriptor) -> &'static str {
    if descriptor
        .accepted_evidence
        .iter()
        .any(|kind| kind == "local_static" || kind == "prototype-proof-envelope")
    {
        "local_or_prototype"
    } else {
        "production_shaped"
    }
}
