//! Versioned reusable read authority. Application-owned permission constraints
//! are signed exactly; only the application can interpret them. This contract
//! does not grant child delegation or reinterpret request-credential v1.
use crate::{Result, canonical_json, decode_hex, digest, public_key, verify_signature};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const POLICY: &str = "castalia.read-policy.v1";
pub const CREDENTIAL: &str = "castalia.read-credential.v1";
pub const PRESENTATION: &str = "castalia.read-presentation.v1";
const INVALID: &str = "invalid_read_authority";
const CREDENTIAL_DOMAIN: &[u8] = b"castalia.read-credential.v1/signature\0";
const PROOF_DOMAIN: &[u8] = b"castalia.read-presentation.v1/signature\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub operation: String,
    pub resource: String,
    pub constraints: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema: String,
    pub issuer: String,
    pub key_id: String,
    pub public_key: String,
    pub receiver: String,
    pub audience: String,
    pub permissions: Vec<Permission>,
    pub max_lifetime_seconds: u64,
}
impl Policy {
    pub fn validate(&self) -> Result<()> {
        if self.schema != POLICY || !(60..=3600).contains(&self.max_lifetime_seconds) {
            return Err(INVALID);
        }
        for s in [&self.issuer, &self.key_id, &self.audience] {
            crate::ascii(s)?;
        }
        if public_key(&self.public_key)?.is_weak() {
            return Err(INVALID);
        }
        let url = url::Url::parse(&self.receiver).map_err(|_| INVALID)?;
        if url.scheme() != "https"
            || url.origin().ascii_serialization() != self.receiver
            || !url.username().is_empty()
            || url.password().is_some()
            || url.path() != "/"
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(INVALID);
        }
        permissions(&self.permissions)?;
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(digest(&canonical_json(self)?))
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claims {
    pub schema: String,
    pub credential_id: String,
    pub holder_public_key: String,
    pub installation_id: String,
    pub issuer: String,
    pub key_id: String,
    pub receiver: String,
    pub audience: String,
    pub policy_digest: String,
    pub permissions: Vec<Permission>,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub claims: Claims,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Call {
    pub operation: String,
    pub resource: String,
    pub parameters: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema: String,
    pub credential_digest: String,
    pub call_digest: String,
    pub receiver: String,
    pub nonce: String,
    pub issued_at: u64,
    pub signature: String,
}
impl Proof {
    pub fn unsigned(credential: &Credential, call: &Call, nonce: String, now: u64) -> Result<Self> {
        decode_hex::<16>(&nonce)?;
        bounded(call)?;
        Ok(Self {
            schema: PRESENTATION.into(),
            credential_digest: digest(&bounded(credential)?),
            call_digest: digest(&bounded(call)?),
            receiver: credential.claims.receiver.clone(),
            nonce,
            issued_at: now,
            signature: String::new(),
        })
    }
    pub fn transcript(&self) -> Result<Vec<u8>> {
        let mut bytes = PROOF_DOMAIN.to_vec();
        bytes.extend(canonical_json(&json!({"schema":self.schema,"credential_digest":self.credential_digest,"call_digest":self.call_digest,"receiver":self.receiver,"nonce":self.nonce,"issued_at":self.issued_at}))?);
        Ok(bytes)
    }
}
fn bounded(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = canonical_json(value)?;
    if bytes.len() > 32768 {
        return Err(INVALID);
    }
    Ok(bytes)
}
fn permissions(values: &[Permission]) -> Result<()> {
    if values.is_empty() || values.len() > 32 {
        return Err(INVALID);
    }
    for (i, p) in values.iter().enumerate() {
        crate::ascii(&p.operation)?;
        crate::ascii(&p.resource)?;
        if !p.constraints.is_object() || values[..i].contains(p) {
            return Err(INVALID);
        }
    }
    bounded(&values)?;
    Ok(())
}
fn validate_claims(policy: &Policy, claims: &Claims, now: u64) -> Result<()> {
    if claims.schema != CREDENTIAL
        || claims.issuer != policy.issuer
        || claims.key_id != policy.key_id
        || claims.receiver != policy.receiver
        || claims.audience != policy.audience
        || claims.policy_digest != policy.digest()?
        || !crate::grant_validity::GrantValidity::dated(claims.issued_at, claims.expires_at)
            .map_err(|_| INVALID)?
            .contains(now)
        || claims.expires_at - claims.issued_at > policy.max_lifetime_seconds
    {
        return Err(INVALID);
    }
    decode_hex::<16>(&claims.credential_id)?;
    decode_hex::<16>(&claims.installation_id)?;
    if public_key(&claims.holder_public_key)?.is_weak() {
        return Err(INVALID);
    }
    permissions(&claims.permissions)?;
    // Subset of explicitly approved permission records. Applications may issue
    // narrower policies after validating their own constraint vocabulary.
    if claims
        .permissions
        .iter()
        .any(|p| !policy.permissions.contains(p))
    {
        return Err(INVALID);
    }
    Ok(())
}
pub fn issue(policy: &Policy, claims: Claims, signer: &SigningKey, now: u64) -> Result<Credential> {
    validate_claims(policy, &claims, now)?;
    if hex::encode(signer.verifying_key().to_bytes()) != policy.public_key {
        return Err(INVALID);
    }
    let mut bytes = CREDENTIAL_DOMAIN.to_vec();
    bytes.extend(bounded(&claims)?);
    Ok(Credential {
        signature: hex::encode(signer.sign(&bytes).to_bytes()),
        claims,
    })
}
pub fn verify_credential(policy: &Policy, credential: &Credential, now: u64) -> Result<()> {
    validate_claims(policy, &credential.claims, now)?;
    let mut bytes = CREDENTIAL_DOMAIN.to_vec();
    bytes.extend(bounded(&credential.claims)?);
    verify_signature(&policy.public_key, &bytes, &credential.signature)
}
/// The host supplies current policy and status from its trusted registry. It
/// must atomically consume (credential_id, nonce) in its replay ledger before
/// exposing a result. A claimed status from a network request is never trusted.
pub fn verify_call(
    policy: &Policy,
    credential: &Credential,
    call: &Call,
    proof: &Proof,
    active: bool,
    now: u64,
) -> Result<Vec<Permission>> {
    verify_credential(policy, credential, now)?;
    let expected = Proof::unsigned(credential, call, proof.nonce.clone(), proof.issued_at)?;
    if !active
        || proof.schema != PRESENTATION
        || proof.issued_at > now
        || now - proof.issued_at >= 60
        || proof.issued_at < credential.claims.issued_at
        || proof.receiver != expected.receiver
        || proof.credential_digest != expected.credential_digest
        || proof.call_digest != expected.call_digest
    {
        return Err(INVALID);
    }
    verify_signature(
        &credential.claims.holder_public_key,
        &proof.transcript()?,
        &proof.signature,
    )?;
    let permitted: Vec<_> = credential
        .claims
        .permissions
        .iter()
        .filter(|p| p.operation == call.operation && p.resource == call.resource)
        .cloned()
        .collect();
    if permitted.is_empty() {
        return Err(INVALID);
    }
    Ok(permitted)
}
