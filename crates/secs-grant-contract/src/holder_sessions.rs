//! Explicit, finite session-key authority authorized by a v2 grant holder.
//!
//! This does not change ordinary same-holder v1/v2 derivation. An issuer must
//! explicitly enable exchange and enforce its current parent registry, policy,
//! challenge idempotency and replay state. Receivers must call `verify_parent`
//! against that current parent, not merely verify the session issuer signature.
use crate::{
    IssuerPin, Proof, Result, SAFE, canonical, digest, hex, key, scoped_grants as v2, sign, text,
    verify,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

pub const CHALLENGE: &str = "secs.holder-session-challenge.v1";
pub const AUTHORIZATION: &str = "secs.holder-session-authorization.v1";
pub const CREDENTIAL: &str = "secs.holder-session-credential.v1";
pub const PRESENTATION: &str = "secs.holder-session-presentation.v1";
pub const STATUS: &str = "secs.holder-session-status.v1";
const INVALID: &str = "invalid_holder_session";
const AUTHORIZE_DOMAIN: &str = "secs.holder-session-authorization.v1/signature";
const POSSESSION_DOMAIN: &str = "secs.holder-session-possession.v1/signature";
const CREDENTIAL_DOMAIN: &str = "secs.holder-session-credential.v1/signature";
const PROOF_DOMAIN: &str = "secs.holder-session-presentation.v1/signature";
const STATUS_DOMAIN: &str = "secs.holder-session-status.v1/signature";

/// Context is receiver-owned / Wallet-observed, never inferred from signed claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    pub origin: String,
    pub audience: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub schema: String,
    pub challenge_id: String,
    pub request_id: String,
    pub nonce: String,
    pub issuer: String,
    pub key_id: String,
    pub service: String,
    pub audience: String,
    pub origin: String,
    pub parent_grant_id: String,
    pub parent_grant_digest: String,
    pub parent_revision: String,
    pub holder_public_key: String,
    /// Approving Wallet installation; must match a bound parent, if present.
    pub installation_id: String,
    /// Fresh application instance; never impersonates the Wallet installation.
    pub session_installation_id: String,
    pub session_public_key: String,
    pub permissions: Vec<v2::Permission>,
    pub issued_at: u64,
    pub review_deadline: u64,
    pub expires_at: u64,
}

/// Broker-private input. Never return the parent grant to the application/MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub schema: String,
    pub challenge: Challenge,
    pub parent_grant: v2::Grant,
    pub holder_signature: String,
    pub session_signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    pub schema: String,
    pub credential_id: String,
    pub challenge_digest: String,
    pub challenge: Challenge,
}
/// Application-owned finite authority. Contains parent references, not the root.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    pub schema: String,
    pub request_id: String,
    pub challenge_id: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}

fn status_claims(p: &StatusRequest) -> Value {
    json!({"schema":p.schema,"request_id":p.request_id,"challenge_id":p.challenge_id,
        "nonce":p.nonce,"issued_at":p.issued_at,"expires_at":p.expires_at})
}

pub fn prove_status(
    c: &Challenge,
    nonce: String,
    now: u64,
    session: &SigningKey,
) -> Result<StatusRequest> {
    structure(
        c,
        &Context {
            origin: c.origin.clone(),
            audience: c.audience.clone(),
        },
        now,
    )?;
    hex::<16>(&nonce)?;
    if hex::encode(session.verifying_key().to_bytes()) != c.session_public_key {
        return Err(INVALID);
    }
    let mut proof = StatusRequest {
        schema: STATUS.into(),
        request_id: c.request_id.clone(),
        challenge_id: c.challenge_id.clone(),
        nonce,
        issued_at: now,
        expires_at: now.checked_add(60).ok_or(INVALID)?.min(c.expires_at),
        signature: String::new(),
    };
    proof.signature = sign(STATUS_DOMAIN, &status_claims(&proof), session)?;
    Ok(proof)
}

/// Status is original-outcome reconciliation, never permission to renew or read.
pub fn verify_status(c: &Challenge, p: &StatusRequest, context: &Context, now: u64) -> Result<()> {
    structure(c, context, now)?;
    hex::<16>(&p.nonce)?;
    if p.schema != STATUS
        || p.request_id != c.request_id
        || p.challenge_id != c.challenge_id
        || p.issued_at < c.issued_at
        || p.issued_at > now
        || now >= p.expires_at
        || p.expires_at > c.expires_at
        || p.expires_at - p.issued_at > 60
    {
        return Err(INVALID);
    }
    verify(
        STATUS_DOMAIN,
        &status_claims(p),
        &p.signature,
        &c.session_public_key,
    )
}

fn structure(c: &Challenge, context: &Context, now: u64) -> Result<()> {
    canonical(c)?;
    for value in [&c.issuer, &c.key_id, &c.service, &c.origin, &c.audience] {
        text(value)?;
    }
    hex::<16>(&c.challenge_id)?;
    hex::<16>(&c.request_id)?;
    hex::<32>(&c.nonce)?;
    hex::<16>(&c.parent_grant_id)?;
    hex::<32>(&c.parent_grant_digest)?;
    hex::<32>(&c.parent_revision)?;
    hex::<16>(&c.installation_id)?;
    hex::<16>(&c.session_installation_id)?;
    key(&c.holder_public_key)?;
    key(&c.session_public_key)?;
    if c.schema != CHALLENGE
        || c.origin != context.origin
        || c.audience != context.audience
        || c.holder_public_key == c.session_public_key
        || now > SAFE
        || c.issued_at > now
        || c.issued_at >= c.expires_at
        || now >= c.expires_at
        || c.expires_at > SAFE
        || c.review_deadline
            != c.issued_at
                .checked_add(120)
                .ok_or(INVALID)?
                .min(c.expires_at)
        || c.permissions.is_empty()
        || c.permissions.len() > 64
    {
        return Err(INVALID);
    }
    for p in &c.permissions {
        p.validate(&c.service)?;
    }
    Ok(())
}

fn parent_binding(
    pin: &IssuerPin,
    parent: &v2::Grant,
    c: &Challenge,
    context: &Context,
    now: u64,
) -> Result<()> {
    structure(c, context, now)?;
    v2::verify_grant(pin, parent, now)?;
    let g = &parent.claims;
    if c.issuer != pin.issuer
        || c.key_id != pin.key_id
        || c.service != pin.service
        || c.parent_grant_id != g.grant_id
        || c.parent_grant_digest != digest(parent)?
        || c.parent_revision != g.revision
        || c.holder_public_key != g.holder_public_key
        || g.installation_id
            .as_ref()
            .is_some_and(|id| id != &c.installation_id)
        || !g.validity.contains(c.issued_at)
        || g.validity.end().is_some_and(|end| c.expires_at > end)
        || c.expires_at - c.issued_at > g.max_credential_lifetime_seconds
    {
        return Err(INVALID);
    }
    v2::permissions_within(&c.permissions, &g.permissions)
}

pub fn review_challenge(
    pin: &IssuerPin,
    parent: &v2::Grant,
    c: &Challenge,
    context: &Context,
    now: u64,
) -> Result<()> {
    parent_binding(pin, parent, c, context, now)?;
    if now >= c.review_deadline {
        return Err(INVALID);
    }
    Ok(())
}

/// A temporary key can prove possession only of a typed, finite challenge.
pub fn prove_possession(c: &Challenge, session: &SigningKey, now: u64) -> Result<String> {
    structure(
        c,
        &Context {
            origin: c.origin.clone(),
            audience: c.audience.clone(),
        },
        now,
    )?;
    if hex::encode(session.verifying_key().to_bytes()) != c.session_public_key
        || now >= c.review_deadline
    {
        return Err(INVALID);
    }
    sign(POSSESSION_DOMAIN, c, session)
}

/// Caller supplies the independently obtained temporary-key PoP before approval.
pub fn authorize(
    pin: &IssuerPin,
    parent: v2::Grant,
    challenge: Challenge,
    session_signature: String,
    context: &Context,
    holder: &SigningKey,
    now: u64,
) -> Result<Authorization> {
    review_challenge(pin, &parent, &challenge, context, now)?;
    if hex::encode(holder.verifying_key().to_bytes()) != challenge.holder_public_key {
        return Err(INVALID);
    }
    verify(
        POSSESSION_DOMAIN,
        &challenge,
        &session_signature,
        &challenge.session_public_key,
    )?;
    let holder_signature = sign(AUTHORIZE_DOMAIN, &challenge, holder)?;
    let a = Authorization {
        schema: AUTHORIZATION.into(),
        challenge,
        parent_grant: parent,
        holder_signature,
        session_signature,
    };
    canonical(&a)?;
    Ok(a)
}

pub fn verify_authorization(
    pin: &IssuerPin,
    a: &Authorization,
    context: &Context,
    now: u64,
) -> Result<()> {
    canonical(a)?;
    if a.schema != AUTHORIZATION {
        return Err(INVALID);
    }
    review_challenge(pin, &a.parent_grant, &a.challenge, context, now)?;
    verify(
        AUTHORIZE_DOMAIN,
        &a.challenge,
        &a.holder_signature,
        &a.challenge.holder_public_key,
    )?;
    verify(
        POSSESSION_DOMAIN,
        &a.challenge,
        &a.session_signature,
        &a.challenge.session_public_key,
    )
}

/// Issuer still must verify current parent/policy and consume the exact challenge
/// transactionally. A stateless signature function is not that authorization.
pub fn issue(
    pin: &IssuerPin,
    a: &Authorization,
    id: String,
    context: &Context,
    issuer: &SigningKey,
    now: u64,
) -> Result<Credential> {
    verify_authorization(pin, a, context, now)?;
    hex::<16>(&id)?;
    if hex::encode(issuer.verifying_key().to_bytes()) != pin.public_key {
        return Err(INVALID);
    }
    let claims = CredentialClaims {
        schema: CREDENTIAL.into(),
        credential_id: id,
        challenge_digest: digest(&a.challenge)?,
        challenge: a.challenge.clone(),
    };
    let credential = Credential {
        signature: sign(CREDENTIAL_DOMAIN, &claims, issuer)?,
        claims,
    };
    canonical(&credential)?;
    Ok(credential)
}

/// Verifies a returned finite token, not current parent state or permission to run.
pub fn verify_credential(
    pin: &IssuerPin,
    c: &Credential,
    context: &Context,
    now: u64,
) -> Result<()> {
    canonical(c)?;
    structure(&c.claims.challenge, context, now)?;
    hex::<16>(&c.claims.credential_id)?;
    let challenge = &c.claims.challenge;
    if c.claims.schema != CREDENTIAL
        || c.claims.challenge_digest != digest(challenge)?
        || challenge.issuer != pin.issuer
        || challenge.key_id != pin.key_id
        || challenge.service != pin.service
    {
        return Err(INVALID);
    }
    verify(CREDENTIAL_DOMAIN, &c.claims, &c.signature, &pin.public_key)
}

/// Mandatory at the receiver, with the canonical currently-active parent supplied
/// by a trusted registry. Revocation/replacement cannot be inferred cryptographically.
pub fn verify_parent(
    pin: &IssuerPin,
    parent: &v2::Grant,
    c: &Credential,
    context: &Context,
    now: u64,
) -> Result<()> {
    verify_credential(pin, c, context, now)?;
    parent_binding(pin, parent, &c.claims.challenge, context, now)
}

fn call_allowed(c: &Credential, call: &Value) -> Result<()> {
    canonical(call)?;
    let object = call.as_object().ok_or(INVALID)?;
    if object.len() != 3
        || !object.contains_key("parameters")
        || !c.claims.challenge.permissions.iter().any(|p| {
            Some(p.operation.as_str()) == call["operation"].as_str()
                && Some(p.resource.as_str()) == call["resource"].as_str()
        })
    {
        return Err(INVALID);
    }
    Ok(())
}
fn proof_claims(p: &Proof) -> Value {
    json!({"schema":p.schema,"credential_digest":p.credential_digest,"call_digest":p.call_digest,
        "nonce":p.nonce,"issued_at":p.issued_at,"expires_at":p.expires_at})
}
pub fn present(
    pin: &IssuerPin,
    c: &Credential,
    call: &Value,
    nonce: String,
    context: &Context,
    now: u64,
    session: &SigningKey,
) -> Result<Proof> {
    verify_credential(pin, c, context, now)?;
    call_allowed(c, call)?;
    hex::<16>(&nonce)?;
    if hex::encode(session.verifying_key().to_bytes()) != c.claims.challenge.session_public_key {
        return Err(INVALID);
    }
    let mut p = Proof {
        schema: PRESENTATION.into(),
        credential_digest: digest(c)?,
        call_digest: digest(call)?,
        nonce,
        issued_at: now,
        expires_at: now
            .checked_add(60)
            .ok_or(INVALID)?
            .min(c.claims.challenge.expires_at),
        signature: String::new(),
    };
    p.signature = sign(PROOF_DOMAIN, &proof_claims(&p), session)?;
    canonical(&json!({"credential":c,"call":call,"proof":p}))?;
    Ok(p)
}

pub fn verify_presentation(
    pin: &IssuerPin,
    parent: &v2::Grant,
    c: &Credential,
    call: &Value,
    proof: &Proof,
    context: &Context,
    now: u64,
) -> Result<()> {
    verify_parent(pin, parent, c, context, now)?;
    call_allowed(c, call)?;
    hex::<16>(&proof.nonce)?;
    if proof.schema != PRESENTATION
        || proof.credential_digest != digest(c)?
        || proof.call_digest != digest(call)?
        || proof.issued_at < c.claims.challenge.issued_at
        || proof.issued_at > now
        || now >= proof.expires_at
        || proof.expires_at > c.claims.challenge.expires_at
        || proof.expires_at - proof.issued_at > 60
    {
        return Err(INVALID);
    }
    verify(
        PROOF_DOMAIN,
        &proof_claims(proof),
        &proof.signature,
        &c.claims.challenge.session_public_key,
    )
}
