//! Signed v2 holder authority with explicit role selectors. V1 is never rewritten.
//! Cryptography and structural narrowing only: installed receiver contracts,
//! current resource/policy/revocation state, replay and transactions remain mandatory.
use super::{
    IssuerPin, MAX_ROOT_CLAIMS, Proof, Result, SAFE, canonical, digest, hex, key, sign, text,
    verify,
};
use crate::compound_resources::{EffectContract, EffectRule, RoleSelection};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
const INVALID: &str = "invalid_scoped_holder_authority";
pub const GRANT: &str = "secs.holder-grant.v2";
pub const CREDENTIAL: &str = "secs.holder-credential.v2";
pub const PRESENTATION: &str = "secs.holder-presentation.v2";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub operation: String,
    pub resource: String,
    pub roles: Vec<RoleSelection>,
    pub constraints: Value,
}
pub type GrantClaims = super::GrantClaims<Permission>;
pub type Grant = super::Grant<Permission>;
pub type CredentialClaims = super::CredentialClaims<Permission>;
pub type Credential = super::Credential<Permission>;
impl Permission {
    pub fn validate(&self, service: &str) -> Result<()> {
        text(service)?;
        text(&self.operation)?;
        text(&self.resource)?;
        if self.roles.is_empty() || self.roles.len() > 16 || !self.constraints.is_object() {
            return Err(INVALID);
        }
        for (i, r) in self.roles.iter().enumerate() {
            text(&r.role)?;
            r.selector.validate()?;
            if r.selector.service != service || self.roles[..i].iter().any(|p| p.role == r.role) {
                return Err(INVALID);
            }
        }
        canonical(self)?;
        Ok(())
    }
    /// The installed contract, rather than signed caller metadata, defines all roles.
    pub fn effect_rule(&self, contract: &EffectContract) -> Result<EffectRule> {
        self.validate(&contract.service)?;
        let rule = EffectRule {
            service: contract.service.clone(),
            operation: self.operation.clone(),
            roles: self.roles.clone(),
        };
        rule.validate(contract)?;
        Ok(rule)
    }
}
fn permissions(p: &[Permission]) -> Result<()> {
    if p.is_empty() || p.len() > 64 {
        return Err(INVALID);
    }
    for (i, r) in p.iter().enumerate() {
        let service = r.roles.first().ok_or(INVALID)?.selector.service.as_str();
        r.validate(service)?;
        if p[..i].contains(r) {
            return Err(INVALID);
        }
    }
    canonical(p)?;
    Ok(())
}
/// Every child permission narrows one whole parent permission. Role pairs cannot
/// be mixed and guard removal is not a valid same-holder attenuation.
pub fn permissions_within(child: &[Permission], parent: &[Permission]) -> Result<()> {
    permissions(child)?;
    permissions(parent)?;
    for c in child {
        let mut found = false;
        for p in parent {
            if c.operation != p.operation
                || c.resource != p.resource
                || c.constraints != p.constraints
                || c.roles.len() != p.roles.len()
            {
                continue;
            }
            let mut narrower = true;
            for role in &c.roles {
                match p.roles.iter().find(|r| r.role == role.role) {
                    Some(r) => narrower &= role.selector.within(&r.selector)?,
                    None => narrower = false,
                }
            }
            found |= narrower;
        }
        if !found {
            return Err(INVALID);
        }
    }
    Ok(())
}
fn validate_grant(pin: &IssuerPin, c: &GrantClaims, now: u64) -> Result<()> {
    // Reserve room for the signed parent, equal-scope child and presentation.
    // A root that fits alone must not imply an unrepresentable equal child.
    if canonical(c)?.len() > MAX_ROOT_CLAIMS {
        return Err(INVALID);
    }
    for s in [&pin.issuer, &pin.key_id, &pin.service] {
        text(s)?
    }
    key(&pin.public_key)?;
    hex::<16>(&c.grant_id)?;
    hex::<32>(&c.revision)?;
    key(&c.holder_public_key)?;
    if let Some(i) = &c.installation_id {
        hex::<16>(i)?;
    }
    if c.schema != GRANT
        || c.issuer != pin.issuer
        || c.key_id != pin.key_id
        || c.service != pin.service
        || c.onward_delegation
        || !c.validity.contains(now)
        || !(60..=3600).contains(&c.max_credential_lifetime_seconds)
    {
        return Err(INVALID);
    }
    for p in &c.permissions {
        p.validate(&c.service)?;
    }
    permissions(&c.permissions)
}
pub fn issue_grant(
    pin: &IssuerPin,
    claims: GrantClaims,
    k: &SigningKey,
    now: u64,
) -> Result<Grant> {
    validate_grant(pin, &claims, now)?;
    if hex::encode(k.verifying_key().to_bytes()) != pin.public_key {
        return Err(INVALID);
    }
    let signature = sign("secs.holder-grant.v2/signature", &claims, k)?;
    Ok(Grant { claims, signature })
}
pub fn verify_grant(pin: &IssuerPin, g: &Grant, now: u64) -> Result<()> {
    validate_grant(pin, &g.claims, now)?;
    verify(
        "secs.holder-grant.v2/signature",
        &g.claims,
        &g.signature,
        &pin.public_key,
    )
}
fn validate_credential(pin: &IssuerPin, c: &Credential, now: u64) -> Result<()> {
    verify_grant(pin, &c.grant, now)?;
    let x = &c.claims;
    let g = &c.grant.claims;
    hex::<16>(&x.credential_id)?;
    if x.schema != CREDENTIAL
        || x.grant_digest != digest(&c.grant)?
        || x.holder_public_key != g.holder_public_key
        || x.issued_at > now
        || now >= x.expires_at
        || x.expires_at > SAFE
        || x.expires_at - x.issued_at > g.max_credential_lifetime_seconds
        || !g.validity.contains(x.issued_at)
        || g.validity.end().is_some_and(|end| x.expires_at > end)
        || g.installation_id
            .as_ref()
            .is_some_and(|i| Some(i) != x.installation_id.as_ref())
    {
        return Err(INVALID);
    }
    if let Some(i) = &x.installation_id {
        hex::<16>(i)?;
    }
    permissions_within(&x.permissions, &g.permissions)
}
#[allow(clippy::too_many_arguments)]
pub fn derive_credential(
    pin: &IssuerPin,
    grant: Grant,
    permissions: Vec<Permission>,
    installation_id: Option<String>,
    credential_id: String,
    issued_at: u64,
    expires_at: u64,
    k: &SigningKey,
) -> Result<Credential> {
    let claims = CredentialClaims {
        schema: CREDENTIAL.into(),
        credential_id,
        grant_digest: digest(&grant)?,
        holder_public_key: hex::encode(k.verifying_key().to_bytes()),
        installation_id,
        permissions,
        issued_at,
        expires_at,
    };
    let mut c = Credential {
        grant,
        claims,
        signature: String::new(),
    };
    validate_credential(pin, &c, issued_at)?;
    c.signature = sign("secs.holder-credential.v2/signature", &c.claims, k)?;
    canonical(&c)?;
    Ok(c)
}
pub fn verify_credential(pin: &IssuerPin, c: &Credential, now: u64) -> Result<()> {
    canonical(c)?;
    validate_credential(pin, c, now)?;
    verify(
        "secs.holder-credential.v2/signature",
        &c.claims,
        &c.signature,
        &c.claims.holder_public_key,
    )
}
fn proof_claims(p: &Proof) -> Value {
    serde_json::json!({"schema":p.schema,"credential_digest":p.credential_digest,"call_digest":p.call_digest,"nonce":p.nonce,"issued_at":p.issued_at,"expires_at":p.expires_at})
}
pub fn present(
    pin: &IssuerPin,
    c: &Credential,
    call: &Value,
    nonce: String,
    now: u64,
    k: &SigningKey,
) -> Result<Proof> {
    verify_credential(pin, c, now)?;
    if hex::encode(k.verifying_key().to_bytes()) != c.claims.holder_public_key {
        return Err(INVALID);
    }
    hex::<16>(&nonce)?;
    let mut p = Proof {
        schema: PRESENTATION.into(),
        credential_digest: digest(c)?,
        call_digest: digest(call)?,
        nonce,
        issued_at: now,
        expires_at: now.checked_add(60).ok_or(INVALID)?.min(c.claims.expires_at),
        signature: String::new(),
    };
    p.signature = sign(
        "secs.holder-presentation.v2/signature",
        &proof_claims(&p),
        k,
    )?;
    if canonical(&serde_json::json!({"credential": c, "call": call, "proof": p}))?.len() > 130000 {
        return Err(INVALID);
    }
    Ok(p)
}
pub fn verify_presentation(
    pin: &IssuerPin,
    c: &Credential,
    call: &Value,
    p: &Proof,
    now: u64,
) -> Result<()> {
    verify_credential(pin, c, now)?;
    hex::<16>(&p.nonce)?;
    if p.schema != PRESENTATION
        || p.credential_digest != digest(c)?
        || p.call_digest != digest(call)?
        || p.issued_at < c.claims.issued_at
        || p.issued_at > now
        || p.expires_at <= now
        || p.expires_at > c.claims.expires_at
        || p.expires_at - p.issued_at > 60
    {
        return Err(INVALID);
    }
    verify(
        "secs.holder-presentation.v2/signature",
        &proof_claims(p),
        &p.signature,
        &c.claims.holder_public_key,
    )
}
