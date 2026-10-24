//! Provider-signed reusable grants and same-holder credentials. No child grants.
//! This verifies cryptographic authority, not current provider status or ancestry.
//! Receivers MUST check current grant/revision/revocation and consume proof nonces
//! atomically before exposing results; discovery and transport origins confer no authority.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest, Sha256};
pub type Result<T> = std::result::Result<T, &'static str>;
pub const GRANT: &str = "secs.holder-grant.v1";
pub const CREDENTIAL: &str = "secs.holder-credential.v1";
pub const PRESENTATION: &str = "secs.holder-presentation.v1";
const MAX: usize = 131072;
const MAX_ROOT_CLAIMS: usize = 61440;
const SAFE: u64 = 9007199254740991;
const INVALID: &str = "invalid_holder_authority";
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerPin {
    pub issuer: String,
    pub key_id: String,
    pub public_key: String,
    pub service: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Validity {
    Dated { not_before: u64, not_after: u64 },
    UntilRevoked { not_before: u64 },
}
impl Serialize for Validity {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let mut v = serde_json::json!({"schema":"castalia.grant-validity.v1"});
        match self {
            Self::Dated {
                not_before,
                not_after,
            } => {
                v["mode"] = "dated".into();
                v["not_before"] = (*not_before).into();
                v["not_after"] = (*not_after).into()
            }
            Self::UntilRevoked { not_before } => {
                v["mode"] = "until_revoked".into();
                v["not_before"] = (*not_before).into()
            }
        }
        v.serialize(s)
    }
}
impl<'de> Deserialize<'de> for Validity {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
        enum Wire {
            Dated {
                schema: String,
                not_before: u64,
                not_after: u64,
            },
            UntilRevoked {
                schema: String,
                not_before: u64,
            },
        }
        let (schema, value) = match Wire::deserialize(d)? {
            Wire::Dated {
                schema,
                not_before,
                not_after,
            } => (
                schema,
                Self::Dated {
                    not_before,
                    not_after,
                },
            ),
            Wire::UntilRevoked { schema, not_before } => {
                (schema, Self::UntilRevoked { not_before })
            }
        };
        if schema != "castalia.grant-validity.v1" {
            return Err(serde::de::Error::custom("invalid_validity"));
        }
        Ok(value)
    }
}
impl Validity {
    pub fn contains(&self, now: u64) -> bool {
        match self {
            Self::Dated {
                not_before,
                not_after,
            } => *not_before <= now && now < *not_after && *not_after <= SAFE,
            Self::UntilRevoked { not_before } => *not_before <= now && now <= SAFE,
        }
    }
    pub fn end(&self) -> Option<u64> {
        match self {
            Self::Dated { not_after, .. } => Some(*not_after),
            Self::UntilRevoked { .. } => None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub kind: String,
    pub id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    All,
    Paths { roots: Vec<Vec<Node>> },
}
impl Scope {
    fn validate(&self) -> Result<()> {
        if let Self::Paths { roots } = self {
            if roots.is_empty() || roots.len() > 16 {
                return Err(INVALID);
            }
            for (i, p) in roots.iter().enumerate() {
                if p.is_empty() || p.len() > 32 || roots[..i].contains(p) {
                    return Err(INVALID);
                }
                for (j, n) in p.iter().enumerate() {
                    text(&n.kind)?;
                    text(&n.id)?;
                    if p[..j].contains(n) {
                        return Err(INVALID);
                    }
                }
            }
        }
        Ok(())
    }
    pub fn within(&self, parent: &Self) -> bool {
        match (self, parent) {
            (_, Self::All) => true,
            (Self::All, _) => false,
            (Self::Paths { roots: a }, Self::Paths { roots: b }) => {
                a.iter().all(|p| b.iter().any(|r| p.starts_with(r)))
            }
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permission {
    pub operation: String,
    pub resource: String,
    pub scope: Scope,
    pub constraints: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaims {
    pub schema: String,
    pub grant_id: String,
    pub revision: String,
    pub issuer: String,
    pub key_id: String,
    pub service: String,
    pub holder_public_key: String,
    pub installation_id: Option<String>,
    pub validity: Validity,
    pub max_credential_lifetime_seconds: u64,
    pub onward_delegation: bool,
    pub permissions: Vec<Permission>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub claims: GrantClaims,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    pub schema: String,
    pub credential_id: String,
    pub grant_digest: String,
    pub holder_public_key: String,
    pub installation_id: Option<String>,
    pub permissions: Vec<Permission>,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub grant: Grant,
    pub claims: CredentialClaims,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema: String,
    pub credential_digest: String,
    pub call_digest: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
fn text(s: &str) -> Result<()> {
    if s.is_empty() || s.len() > 256 || !s.bytes().all(|b| b.is_ascii_graphic() && b != b'*') {
        Err(INVALID)
    } else {
        Ok(())
    }
}
fn hex<const N: usize>(s: &str) -> Result<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(INVALID);
    }
    hex::decode(s)
        .map_err(|_| INVALID)?
        .try_into()
        .map_err(|_| INVALID)
}
fn key(s: &str) -> Result<VerifyingKey> {
    let k = VerifyingKey::from_bytes(&hex::<32>(s)?).map_err(|_| INVALID)?;
    if k.is_weak() { Err(INVALID) } else { Ok(k) }
}
fn safe(v: &Value, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(INVALID);
    }
    match v {
        Value::Number(n) => {
            if n.as_u64().is_some_and(|n| n <= SAFE)
                || n.as_i64()
                    .is_some_and(|n| n >= -(SAFE as i64) && n <= SAFE as i64)
            {
                Ok(())
            } else {
                Err(INVALID)
            }
        }
        Value::Array(a) => {
            for x in a {
                safe(x, depth + 1)?
            }
            Ok(())
        }
        Value::Object(o) => {
            if o.contains_key("$serde_json::private::Number") {
                return Err(INVALID);
            }
            for x in o.values() {
                safe(x, depth + 1)?
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
pub fn canonical<T: Serialize + ?Sized>(v: &T) -> Result<Vec<u8>> {
    safe(&serde_json::to_value(v).map_err(|_| INVALID)?, 0)?;
    let b = serde_jcs::to_vec(v).map_err(|_| INVALID)?;
    if b.len() > MAX { Err(INVALID) } else { Ok(b) }
}
pub fn digest<T: Serialize + ?Sized>(v: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical(v)?)))
}
fn transcript(domain: &str, v: &impl Serialize) -> Result<Vec<u8>> {
    let mut b = domain.as_bytes().to_vec();
    b.push(0);
    b.extend(canonical(v)?);
    Ok(b)
}
fn sign(domain: &str, v: &impl Serialize, k: &SigningKey) -> Result<String> {
    Ok(hex::encode(k.sign(&transcript(domain, v)?).to_bytes()))
}
fn verify(domain: &str, v: &impl Serialize, s: &str, k: &str) -> Result<()> {
    key(k)?
        .verify_strict(
            &transcript(domain, v)?,
            &Signature::from_bytes(&hex::<64>(s)?),
        )
        .map_err(|_| INVALID)
}
fn permissions(p: &[Permission]) -> Result<()> {
    if p.is_empty() || p.len() > 64 {
        return Err(INVALID);
    }
    for (i, r) in p.iter().enumerate() {
        text(&r.operation)?;
        text(&r.resource)?;
        r.scope.validate()?;
        if !r.constraints.is_object() || p[..i].contains(r) {
            return Err(INVALID);
        }
        safe(&r.constraints, 8)?;
    }
    canonical(p)?;
    Ok(())
}
pub fn permissions_within(child: &[Permission], parent: &[Permission]) -> Result<()> {
    permissions(child)?;
    permissions(parent)?;
    if child.iter().all(|c| {
        parent.iter().any(|p| {
            c.operation == p.operation
                && c.resource == p.resource
                && c.constraints == p.constraints
                && c.scope.within(&p.scope)
        })
    }) {
        Ok(())
    } else {
        Err(INVALID)
    }
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
    let signature = sign("secs.holder-grant.v1/signature", &claims, k)?;
    Ok(Grant { claims, signature })
}
pub fn verify_grant(pin: &IssuerPin, g: &Grant, now: u64) -> Result<()> {
    validate_grant(pin, &g.claims, now)?;
    verify(
        "secs.holder-grant.v1/signature",
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
    c.signature = sign("secs.holder-credential.v1/signature", &c.claims, k)?;
    canonical(&c)?;
    Ok(c)
}
pub fn verify_credential(pin: &IssuerPin, c: &Credential, now: u64) -> Result<()> {
    canonical(c)?;
    validate_credential(pin, c, now)?;
    verify(
        "secs.holder-credential.v1/signature",
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
        "secs.holder-presentation.v1/signature",
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
        "secs.holder-presentation.v1/signature",
        &proof_claims(p),
        &p.signature,
        &c.claims.holder_public_key,
    )
}
/// Duplicate fields are rejected recursively before closed typed decoding.
pub fn parse<T: DeserializeOwned>(raw: &[u8]) -> Result<T> {
    #[derive(Debug)]
    struct Unique(Value);
    impl<'de> Deserialize<'de> for Unique {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
            struct V;
            impl<'de> serde::de::Visitor<'de> for V {
                type Value = Unique;
                fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                    f.write_str("bounded unique-key JSON")
                }
                fn visit_bool<E: serde::de::Error>(
                    self,
                    v: bool,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_string<E: serde::de::Error>(
                    self,
                    v: String,
                ) -> std::result::Result<Unique, E> {
                    Ok(Unique(v.into()))
                }
                fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Unique, E> {
                    Ok(Unique(Value::Null))
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut v = vec![];
                    while let Some(Unique(x)) = a.next_element()? {
                        v.push(x)
                    }
                    Ok(Unique(Value::Array(v)))
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> std::result::Result<Unique, A::Error> {
                    let mut v = serde_json::Map::new();
                    while let Some((k, Unique(x))) = a.next_entry::<String, Unique>()? {
                        if v.insert(k, x).is_some() {
                            return Err(serde::de::Error::custom("duplicate_field"));
                        }
                    }
                    Ok(Unique(Value::Object(v)))
                }
            }
            d.deserialize_any(V)
        }
    }
    if raw.len() > MAX {
        return Err(INVALID);
    }
    let Unique(v) = serde_json::from_slice(raw).map_err(|_| INVALID)?;
    safe(&v, 0)?;
    serde_json::from_value(v).map_err(|_| INVALID)
}
