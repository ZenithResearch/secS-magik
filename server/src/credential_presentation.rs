//! Generic request credentials and presentations. No application operation parser lives here.
use crate::devgraph_work_request::{strict_json, Result, MAX_SAFE};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CREDENTIAL_SCHEMA: &str = "castalia.request-credential.v1";
pub const PRESENTATION_SCHEMA: &str = "castalia.credential-presentation.v2";
pub const REQUEST_SCHEMA: &str = "castalia.credential-presentation-request.v2";
pub const MAX_ENVELOPE: usize = 262_144;
pub const MAX_REQUEST: usize = 131_072;

pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    fn append(value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Object(fields) => {
                out.push(b'{');
                let mut keys: Vec<_> = fields.keys().collect();
                keys.sort_unstable();
                for (i, key) in keys.into_iter().enumerate() {
                    if !key.is_ascii() {
                        return Err("non_ascii_field");
                    }
                    if i != 0 {
                        out.push(b',');
                    }
                    serde_json::to_writer(&mut *out, key).map_err(|_| "encoding_failed")?;
                    out.push(b':');
                    append(&fields[key], out)?;
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i != 0 {
                        out.push(b',');
                    }
                    append(item, out)?;
                }
                out.push(b']');
            }
            Value::Number(n) => {
                if let Some(n) = n.as_u64().filter(|n| *n <= MAX_SAFE) {
                    out.extend(n.to_string().as_bytes());
                } else if let Some(n) = n.as_i64().filter(|n| n.unsigned_abs() <= MAX_SAFE) {
                    out.extend(n.to_string().as_bytes());
                } else {
                    return Err("invalid_canonical_number");
                }
            }
            _ => serde_json::to_writer(out, value).map_err(|_| "encoding_failed")?,
        }
        Ok(())
    }
    let mut out = Vec::new();
    append(
        &serde_json::to_value(value).map_err(|_| "encoding_failed")?,
        &mut out,
    )?;
    Ok(out)
}
pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex<const N: usize>(text: &str) -> Result<[u8; N]> {
    if text.len() != N * 2
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid_hex");
    }
    let mut out = [0; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| "invalid_hex")?;
    }
    Ok(out)
}
fn label(value: &str) -> bool {
    !value.is_empty() && value.len() <= 200 && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
fn display(value: &str, maximum: usize) -> bool {
    !value.is_empty() && value.len() <= maximum && !value.chars().any(|c| {
        matches!(c as u32, 0..=0x1f | 0x7f..=0x9f | 0x061c | 0x200e..=0x200f | 0x202a..=0x202e | 0x2066..=0x2069)
    })
}
fn origin(value: &str) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    let loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return false,
    };
    (parsed.scheme() == "https" || (parsed.scheme() == "http" && loopback))
        && parsed.origin().ascii_serialization() == value
        && !parsed.host_str().is_some_and(|host| host.ends_with('.'))
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub kind: String,
    pub id: String,
}
impl Caller {
    pub fn validate(&self) -> Result<()> {
        if !label(&self.id)
            || !matches!(self.kind.as_str(), "browser" | "terminal")
            || (self.kind == "browser" && !origin(&self.id))
        {
            return Err("invalid_caller");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    pub title: String,
    pub statements: Vec<String>,
}
impl Disclosure {
    pub fn validate(&self) -> Result<()> {
        if !display(&self.title, 160)
            || self.statements.is_empty()
            || self.statements.len() > 144
            || self.statements.iter().any(|s| !display(s, 512))
        {
            return Err("invalid_disclosure");
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(sha256(&canonical(self)?))
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    pub schema: String,
    pub issuer: String,
    pub key_id: String,
    pub holder_public_key: String,
    pub audience: String,
    pub caller: Caller,
    pub request_digest_sha256: String,
    pub disclosure_digest_sha256: String,
    pub policy_digest_sha256: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationRequest {
    pub schema: String,
    pub request_bytes_base64: String,
    pub disclosure: Disclosure,
    pub credential: Credential,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    pub schema: String,
    pub holder_public_key: String,
    pub issuer: String,
    pub key_id: String,
    pub audience: String,
    pub caller: Caller,
    pub request_digest_sha256: String,
    pub credential_digest_sha256: String,
    pub disclosure_digest_sha256: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub signature: String,
}
fn lifetime(issued: u64, expires: u64, now: u64, maximum: u64) -> Result<()> {
    if issued > now
        || expires <= now
        || issued >= expires
        || expires > MAX_SAFE
        || expires - issued > maximum
    {
        return Err("invalid_credential_lifetime");
    }
    Ok(())
}
impl Credential {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        serde_json::from_value(strict_json(raw, MAX_ENVELOPE)?).map_err(|_| "invalid_credential")
    }
    pub fn preimage(&self) -> Result<Vec<u8>> {
        let mut out = b"castalia.request-credential.v1/signature\0".to_vec();
        out.extend(canonical(&self.claims)?);
        Ok(out)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(sha256(&canonical(self)?))
    }
    pub fn verify(
        &self,
        issuer: &str,
        key_id: &str,
        public: &VerifyingKey,
        audience: &str,
        caller: &Caller,
        now: u64,
    ) -> Result<()> {
        let c = &self.claims;
        if c.schema != CREDENTIAL_SCHEMA
            || c.issuer != issuer
            || c.key_id != key_id
            || c.audience != audience
            || &c.caller != caller
            || !label(&c.issuer)
            || !label(&c.key_id)
            || !label(&c.audience)
        {
            return Err("credential_binding_mismatch");
        }
        c.caller.validate()?;
        unhex::<32>(&c.holder_public_key)?;
        unhex::<32>(&c.request_digest_sha256)?;
        unhex::<32>(&c.disclosure_digest_sha256)?;
        unhex::<32>(&c.policy_digest_sha256)?;
        unhex::<16>(&c.nonce)?;
        lifetime(c.issued_at, c.expires_at, now, 120)?;
        public
            .verify_strict(
                &self.preimage()?,
                &Signature::from_bytes(&unhex::<64>(&self.signature)?),
            )
            .map_err(|_| "invalid_credential_signature")
    }
}
impl Presentation {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        serde_json::from_value(strict_json(raw, MAX_ENVELOPE)?).map_err(|_| "invalid_presentation")
    }
    pub fn preimage(&self) -> Result<Vec<u8>> {
        let mut value = serde_json::to_value(self).map_err(|_| "encoding_failed")?;
        value
            .as_object_mut()
            .ok_or("encoding_failed")?
            .remove("signature");
        let mut out = b"castalia.credential-presentation.v2/signature\0".to_vec();
        out.extend(canonical(&value)?);
        Ok(out)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(sha256(&canonical(self)?))
    }
    pub fn verify(&self, credential: &Credential, now: u64) -> Result<()> {
        let c = &credential.claims;
        if self.schema != PRESENTATION_SCHEMA
            || self.holder_public_key != c.holder_public_key
            || self.issuer != c.issuer
            || self.key_id != c.key_id
            || self.audience != c.audience
            || self.caller != c.caller
            || self.request_digest_sha256 != c.request_digest_sha256
            || self.disclosure_digest_sha256 != c.disclosure_digest_sha256
            || self.credential_digest_sha256 != credential.digest()?
            || self.expires_at > c.expires_at
            || self.issued_at < c.issued_at
        {
            return Err("presentation_binding_mismatch");
        }
        lifetime(self.issued_at, self.expires_at, now, 60)?;
        unhex::<16>(&self.nonce)?;
        let public = VerifyingKey::from_bytes(&unhex::<32>(&self.holder_public_key)?)
            .map_err(|_| "invalid_holder_key")?;
        public
            .verify_strict(
                &self.preimage()?,
                &Signature::from_bytes(&unhex::<64>(&self.signature)?),
            )
            .map_err(|_| "invalid_presentation_signature")
    }
}
/// Standard, padded base64. The existing v1 authority transport uses base64url separately.
pub fn encode_request(bytes: &[u8]) -> String {
    let mut result = crate::devgraph_authority::encode_base64url(bytes)
        .replace('-', "+")
        .replace('_', "/");
    while !result.len().is_multiple_of(4) {
        result.push('=');
    }
    result
}
pub fn strict_value(raw: &[u8]) -> Result<Value> {
    strict_json(raw, MAX_ENVELOPE)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_bytes_are_independent_of_json_feature_map_order() {
        let value: Value =
            serde_json::from_str(r#"{"z":{"y":2,"a":"é"},"b":[{"z":1,"a":-2}],"a":0}"#).unwrap();
        assert_eq!(
            canonical(&value).unwrap(),
            "{\"a\":0,\"b\":[{\"a\":-2,\"z\":1}],\"z\":{\"a\":\"é\",\"y\":2}}".as_bytes()
        );
        for raw in ["1.5", "9007199254740992", "-9007199254740992"] {
            let value: Value = serde_json::from_str(raw).unwrap();
            assert!(canonical(&value).is_err(), "{raw}");
        }
    }
}
