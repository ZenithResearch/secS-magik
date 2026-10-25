//! Application-neutral credential-bound presentation contract.
//! No application operations, executable profiles, keys, clocks or storage live here.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{
    Deserialize, Serialize,
    de::{self, MapAccess, SeqAccess, Visitor},
};
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use std::fmt;

pub mod grant_validity;
pub mod read_authority;

pub type Result<T> = core::result::Result<T, &'static str>;
pub const MAX_SAFE: u64 = 9_007_199_254_740_991;
pub const MAX_REQUEST_BYTES: usize = 131_072;
pub const MAX_ENVELOPE_BYTES: usize = 262_144;
pub const CREDENTIAL_DOMAIN: &[u8] = b"castalia.request-credential.v1/signature\0";
pub const PRESENTATION_DOMAIN: &[u8] = b"castalia.credential-presentation.v2/signature\0";
const INVALID: &str = "invalid_credential_presentation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub kind: String,
    pub id: String,
}
impl Caller {
    pub fn validate(&self) -> Result<()> {
        ascii(&self.id)?;
        match self.kind.as_str() {
            "terminal" => Ok(()),
            "browser" => {
                let url = url::Url::parse(&self.id).map_err(|_| INVALID)?;
                let host = url.host().ok_or(INVALID)?;
                let loopback = match host {
                    url::Host::Domain(name) => name == "localhost",
                    url::Host::Ipv4(ip) => ip.is_loopback(),
                    url::Host::Ipv6(ip) => ip.is_loopback(),
                };
                if (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
                    || !url.username().is_empty()
                    || url.password().is_some()
                    || url.path() != "/"
                    || url.query().is_some()
                    || url.fragment().is_some()
                    || url.host_str().is_some_and(|host| host.ends_with('.'))
                    || url.origin().ascii_serialization() != self.id
                {
                    return Err(INVALID);
                }
                Ok(())
            }
            _ => Err(INVALID),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustPin {
    pub issuer: String,
    pub key_id: String,
    pub public_key: String,
    pub audience: String,
    pub callers: Vec<Caller>,
}
impl TrustPin {
    fn validate(&self) -> Result<()> {
        ascii(&self.issuer)?;
        ascii(&self.key_id)?;
        ascii(&self.audience)?;
        public_key(&self.public_key)?;
        if self.callers.is_empty() || self.callers.len() > 64 {
            return Err(INVALID);
        }
        for caller in &self.callers {
            caller.validate()?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    pub schema: String,
    pub caller: Caller,
    pub pins: Vec<TrustPin>,
}
impl TrustConfig {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let value: Self = parse(raw, MAX_ENVELOPE_BYTES)?;
        if value.schema != "castalia.wallet-presentation-trust.v1" {
            return Err(INVALID);
        }
        value.caller.validate()?;
        validate_pins(&value.pins)?;
        Ok(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Disclosure {
    pub title: String,
    pub statements: Vec<String>,
}
impl Disclosure {
    fn validate(&self) -> Result<()> {
        display(&self.title, 160)?;
        if self.statements.is_empty() || self.statements.len() > 144 {
            return Err(INVALID);
        }
        for statement in &self.statements {
            display(statement, 512)?;
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub claims: CredentialClaims,
    pub signature: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationRequest {
    pub schema: String,
    pub request_bytes_base64: String,
    pub disclosure: Disclosure,
    pub credential: Credential,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPresentation {
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
}
#[derive(Debug, Serialize)]
pub struct Presentation {
    #[serde(flatten)]
    unsigned: UnsignedPresentation,
    signature: String,
}
impl Presentation {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut value = strict_json(raw, MAX_ENVELOPE_BYTES)?;
        let signature = value
            .as_object_mut()
            .ok_or(INVALID)?
            .remove("signature")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(INVALID)?;
        decode_hex::<64>(&signature)?;
        let unsigned: UnsignedPresentation = serde_json::from_value(value).map_err(|_| INVALID)?;
        validate_unsigned(&unsigned)?;
        Ok(Self {
            unsigned,
            signature,
        })
    }
    pub fn canonical(&self) -> Result<Vec<u8>> {
        canonical_json(self)
    }
    pub fn unsigned(&self) -> &UnsignedPresentation {
        &self.unsigned
    }
}

/// Immutable intent and issuer authorization. Consumed by preparation after approval.
#[derive(Debug)]
pub struct PreparedRequest {
    request: PresentationRequest,
    canonical_request: Vec<u8>,
    credential_digest: String,
    prepared_at: u64,
    confirm_by: u64,
}
impl PreparedRequest {
    pub fn canonical_request(&self) -> &[u8] {
        &self.canonical_request
    }
    pub fn holder_public_key(&self) -> &str {
        &self.request.credential.claims.holder_public_key
    }
    pub fn summary(&self) -> Result<Vec<u8>> {
        let claims = &self.request.credential.claims;
        canonical_json(&serde_json::json!({
            "disclosure": self.request.disclosure, "issuer": claims.issuer,
            "key_id": claims.key_id, "holder_public_key": claims.holder_public_key,
            "audience": claims.audience, "caller": claims.caller,
            "request_digest_sha256": claims.request_digest_sha256,
            "credential_digest_sha256": self.credential_digest,
            "disclosure_digest_sha256": claims.disclosure_digest_sha256,
            "policy_digest_sha256": claims.policy_digest_sha256,
            "expires_at": claims.expires_at, "confirm_by": self.confirm_by,
        }))
    }
    pub fn prepare_presentation(self, now: u64, nonce: &[u8; 16]) -> Result<PreparedPresentation> {
        if now < self.prepared_at || now >= self.confirm_by {
            return Err("expired_credential_consent");
        }
        let claims = self.request.credential.claims;
        let unsigned = UnsignedPresentation {
            schema: "castalia.credential-presentation.v2".into(),
            holder_public_key: claims.holder_public_key,
            issuer: claims.issuer,
            key_id: claims.key_id,
            audience: claims.audience,
            caller: claims.caller,
            request_digest_sha256: claims.request_digest_sha256,
            credential_digest_sha256: self.credential_digest,
            disclosure_digest_sha256: claims.disclosure_digest_sha256,
            nonce: hex::encode(nonce),
            issued_at: now,
            expires_at: (now + 60).min(claims.expires_at),
        };
        let transcript = presentation_transcript(&unsigned)?;
        Ok(PreparedPresentation {
            unsigned,
            transcript,
        })
    }
}
#[derive(Debug)]
pub struct PreparedPresentation {
    unsigned: UnsignedPresentation,
    transcript: Vec<u8>,
}
impl PreparedPresentation {
    pub fn signature_transcript(&self) -> &[u8] {
        &self.transcript
    }
}

pub fn prepare_request(
    raw: &[u8],
    pins: &[TrustPin],
    caller: &Caller,
    holder: &str,
    now: u64,
) -> Result<PreparedRequest> {
    if now > MAX_SAFE - 120 {
        return Err("invalid_clock");
    }
    caller.validate()?;
    public_key(holder)?;
    validate_pins(pins)?;
    let request: PresentationRequest = parse(raw, MAX_ENVELOPE_BYTES)?;
    if request.schema != "castalia.credential-presentation-request.v2" {
        return Err(INVALID);
    }
    request.disclosure.validate()?;
    let bytes = STANDARD
        .decode(&request.request_bytes_base64)
        .map_err(|_| INVALID)?;
    if bytes.is_empty()
        || bytes.len() > MAX_REQUEST_BYTES
        || STANDARD.encode(&bytes) != request.request_bytes_base64
    {
        return Err(INVALID);
    }
    let claims = &request.credential.claims;
    if claims.schema != "castalia.request-credential.v1"
        || claims.holder_public_key != holder
        || &claims.caller != caller
        || claims.request_digest_sha256 != digest(&bytes)
        || claims.disclosure_digest_sha256 != digest(&canonical_json(&request.disclosure)?)
    {
        return Err(INVALID);
    }
    ascii(&claims.issuer)?;
    ascii(&claims.key_id)?;
    ascii(&claims.audience)?;
    decode_hex::<32>(&claims.request_digest_sha256)?;
    decode_hex::<32>(&claims.disclosure_digest_sha256)?;
    decode_hex::<32>(&claims.policy_digest_sha256)?;
    decode_hex::<16>(&claims.nonce)?;
    lifetime(claims.issued_at, claims.expires_at, now, 120)?;
    let pin = pins
        .iter()
        .find(|pin| {
            pin.issuer == claims.issuer
                && pin.key_id == claims.key_id
                && pin.audience == claims.audience
                && pin.callers.contains(caller)
        })
        .ok_or("untrusted_credential_issuer")?;
    let mut transcript = CREDENTIAL_DOMAIN.to_vec();
    transcript.extend(canonical_json(claims)?);
    verify_signature(&pin.public_key, &transcript, &request.credential.signature)?;
    let canonical_request = canonical_json(&request)?;
    let credential_digest = digest(&canonical_json(&request.credential)?);
    let confirm_by = (now + 120).min(claims.expires_at);
    Ok(PreparedRequest {
        request,
        canonical_request,
        credential_digest,
        prepared_at: now,
        confirm_by,
    })
}

pub fn complete(prepared: PreparedPresentation, signature: &[u8; 64]) -> Result<Presentation> {
    let signature = hex::encode(signature);
    verify_signature(
        &prepared.unsigned.holder_public_key,
        &prepared.transcript,
        &signature,
    )?;
    Ok(Presentation {
        unsigned: prepared.unsigned,
        signature,
    })
}
/// Verify issuer authorization and the holder proof. Receiver policy/replay remain separate.
pub fn verify_presentation(
    request: &[u8],
    raw: &[u8],
    pins: &[TrustPin],
    caller: &Caller,
    now: u64,
) -> Result<Presentation> {
    let presentation = Presentation::parse(raw)?;
    let p = &presentation.unsigned;
    let prepared = prepare_request(request, pins, caller, &p.holder_public_key, now)?;
    let c = &prepared.request.credential.claims;
    if p.issuer != c.issuer
        || p.key_id != c.key_id
        || p.audience != c.audience
        || p.caller != c.caller
        || p.request_digest_sha256 != c.request_digest_sha256
        || p.disclosure_digest_sha256 != c.disclosure_digest_sha256
        || p.credential_digest_sha256 != prepared.credential_digest
        || p.issued_at < c.issued_at
        || p.expires_at > c.expires_at
    {
        return Err(INVALID);
    }
    lifetime(p.issued_at, p.expires_at, now, 60)?;
    verify_signature(
        &p.holder_public_key,
        &presentation_transcript(p)?,
        &presentation.signature,
    )?;
    Ok(presentation)
}
fn validate_unsigned(p: &UnsignedPresentation) -> Result<()> {
    if p.schema != "castalia.credential-presentation.v2" {
        return Err(INVALID);
    }
    public_key(&p.holder_public_key)?;
    ascii(&p.issuer)?;
    ascii(&p.key_id)?;
    ascii(&p.audience)?;
    p.caller.validate()?;
    decode_hex::<32>(&p.request_digest_sha256)?;
    decode_hex::<32>(&p.credential_digest_sha256)?;
    decode_hex::<32>(&p.disclosure_digest_sha256)?;
    decode_hex::<16>(&p.nonce)?;
    lifetime(p.issued_at, p.expires_at, p.issued_at, 60)
}
fn presentation_transcript(unsigned: &UnsignedPresentation) -> Result<Vec<u8>> {
    validate_unsigned(unsigned)?;
    let mut bytes = PRESENTATION_DOMAIN.to_vec();
    bytes.extend(canonical_json(unsigned)?);
    Ok(bytes)
}
fn validate_pins(pins: &[TrustPin]) -> Result<()> {
    if pins.is_empty() || pins.len() > 64 {
        return Err("untrusted_credential_issuer");
    }
    for pin in pins {
        pin.validate()?;
    }
    Ok(())
}
fn lifetime(issued: u64, expires: u64, now: u64, max: u64) -> Result<()> {
    if expires > MAX_SAFE
        || issued >= expires
        || expires - issued > max
        || issued > now
        || now >= expires
    {
        return Err("expired_credential_presentation");
    }
    Ok(())
}
fn ascii(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 200 || !value.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(INVALID);
    }
    Ok(())
}
fn display(value: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len()>max || value.chars().any(|c| matches!(c, '\u{0000}'..='\u{001f}'|'\u{007f}'..='\u{009f}'|'\u{061c}'|'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')) { return Err(INVALID); }
    Ok(())
}
pub fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(INVALID);
    }
    hex::decode(value)
        .map_err(|_| INVALID)?
        .try_into()
        .map_err(|_| INVALID)
}
fn public_key(value: &str) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(&decode_hex::<32>(value)?).map_err(|_| INVALID)
}
fn verify_signature(key: &str, transcript: &[u8], signature: &str) -> Result<()> {
    public_key(key)?
        .verify_strict(
            transcript,
            &Signature::from_bytes(&decode_hex::<64>(signature)?),
        )
        .map_err(|_| "invalid_credential_signature")
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Stable ASCII-key canonical JSON, independent of serde_json map feature flags.
pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>> {
    fn append(value: &Value, out: &mut Vec<u8>) -> Result<()> {
        match value {
            Value::Object(map) => {
                out.push(b'{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort_unstable();
                for (i, key) in keys.into_iter().enumerate() {
                    if !key.is_ascii() {
                        return Err(INVALID);
                    }
                    if i > 0 {
                        out.push(b',');
                    }
                    out.extend(serde_json::to_vec(key).map_err(|_| INVALID)?);
                    out.push(b':');
                    append(&map[key], out)?;
                }
                out.push(b'}');
            }
            Value::Array(items) => {
                out.push(b'[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(b',');
                    }
                    append(item, out)?;
                }
                out.push(b']');
            }
            Value::Number(n) if n.as_u64().is_none_or(|n| n > MAX_SAFE) => return Err(INVALID),
            other => out.extend(serde_json::to_vec(other).map_err(|_| INVALID)?),
        }
        Ok(())
    }
    let value = serde_json::to_value(value).map_err(|_| INVALID)?;
    let mut out = Vec::new();
    append(&value, &mut out)?;
    Ok(out)
}
pub fn parse<T: serde::de::DeserializeOwned>(raw: &[u8], maximum: usize) -> Result<T> {
    serde_json::from_value(strict_json(raw, maximum)?).map_err(|_| INVALID)
}
fn strict_json(raw: &[u8], maximum: usize) -> Result<Value> {
    if raw.is_empty() || raw.len() > maximum {
        return Err(INVALID);
    }
    struct Strict(Value);
    impl<'de> Deserialize<'de> for Strict {
        fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
            struct V;
            impl<'de> Visitor<'de> for V {
                type Value = Strict;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("strict JSON")
                }
                fn visit_bool<E: de::Error>(self, v: bool) -> core::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_u64<E: de::Error>(self, v: u64) -> core::result::Result<Strict, E> {
                    if v > MAX_SAFE {
                        return Err(E::custom("unsafe integer"));
                    }
                    Ok(Strict(v.into()))
                }
                fn visit_i64<E: de::Error>(self, v: i64) -> core::result::Result<Strict, E> {
                    if v < 0 {
                        return Err(E::custom("negative integer"));
                    }
                    self.visit_u64(v as u64)
                }
                fn visit_str<E: de::Error>(self, v: &str) -> core::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_string<E: de::Error>(self, v: String) -> core::result::Result<Strict, E> {
                    Ok(Strict(v.into()))
                }
                fn visit_unit<E: de::Error>(self) -> core::result::Result<Strict, E> {
                    Ok(Strict(Value::Null))
                }
                fn visit_seq<A: SeqAccess<'de>>(
                    self,
                    mut a: A,
                ) -> core::result::Result<Strict, A::Error> {
                    let mut v = Vec::new();
                    while let Some(Strict(item)) = a.next_element()? {
                        v.push(item);
                    }
                    Ok(Strict(Value::Array(v)))
                }
                fn visit_map<A: MapAccess<'de>>(
                    self,
                    mut a: A,
                ) -> core::result::Result<Strict, A::Error> {
                    let mut m = Map::new();
                    while let Some(key) = a.next_key::<String>()? {
                        if m.contains_key(&key) {
                            return Err(de::Error::custom("duplicate key"));
                        }
                        let Strict(v) = a.next_value()?;
                        m.insert(key, v);
                    }
                    Ok(Strict(Value::Object(m)))
                }
            }
            d.deserialize_any(V)
        }
    }
    serde_json::from_slice::<Strict>(raw)
        .map(|v| v.0)
        .map_err(|_| INVALID)
}
