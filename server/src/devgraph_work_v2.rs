//! Credential-bound Devgraph authority v2. V1 request bytes and projections remain independent.
use crate::credential_presentation::{
    self as generic, canonical, Caller, Credential, CredentialClaims, Disclosure, Presentation,
    PresentationRequest,
};
use crate::devgraph_authority::{
    actor_id_for_public_key, encode_base64url, idempotency_key_digest_sha256,
};
use crate::devgraph_work_authority::{digest, WorkPolicy};
use crate::devgraph_work_request::{strict_json, Result, WorkRequest, MAX_SAFE};
use crate::identity::{NodeVerifierIdentity, PublicVerifierKeyRegistry};
use crate::ledger::Ledger;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;

pub const SCHEMA: &str = "secs-devgraph-work-authority.v2";
pub const REPLAY_SCOPE: &str = "credential:operation:nonce";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    pub schema: String,
    pub schema_version: u64,
    pub issuer: String,
    pub callers: Vec<Caller>,
}
impl CredentialConfig {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let result: Self = serde_json::from_value(strict_json(raw, 65536)?)
            .map_err(|_| "invalid_credential_config")?;
        result.validate()?;
        Ok(result)
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != "secs-devgraph-credential-config.v2"
            || self.schema_version != 2
            || self.issuer.is_empty()
            || self.issuer.len() > 200
            || !self.issuer.bytes().all(|b| (0x20..=0x7e).contains(&b))
            || self.callers.is_empty()
            || self.callers.len() > 64
        {
            return Err("invalid_credential_config");
        }
        for (i, caller) in self.callers.iter().enumerate() {
            caller.validate()?;
            if self.callers[..i].contains(caller) {
                return Err("duplicate_caller");
            }
        }
        Ok(())
    }
    pub fn require_caller(&self, caller: &Caller) -> Result<()> {
        self.validate()?;
        caller.validate()?;
        if !self.callers.contains(caller) {
            return Err("untrusted_caller");
        }
        Ok(())
    }
}
fn parse_request(raw: &[u8]) -> Result<WorkRequest> {
    let value = strict_json(raw, 65_536)?;
    if value["schema"] == "devgraph.work-request.v1"
        && value["operation"]
            .as_str()
            .is_some_and(|op| op.starts_with("workflow."))
    {
        return Err("unsupported_workflow_operation");
    }
    WorkRequest::parse(raw)
}

/// Application-owned wrapper. Wallet only hashes these opaque bytes.
pub fn request_bytes(request: &WorkRequest, key: &str) -> Result<Vec<u8>> {
    let idempotency = idempotency_key_digest_sha256(key).map_err(|_| "invalid_idempotency_key")?;
    let mut out = b"devgraph.credential-request.v2\0".to_vec();
    out.extend(canonical(&json!({"schema":"devgraph.credential-request.v2","request":request.value,"idempotency_key_digest_sha256":idempotency}))?);
    if out.len() > generic::MAX_REQUEST {
        return Err("credential_request_too_large");
    }
    Ok(out)
}
/// Every canonical request byte appears in the attested disclosure; no truncation.
pub fn disclosure(request: &WorkRequest, key: &str) -> Result<Disclosure> {
    let mut statements = vec![
        format!("Operation: {}", request.operation),
        format!("Resources: {}", request.resources.join(", ")),
        format!(
            "Expected version: {}",
            request.value["expected_version"]
                .as_u64()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "new".into())
        ),
        format!(
            "Idempotency digest: {}",
            idempotency_key_digest_sha256(key).map_err(|_| "invalid_idempotency_key")?
        ),
    ];
    let mut text =
        std::str::from_utf8(&request.canonical).map_err(|_| "invalid_request_encoding")?;
    let mut index = 1;
    while !text.is_empty() {
        if index > 140 {
            return Err("disclosure_too_large");
        }
        let mut end = text.len().min(480);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        statements.push(format!("Request part {index}: {}", &text[..end]));
        text = &text[end..];
        index += 1;
    }
    let result = Disclosure {
        title: "Devgraph request".into(),
        statements,
    };
    result.validate()?;
    Ok(result)
}

pub(crate) struct CredentialSignaturePreimage(Vec<u8>);
impl CredentialSignaturePreimage {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
pub(crate) struct ProjectionSignaturePreimage(Vec<u8>);
impl ProjectionSignaturePreimage {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub struct CredentialInput<'a> {
    pub request_json: &'a [u8],
    pub idempotency_key: &'a str,
    pub holder_public_key: &'a str,
    pub caller: &'a Caller,
    pub nonce: [u8; 16],
    pub now: u64,
}
/// A preflight attestation only. Does not reserve replay state or execute a mutation.
pub fn issue_credential(
    identity: &NodeVerifierIdentity,
    registry: &PublicVerifierKeyRegistry,
    policy: &WorkPolicy,
    config: &CredentialConfig,
    input: CredentialInput<'_>,
) -> Result<PresentationRequest> {
    config.require_caller(input.caller)?;
    registry
        .require_devgraph_authority_signer_v1(
            identity.signer_key_id(),
            identity.public_key(),
            input.now,
        )
        .map_err(|_| "untrusted_secs_verifier_key")?;
    let holder = generic::unhex::<32>(input.holder_public_key)?;
    ed25519_dalek::VerifyingKey::from_bytes(&holder).map_err(|_| "invalid_holder_key")?;
    let actor = actor_id_for_public_key(&holder);
    let request = parse_request(input.request_json)?;
    let expires = policy.authorize_until_bounded(&actor, &request, input.now, 120)?;
    let bytes = request_bytes(&request, input.idempotency_key)?;
    let disclosure = disclosure(&request, input.idempotency_key)?;
    let mut credential = Credential {
        claims: CredentialClaims {
            schema: generic::CREDENTIAL_SCHEMA.into(),
            issuer: config.issuer.clone(),
            key_id: identity.signer_key_id().into(),
            holder_public_key: input.holder_public_key.into(),
            audience: policy.audience.clone(),
            caller: input.caller.clone(),
            request_digest_sha256: generic::sha256(&bytes),
            disclosure_digest_sha256: disclosure.digest()?,
            policy_digest_sha256: policy.digest()?,
            nonce: generic::hex(&input.nonce),
            issued_at: input.now,
            expires_at: expires,
        },
        signature: String::new(),
    };
    credential.signature = generic::hex(
        &identity
            .sign_request_credential(&CredentialSignaturePreimage(credential.preimage()?))
            .map_err(|_| "untrusted_secs_verifier_key")?,
    );
    credential.verify(
        &config.issuer,
        identity.signer_key_id(),
        identity.public_key(),
        &policy.audience,
        input.caller,
        input.now,
    )?;
    let output = PresentationRequest {
        schema: generic::REQUEST_SCHEMA.into(),
        request_bytes_base64: generic::encode_request(&bytes),
        disclosure,
        credential,
    };
    if canonical(&output)?.len() > generic::MAX_ENVELOPE {
        return Err("credential_request_too_large");
    }
    Ok(output)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkProjectionV2 {
    pub actor_id: String,
    pub actor_signature_suite: String,
    pub audience: String,
    pub expires_at: u64,
    pub idempotency_key_digest_sha256: String,
    pub issued_at: u64,
    pub nonce: String,
    pub operation: String,
    pub receiver_policy_digest_sha256: String,
    pub receiver_policy_id: String,
    pub receiver_policy_version: u64,
    pub replay_scope: String,
    pub request_digest_sha256: String,
    pub resources: Vec<String>,
    pub schema: String,
    pub schema_version: u64,
    pub secs_context_id: String,
    pub secs_verifier_key_id: String,
    pub secs_verifier_signature: String,
    pub secs_verifier_signature_suite: String,
    pub session_id: String,
    pub credential_request_digest_sha256: String,
    pub credential_digest_sha256: String,
    pub disclosure_digest_sha256: String,
    pub credential_presentation_digest_sha256: String,
}
impl WorkProjectionV2 {
    pub fn canonical(&self) -> Result<Vec<u8>> {
        canonical(self)
    }
}
pub struct WorkAuthorityInputV2<'a> {
    pub request_json: &'a [u8],
    pub credential_json: &'a [u8],
    pub disclosure_json: &'a [u8],
    pub presentation_json: &'a [u8],
    pub idempotency_key: &'a str,
    pub now: u64,
}
pub async fn issue_work_authority_v2(
    ledger: &Ledger,
    identity: &NodeVerifierIdentity,
    registry: &PublicVerifierKeyRegistry,
    policy: &WorkPolicy,
    config: &CredentialConfig,
    input: WorkAuthorityInputV2<'_>,
) -> Result<WorkProjectionV2> {
    if input.now > MAX_SAFE - 120 {
        return Err("invalid_clock");
    }
    registry
        .require_devgraph_authority_signer_v1(
            identity.signer_key_id(),
            identity.public_key(),
            input.now,
        )
        .map_err(|_| "untrusted_secs_verifier_key")?;
    let request = parse_request(input.request_json)?;
    let credential = Credential::parse(input.credential_json)?;
    let claims = &credential.claims;
    config.require_caller(&claims.caller)?;
    credential.verify(
        &config.issuer,
        identity.signer_key_id(),
        identity.public_key(),
        &policy.audience,
        &claims.caller,
        input.now,
    )?;
    let expected_bytes = request_bytes(&request, input.idempotency_key)?;
    let expected_disclosure = disclosure(&request, input.idempotency_key)?;
    let supplied_disclosure: Disclosure =
        serde_json::from_value(generic::strict_value(input.disclosure_json)?)
            .map_err(|_| "invalid_disclosure")?;
    if supplied_disclosure != expected_disclosure
        || claims.disclosure_digest_sha256 != expected_disclosure.digest()?
        || claims.request_digest_sha256 != generic::sha256(&expected_bytes)
        || claims.policy_digest_sha256 != policy.digest()?
    {
        return Err("credential_request_binding_mismatch");
    }
    let presentation = Presentation::parse(input.presentation_json)?;
    presentation.verify(&credential, input.now)?;
    let actor = actor_id_for_public_key(&generic::unhex::<32>(&claims.holder_public_key)?);
    // Current authority is checked again, independently of the credential's issuance.
    let expires = policy
        .authorize_until_bounded(&actor, &request, input.now, 60)?
        .min(presentation.expires_at);
    let policy_digest = policy.digest()?;
    let presentation_digest = presentation.digest()?;
    let credential_digest = credential.digest()?;
    let context_id = format!(
        "ctx:sha256:{}",
        digest(
            b"secs-devgraph-work-context.v2\0",
            &canonical(
                &json!({"policy":policy_digest,"presentation":presentation_digest,"signer":identity.signer_key_id()})
            )?
        )
    );
    let mut projection = WorkProjectionV2 {
        actor_id: actor,
        actor_signature_suite: "Ed25519".into(),
        audience: policy.audience.clone(),
        expires_at: expires,
        idempotency_key_digest_sha256: idempotency_key_digest_sha256(input.idempotency_key)
            .map_err(|_| "invalid_idempotency_key")?,
        issued_at: presentation.issued_at,
        nonce: presentation.nonce,
        operation: request.operation.clone(),
        receiver_policy_digest_sha256: policy_digest,
        receiver_policy_id: policy.policy_id.clone(),
        receiver_policy_version: policy.policy_version,
        replay_scope: REPLAY_SCOPE.into(),
        request_digest_sha256: digest(request.request_domain(), &request.canonical),
        resources: request.resources,
        schema: SCHEMA.into(),
        schema_version: 2,
        secs_context_id: context_id,
        secs_verifier_key_id: identity.signer_key_id().into(),
        secs_verifier_signature: String::new(),
        secs_verifier_signature_suite: "Ed25519".into(),
        session_id: claims.nonce.clone(),
        credential_request_digest_sha256: claims.request_digest_sha256.clone(),
        credential_digest_sha256: credential_digest,
        disclosure_digest_sha256: claims.disclosure_digest_sha256.clone(),
        credential_presentation_digest_sha256: presentation_digest,
    };
    let mut unsigned = serde_json::to_value(&projection).map_err(|_| "encoding_failed")?;
    unsigned
        .as_object_mut()
        .ok_or("encoding_failed")?
        .remove("secs_verifier_signature");
    let mut preimage = b"secs-devgraph-work-authority.v2/signature\0".to_vec();
    preimage.extend(canonical(&unsigned)?);
    projection.secs_verifier_signature = encode_base64url(
        &identity
            .sign_work_authority_v2(&ProjectionSignaturePreimage(preimage))
            .map_err(|_| "untrusted_secs_verifier_key")?,
    );
    reserve(ledger, &projection, input.now).await?;
    Ok(projection)
}
/// V2 has full 16-byte issuer and holder nonces; never reinterpret v1 replay rows.
async fn reserve(ledger: &Ledger, projection: &WorkProjectionV2, now: u64) -> Result<()> {
    sqlx::query(crate::schema::DEVGRAPH_AUTHORITY_V2_REPLAY_TABLE.ddl)
        .execute(ledger.pool())
        .await
        .map_err(|_| "replay_storage_failed")?;
    let bytes = projection.canonical()?;
    let mut tx = ledger
        .pool()
        .begin()
        .await
        .map_err(|_| "replay_storage_failed")?;
    sqlx::query("DELETE FROM devgraph_authority_v2_replay WHERE expires_at <= ?")
        .bind(now as i64)
        .execute(&mut *tx)
        .await
        .map_err(|_| "replay_storage_failed")?;
    let result = sqlx::query("INSERT OR IGNORE INTO devgraph_authority_v2_replay (session_id, operation, nonce, expires_at, projection) VALUES (?, ?, ?, ?, ?)")
        .bind(&projection.session_id).bind(&projection.operation).bind(&projection.nonce).bind(projection.expires_at as i64).bind(&bytes).execute(&mut *tx).await.map_err(|_| "replay_storage_failed")?;
    if result.rows_affected() == 0 {
        let row = sqlx::query("SELECT projection FROM devgraph_authority_v2_replay WHERE session_id = ? AND operation = ? AND nonce = ?")
            .bind(&projection.session_id).bind(&projection.operation).bind(&projection.nonce).fetch_one(&mut *tx).await.map_err(|_| "replay_storage_failed")?;
        if row
            .try_get::<Vec<u8>, _>("projection")
            .map_err(|_| "replay_storage_failed")?
            != bytes
        {
            return Err("replay_conflict");
        }
    }
    tx.commit().await.map_err(|_| "replay_storage_failed")?;
    Ok(())
}
