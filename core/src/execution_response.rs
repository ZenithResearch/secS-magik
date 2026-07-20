//! Versioned, receiver-signed execution response codec.
//!
//! This transport is intentionally separate from `DecisionResponse`. The manual
//! codec fixes field order, integer encoding, option tags, and framing so exact
//! ingress correlation and output bytes are authenticated without relying on a
//! derived serializer.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub const EXECUTION_RESPONSE_SCHEMA_VERSION: u16 = 1;
pub const EXECUTION_RESPONSE_MAGIC: &[u8; 8] = b"SECSEX1\0";
pub const MAX_EXECUTION_RESPONSE_BYTES: usize = 266_240;
pub const MAX_EXECUTION_RESPONSE_BODY_BYTES: usize = 266_164;
pub const EXECUTION_RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"secs-execution-response-v1/signature";

pub const HANDLER_OUTPUT_MISSING: &str = "handler_output_missing";
pub const HANDLER_OUTPUT_UNEXPECTED: &str = "handler_output_unexpected";
pub const OUTPUT_TOO_LARGE: &str = "output_too_large";
pub const EXECUTION_RESPONSE_TOO_LARGE: &str = "execution_response_too_large";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    VerifierRejected,
    ExecutionRejected,
    Executed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionAuthenticatorKind {
    Ed25519Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResponse {
    pub schema_version: u16,
    pub status: ExecutionStatus,
    pub reason_code: Option<String>,
    pub request_digest: [u8; 32],
    pub context_id: Option<String>,
    pub receipt_id: Option<String>,
    pub output_schema: Option<String>,
    pub output: Option<Vec<u8>>,
    pub authenticator_kind: ExecutionAuthenticatorKind,
    pub signer_key_id: String,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionResponseError {
    EmptyFrame,
    FrameTooLarge,
    MalformedFrame,
    UnknownSchemaVersion,
    UnknownStatus,
    UnknownAuthenticator,
    UnknownOptionTag,
    InvalidUtf8,
    InvalidState,
    UnknownReason,
    ResponseAuthenticationFailed,
}

impl ExecutionResponseError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::ResponseAuthenticationFailed => "response_authentication_failed",
            _ => "execution_response_malformed",
        }
    }
}

impl ExecutionResponse {
    pub fn validate_state(&self) -> Result<(), ExecutionResponseError> {
        if self.schema_version != EXECUTION_RESPONSE_SCHEMA_VERSION {
            return Err(ExecutionResponseError::UnknownSchemaVersion);
        }
        if self.signer_key_id.is_empty() {
            return Err(ExecutionResponseError::InvalidState);
        }
        let valid = match self.status {
            ExecutionStatus::VerifierRejected => {
                self.reason_code.as_deref().is_some_and(is_nonempty)
                    && self.output_schema.is_none()
                    && self.output.is_none()
            }
            ExecutionStatus::ExecutionRejected => {
                self.reason_code.as_deref().is_some_and(is_nonempty)
                    && self.context_id.as_deref().is_some_and(is_nonempty)
                    && self.receipt_id.as_deref().is_some_and(is_nonempty)
                    && self.output_schema.is_none()
                    && self.output.is_none()
            }
            ExecutionStatus::Executed => {
                self.reason_code.is_none()
                    && self.context_id.as_deref().is_some_and(is_nonempty)
                    && self.receipt_id.as_deref().is_some_and(is_nonempty)
                    && self.output_schema.as_deref().is_some_and(is_nonempty)
                    && self.output.is_some()
            }
        };
        if !valid {
            return Err(ExecutionResponseError::InvalidState);
        }
        if self.status == ExecutionStatus::ExecutionRejected
            && !self.reason_code.as_deref().is_some_and(is_execution_reason)
        {
            return Err(ExecutionResponseError::UnknownReason);
        }
        Ok(())
    }

    pub fn canonical_unsigned_body(&self) -> Result<Vec<u8>, ExecutionResponseError> {
        self.validate_state()?;
        let mut body = Vec::new();
        body.extend_from_slice(&self.schema_version.to_le_bytes());
        body.push(match self.status {
            ExecutionStatus::VerifierRejected => 0,
            ExecutionStatus::ExecutionRejected => 1,
            ExecutionStatus::Executed => 2,
        });
        encode_optional_text(&mut body, self.reason_code.as_deref())?;
        body.extend_from_slice(&self.request_digest);
        encode_optional_text(&mut body, self.context_id.as_deref())?;
        encode_optional_text(&mut body, self.receipt_id.as_deref())?;
        encode_optional_text(&mut body, self.output_schema.as_deref())?;
        encode_optional_bytes(&mut body, self.output.as_deref())?;
        body.push(1);
        encode_required_text(&mut body, &self.signer_key_id)?;
        if body.len() > MAX_EXECUTION_RESPONSE_BODY_BYTES {
            return Err(ExecutionResponseError::FrameTooLarge);
        }
        Ok(body)
    }

    pub fn signature_preimage(&self) -> Result<Vec<u8>, ExecutionResponseError> {
        let body = self.canonical_unsigned_body()?;
        let mut preimage =
            Vec::with_capacity(EXECUTION_RESPONSE_SIGNATURE_DOMAIN.len() + body.len());
        preimage.extend_from_slice(EXECUTION_RESPONSE_SIGNATURE_DOMAIN);
        preimage.extend_from_slice(&body);
        Ok(preimage)
    }

    pub fn encode_frame(&self, effective_bound: usize) -> Result<Vec<u8>, ExecutionResponseError> {
        let body = self.canonical_unsigned_body()?;
        let body_len =
            u32::try_from(body.len()).map_err(|_| ExecutionResponseError::FrameTooLarge)?;
        let full_len = EXECUTION_RESPONSE_MAGIC.len() + 4 + body.len() + 64;
        if full_len > effective_bound.min(MAX_EXECUTION_RESPONSE_BYTES) {
            return Err(ExecutionResponseError::FrameTooLarge);
        }
        let mut frame = Vec::with_capacity(full_len);
        frame.extend_from_slice(EXECUTION_RESPONSE_MAGIC);
        frame.extend_from_slice(&body_len.to_le_bytes());
        frame.extend_from_slice(&body);
        frame.extend_from_slice(&self.signature);
        Ok(frame)
    }

    pub fn decode_frame(
        frame: &[u8],
        effective_bound: usize,
    ) -> Result<Self, ExecutionResponseError> {
        if frame.is_empty() {
            return Err(ExecutionResponseError::EmptyFrame);
        }
        if frame.len() > effective_bound.min(MAX_EXECUTION_RESPONSE_BYTES) {
            return Err(ExecutionResponseError::FrameTooLarge);
        }
        if frame.len() < 8 + 4 + 64 || &frame[..8] != EXECUTION_RESPONSE_MAGIC {
            return Err(ExecutionResponseError::MalformedFrame);
        }
        let declared = u32::from_le_bytes(
            frame[8..12]
                .try_into()
                .map_err(|_| ExecutionResponseError::MalformedFrame)?,
        ) as usize;
        if declared > MAX_EXECUTION_RESPONSE_BODY_BYTES {
            return Err(ExecutionResponseError::FrameTooLarge);
        }
        let expected = 8usize
            .checked_add(4)
            .and_then(|value| value.checked_add(declared))
            .and_then(|value| value.checked_add(64))
            .ok_or(ExecutionResponseError::FrameTooLarge)?;
        if expected != frame.len() {
            return Err(ExecutionResponseError::MalformedFrame);
        }
        let body = &frame[12..12 + declared];
        let mut cursor = Cursor::new(body);
        let schema_version = cursor.u16()?;
        if schema_version != EXECUTION_RESPONSE_SCHEMA_VERSION {
            return Err(ExecutionResponseError::UnknownSchemaVersion);
        }
        let status = match cursor.u8()? {
            0 => ExecutionStatus::VerifierRejected,
            1 => ExecutionStatus::ExecutionRejected,
            2 => ExecutionStatus::Executed,
            _ => return Err(ExecutionResponseError::UnknownStatus),
        };
        let reason_code = cursor.optional_text()?;
        let request_digest = cursor.fixed::<32>()?;
        let context_id = cursor.optional_text()?;
        let receipt_id = cursor.optional_text()?;
        let output_schema = cursor.optional_text()?;
        let output = cursor.optional_bytes()?;
        let authenticator_kind = match cursor.u8()? {
            1 => ExecutionAuthenticatorKind::Ed25519Receiver,
            _ => return Err(ExecutionResponseError::UnknownAuthenticator),
        };
        let signer_key_id = cursor.required_text()?;
        if !cursor.is_empty() {
            return Err(ExecutionResponseError::MalformedFrame);
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&frame[12 + declared..]);
        let response = Self {
            schema_version,
            status,
            reason_code,
            request_digest,
            context_id,
            receipt_id,
            output_schema,
            output,
            authenticator_kind,
            signer_key_id,
            signature,
        };
        response.validate_state()?;
        Ok(response)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn decode_and_verify(
        frame: &[u8],
        effective_frame_bound: usize,
        effective_output_bound: usize,
        expected_signer_key_id: &str,
        verifying_key: &VerifyingKey,
        expected_request_digest: [u8; 32],
        expected_output_schema: Option<&str>,
    ) -> Result<Self, ExecutionResponseError> {
        let response = Self::decode_frame(frame, effective_frame_bound)
            .map_err(|_| ExecutionResponseError::ResponseAuthenticationFailed)?;
        if response.signer_key_id != expected_signer_key_id {
            return Err(ExecutionResponseError::ResponseAuthenticationFailed);
        }
        let signature = Signature::from_bytes(&response.signature);
        verifying_key
            .verify(
                &response
                    .signature_preimage()
                    .map_err(|_| ExecutionResponseError::ResponseAuthenticationFailed)?,
                &signature,
            )
            .map_err(|_| ExecutionResponseError::ResponseAuthenticationFailed)?;
        if response.request_digest != expected_request_digest
            || response.output_schema.as_deref() != expected_output_schema
            || response
                .output
                .as_ref()
                .is_some_and(|output| output.len() > effective_output_bound)
        {
            return Err(ExecutionResponseError::ResponseAuthenticationFailed);
        }
        Ok(response)
    }
}

fn is_nonempty(value: &str) -> bool {
    !value.is_empty()
}

fn is_execution_reason(value: &str) -> bool {
    matches!(
        value,
        HANDLER_OUTPUT_MISSING
            | HANDLER_OUTPUT_UNEXPECTED
            | OUTPUT_TOO_LARGE
            | EXECUTION_RESPONSE_TOO_LARGE
            | "handler_unavailable"
            | "handler_timeout"
            | "handler_rejected"
            | "payload_too_large"
            | "permission_denied"
            | "permission_expired"
            | "permission_revoked"
            | "permission_resource_mismatch"
            | "permission_operation_mismatch"
            | "permission_opcode_mismatch"
            | "permission_subject_mismatch"
            | "scoped_nullifier_storage_failed"
            | "duplicate_nullifier"
            | "missing_scoped_nullifier"
            | "unsupported_nullifier_scope"
            | "nullifier_domain_mismatch"
            | "malformed_packet"
            | "expired_claim"
            | "claim_ttl_exceeds_descriptor_max"
            | "invalid_session"
            | "missing_prototype_proof_envelope"
            | "bad_prototype_proof_envelope"
            | "missing_tunnel_key"
            | "bad_mac"
            | "unknown_operation"
            | "prototype_operation_not_production_authorized"
            | "wrong_audience"
            | "wrong_subject"
            | "wrong_origin"
            | "wrong_operation"
            | "wrong_resource"
            | "resource_lock_violation"
            | "authority_amplification"
            | "insufficient_evidence"
            | "invalid_presentation"
            | "invalid_signature"
            | "not_yet_valid_claim"
            | "unsupported_signature_suite"
            | "unknown_issuer"
            | "wrong_issuer_key"
            | "wrong_trust_root"
            | "wrong_registry_root"
            | "wrong_root"
            | "wrong_epoch"
            | "stale"
            | "revoked"
            | "not_final"
            | "equivocated"
            | "malformed"
            | "unsupported_suite"
            | "wrong_binding"
            | "missing_status"
            | "missing_revocation_root"
            | "wrong_revocation_root"
            | "unsupported_revocation_verifier"
            | "unsupported_bls_threshold_finality"
            | "unsupported_rotated_replay_verifier"
            | "missing_live_dregg_verifier"
            | "missing_live_dregg_revocation_verifier"
            | "missing_live_dregg_bls_threshold_verifier"
            | "missing_live_dregg_rotated_replay_verifier"
            | "evidence_tier_too_weak"
            | "unsupported_evidence_kind"
            | "unsupported_evidence_tier"
            | "unsupported_authority_mode"
            | "authority_mode_downgrade"
            | "reserved_authority_mode"
            | "stale_dregg_revocation_root"
            | "invalid_dregg_revocation_proof"
            | "invalid_dregg_finality_qc"
            | "unsupported_dregg_finality_committee"
            | "invalid_dregg_rotated_proof"
            | "invalid_admission"
            | "revoked_issuer"
            | "revoked_credential"
            | "stale_registry_status"
            | "unknown_verifier_key"
            | "revoked_verifier_key"
            | "expired_verifier_key"
            | "not_yet_valid_verifier_key"
            | "untrusted_verifier_key"
            | "bad_caller_proof"
            | "unknown_caller_key"
            | "revoked_caller_key"
            | "expired_caller_key"
            | "not_yet_valid_caller_key"
            | "missing_caller_registry"
            | "privacy_policy_violation"
            | "over_disclosed_presentation"
            | "forbidden_field_present"
            | "internal_error"
    )
}

fn encode_required_text(out: &mut Vec<u8>, value: &str) -> Result<(), ExecutionResponseError> {
    encode_len(out, value.len())?;
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn encode_optional_text(
    out: &mut Vec<u8>,
    value: Option<&str>,
) -> Result<(), ExecutionResponseError> {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            encode_required_text(out, value)?;
        }
    }
    Ok(())
}

fn encode_optional_bytes(
    out: &mut Vec<u8>,
    value: Option<&[u8]>,
) -> Result<(), ExecutionResponseError> {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            encode_len(out, value.len())?;
            out.extend_from_slice(value);
        }
    }
    Ok(())
}

fn encode_len(out: &mut Vec<u8>, len: usize) -> Result<(), ExecutionResponseError> {
    let len = u32::try_from(len).map_err(|_| ExecutionResponseError::FrameTooLarge)?;
    out.extend_from_slice(&len.to_le_bytes());
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ExecutionResponseError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ExecutionResponseError::MalformedFrame)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ExecutionResponseError::MalformedFrame)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ExecutionResponseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ExecutionResponseError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ExecutionResponseError::MalformedFrame)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, ExecutionResponseError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| ExecutionResponseError::MalformedFrame)?,
        ))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], ExecutionResponseError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ExecutionResponseError::MalformedFrame)
    }

    fn required_text(&mut self) -> Result<String, ExecutionResponseError> {
        let len =
            usize::try_from(self.u32()?).map_err(|_| ExecutionResponseError::MalformedFrame)?;
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes)
            .map(ToString::to_string)
            .map_err(|_| ExecutionResponseError::InvalidUtf8)
    }

    fn optional_text(&mut self) -> Result<Option<String>, ExecutionResponseError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.required_text().map(Some),
            _ => Err(ExecutionResponseError::UnknownOptionTag),
        }
    }

    fn optional_bytes(&mut self) -> Result<Option<Vec<u8>>, ExecutionResponseError> {
        match self.u8()? {
            0 => Ok(None),
            1 => {
                let len = usize::try_from(self.u32()?)
                    .map_err(|_| ExecutionResponseError::MalformedFrame)?;
                self.take(len).map(|bytes| Some(bytes.to_vec()))
            }
            _ => Err(ExecutionResponseError::UnknownOptionTag),
        }
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};
    use ed25519_dalek::{Signer, SigningKey};

    const DIGEST: [u8; 32] = [0x22; 32];

    fn signed(mut response: ExecutionResponse) -> ExecutionResponse {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        response.signature = key.sign(&response.signature_preimage().unwrap()).to_bytes();
        response
    }

    fn executed(output: Vec<u8>) -> ExecutionResponse {
        signed(ExecutionResponse {
            schema_version: EXECUTION_RESPONSE_SCHEMA_VERSION,
            status: ExecutionStatus::Executed,
            reason_code: None,
            request_digest: DIGEST,
            context_id: Some("ctx-1".into()),
            receipt_id: Some("receipt-1".into()),
            output_schema: Some("agent.chat.response.v1".into()),
            output: Some(output),
            authenticator_kind: ExecutionAuthenticatorKind::Ed25519Receiver,
            signer_key_id: "receiver-key-1".into(),
            signature: [0; 64],
        })
    }

    #[test]
    fn execution_response_unsigned_body_and_full_frame_are_exact() {
        let response = executed(b"ok".to_vec());
        let body = response.canonical_unsigned_body().unwrap();
        assert_eq!(
            hex(&body),
            "01000200222222222222222222222222222222222222222222222222222222222222222201050000006374782d310109000000726563656970742d3101160000006167656e742e636861742e726573706f6e73652e763101020000006f6b010e00000072656365697665722d6b65792d31"
        );
        let frame = response.encode_frame(MAX_EXECUTION_RESPONSE_BYTES).unwrap();
        assert_eq!(&frame[..8], EXECUTION_RESPONSE_MAGIC);
        assert_eq!(
            u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize,
            body.len()
        );
        assert_eq!(&frame[12..12 + body.len()], body.as_slice());
        assert_eq!(&frame[12 + body.len()..], response.signature.as_slice());
    }

    #[test]
    fn execution_response_accepts_only_three_valid_states() {
        let verifier_rejected = ExecutionResponse {
            schema_version: 1,
            status: ExecutionStatus::VerifierRejected,
            reason_code: Some("wrong_audience".into()),
            request_digest: DIGEST,
            context_id: None,
            receipt_id: None,
            output_schema: None,
            output: None,
            authenticator_kind: ExecutionAuthenticatorKind::Ed25519Receiver,
            signer_key_id: "receiver-key-1".into(),
            signature: [0; 64],
        };
        assert!(verifier_rejected.validate_state().is_ok());

        let execution_rejected = ExecutionResponse {
            status: ExecutionStatus::ExecutionRejected,
            reason_code: Some("handler_timeout".into()),
            context_id: Some("ctx-1".into()),
            receipt_id: Some("receipt-1".into()),
            ..verifier_rejected.clone()
        };
        assert!(execution_rejected.validate_state().is_ok());
        assert!(executed(Vec::new()).validate_state().is_ok());

        for invalid in [
            ExecutionResponse {
                reason_code: None,
                ..verifier_rejected.clone()
            },
            ExecutionResponse {
                output: Some(Vec::new()),
                ..verifier_rejected.clone()
            },
            ExecutionResponse {
                context_id: None,
                ..execution_rejected.clone()
            },
            ExecutionResponse {
                output_schema: Some("x".into()),
                ..execution_rejected.clone()
            },
            ExecutionResponse {
                reason_code: Some("handler_timeout".into()),
                ..executed(vec![1])
            },
            ExecutionResponse {
                output: None,
                ..executed(vec![1])
            },
        ] {
            assert_eq!(
                invalid.validate_state(),
                Err(ExecutionResponseError::InvalidState)
            );
        }
    }

    #[test]
    fn execution_response_rejects_unknown_values_and_unrecognized_p3_reasons() {
        let mut frame = executed(b"ok".to_vec())
            .encode_frame(MAX_EXECUTION_RESPONSE_BYTES)
            .unwrap();
        frame[14] = 9;
        assert_eq!(
            ExecutionResponse::decode_frame(&frame, MAX_EXECUTION_RESPONSE_BYTES),
            Err(ExecutionResponseError::UnknownStatus)
        );

        let invalid_reason = ExecutionResponse {
            status: ExecutionStatus::ExecutionRejected,
            reason_code: Some("new_unreviewed_p3_reason".into()),
            output: None,
            output_schema: None,
            ..executed(b"ok".to_vec())
        };
        assert_eq!(
            invalid_reason.validate_state(),
            Err(ExecutionResponseError::UnknownReason)
        );
        for reason in [
            HANDLER_OUTPUT_MISSING,
            HANDLER_OUTPUT_UNEXPECTED,
            OUTPUT_TOO_LARGE,
            EXECUTION_RESPONSE_TOO_LARGE,
        ] {
            let response = ExecutionResponse {
                reason_code: Some(reason.into()),
                ..invalid_reason.clone()
            };
            assert!(response.validate_state().is_ok());
        }
    }

    #[test]
    fn execution_response_rejects_empty_truncated_oversized_and_trailing_frames() {
        let frame = executed(b"ok".to_vec())
            .encode_frame(MAX_EXECUTION_RESPONSE_BYTES)
            .unwrap();
        assert!(ExecutionResponse::decode_frame(&[], MAX_EXECUTION_RESPONSE_BYTES).is_err());
        assert!(ExecutionResponse::decode_frame(
            &frame[..frame.len() - 1],
            MAX_EXECUTION_RESPONSE_BYTES
        )
        .is_err());
        assert_eq!(
            ExecutionResponse::decode_frame(
                &vec![0; MAX_EXECUTION_RESPONSE_BYTES + 1],
                MAX_EXECUTION_RESPONSE_BYTES
            ),
            Err(ExecutionResponseError::FrameTooLarge)
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            ExecutionResponse::decode_frame(&trailing, MAX_EXECUTION_RESPONSE_BYTES),
            Err(ExecutionResponseError::MalformedFrame)
        );
        let mut duplicate = frame.clone();
        duplicate.extend_from_slice(&frame);
        assert!(ExecutionResponse::decode_frame(&duplicate, MAX_EXECUTION_RESPONSE_BYTES).is_err());
    }

    #[test]
    fn execution_response_authenticates_before_exposure_and_binds_every_field() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let response = executed(b"secret output".to_vec());
        let frame = response.encode_frame(MAX_EXECUTION_RESPONSE_BYTES).unwrap();
        let verified = ExecutionResponse::decode_and_verify(
            &frame,
            MAX_EXECUTION_RESPONSE_BYTES,
            1024,
            "receiver-key-1",
            &key.verifying_key(),
            DIGEST,
            Some("agent.chat.response.v1"),
        )
        .unwrap();
        assert_eq!(
            verified.output.as_deref(),
            Some(b"secret output".as_slice())
        );

        let wrong_key = SigningKey::from_bytes(&[8u8; 32]);
        for result in [
            ExecutionResponse::decode_and_verify(
                &frame,
                MAX_EXECUTION_RESPONSE_BYTES,
                1024,
                "wrong-id",
                &key.verifying_key(),
                DIGEST,
                Some("agent.chat.response.v1"),
            ),
            ExecutionResponse::decode_and_verify(
                &frame,
                MAX_EXECUTION_RESPONSE_BYTES,
                1024,
                "receiver-key-1",
                &wrong_key.verifying_key(),
                DIGEST,
                Some("agent.chat.response.v1"),
            ),
            ExecutionResponse::decode_and_verify(
                &frame,
                MAX_EXECUTION_RESPONSE_BYTES,
                1024,
                "receiver-key-1",
                &key.verifying_key(),
                [9; 32],
                Some("agent.chat.response.v1"),
            ),
            ExecutionResponse::decode_and_verify(
                &frame,
                MAX_EXECUTION_RESPONSE_BYTES,
                1024,
                "receiver-key-1",
                &key.verifying_key(),
                DIGEST,
                Some("wrong.schema"),
            ),
        ] {
            assert_eq!(
                result,
                Err(ExecutionResponseError::ResponseAuthenticationFailed)
            );
        }

        let mut substituted = frame.clone();
        let output_offset = substituted
            .windows(b"secret output".len())
            .position(|window| window == b"secret output")
            .unwrap();
        substituted[output_offset] ^= 1;
        assert_eq!(
            ExecutionResponse::decode_and_verify(
                &substituted,
                MAX_EXECUTION_RESPONSE_BYTES,
                1024,
                "receiver-key-1",
                &key.verifying_key(),
                DIGEST,
                Some("agent.chat.response.v1")
            ),
            Err(ExecutionResponseError::ResponseAuthenticationFailed)
        );
    }

    #[test]
    fn execution_response_enforces_exact_frame_and_output_bounds() {
        let response = executed(vec![7; 8]);
        let frame = response.encode_frame(MAX_EXECUTION_RESPONSE_BYTES).unwrap();
        assert!(ExecutionResponse::decode_frame(&frame, frame.len()).is_ok());
        assert_eq!(
            ExecutionResponse::decode_frame(&frame, frame.len() - 1),
            Err(ExecutionResponseError::FrameTooLarge)
        );
        let key = SigningKey::from_bytes(&[7u8; 32]);
        assert!(ExecutionResponse::decode_and_verify(
            &frame,
            frame.len(),
            8,
            "receiver-key-1",
            &key.verifying_key(),
            DIGEST,
            Some("agent.chat.response.v1")
        )
        .is_ok());
        assert_eq!(
            ExecutionResponse::decode_and_verify(
                &frame,
                frame.len(),
                7,
                "receiver-key-1",
                &key.verifying_key(),
                DIGEST,
                Some("agent.chat.response.v1")
            ),
            Err(ExecutionResponseError::ResponseAuthenticationFailed)
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
