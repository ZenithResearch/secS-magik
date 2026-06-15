//! Bounded production-shaped `membership.provision` handler (#78).
//!
//! ## Runtime posture decision (#78)
//!
//! `membership.provision` is an **active runtime operation**: the default
//! runtime bindings register this handler in every runtime mode, resolving
//! the previous contract mismatch where `ReceiverManifest::default_v0()`
//! advertised `handler_id = "membership/provision"` that
//! `register_runtime_bindings()` never bound. Deferral was rejected because
//! it would require runtime-mode-aware manifest selection and would point
//! away from the active-operation path that #80 (active-descriptor E2E) and
//! the M13+ permission milestones build on.
//!
//! A handler binding is **not** authority. Reaching this handler requires a
//! verifier-signed context, and those remain gated upstream:
//!
//! - descriptor-only `production_verified` verification for canonical `0x44`
//!   still fails closed with `insufficient_evidence` (#77);
//! - live TCP ingress supplies no evidence refs yet (#79 landed API-only),
//!   so runtime ingress cannot mint evidence-backed contexts;
//! - evidence-backed contexts require wallet proof-of-possession plus
//!   receiver-held trusted-issuer membership credentials (Track E).
//!
//! The v0 effect of a provisioned membership is the auditable
//! verify+execute receipt chain for the verified context — this handler
//! deliberately defines no further application/business semantics. It is a
//! bounded native program: no subprocesses, no PATH dependence, no storage
//! or logging of payload/evidence material.

use crate::gateway::{ExecutionLimits, HandlerOutcome, MachineProgram};
use crate::verifier::VerifiedCallContext;
use async_trait::async_trait;

/// Handler id advertised by the canonical `0x44` descriptor.
pub const MEMBERSHIP_PROVISION_HANDLER_ID: &str = "membership/provision";

pub struct MembershipProvisionProgram;

#[async_trait]
impl MachineProgram for MembershipProvisionProgram {
    async fn execute(
        &self,
        _context: &VerifiedCallContext,
        payload: &[u8],
        limits: ExecutionLimits,
    ) -> HandlerOutcome {
        // The router enforces payload bounds before invocation; this check is
        // defensive so the handler stays bounded even if called directly.
        if payload.len() > limits.max_payload_bytes {
            return HandlerOutcome::rejected("payload_too_large");
        }
        HandlerOutcome::succeeded()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_handler_accepts_within_limits_and_rejects_oversize() {
        let program = MembershipProvisionProgram;
        let limits = ExecutionLimits::default();
        let context = crate::verifier::VerifiedCallContext {
            schema_version: 2,
            descriptor_fingerprint: String::new(),
            context_id: "ctx_membership_test".to_string(),
            packet_hash: [7u8; 32],
            session_id: [1u8; 16],
            nonce: [2u8; 12],
            opcode: 0x44,
            operation: "membership.provision".to_string(),
            resource: None,
            subject: crate::verifier::VerifiedSubject {
                subject_id: "did:example:alice#key-1".to_string(),
                key_id: "did:example:alice#key-1#key".to_string(),
            },
            audience: "secS://local-test".to_string(),
            evidence_summary: vec![],
            capability_result: String::new(),
            credential_result: String::new(),
            issued_at: 100,
            expires_at: 200,
            replay_scope: "session:opcode:nonce".to_string(),
            handler_id: Some(MEMBERSHIP_PROVISION_HANDLER_ID.to_string()),
        };

        let accepted = program
            .execute(&context, br#"{"membership":"requested"}"#, limits)
            .await;
        assert_eq!(accepted.decision, crate::receipt::Decision::Accepted);
        assert_eq!(accepted.output_bytes, 0, "handler emits no output bytes");

        let oversized = vec![0u8; limits.max_payload_bytes + 1];
        let rejected = program.execute(&context, &oversized, limits).await;
        assert_eq!(rejected.decision, crate::receipt::Decision::Rejected);
        assert_eq!(rejected.reason.as_deref(), Some("payload_too_large"));
    }
}
