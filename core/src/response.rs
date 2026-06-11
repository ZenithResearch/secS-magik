//! Versioned caller decision response (M12.2).
//!
//! The gateway answers each connection with at most one `DecisionResponse`
//! frame: accept/reject, the typed reason on reject, and ledger references
//! (context id / receipt id) the caller or an operator can use to inspect the
//! decision. It is a **redaction-safe projection**: no payload bytes, no raw
//! evidence, no raw signature bytes ever appear here — only server-generated
//! identifiers and the typed reason vocabulary.
//!
//! Boundary: this is a local decision projection returned to the caller. It
//! is not handler output, not public auditability (#37), and not deployment
//! proof (#33).

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Bump on any change to the response shape.
pub const DECISION_RESPONSE_SCHEMA_VERSION: u16 = 1;

/// Upper bound a reader should accept for one encoded response frame. The
/// fixed-shape projection stays far below this by construction.
pub const MAX_DECISION_RESPONSE_BYTES: usize = 1024;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDecision {
    Accepted,
    Rejected,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DecisionResponse {
    pub schema_version: u16,
    pub decision: ResponseDecision,
    /// Typed reason code on reject (the server's stable reason vocabulary,
    /// never free-form text derived from caller input). `None` on accept.
    pub reason_code: Option<String>,
    /// Verified-context reference for ledger inspection, when one exists.
    pub context_id: Option<String>,
    /// Receipt reference for ledger inspection, when one was persisted.
    pub receipt_id: Option<String>,
}

impl DecisionResponse {
    pub fn accepted(context_id: Option<String>, receipt_id: Option<String>) -> Self {
        Self {
            schema_version: DECISION_RESPONSE_SCHEMA_VERSION,
            decision: ResponseDecision::Accepted,
            reason_code: None,
            context_id,
            receipt_id,
        }
    }

    pub fn rejected(
        reason_code: impl Into<String>,
        context_id: Option<String>,
        receipt_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: DECISION_RESPONSE_SCHEMA_VERSION,
            decision: ResponseDecision::Rejected,
            reason_code: Some(reason_code.into()),
            context_id,
            receipt_id,
        }
    }

    pub fn is_accepted(&self) -> bool {
        self.decision == ResponseDecision::Accepted
    }

    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("decision response serialization is infallible")
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > MAX_DECISION_RESPONSE_BYTES {
            return None;
        }
        bincode::deserialize(bytes).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn accepted_response_round_trips_with_schema_version() {
        let response = DecisionResponse::accepted(
            Some("ctx-v1-100-10-aabbccdd".to_string()),
            Some("receipt-execute-100-10-aabbccdd".to_string()),
        );

        let decoded = DecisionResponse::decode(&response.encode()).unwrap();
        assert_eq!(decoded, response);
        assert_eq!(decoded.schema_version, DECISION_RESPONSE_SCHEMA_VERSION);
        assert!(decoded.is_accepted());
        assert_eq!(decoded.reason_code, None);
    }

    #[test]
    fn rejected_response_carries_typed_reason_and_receipt_reference() {
        let response = DecisionResponse::rejected(
            "bad_caller_proof",
            None,
            Some("receipt-reject-100-10-aabbccdd".to_string()),
        );

        let decoded = DecisionResponse::decode(&response.encode()).unwrap();
        assert!(!decoded.is_accepted());
        assert_eq!(decoded.reason_code.as_deref(), Some("bad_caller_proof"));
        assert_eq!(
            decoded.receipt_id.as_deref(),
            Some("receipt-reject-100-10-aabbccdd")
        );
    }

    #[test]
    fn encoded_response_stays_far_below_the_frame_cap() {
        // Fixed-shape projection: even with generous id lengths the frame is
        // a small fraction of MAX_DECISION_RESPONSE_BYTES.
        let response = DecisionResponse::rejected(
            "prototype_operation_not_production_authorized",
            Some("ctx-v1-18446744073709551615-ff-aabbccddeeff0011".to_string()),
            Some("receipt-reject-18446744073709551615-ff-aabbccddeeff0011".to_string()),
        );

        assert!(response.encode().len() <= MAX_DECISION_RESPONSE_BYTES / 4);
    }

    #[test]
    fn decode_rejects_empty_oversized_and_garbage_frames() {
        assert!(DecisionResponse::decode(b"").is_none());
        assert!(DecisionResponse::decode(&[0u8; MAX_DECISION_RESPONSE_BYTES + 1]).is_none());
        assert!(DecisionResponse::decode(b"not a response frame").is_none());
    }
}
