//! Receiver-held caller key registry and caller proof-of-origin verification
//! (M12.1). Mirrors the fail-closed structure of `PublicVerifierKeyRegistry`:
//! status, validity window, revocation, and duplicate-id handling all reject.
//!
//! Boundary: caller proof-of-origin is necessary but never sufficient
//! authority. It identifies who sent the packet; it does not replace wallet,
//! issuer, or Dregg evidence, and it never grants `membership.provision`.

use crate::identity::VerificationKeyStatus;
use crate::verifier::VerificationError;
use ed25519_dalek::VerifyingKey;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// A caller public key the receiver has chosen to trust as a packet origin.
#[derive(Debug, Clone)]
pub struct CallerKey {
    pub key_id: String,
    pub subject_id: String,
    pub algorithm: String,
    pub public_key: VerifyingKey,
    pub status: VerificationKeyStatus,
    pub not_before: Option<u64>,
    pub not_after: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl CallerKey {
    pub fn active(
        key_id: impl Into<String>,
        subject_id: impl Into<String>,
        public_key: VerifyingKey,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            subject_id: subject_id.into(),
            algorithm: "ed25519".to_string(),
            public_key,
            status: VerificationKeyStatus::Active,
            not_before: None,
            not_after: None,
            revoked_at: None,
        }
    }

    pub fn with_status(mut self, status: VerificationKeyStatus) -> Self {
        self.status = status;
        self
    }

    pub fn with_validity_window(mut self, not_before: Option<u64>, not_after: Option<u64>) -> Self {
        self.not_before = not_before;
        self.not_after = not_after;
        self
    }

    pub fn with_revoked_at(mut self, revoked_at: Option<u64>) -> Self {
        self.revoked_at = revoked_at;
        self
    }

    fn ensure_active_at(&self, _now: u64) -> Result<(), VerificationError> {
        // Implemented in M12.1.2 — skeleton accepts unconditionally so the
        // RED matrix in tests/caller_auth.rs demonstrates the gap.
        Ok(())
    }
}

/// The identity established by a verified caller proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub subject_id: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Default)]
pub struct CallerKeyRegistry {
    keys: HashMap<String, CallerKey>,
    duplicate_key_ids: HashSet<String>,
}

impl CallerKeyRegistry {
    pub fn from_keys(keys: impl IntoIterator<Item = CallerKey>) -> Self {
        let mut registry = Self::default();
        for key in keys {
            registry.keys.insert(key.key_id.clone(), key);
        }
        registry
    }

    pub fn get(&self, key_id: &str) -> Option<&CallerKey> {
        self.keys.get(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Load a caller key registry from a JSON file. Implemented in M12.1.2.
pub fn load_caller_registry_from_path(_path: &Path) -> Result<CallerKeyRegistry, String> {
    Err("caller registry loading not implemented".to_string())
}

/// Verify the packet's caller proof-of-origin against the receiver-held
/// registry. Implemented in M12.1.3.
pub fn verify_caller_proof(
    _packet: &libsec_core::ZenithPacket,
    _registry: &CallerKeyRegistry,
    _now: u64,
) -> Result<AuthenticatedCaller, VerificationError> {
    Err(VerificationError::InternalError)
}
