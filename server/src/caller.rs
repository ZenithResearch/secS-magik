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

    pub(crate) fn ensure_active_at(&self, now: u64) -> Result<(), VerificationError> {
        match self.status {
            VerificationKeyStatus::Active => {}
            VerificationKeyStatus::Revoked => return Err(VerificationError::RevokedCallerKey),
            VerificationKeyStatus::Expired => return Err(VerificationError::ExpiredCallerKey),
            VerificationKeyStatus::Unknown => return Err(VerificationError::UnknownCallerKey),
            VerificationKeyStatus::NotYetValid => {
                return Err(VerificationError::NotYetValidCallerKey)
            }
        }

        if let Some(not_before) = self.not_before {
            if now < not_before {
                return Err(VerificationError::NotYetValidCallerKey);
            }
        }
        if let Some(not_after) = self.not_after {
            if now > not_after {
                return Err(VerificationError::ExpiredCallerKey);
            }
        }
        if let Some(revoked_at) = self.revoked_at {
            if revoked_at <= now {
                return Err(VerificationError::RevokedCallerKey);
            }
        }

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
            if registry.keys.contains_key(&key.key_id) {
                // Duplicate ids fail closed: neither entry is usable, mirroring
                // PublicVerifierKeyRegistry.
                registry.duplicate_key_ids.insert(key.key_id.clone());
            }
            registry.keys.insert(key.key_id.clone(), key);
        }
        registry
    }

    pub fn get(&self, key_id: &str) -> Option<&CallerKey> {
        if self.duplicate_key_ids.contains(key_id) {
            return None;
        }
        self.keys.get(key_id)
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Load a caller key registry from a JSON file of the shape:
///
/// ```json
/// {
///   "fixture_only": false,
///   "callers": [
///     {
///       "key_id": "caller:alpha",
///       "subject_id": "did:example:alpha",
///       "algorithm": "ed25519",
///       "public_key_hex": "<64 hex chars>",
///       "status": "active",
///       "not_before": 0,
///       "not_after": 0,
///       "revoked_at": 0
///     }
///   ]
/// }
/// ```
///
/// `status` accepts active/revoked/expired/not_yet_valid (anything else maps
/// to Unknown and fails closed at verification). Zero/absent window fields
/// mean "unset". Returns the parsed registry plus the file's `fixture_only`
/// marker so production config can refuse fixture registries without the
/// explicit smoke allowance.
pub fn load_caller_registry_from_path(path: &Path) -> Result<(CallerKeyRegistry, bool), String> {
    let bytes = std::fs::read(path).map_err(|error| error.to_string())?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let fixture_only = value
        .get("fixture_only")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let entries = value
        .get("callers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "caller registry must contain a callers array".to_string())?;

    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        let key_id = require_string(entry, "key_id")?;
        let subject_id = require_string(entry, "subject_id")?;
        let algorithm = require_string(entry, "algorithm")?;
        if algorithm != "ed25519" {
            return Err(format!(
                "caller {key_id:?} has unsupported algorithm {algorithm:?}"
            ));
        }
        let public_key_hex = require_string(entry, "public_key_hex")?;
        let public_key_bytes = parse_hex_32(&public_key_hex)
            .ok_or_else(|| format!("caller {key_id:?} public_key_hex must be 64 hex chars"))?;
        let public_key = VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|_| format!("caller {key_id:?} public key is not a valid Ed25519 key"))?;
        let status = match entry.get("status").and_then(serde_json::Value::as_str) {
            Some("active") | None => VerificationKeyStatus::Active,
            Some("revoked") => VerificationKeyStatus::Revoked,
            Some("expired") => VerificationKeyStatus::Expired,
            Some("not_yet_valid") => VerificationKeyStatus::NotYetValid,
            Some(_) => VerificationKeyStatus::Unknown,
        };
        let window = |field: &str| {
            entry
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .filter(|value| *value > 0)
        };
        keys.push(CallerKey {
            key_id,
            subject_id,
            algorithm,
            public_key,
            status,
            not_before: window("not_before"),
            not_after: window("not_after"),
            revoked_at: window("revoked_at"),
        });
    }

    Ok((CallerKeyRegistry::from_keys(keys), fixture_only))
}

fn require_string(entry: &serde_json::Value, field: &str) -> Result<String, String> {
    entry
        .get(field)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("caller registry entry missing required field {field:?}"))
}

fn parse_hex_32(input: &str) -> Option<[u8; 32]> {
    crate::payload::parse_hex_32(input)
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn verifying_key(seed: u8) -> VerifyingKey {
        SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    #[test]
    fn registry_returns_registered_active_key() {
        let registry = CallerKeyRegistry::from_keys([CallerKey::active(
            "caller:alpha",
            "did:example:alpha",
            verifying_key(1),
        )]);

        let key = registry.get("caller:alpha").unwrap();
        assert_eq!(key.subject_id, "did:example:alpha");
        assert!(key.ensure_active_at(1_000).is_ok());
    }

    #[test]
    fn duplicate_key_ids_block_lookup_for_all_entries() {
        let registry = CallerKeyRegistry::from_keys([
            CallerKey::active("caller:alpha", "did:example:alpha", verifying_key(1)),
            CallerKey::active("caller:alpha", "did:example:impostor", verifying_key(2)),
        ]);

        assert!(registry.get("caller:alpha").is_none());
    }

    #[test]
    fn loader_parses_registry_and_fixture_marker() {
        let key = verifying_key(3);
        let hex: String = key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let json = format!(
            r#"{{"fixture_only": true, "callers": [{{
                "key_id": "caller:file",
                "subject_id": "did:example:file",
                "algorithm": "ed25519",
                "public_key_hex": "{hex}",
                "status": "active",
                "not_before": 100,
                "not_after": 2000
            }}]}}"#
        );
        let path =
            std::env::temp_dir().join(format!("caller-registry-{}.json", std::process::id()));
        std::fs::write(&path, json).unwrap();

        let (registry, fixture_only) = load_caller_registry_from_path(&path).unwrap();
        std::fs::remove_file(&path).ok();

        assert!(fixture_only);
        let entry = registry.get("caller:file").unwrap();
        assert_eq!(entry.subject_id, "did:example:file");
        assert_eq!(entry.not_before, Some(100));
        assert_eq!(entry.not_after, Some(2000));
        assert!(entry.ensure_active_at(50).is_err());
        assert!(entry.ensure_active_at(500).is_ok());
        assert!(entry.ensure_active_at(3000).is_err());
    }

    #[test]
    fn loader_rejects_unsupported_algorithm_and_missing_fields() {
        let path =
            std::env::temp_dir().join(format!("caller-registry-bad-{}.json", std::process::id()));

        std::fs::write(&path, r#"{"callers": [{"key_id": "caller:x", "subject_id": "s", "algorithm": "rsa", "public_key_hex": "00"}]}"#).unwrap();
        assert!(load_caller_registry_from_path(&path).is_err());

        std::fs::write(&path, r#"{"callers": [{"subject_id": "s"}]}"#).unwrap();
        assert!(load_caller_registry_from_path(&path).is_err());

        std::fs::write(&path, r#"{}"#).unwrap();
        assert!(load_caller_registry_from_path(&path).is_err());
        std::fs::remove_file(&path).ok();
    }
}
