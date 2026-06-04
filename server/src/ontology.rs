//! Shared semantic constants for the current prototype server ontology.
//!
//! Keep values here when multiple runtime or test surfaces need the same
//! receiver/subject identity vocabulary. This avoids hardcoded drift while the
//! production configuration surface is still being carved out.

pub const DEFAULT_RECEIVER_AUDIENCE: &str = "secS://receiver-a";
pub const PROTOTYPE_LOCAL_SUBJECT: &str = "prototype.local-dev.subject";
pub const LOCAL_TEST_AUDIENCE: &str = "secS://local-test";
pub const LOCAL_TEST_ORIGIN: &str = "https://gallery.localhost";

pub const LOCAL_PROTOTYPE_SIGNER_ID: &str = "verifier:local-prototype";
pub const UNVERIFIED_PROTOTYPE_OPERATION: &str = "unverified.prototype";
pub const REPLAY_DETECTED_REASON: &str = "replay_detected";
pub const REPLAY_RESERVATION_FAILED_REASON: &str = "replay_reservation_failed";
