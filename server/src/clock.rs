//! Single fail-closed wall-clock definition for the verification hot path.
//!
//! `SystemTime::now()` can fail (pre-epoch clock). Before M12.5 the gateway and
//! ingress fell back to `0`, which made every `now > expires_at` style check
//! evaluate as "not expired" — fail-open exactly where expiry gates live
//! verification. This module defines the one fail-closed policy: an unreadable
//! clock yields a sentinel that verification entry points explicitly reject.
//!
//! Boundary: this is not a trusted or monotonic time source and adds no NTP
//! dependency; it only removes the fail-open fallback.

use std::time::{SystemTime, UNIX_EPOCH};

/// Returned when the wall clock cannot be read. `u64::MAX` pushes every expiry
/// comparison toward "expired", and verification entry points reject it
/// outright so a clock-read failure can never be treated as fresh time.
pub const CLOCK_READ_FAILURE_SENTINEL: u64 = u64::MAX;

/// Read unix seconds, returning [`CLOCK_READ_FAILURE_SENTINEL`] on failure.
pub fn failclosed_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(CLOCK_READ_FAILURE_SENTINEL)
}

/// True when `now` carries the clock-read failure sentinel and must be
/// rejected by any verification or routing decision.
pub fn is_clock_read_failure(now: u64) -> bool {
    now == CLOCK_READ_FAILURE_SENTINEL
}
