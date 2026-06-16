//! Re-export of the receiver-local permission model, which lives in the
//! standalone wasm-compatible [`secs_permissions`] crate so the gateway, the
//! `secs-permctl` CLI, and the browser control panel all share one model.
//! `server::permissions::X` continues to resolve to the same types.

pub use secs_permissions::*;
