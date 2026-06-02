//! Signed receipt and audit event boundary.
//!
//! Receipt types are separated from ingress and gateway routing so verified,
//! rejected, executed, and forwarded events can become durable audit records in
//! the receipt implementation slice.
