use crate::identity::{
    explicit_test_fixture_identity, NodeVerifierIdentity, PublicVerifierKeyRegistry,
};
use crate::ledger::{Ledger, ReplayReservationOutcome};
use crate::manifest::ReceiverManifest;
use crate::ontology::{
    DEFAULT_RECEIVER_AUDIENCE, LOCAL_PROTOTYPE_SIGNER_ID, REPLAY_DETECTED_REASON,
    REPLAY_RESERVATION_FAILED_REASON, UNVERIFIED_PROTOTYPE_OPERATION,
};
use crate::permissions::PermissionPolicy;
use crate::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind};
use crate::runtime_mode::RuntimeMode;
use crate::schema::{apply_schema, TELEMETRY_TABLES};
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use async_trait::async_trait;
use libsec_core::ZenithPacket;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Child;
use tokio::time::timeout;

const DESCRIPTOR_CONTEXT_MISMATCH_REASON: &str = "descriptor_context_mismatch";
const LOCAL_DEV_RECEIPT_SIGNING_KEY: [u8; 32] = [7u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandlerOutcome {
    pub decision: Decision,
    pub reason: Option<String>,
    pub output_bytes: usize,
}

impl HandlerOutcome {
    pub fn succeeded() -> Self {
        Self {
            decision: Decision::Accepted,
            reason: None,
            output_bytes: 0,
        }
    }

    pub fn succeeded_with_output_bytes(output_bytes: usize) -> Self {
        Self {
            decision: Decision::Accepted,
            reason: None,
            output_bytes,
        }
    }

    pub fn rejected(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Rejected,
            reason: Some(reason.into()),
            output_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionLimits {
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
    pub handler_timeout: Duration,
}

impl Default for ExecutionLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            handler_timeout: Duration::from_secs(30),
        }
    }
}

#[async_trait]
pub trait MachineProgram: Send + Sync {
    async fn execute(
        &self,
        context: &VerifiedCallContext,
        payload: &[u8],
        limits: ExecutionLimits,
    ) -> HandlerOutcome;
}

pub struct ConfigurableRouter {
    programs: HashMap<String, Box<dyn MachineProgram>>,
    pool: SqlitePool,
    ledger: Ledger,
    limits: ExecutionLimits,
    identity: NodeVerifierIdentity,
    verifier_keys: PublicVerifierKeyRegistry,
    caller_keys: Option<crate::caller::CallerKeyRegistry>,
    expected_audience: String,
    /// Active manifest the router validates contexts against (M13.3). Defaults
    /// to `default_v0()`; the demo installs a manifest carrying the dev-bounded
    /// `demo.file.write` descriptor so `default_v0` stays the production set.
    manifest: ReceiverManifest,
    /// Optional receiver-local permission policy (M13). When set, every verified
    /// context is evaluated against it before handler dispatch (fail-closed).
    permission_policy: Option<PermissionPolicy>,
}

impl ConfigurableRouter {
    pub fn new(pool: SqlitePool) -> Self {
        Self::with_limits(pool, ExecutionLimits::default())
    }

    pub fn with_limits(pool: SqlitePool, limits: ExecutionLimits) -> Self {
        Self::with_limits_and_identity(
            pool,
            limits,
            explicit_test_fixture_identity(
                LOCAL_PROTOTYPE_SIGNER_ID,
                LOCAL_DEV_RECEIPT_SIGNING_KEY,
            ),
        )
    }

    pub fn with_identity(pool: SqlitePool, identity: NodeVerifierIdentity) -> Self {
        Self::with_limits_and_identity(pool, ExecutionLimits::default(), identity)
    }

    pub fn with_limits_and_identity(
        pool: SqlitePool,
        limits: ExecutionLimits,
        identity: NodeVerifierIdentity,
    ) -> Self {
        Self::with_limits_identity_and_audience(
            pool,
            limits,
            identity,
            DEFAULT_RECEIVER_AUDIENCE.to_string(),
        )
    }

    pub fn with_limits_identity_and_audience(
        pool: SqlitePool,
        limits: ExecutionLimits,
        identity: NodeVerifierIdentity,
        expected_audience: impl Into<String>,
    ) -> Self {
        let verifier_keys = PublicVerifierKeyRegistry::from_keys([identity.public_verifier_key()]);
        Self {
            programs: HashMap::new(),
            ledger: Ledger::new(pool.clone()),
            pool,
            limits,
            identity,
            verifier_keys,
            caller_keys: None,
            expected_audience: expected_audience.into(),
            manifest: ReceiverManifest::default_v0(),
            permission_policy: None,
        }
    }

    /// Install the active manifest (M13.3). The demo installs `default_v0()`
    /// plus the dev-bounded `demo.file.write` descriptor.
    pub fn set_manifest(&mut self, manifest: ReceiverManifest) {
        self.manifest = manifest;
    }

    /// Install a receiver-local permission policy (M13). With no policy the
    /// router does not enforce permissions (existing behavior); with one, every
    /// verified context is evaluated fail-closed before handler dispatch.
    pub fn set_permission_policy(&mut self, policy: PermissionPolicy) {
        self.permission_policy = Some(policy);
    }

    pub fn has_permission_policy(&self) -> bool {
        self.permission_policy.is_some()
    }

    /// Install the receiver-held caller key registry (M12.1). Required for
    /// `production_verified` runtime verification; optional fixture seam in
    /// local/dev modes.
    pub fn set_caller_registry(&mut self, caller_keys: crate::caller::CallerKeyRegistry) {
        self.caller_keys = Some(caller_keys);
    }

    pub fn caller_keys(&self) -> Option<&crate::caller::CallerKeyRegistry> {
        self.caller_keys.as_ref()
    }

    pub fn with_verifier_registry(
        pool: SqlitePool,
        verifier_keys: PublicVerifierKeyRegistry,
    ) -> Self {
        let mut router = Self::new(pool);
        router.verifier_keys = verifier_keys;
        router
    }

    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    pub fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        let handler_id = self
            .manifest
            .lookup(opcode)
            .map(|descriptor| descriptor.handler_id.clone())
            .unwrap_or_else(|_| format!("opcode/{opcode:02x}"));
        self.register_handler(handler_id, program);
    }

    pub fn register_handler(
        &mut self,
        handler_id: impl Into<String>,
        program: Box<dyn MachineProgram>,
    ) {
        self.programs.insert(handler_id.into(), program);
    }

    pub fn identity(&self) -> &NodeVerifierIdentity {
        &self.identity
    }

    pub async fn route(&self, opcode: u8, payload: Vec<u8>) {
        let payload_size = payload.len() as i64;
        let timestamp = current_unix_seconds();

        if let Err(e) = sqlx::query(
            "INSERT INTO node_telemetry (opcode, payload_size, operation) VALUES (?, ?, ?)",
        )
        .bind(i64::from(opcode))
        .bind(payload_size)
        .bind(UNVERIFIED_PROTOTYPE_OPERATION)
        .execute(&self.pool)
        .await
        {
            eprintln!("secS [Telemetry]: failed to write log - {}", e);
        }
        if let Err(e) = self
            .ledger
            .record_event(
                ReceiptEventKind::PacketReceived,
                None,
                Some(opcode),
                Some(UNVERIFIED_PROTOTYPE_OPERATION),
                None,
                Some(&format!("payload_size:{payload_size}")),
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write unverified event - {}", e);
        }

        let handler_id = self
            .manifest
            .lookup(opcode)
            .ok()
            .map(|descriptor| descriptor.handler_id.clone());
        match handler_id
            .as_deref()
            .and_then(|handler_id| self.programs.get(handler_id))
        {
            Some(_) => eprintln!(
                "secS [Router]: rejected unverified handler route for opcode {:#04x}",
                opcode
            ),
            None => eprintln!("secS [Router]: rejected unmapped opcode {:#04x}", opcode),
        }
    }

    pub async fn record_reject(&self, packet: &ZenithPacket, error: VerificationError) -> String {
        let timestamp = current_unix_seconds();
        let receipt_id = format!(
            "receipt-reject-{timestamp}-{:02x}-{}",
            packet.opcode,
            packet_receipt_suffix(packet)
        );
        let receipt = Receipt::reject_from_packet(receipt_id.clone(), packet, error, timestamp);
        let packet_hash = receipt.packet_hash;
        let reason = receipt.reason.clone();
        self.record_signed_receipt(receipt).await;
        if let Err(e) = self
            .ledger
            .record_event(
                ReceiptEventKind::PacketRejected,
                Some(packet_hash),
                Some(packet.opcode),
                None,
                None,
                reason.as_deref(),
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write reject event - {}", e);
        }
        receipt_id
    }

    /// Route a signed context and return the redaction-safe decision
    /// projection (M12.2) for the caller: decision, typed reason, and the
    /// ledger references. Never carries payload, evidence, or signature
    /// bytes.
    pub async fn route_verified(
        &self,
        signed: &SignedVerifiedCallContext,
        payload: Vec<u8>,
    ) -> libsec_core::response::DecisionResponse {
        let context = &signed.context;
        let payload_size = payload.len() as i64;
        let timestamp = current_unix_seconds();

        let verification_result = match self.identity.authenticator_kind() {
            AuthenticatorKind::LocalDevUntrusted => {
                self.verifier_keys
                    .verify_signed_context(signed, &self.expected_audience, timestamp)
            }
            _ if signed.authenticator_kind == AuthenticatorKind::LocalDevUntrusted
                || signed.signer_key_id == LOCAL_PROTOTYPE_SIGNER_ID =>
            {
                Err(VerificationError::UntrustedVerifierKey)
            }
            _ => self.verifier_keys.verify_production_signed_context(
                signed,
                &self.expected_audience,
                timestamp,
            ),
        };
        if let Err(error) = verification_result {
            let reason = error.reason_code();
            let mut receipt_id = None;
            if should_emit_signed_context_reject(&error) {
                receipt_id = Some(
                    self.record_verified_reject_receipt(signed, reason, timestamp)
                        .await,
                );
                self.record_operation_event(
                    ReceiptEventKind::PacketRejected,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
            }
            eprintln!(
                "secS [Router]: rejected signed context before routing - {}",
                reason
            );
            return libsec_core::response::DecisionResponse::rejected(
                reason,
                Some(context.context_id.clone()),
                receipt_id,
            );
        }

        if !signed_context_matches_active_manifest(context, &self.manifest) {
            let reason = DESCRIPTOR_CONTEXT_MISMATCH_REASON;
            let receipt_id = self
                .record_verified_reject_receipt(signed, reason, timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::PacketRejected,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            eprintln!(
                "secS [Router]: rejected signed context that mismatches active descriptor - {}",
                reason
            );
            return libsec_core::response::DecisionResponse::rejected(
                reason,
                Some(context.context_id.clone()),
                Some(receipt_id),
            );
        }

        if production_context_uses_dev_descriptor(
            signed,
            self.identity.authenticator_kind(),
            &self.manifest,
        ) {
            let reason = VerificationError::PrototypeOperationNotProductionAuthorized.reason_code();
            let receipt_id = self
                .record_verified_reject_receipt(signed, reason, timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::PacketRejected,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            eprintln!(
                "secS [Router]: rejected production signed context for dev/prototype descriptor before handler lookup - {}",
                reason
            );
            return libsec_core::response::DecisionResponse::rejected(
                reason,
                Some(context.context_id.clone()),
                Some(receipt_id),
            );
        }

        match self
            .ledger
            .reserve_replay(context, &signed.signer_key_id, timestamp)
            .await
        {
            Ok(ReplayReservationOutcome::Reserved) => {}
            Ok(ReplayReservationOutcome::Duplicate) => {
                let reason = REPLAY_DETECTED_REASON;
                let receipt_id = self
                    .record_verified_reject_receipt(signed, reason, timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::PacketRejected,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                eprintln!(
                    "secS [Router]: rejected replayed verified context {} before handler execution",
                    context.context_id
                );
                return libsec_core::response::DecisionResponse::rejected(
                    reason,
                    Some(context.context_id.clone()),
                    Some(receipt_id),
                );
            }
            Err(e) => {
                let reason = REPLAY_RESERVATION_FAILED_REASON;
                eprintln!("secS [Ledger]: failed to reserve replay slot - {}", e);
                let receipt_id = self
                    .record_verified_reject_receipt(signed, reason, timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::PacketRejected,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                return libsec_core::response::DecisionResponse::rejected(
                    reason,
                    Some(context.context_id.clone()),
                    Some(receipt_id),
                );
            }
        }

        if let Err(e) = sqlx::query(
            "INSERT INTO node_telemetry (opcode, payload_size, operation) VALUES (?, ?, ?)",
        )
        .bind(i64::from(context.opcode))
        .bind(payload_size)
        .bind(&context.operation)
        .execute(&self.pool)
        .await
        {
            eprintln!("secS [Telemetry]: failed to write verified log - {}", e);
        }

        // The verify receipt is part of the inspectable chain; the caller
        // response references the final execute receipt below.
        let _verify_receipt_id = self.record_verify_receipt(signed, timestamp).await;
        self.record_operation_event(ReceiptEventKind::OperationRouted, signed, timestamp, None)
            .await;

        // M13: receiver-local permission gate. The context is verified and the
        // descriptor matches the active manifest; now enforce the permission
        // policy (fail-closed) on the authenticated caller, opcode, operation,
        // and the resource bound into the signed context, before any handler
        // side effect. A denial records an execute-reject receipt with the
        // typed permission reason.
        if let Some(policy) = &self.permission_policy {
            let resource = context.resource.as_deref().unwrap_or("");
            if let Err(deny) = policy.evaluate(
                &context.subject.subject_id,
                context.opcode,
                &context.operation,
                resource,
                timestamp,
            ) {
                let reason = deny.code();
                let receipt_id = self
                    .record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::HandlerFailed,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                eprintln!(
                    "secS [Router]: permission denied for {} on {} ({:#04x}) - {}",
                    context.subject.subject_id, context.operation, context.opcode, reason
                );
                return libsec_core::response::DecisionResponse::rejected(
                    reason,
                    Some(context.context_id.clone()),
                    Some(receipt_id),
                );
            }
        }

        if payload.len() > self.limits.max_payload_bytes {
            let reason = "payload_too_large";
            let receipt_id = self
                .record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::HandlerFailed,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            return libsec_core::response::DecisionResponse::rejected(
                reason,
                Some(context.context_id.clone()),
                Some(receipt_id),
            );
        }

        let Some(handler_id) = context.handler_id.as_deref() else {
            let reason = "handler_unavailable";
            let receipt_id = self
                .record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::HandlerFailed,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            eprintln!(
                "secS [Router]: rejected verified operation without descriptor handler {} ({:#04x})",
                context.operation, context.opcode
            );
            return libsec_core::response::DecisionResponse::rejected(
                reason,
                Some(context.context_id.clone()),
                Some(receipt_id),
            );
        };

        match self.programs.get(handler_id) {
            Some(program) => {
                self.record_operation_event(
                    ReceiptEventKind::HandlerStarted,
                    signed,
                    timestamp,
                    Some(&format!("payload_size:{payload_size}")),
                )
                .await;
                let outcome = match timeout(
                    self.limits.handler_timeout,
                    program.execute(context, &payload, self.limits),
                )
                .await
                {
                    Ok(outcome) => outcome,
                    Err(_) => HandlerOutcome::rejected("handler_timeout"),
                };
                let outcome = if outcome.output_bytes > self.limits.max_output_bytes {
                    HandlerOutcome::rejected("output_too_large")
                } else {
                    outcome
                };
                let reason = outcome.reason.as_deref();
                let receipt_id = self
                    .record_execution_receipt(signed, outcome.decision, reason, timestamp)
                    .await;
                let event_kind = match outcome.decision {
                    Decision::Accepted => ReceiptEventKind::HandlerSucceeded,
                    Decision::Rejected => ReceiptEventKind::HandlerFailed,
                };
                self.record_operation_event(event_kind, signed, timestamp, reason)
                    .await;
                match outcome.decision {
                    Decision::Accepted => libsec_core::response::DecisionResponse::accepted(
                        Some(context.context_id.clone()),
                        Some(receipt_id),
                    ),
                    Decision::Rejected => libsec_core::response::DecisionResponse::rejected(
                        outcome.reason.as_deref().unwrap_or("handler_rejected"),
                        Some(context.context_id.clone()),
                        Some(receipt_id),
                    ),
                }
            }
            None => {
                let reason = "handler_unavailable";
                let receipt_id = self
                    .record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::HandlerFailed,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                eprintln!(
                    "secS [Router]: rejected verified operation without handler {} ({:#04x})",
                    context.operation, context.opcode
                );
                libsec_core::response::DecisionResponse::rejected(
                    reason,
                    Some(context.context_id.clone()),
                    Some(receipt_id),
                )
            }
        }
    }

    async fn record_verified_reject_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        reason: &str,
        timestamp: u64,
    ) -> String {
        let receipt_id = format!(
            "receipt-reject-{timestamp}-{:02x}-{}",
            signed.context.opcode,
            context_receipt_suffix(&signed.context)
        );
        let receipt = Receipt::reject_from_verified_context(
            receipt_id.clone(),
            &signed.context,
            reason,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
        receipt_id
    }

    async fn record_verify_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        timestamp: u64,
    ) -> String {
        let receipt_id = format!(
            "receipt-verify-{timestamp}-{:02x}-{}",
            signed.context.opcode,
            context_receipt_suffix(&signed.context)
        );
        let receipt = Receipt::verify_from_signed_context(receipt_id.clone(), signed, timestamp);
        self.record_signed_receipt(receipt).await;
        self.record_operation_event(ReceiptEventKind::PacketVerified, signed, timestamp, None)
            .await;
        receipt_id
    }

    async fn record_execution_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        decision: Decision,
        reason: Option<&str>,
        timestamp: u64,
    ) -> String {
        let receipt_id = format!(
            "receipt-execute-{timestamp}-{:02x}-{}",
            signed.context.opcode,
            context_receipt_suffix(&signed.context)
        );
        let receipt = Receipt::execution(
            receipt_id.clone(),
            &signed.context,
            decision,
            reason,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
        receipt_id
    }

    async fn record_signed_receipt(&self, receipt: Receipt) {
        let signed = match self.identity.sign_receipt(receipt) {
            Ok(receipt) => receipt,
            Err(error) => {
                eprintln!(
                    "secS [Ledger]: failed to sign receipt - {}",
                    error.reason_code()
                );
                return;
            }
        };
        // Use atomic tx-wrapped receipt + ReceiptEmitted for #25 atomic chain persistence.
        // Failure here surfaces as audit failure (no silent split); incomplete marker can be added in future H4/H5 if needed.
        if let Err(e) = self
            .ledger
            .record_receipt_with_emitted_event(
                &signed,
                ReceiptEventKind::ReceiptEmitted,
                Some(signed.packet_hash),
                Some(signed.opcode),
                signed.operation.as_deref(),
                signed.handler_id.as_deref(),
                Some(signed.kind.as_str()),
                signed.timestamp,
            )
            .await
        {
            eprintln!(
                "secS [Ledger]: failed to write receipt+event atomically - {}",
                e
            );
        }
    }

    async fn record_operation_event(
        &self,
        event_kind: ReceiptEventKind,
        signed: &SignedVerifiedCallContext,
        timestamp: u64,
        reason: Option<&str>,
    ) {
        let context = &signed.context;
        if let Err(e) = self
            .ledger
            .record_event(
                event_kind,
                Some(context.packet_hash),
                Some(context.opcode),
                Some(&context.operation),
                context.handler_id.as_deref(),
                reason,
                timestamp,
            )
            .await
        {
            eprintln!("secS [Ledger]: failed to write operation event - {}", e);
        }
    }
}
pub async fn init_telemetry_schema(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    apply_schema(pool, TELEMETRY_TABLES).await?;
    Ledger::new(pool.clone()).init_schema().await
}

fn current_unix_seconds() -> u64 {
    // Fail-closed: a clock-read failure yields the sentinel, which the
    // verifier and signed-context checks reject as expired (M12.5).
    crate::clock::failclosed_unix_seconds()
}

fn should_emit_signed_context_reject(error: &VerificationError) -> bool {
    matches!(
        error,
        VerificationError::ExpiredClaim
            | VerificationError::WrongAudience
            | VerificationError::InvalidSignature
            | VerificationError::UnknownVerifierKey
            | VerificationError::RevokedVerifierKey
            | VerificationError::ExpiredVerifierKey
            | VerificationError::NotYetValidVerifierKey
    )
}

fn signed_context_matches_active_manifest(
    context: &VerifiedCallContext,
    manifest: &ReceiverManifest,
) -> bool {
    let Ok(descriptor) = manifest.lookup(context.opcode) else {
        return false;
    };
    // #81: the context's descriptor authorization fingerprint must match the
    // ACTIVE descriptor exactly — operation/handler checks stay as cheap
    // guards, but the fingerprint binds every authorization-relevant field
    // (credentials, capabilities, evidence, schema, target kind, replay
    // scope, TTL bound, range). Empty fingerprints never route.
    if context.descriptor_fingerprint.is_empty()
        || context.descriptor_fingerprint != descriptor.authorization_fingerprint()
    {
        return false;
    }
    // The context's actual TTL span must also respect the ACTIVE bound: a
    // stale-but-looser descriptor must not let an overlong context ride in.
    if context.expires_at.saturating_sub(context.issued_at) > descriptor.max_ttl_seconds {
        return false;
    }
    context.operation == descriptor.name.as_str()
        && context.handler_id.as_deref() == Some(descriptor.handler_id.as_str())
}

fn production_context_uses_dev_descriptor(
    signed: &SignedVerifiedCallContext,
    router_authenticator_kind: AuthenticatorKind,
    manifest: &ReceiverManifest,
) -> bool {
    if router_authenticator_kind == AuthenticatorKind::LocalDevUntrusted {
        return false;
    }
    let Ok(descriptor) = manifest.lookup(signed.context.opcode) else {
        return true;
    };
    descriptor.dev_binding
        || descriptor.handler_id.starts_with("dev/")
        || descriptor.name.as_str().starts_with("candidate.dev")
        || (descriptor.target_kind == crate::manifest::TargetKind::LegacyCoreExample
            && descriptor
                .accepted_evidence
                .iter()
                .any(|evidence| evidence == "prototype-proof-envelope"))
}

fn context_receipt_suffix(context: &VerifiedCallContext) -> String {
    let hash_prefix = context.packet_hash[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{}-{hash_prefix}", context.context_id)
}

fn packet_receipt_suffix(packet: &ZenithPacket) -> String {
    let bytes = bincode::serialize(packet).unwrap_or_default();
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let hash_prefix = digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let nonce_suffix = packet.nonce[4..]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{nonce_suffix}-{hash_prefix}")
}

pub struct SubprocessForwarder {
    pub program: String,
    pub args: Vec<String>,
}

impl SubprocessForwarder {
    pub fn new(program: &str, args: Vec<&str>) -> Self {
        Self {
            program: program.to_string(),
            args: args.into_iter().map(|s| s.to_string()).collect(),
        }
    }
}

struct ProcessGroupGuard {
    #[cfg(unix)]
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn new(child: &Child) -> Self {
        Self {
            #[cfg(unix)]
            pid: child.id(),
        }
    }

    async fn terminate(&mut self, child: &mut Child) {
        #[cfg(unix)]
        if let Some(pid) = self.pid.take() {
            signal_process_group(pid, SIGTERM);
            tokio::time::sleep(Duration::from_millis(20)).await;
            signal_process_group(pid, SIGKILL);
            let _ = child.wait().await;
            return;
        }

        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    fn disarm(&mut self) {
        #[cfg(unix)]
        {
            self.pid = None;
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.pid.take() {
            signal_process_group(pid, SIGKILL);
        }
    }
}

#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIGKILL: i32 = 9;

#[cfg(unix)]
unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(unix)]
fn signal_process_group(pid: u32, signal: i32) {
    let Ok(pid) = i32::try_from(pid) else {
        return;
    };
    let _ = unsafe { kill(-pid, signal) };
}

async fn read_one_chunk<R: AsyncRead + Unpin>(
    reader: &mut Option<R>,
    limit: usize,
) -> Result<usize, std::io::Error> {
    let Some(stream) = reader.as_mut() else {
        return Ok(0);
    };
    let mut buffer = vec![0u8; limit.clamp(1, 8192)];
    let read = stream.read(&mut buffer).await?;
    if read == 0 {
        *reader = None;
    }
    Ok(read)
}

async fn wait_for_bounded_subprocess_output(
    mut child: Child,
    mut guard: ProcessGroupGuard,
    limit: usize,
    timeout_duration: Duration,
) -> HandlerOutcome {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut output_bytes = 0usize;
    let sleep = tokio::time::sleep(timeout_duration);
    tokio::pin!(sleep);

    loop {
        if output_bytes > limit {
            guard.terminate(&mut child).await;
            return HandlerOutcome::rejected("output_too_large");
        }

        if stdout.is_none() && stderr.is_none() {
            match child.wait().await {
                Ok(status) if status.success() => {
                    guard.disarm();
                    return HandlerOutcome::succeeded_with_output_bytes(output_bytes);
                }
                Ok(_) => {
                    guard.disarm();
                    return HandlerOutcome::rejected("handler_exit_failed");
                }
                Err(_) => return HandlerOutcome::rejected("handler_wait_failed"),
            }
        }

        tokio::select! {
            _ = &mut sleep => {
                guard.terminate(&mut child).await;
                return HandlerOutcome::rejected("handler_timeout");
            }
            result = read_one_chunk(&mut stdout, limit.saturating_sub(output_bytes).saturating_add(1)), if stdout.is_some() => {
                match result {
                    Ok(read) => output_bytes = output_bytes.saturating_add(read),
                    Err(_) => {
                        guard.terminate(&mut child).await;
                        return HandlerOutcome::rejected("handler_wait_failed");
                    }
                }
            }
            result = read_one_chunk(&mut stderr, limit.saturating_sub(output_bytes).saturating_add(1)), if stderr.is_some() => {
                match result {
                    Ok(read) => output_bytes = output_bytes.saturating_add(read),
                    Err(_) => {
                        guard.terminate(&mut child).await;
                        return HandlerOutcome::rejected("handler_wait_failed");
                    }
                }
            }
        }
    }
}

#[async_trait]
impl MachineProgram for SubprocessForwarder {
    async fn execute(
        &self,
        context: &VerifiedCallContext,
        payload: &[u8],
        limits: ExecutionLimits,
    ) -> HandlerOutcome {
        let Some(handler_id) = context.handler_id.as_deref() else {
            return HandlerOutcome::rejected("handler_unavailable");
        };
        if !handler_id.starts_with("dev/") {
            return HandlerOutcome::rejected("handler_not_dev_bound");
        }
        println!(
            "secS [Subprocess]: invoking verified dev handler `{}` via `{} {:?}`",
            handler_id, self.program, self.args
        );
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        {
            command.process_group(0);
        }
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("secS [Subprocess]: failed to spawn - {}", e);
                return HandlerOutcome::rejected("handler_spawn_failed");
            }
        };
        let mut guard = ProcessGroupGuard::new(&child);

        if let Some(mut stdin) = child.stdin.take() {
            match timeout(
                limits.handler_timeout,
                tokio::io::AsyncWriteExt::write_all(&mut stdin, payload),
            )
            .await
            {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if e.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!(
                            "secS [Subprocess]: failed to write payload to stdin - {}",
                            e
                        );
                        guard.terminate(&mut child).await;
                        return HandlerOutcome::rejected("handler_stdin_failed");
                    }
                }
                Err(_) => {
                    guard.terminate(&mut child).await;
                    return HandlerOutcome::rejected("handler_timeout");
                }
            }
        }
        wait_for_bounded_subprocess_output(
            child,
            guard,
            limits.max_output_bytes,
            limits.handler_timeout,
        )
        .await
    }
}

pub struct LocalRustQueue;

#[async_trait]
impl MachineProgram for LocalRustQueue {
    async fn execute(
        &self,
        context: &VerifiedCallContext,
        payload: &[u8],
        _limits: ExecutionLimits,
    ) -> HandlerOutcome {
        println!(
            "secS [Native Rust]: enqueueing {} bytes for handler {:?}...",
            payload.len(),
            context.handler_id
        );
        HandlerOutcome::succeeded()
    }
}

pub fn register_runtime_bindings(router: &mut ConfigurableRouter, runtime_mode: RuntimeMode) {
    // #78 active-binding posture: the canonical 0x44 descriptor's
    // membership/provision handler is registered in every runtime mode so
    // the default manifest and default bindings agree. The binding grants no
    // authority: descriptor-only production verification still fails closed
    // (#77) and live ingress carries no evidence refs yet (#79 API-only) —
    // only evidence-backed verifier-signed contexts can reach it. See
    // server/src/membership.rs for the full decision record.
    router.register_handler(
        crate::membership::MEMBERSHIP_PROVISION_HANDLER_ID,
        Box::new(crate::membership::MembershipProvisionProgram),
    );
    if matches!(
        runtime_mode,
        RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel
    ) {
        router.register_handler("dev/json-validate", Box::new(LocalRustQueue));
        register_dev_subprocess_bindings(router);
    }
}

pub fn register_prototype_bindings(router: &mut ConfigurableRouter) {
    register_runtime_bindings(router, RuntimeMode::LocalDevPlaintext);
}

pub fn register_dev_subprocess_bindings(router: &mut ConfigurableRouter) {
    router.register_handler(
        "dev/bash-echo",
        Box::new(SubprocessForwarder::new(
            "bash",
            vec!["-c", "echo 'Bash received payload:'; cat"],
        )),
    );
    router.register_handler(
        "dev/jq-identity",
        Box::new(SubprocessForwarder::new("jq", vec!["."])),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subprocess_forwarder_new_copies_program_and_args() {
        let forwarder = SubprocessForwarder::new("bash", vec!["-c", "cat"]);

        assert_eq!(forwarder.program, "bash");
        assert_eq!(forwarder.args, vec!["-c".to_string(), "cat".to_string()]);
    }
}
