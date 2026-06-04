use crate::identity::{
    explicit_test_fixture_identity, NodeVerifierIdentity, PublicVerifierKeyRegistry,
};
use crate::ledger::{Ledger, ReplayReservationOutcome};
use crate::ontology::{
    DEFAULT_RECEIVER_AUDIENCE, LOCAL_PROTOTYPE_SIGNER_ID, REPLAY_DETECTED_REASON,
    REPLAY_RESERVATION_FAILED_REASON, UNVERIFIED_PROTOTYPE_OPERATION,
};
use crate::receipt::{AuthenticatorKind, Decision, Receipt, ReceiptEventKind};
use crate::runtime_mode::RuntimeMode;
use crate::schema::{apply_schema, TELEMETRY_TABLES};
use crate::verifier::{SignedVerifiedCallContext, VerificationError, VerifiedCallContext};
use async_trait::async_trait;
use libsec_core::ZenithPacket;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

const PROTOTYPE_RECEIPT_SIGNING_KEY: [u8; 32] = [7u8; 32];

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
    expected_audience: String,
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
                PROTOTYPE_RECEIPT_SIGNING_KEY,
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
            expected_audience: expected_audience.into(),
        }
    }

    pub fn expected_audience(&self) -> &str {
        &self.expected_audience
    }

    pub fn register(&mut self, opcode: u8, program: Box<dyn MachineProgram>) {
        let handler_id = crate::manifest::ReceiverManifest::default_v0()
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

        let handler_id = crate::manifest::ReceiverManifest::default_v0()
            .lookup(opcode)
            .ok()
            .map(|descriptor| descriptor.handler_id.clone());
        match handler_id.as_deref().and_then(|handler_id| self.programs.get(handler_id)) {
            Some(_) => eprintln!(
                "secS [Router]: rejected unverified handler route for opcode {:#04x}",
                opcode
            ),
            None => eprintln!("secS [Router]: rejected unmapped opcode {:#04x}", opcode),
        }
    }

    pub async fn record_reject(&self, packet: &ZenithPacket, error: VerificationError) {
        let timestamp = current_unix_seconds();
        let receipt = Receipt::reject_from_packet(
            format!("receipt-reject-{timestamp}-{:02x}", packet.opcode),
            packet,
            error,
            timestamp,
        );
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
    }

    pub async fn route_verified(&self, signed: &SignedVerifiedCallContext, payload: Vec<u8>) {
        let context = &signed.context;
        let payload_size = payload.len() as i64;
        let timestamp = current_unix_seconds();

        let verification_result = match self.identity.authenticator_kind() {
            AuthenticatorKind::LocalDevUntrusted => {
                self.verifier_keys
                    .verify_signed_context(signed, &self.expected_audience, timestamp)
            }
            _ => self.verifier_keys.verify_production_signed_context(
                signed,
                &self.expected_audience,
                timestamp,
            ),
        };
        if let Err(error) = verification_result {
            let reason = error.reason_code();
            if should_emit_signed_context_reject(&error) {
                self.record_verified_reject_receipt(signed, reason, timestamp)
                    .await;
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
            return;
        }

        match self
            .ledger
            .reserve_replay(context, &signed.signer_key_id, timestamp)
            .await
        {
            Ok(ReplayReservationOutcome::Reserved) => {}
            Ok(ReplayReservationOutcome::Duplicate) => {
                let reason = REPLAY_DETECTED_REASON;
                self.record_verified_reject_receipt(signed, reason, timestamp)
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
                return;
            }
            Err(e) => {
                let reason = REPLAY_RESERVATION_FAILED_REASON;
                eprintln!("secS [Ledger]: failed to reserve replay slot - {}", e);
                self.record_verified_reject_receipt(signed, reason, timestamp)
                    .await;
                self.record_operation_event(
                    ReceiptEventKind::PacketRejected,
                    signed,
                    timestamp,
                    Some(reason),
                )
                .await;
                return;
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

        self.record_verify_receipt(signed, timestamp).await;
        self.record_operation_event(ReceiptEventKind::OperationRouted, signed, timestamp, None)
            .await;

        if payload.len() > self.limits.max_payload_bytes {
            let reason = "payload_too_large";
            self.record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
                .await;
            self.record_operation_event(
                ReceiptEventKind::HandlerFailed,
                signed,
                timestamp,
                Some(reason),
            )
            .await;
            return;
        }

        let Some(handler_id) = context.handler_id.as_deref() else {
            let reason = "handler_unavailable";
            self.record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
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
            return;
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
                self.record_execution_receipt(signed, outcome.decision, reason, timestamp)
                    .await;
                let event_kind = match outcome.decision {
                    Decision::Accepted => ReceiptEventKind::HandlerSucceeded,
                    Decision::Rejected => ReceiptEventKind::HandlerFailed,
                };
                self.record_operation_event(event_kind, signed, timestamp, reason)
                    .await;
            }
            None => {
                let reason = "handler_unavailable";
                self.record_execution_receipt(signed, Decision::Rejected, Some(reason), timestamp)
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
            }
        }
    }

    async fn record_verified_reject_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        reason: &str,
        timestamp: u64,
    ) {
        let receipt = Receipt::reject_from_verified_context(
            format!(
                "receipt-reject-{timestamp}-{:02x}-{}",
                signed.context.opcode,
                context_receipt_suffix(&signed.context)
            ),
            &signed.context,
            reason,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
    }

    async fn record_verify_receipt(&self, signed: &SignedVerifiedCallContext, timestamp: u64) {
        let receipt = Receipt::verify_from_signed_context(
            format!(
                "receipt-verify-{timestamp}-{:02x}-{}",
                signed.context.opcode,
                context_receipt_suffix(&signed.context)
            ),
            signed,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
        self.record_operation_event(ReceiptEventKind::PacketVerified, signed, timestamp, None)
            .await;
    }

    async fn record_execution_receipt(
        &self,
        signed: &SignedVerifiedCallContext,
        decision: Decision,
        reason: Option<&str>,
        timestamp: u64,
    ) {
        let receipt = Receipt::execution(
            format!(
                "receipt-execute-{timestamp}-{:02x}-{}",
                signed.context.opcode,
                context_receipt_suffix(&signed.context)
            ),
            &signed.context,
            decision,
            reason,
            timestamp,
        );
        self.record_signed_receipt(receipt).await;
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
        if let Err(e) = self.ledger.record_receipt(&signed).await {
            eprintln!("secS [Ledger]: failed to write receipt - {}", e);
            return;
        }
        if let Err(e) = self
            .ledger
            .record_event(
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
            eprintln!("secS [Ledger]: failed to write receipt event - {}", e);
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
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn should_emit_signed_context_reject(error: &VerificationError) -> bool {
    matches!(
        error,
        VerificationError::ExpiredClaim
            | VerificationError::WrongAudience
            | VerificationError::InvalidSignature
    )
}

fn context_receipt_suffix(context: &VerifiedCallContext) -> String {
    let hash_prefix = context.packet_hash[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{}-{hash_prefix}", context.context_id)
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
        let mut child = match tokio::process::Command::new(&self.program)
            .args(&self.args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("secS [Subprocess]: failed to spawn - {}", e);
                return HandlerOutcome::rejected("handler_spawn_failed");
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = tokio::io::AsyncWriteExt::write_all(&mut stdin, payload).await {
                eprintln!(
                    "secS [Subprocess]: failed to write payload to stdin - {}",
                    e
                );
                return HandlerOutcome::rejected("handler_stdin_failed");
            }
        }
        match child.wait_with_output().await {
            Ok(output) if output.status.success() => {
                let output_bytes = output.stdout.len().saturating_add(output.stderr.len());
                if output_bytes > limits.max_output_bytes {
                    HandlerOutcome::rejected("output_too_large")
                } else {
                    HandlerOutcome::succeeded_with_output_bytes(output_bytes)
                }
            }
            Ok(_) => HandlerOutcome::rejected("handler_exit_failed"),
            Err(_) => HandlerOutcome::rejected("handler_wait_failed"),
        }
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
    router.register_handler("dev/json-validate", Box::new(LocalRustQueue));
    if matches!(
        runtime_mode,
        RuntimeMode::LocalDevPlaintext | RuntimeMode::LocalDevTunnel
    ) {
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
    router.register_handler("dev/jq-identity", Box::new(SubprocessForwarder::new("jq", vec!["."])));
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
